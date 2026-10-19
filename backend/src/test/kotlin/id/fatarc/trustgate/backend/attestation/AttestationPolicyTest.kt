package id.fatarc.trustgate.backend.attestation

import com.google.common.truth.Truth.assertThat
import id.fatarc.trustgate.testing.TestAttestation
import id.fatarc.trustgate.testing.TestKey
import id.fatarc.trustgate.testing.developmentPolicy
import id.fatarc.trustgate.testing.selfSignedChain
import id.fatarc.trustgate.testing.strictPolicyTrusting
import org.junit.Test
import java.security.PublicKey

class AttestationPolicyTest {
    private val key = TestKey()
    private val challenge = "registration-challenge".toByteArray()
    private val attestation = TestAttestation()
    private val strict = strictPolicyTrusting(attestation, minimumOsPatchLevel = 202601)

    private fun problem(
        policy: AttestationPolicy = strict,
        revocations: RevocationList = RevocationList.EMPTY,
        chain: (PublicKey) -> List<ByteArray> = { attestation.chainFor(it, challenge) },
    ): String? = policy.problemWith(KeyAttestationVerifier.verify(chain(key.pair.public), key.encodedPublicKey, challenge), revocations)

    @Test
    fun `a hardware key attested for this app on a verified device passes the strict policy`() {
        assertThat(problem()).isNull()
    }

    @Test
    fun `a chain that doesn't end at a pinned root is refused`() {
        assertThat(problem { TestAttestation().chainFor(it, challenge) }).contains("Google attestation root")
    }

    @Test
    fun `a key generated for another app is refused`() {
        assertThat(problem { attestation.chainFor(it, challenge, packageName = "com.example.clone") }).contains("another app")
    }

    @Test
    fun `a key from a repackaged app is refused by its signing certificate`() {
        assertThat(problem { attestation.chainFor(it, challenge, signerDigest = "ab".repeat(32)) }).contains("repackaged")
    }

    @Test
    fun `an imported key is refused`() {
        assertThat(problem { attestation.chainFor(it, challenge, origin = 2) }).contains("instead of being generated")
    }

    @Test
    fun `a software key is refused by the strict policy and accepted in development`() {
        val chain: (PublicKey) -> List<ByteArray> = { attestation.chainFor(it, challenge, securityLevel = 0) }

        assertThat(problem(chain = chain)).contains("secure hardware")
        assertThat(problem(policy = developmentPolicy, chain = chain)).isNull()
    }

    @Test
    fun `an unlocked bootloader or unverified boot is refused by the strict policy`() {
        assertThat(problem { attestation.chainFor(it, challenge, bootloaderLocked = false) }).contains("locked bootloader")
        assertThat(problem { attestation.chainFor(it, challenge, verifiedBootState = 2) }).contains("verified system")
    }

    @Test
    fun `a security patch level older than the minimum is refused`() {
        assertThat(problem { attestation.chainFor(it, challenge, osPatchLevel = 202312) }).contains("patch level")
    }

    @Test
    fun `a certificate Google revoked is refused anywhere in the chain`() {
        val chain = attestation.chainFor(key.pair.public, challenge)
        val serial = KeyAttestationVerifier.verify(chain, key.encodedPublicKey, challenge).certificateSerials.last()
        val revocations = RevocationList.parse("""{"entries": {"$serial": {"status": "REVOKED", "reason": "KEY_COMPROMISE"}}}""")

        assertThat(problem(revocations = revocations) { chain }).contains("revoked")
    }

    @Test
    fun `a device that can't attest is refused by the strict policy and accepted in development`() {
        val selfSigned: (PublicKey) -> List<ByteArray> = { selfSignedChain(key) }

        assertThat(problem(chain = selfSigned)).contains("only attested keys")
        assertThat(problem(policy = developmentPolicy, chain = selfSigned)).isNull()
    }
}
