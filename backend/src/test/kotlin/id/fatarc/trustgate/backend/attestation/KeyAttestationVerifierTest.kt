package id.fatarc.trustgate.backend.attestation

import com.google.common.truth.Truth.assertThat
import id.fatarc.trustgate.testing.TestAttestation
import id.fatarc.trustgate.testing.TestKey
import id.fatarc.trustgate.testing.selfSignedChain
import org.junit.Test

class KeyAttestationVerifierTest {
    private val key = TestKey()
    private val challenge = "registration-challenge".toByteArray()

    @Test
    fun `an attestation chain for the key and challenge verifies`() {
        val report = KeyAttestationVerifier.verify(TestAttestation().chainFor(key.pair.public, challenge), key.encodedPublicKey, challenge)

        assertThat(report.isVerified).isTrue()
        assertThat(report.chainLength).isEqualTo(2)
        assertThat(report.description?.rootOfTrust?.deviceLocked).isTrue()
    }

    @Test
    fun `an attestation for another challenge is attested but not verified`() {
        val report = KeyAttestationVerifier.verify(
            TestAttestation().chainFor(key.pair.public, "another".toByteArray()),
            key.encodedPublicKey,
            challenge,
        )

        assertThat(report.isAttested).isTrue()
        assertThat(report.challengeMatches).isFalse()
        assertThat(report.isVerified).isFalse()
    }

    @Test
    fun `a self-signed certificate is well formed but carries no attestation`() {
        val report = KeyAttestationVerifier.verify(selfSignedChain(key), key.encodedPublicKey, challenge)

        assertThat(report.wellFormed).isTrue()
        assertThat(report.isAttested).isFalse()
        assertThat(report.leafMatchesKey).isTrue()
        assertThat(report.chainSignaturesValid).isTrue()
    }

    @Test
    fun `bytes that aren't certificates are reported as malformed`() {
        val report = KeyAttestationVerifier.verify(listOf(byteArrayOf(0x30, 0x03, 0x01, 0x02, 0x03)), key.encodedPublicKey, challenge)

        assertThat(report.wellFormed).isFalse()
    }
}
