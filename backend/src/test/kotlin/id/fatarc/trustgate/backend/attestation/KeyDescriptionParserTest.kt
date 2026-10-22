package id.fatarc.trustgate.backend.attestation

import com.google.common.truth.Truth.assertThat
import id.fatarc.trustgate.testing.DerWriter.explicit
import id.fatarc.trustgate.testing.DerWriter.integer
import id.fatarc.trustgate.testing.DerWriter.octetString
import id.fatarc.trustgate.testing.DerWriter.tlv
import id.fatarc.trustgate.testing.attestationApplicationId
import id.fatarc.trustgate.testing.keyDescription
import id.fatarc.trustgate.testing.rootOfTrust
import id.fatarc.trustgate.domain.api.SecurityLevel
import id.fatarc.trustgate.domain.api.VerifiedBootState
import org.junit.Test

class KeyDescriptionParserTest {
    private val challenge = "registration-challenge".toByteArray()

    @Test
    fun `reads security levels, challenge, and root of trust`() {
        val description = KeyDescriptionParser.parse(
            keyDescription(
                challenge,
                hardwareEnforced = listOf(
                    explicit(504, integer(2)),
                    explicit(704, rootOfTrust(locked = true, bootState = 0)),
                ),
            ),
        )

        assertThat(description.attestationVersion).isEqualTo(100)
        assertThat(description.attestationSecurityLevel).isEqualTo(SecurityLevel.TRUSTED_ENVIRONMENT)
        assertThat(description.keymasterSecurityLevel).isEqualTo(SecurityLevel.TRUSTED_ENVIRONMENT)
        assertThat(description.attestationChallenge).isEqualTo(challenge)
        assertThat(description.rootOfTrust).isEqualTo(RootOfTrust(deviceLocked = true, verifiedBootState = VerifiedBootState.VERIFIED))
        assertThat(description.userAuthRequired).isTrue()
    }

    @Test
    fun `a key marked noAuthRequired does not count as requiring authentication`() {
        val description = KeyDescriptionParser.parse(
            keyDescription(challenge, hardwareEnforced = listOf(explicit(503, tlv(0x05, ByteArray(0))))),
        )

        assertThat(description.userAuthRequired).isFalse()
    }

    @Test
    fun `a software key is judged by its software-enforced list`() {
        val description = KeyDescriptionParser.parse(
            keyDescription(challenge, securityLevel = 0, softwareEnforced = listOf(explicit(504, integer(2)))),
        )

        assertThat(description.keymasterSecurityLevel).isEqualTo(SecurityLevel.SOFTWARE)
        assertThat(description.userAuthRequired).isTrue()
        assertThat(description.rootOfTrust).isNull()
    }

    @Test
    fun `an unlocked bootloader is reported`() {
        val description = KeyDescriptionParser.parse(
            keyDescription(challenge, hardwareEnforced = listOf(explicit(704, rootOfTrust(locked = false, bootState = 2)))),
        )

        assertThat(description.rootOfTrust).isEqualTo(RootOfTrust(deviceLocked = false, verifiedBootState = VerifiedBootState.UNVERIFIED))
    }

    @Test
    fun `reads the app identity, origin, patch level, and auth timeout`() {
        val description = KeyDescriptionParser.parse(
            keyDescription(
                challenge,
                softwareEnforced = listOf(explicit(709, octetString(attestationApplicationId("id.fatarc.trustgate", "0f".repeat(32))))),
                hardwareEnforced = listOf(
                    explicit(504, integer(2)),
                    explicit(505, integer(30)),
                    explicit(702, integer(0)),
                    explicit(706, integer(202609)),
                ),
            ),
        )

        assertThat(description.applicationId?.packageNames).containsExactly("id.fatarc.trustgate")
        assertThat(description.applicationId?.signatureDigests).containsExactly("0f".repeat(32))
        assertThat(description.origin).isEqualTo(KeyOrigin.GENERATED)
        assertThat(description.osPatchLevel).isEqualTo(202609)
        assertThat(description.authTimeoutSeconds).isEqualTo(30)
    }
}
