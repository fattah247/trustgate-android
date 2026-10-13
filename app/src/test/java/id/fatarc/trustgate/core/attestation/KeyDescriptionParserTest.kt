package id.fatarc.trustgate.core.attestation

import com.google.common.truth.Truth.assertThat
import org.junit.Test
import java.io.ByteArrayOutputStream

class KeyDescriptionParserTest {
    private val challenge = "registration-challenge".toByteArray()

    @Test
    fun `reads security levels, challenge, and root of trust`() {
        val description = KeyDescriptionParser.parse(
            keyDescription(
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
            keyDescription(hardwareEnforced = listOf(explicit(503, byteArrayOf(0x05, 0x00)))),
        )

        assertThat(description.userAuthRequired).isFalse()
    }

    @Test
    fun `a software key is judged by its software-enforced list`() {
        val description = KeyDescriptionParser.parse(
            keyDescription(
                securityLevel = 0,
                softwareEnforced = listOf(explicit(504, integer(2))),
            ),
        )

        assertThat(description.keymasterSecurityLevel).isEqualTo(SecurityLevel.SOFTWARE)
        assertThat(description.userAuthRequired).isTrue()
        assertThat(description.rootOfTrust).isNull()
    }

    @Test
    fun `an unlocked bootloader is reported`() {
        val description = KeyDescriptionParser.parse(
            keyDescription(hardwareEnforced = listOf(explicit(704, rootOfTrust(locked = false, bootState = 2)))),
        )

        assertThat(description.rootOfTrust).isEqualTo(RootOfTrust(deviceLocked = false, verifiedBootState = VerifiedBootState.UNVERIFIED))
    }

    @Test
    fun `the certificate extension wrapper is removed before parsing`() {
        val inner = keyDescription()

        assertThat(Der.unwrapOctetString(tlv(0x04, inner))).isEqualTo(inner)
    }

    @Test
    fun `an empty chain reports nothing attested`() {
        val report = KeyAttestationVerifier.verify(emptyList(), byteArrayOf(1), challenge)

        assertThat(report.isAttested).isFalse()
        assertThat(report.isVerified).isFalse()
    }

    // A minimal DER writer, enough to build KeyDescription records by hand.

    private fun keyDescription(
        securityLevel: Int = 1,
        softwareEnforced: List<ByteArray> = emptyList(),
        hardwareEnforced: List<ByteArray> = emptyList(),
    ): ByteArray = sequence(
        integer(100),
        enumerated(securityLevel),
        integer(100),
        enumerated(securityLevel),
        tlv(0x04, challenge),
        tlv(0x04, ByteArray(0)),
        sequence(*softwareEnforced.toTypedArray()),
        sequence(*hardwareEnforced.toTypedArray()),
    )

    private fun rootOfTrust(locked: Boolean, bootState: Int): ByteArray = sequence(
        tlv(0x04, ByteArray(32)),
        tlv(0x01, byteArrayOf(if (locked) 0xFF.toByte() else 0)),
        enumerated(bootState),
        tlv(0x04, ByteArray(32)),
    )

    private fun sequence(vararg children: ByteArray): ByteArray =
        tlv(0x30, children.fold(ByteArray(0)) { acc, child -> acc + child })

    private fun integer(value: Int): ByteArray = tlv(0x02, minimalBytes(value))

    private fun enumerated(value: Int): ByteArray = tlv(0x0A, minimalBytes(value))

    /** [n] EXPLICIT with the high-tag-number form AuthorizationList uses. */
    private fun explicit(tagNumber: Int, inner: ByteArray): ByteArray {
        val tag = ByteArrayOutputStream()
        tag.write(0xBF)
        val groups = generateSequence(tagNumber) { it shr 7 }.takeWhile { it > 0 }.map { it and 0x7F }.toList().reversed()
        groups.forEachIndexed { index, group -> tag.write(if (index < groups.lastIndex) group or 0x80 else group) }
        return tag.toByteArray() + length(inner.size) + inner
    }

    private fun tlv(tag: Int, content: ByteArray): ByteArray = byteArrayOf(tag.toByte()) + length(content.size) + content

    private fun length(size: Int): ByteArray = when {
        size < 0x80 -> byteArrayOf(size.toByte())
        size <= 0xFF -> byteArrayOf(0x81.toByte(), size.toByte())
        else -> byteArrayOf(0x82.toByte(), (size shr 8).toByte(), size.toByte())
    }

    private fun minimalBytes(value: Int): ByteArray = when {
        value in 0..0x7F -> byteArrayOf(value.toByte())
        else -> byteArrayOf((value shr 8).toByte(), value.toByte())
    }
}
