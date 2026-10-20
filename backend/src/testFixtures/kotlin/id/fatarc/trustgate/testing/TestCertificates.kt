package id.fatarc.trustgate.testing

import id.fatarc.trustgate.domain.signing.ReferenceSigningScheme
import id.fatarc.trustgate.testing.DerWriter.bitString
import id.fatarc.trustgate.testing.DerWriter.boolean
import id.fatarc.trustgate.testing.DerWriter.enumerated
import id.fatarc.trustgate.testing.DerWriter.explicit
import id.fatarc.trustgate.testing.DerWriter.integer
import id.fatarc.trustgate.testing.DerWriter.octetString
import id.fatarc.trustgate.testing.DerWriter.oid
import id.fatarc.trustgate.testing.DerWriter.sequence
import id.fatarc.trustgate.testing.DerWriter.set
import id.fatarc.trustgate.testing.DerWriter.tlv
import id.fatarc.trustgate.testing.DerWriter.utcTime
import id.fatarc.trustgate.testing.DerWriter.utf8String
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature

private val ECDSA_WITH_SHA256 = sequence(oid(1, 2, 840, 10045, 4, 3, 2))
private val KEY_DESCRIPTION = oid(1, 3, 6, 1, 4, 1, 11129, 2, 1, 17)

/** What Keystore returns for a key on a device that can't attest: one certificate the key signs itself. */
fun selfSignedChain(key: TestKey): List<ByteArray> =
    listOf(certificate(key.pair.public, subject = "key", issuerKey = key.pair.private, issuer = "key"))

fun certificate(
    subjectKey: PublicKey,
    subject: String,
    issuerKey: PrivateKey,
    issuer: String,
    keyDescription: ByteArray? = null,
): ByteArray {
    val extensions = keyDescription?.let { explicit(3, sequence(sequence(KEY_DESCRIPTION, octetString(it)))) }
    val tbs = sequence(
        explicit(0, integer(2)),
        integer(1),
        ECDSA_WITH_SHA256,
        name(issuer),
        sequence(utcTime("260101000000Z"), utcTime("360101000000Z")),
        name(subject),
        subjectKey.encoded,
        *listOfNotNull(extensions).toTypedArray(),
    )
    val signature = Signature.getInstance(ReferenceSigningScheme.SIGNATURE_ALGORITHM).run {
        initSign(issuerKey)
        update(tbs)
        sign()
    }
    return sequence(tbs, ECDSA_WITH_SHA256, bitString(signature))
}

const val TEST_PACKAGE = "id.fatarc.trustgate"

/** SHA-256 of the signing certificate the test app is "signed" with, lowercase hex. */
val TEST_SIGNER_DIGEST: String = ReferenceSigningScheme.sha256Hex("test signing certificate")

/** Stands in for a device's attestation: certifies keys under one root with a KeyDescription extension. */
class TestAttestation(private val root: TestKey = TestKey()) {
    private val rootCertificate = certificate(root.pair.public, subject = "root", issuerKey = root.pair.private, issuer = "root")

    val rootKeyFingerprint: String = ReferenceSigningScheme.sha256Hex(root.encodedPublicKey)

    fun chainFor(
        subjectKey: PublicKey,
        challenge: ByteArray,
        requiresAuthentication: Boolean = false,
        packageName: String = TEST_PACKAGE,
        signerDigest: String = TEST_SIGNER_DIGEST,
        securityLevel: Int = 1,
        bootloaderLocked: Boolean = true,
        verifiedBootState: Int = 0,
        osPatchLevel: Int = 202609,
        authTimeoutSeconds: Int? = null,
        origin: Int = 0,
        appVersionCode: Int = 1,
    ): List<ByteArray> {
        val enforced = listOfNotNull(
            if (requiresAuthentication) explicit(504, integer(2)) else explicit(503, tlv(0x05, ByteArray(0))),
            authTimeoutSeconds?.let { explicit(505, integer(it)) },
            explicit(702, integer(origin)),
            explicit(704, rootOfTrust(locked = bootloaderLocked, bootState = verifiedBootState)),
            explicit(706, integer(osPatchLevel)),
        )
        // Keystore itself adds the app's identity, so it sits in the software-enforced list.
        val applicationId = explicit(709, octetString(attestationApplicationId(packageName, signerDigest, appVersionCode)))
        val description = if (securityLevel == 0) {
            keyDescription(challenge, securityLevel = 0, softwareEnforced = enforced + applicationId)
        } else {
            keyDescription(challenge, securityLevel = securityLevel, softwareEnforced = listOf(applicationId), hardwareEnforced = enforced)
        }
        val leaf = certificate(subjectKey, subject = "key", issuerKey = root.pair.private, issuer = "root", keyDescription = description)
        return listOf(leaf, rootCertificate)
    }
}

fun attestationApplicationId(packageName: String, signerDigest: String, versionCode: Int = 1): ByteArray = sequence(
    set(sequence(octetString(packageName.toByteArray()), integer(versionCode))),
    set(octetString(signerDigest.chunked(2).map { it.toInt(16).toByte() }.toByteArray())),
)

/** KeyDescription: version, levels, challenge, unique ID, then the software and hardware enforced lists. */
fun keyDescription(
    challenge: ByteArray,
    securityLevel: Int = 1,
    softwareEnforced: List<ByteArray> = emptyList(),
    hardwareEnforced: List<ByteArray> = emptyList(),
): ByteArray = sequence(
    integer(100),
    enumerated(securityLevel),
    integer(100),
    enumerated(securityLevel),
    octetString(challenge),
    octetString(ByteArray(0)),
    sequence(*softwareEnforced.toTypedArray()),
    sequence(*hardwareEnforced.toTypedArray()),
)

fun rootOfTrust(locked: Boolean, bootState: Int): ByteArray = sequence(
    octetString(ByteArray(32)),
    boolean(locked),
    enumerated(bootState),
    octetString(ByteArray(32)),
)

private fun name(commonName: String): ByteArray = sequence(set(sequence(oid(2, 5, 4, 3), utf8String(commonName))))
