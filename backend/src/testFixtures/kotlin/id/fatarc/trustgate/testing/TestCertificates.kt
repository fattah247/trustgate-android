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

/** Stands in for a device's attestation: certifies keys under one root with a KeyDescription extension. */
class TestAttestation(private val root: TestKey = TestKey()) {
    private val rootCertificate = certificate(root.pair.public, subject = "root", issuerKey = root.pair.private, issuer = "root")

    fun chainFor(subjectKey: PublicKey, challenge: ByteArray, requiresAuthentication: Boolean = false): List<ByteArray> {
        val enforced = listOf(
            if (requiresAuthentication) explicit(504, integer(2)) else explicit(503, tlv(0x05, ByteArray(0))),
            explicit(704, rootOfTrust(locked = true, bootState = 0)),
        )
        val leaf = certificate(
            subjectKey = subjectKey,
            subject = "key",
            issuerKey = root.pair.private,
            issuer = "root",
            keyDescription = keyDescription(challenge, hardwareEnforced = enforced),
        )
        return listOf(leaf, rootCertificate)
    }
}

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
