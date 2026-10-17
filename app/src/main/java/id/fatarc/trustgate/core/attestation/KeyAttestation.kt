package id.fatarc.trustgate.core.attestation

import id.fatarc.trustgate.domain.signing.ReferenceSigningScheme
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/** Where a key lives, as Android Keystore or its attestation reports it. */
enum class SecurityLevel {
    SOFTWARE,
    TRUSTED_ENVIRONMENT,
    STRONGBOX,
    UNKNOWN,
}

enum class VerifiedBootState {
    VERIFIED,
    SELF_SIGNED,
    UNVERIFIED,
    FAILED,
}

data class RootOfTrust(
    val deviceLocked: Boolean,
    val verifiedBootState: VerifiedBootState,
)

/** The fields of Android's KeyDescription attestation extension that the backend acts on. */
class KeyDescription(
    val attestationVersion: Int,
    val attestationSecurityLevel: SecurityLevel,
    val keymasterSecurityLevel: SecurityLevel,
    val attestationChallenge: ByteArray,
    val rootOfTrust: RootOfTrust?,
    /** The key can only be used after the person authenticates, as enforced at [keymasterSecurityLevel]. */
    val userAuthRequired: Boolean,
)

/** What the backend learned from a key's attestation certificate chain. */
data class AttestationReport(
    val chainLength: Int,
    /** Each certificate is signed by the next, and the last one signs itself. */
    val chainSignaturesValid: Boolean,
    /** The first certificate certifies the very key being registered. */
    val leafMatchesKey: Boolean,
    /** The attestation carries the one-time challenge the backend issued for this registration. */
    val challengeMatches: Boolean,
    val description: KeyDescription?,
    /** First 16 hex characters of the root's public key hash, for comparing against known roots. */
    val rootKeyFingerprint: String?,
    /** Every certificate parsed, and the attestation extension, when present, could be read. */
    val wellFormed: Boolean = true,
) {
    val isAttested: Boolean get() = description != null

    /** Everything checks out. Production also pins the root to Google's and consults the revocation list. */
    val isVerified: Boolean get() = isAttested && chainSignaturesValid && leafMatchesKey && challengeMatches

    companion object {
        val None = AttestationReport(
            chainLength = 0,
            chainSignaturesValid = false,
            leafMatchesKey = false,
            challengeMatches = false,
            description = null,
            rootKeyFingerprint = null,
        )
    }
}

object KeyAttestationVerifier {
    const val KEY_DESCRIPTION_OID = "1.3.6.1.4.1.11129.2.1.17"

    fun verify(
        chain: List<ByteArray>,
        expectedPublicKey: ByteArray,
        expectedChallenge: ByteArray,
    ): AttestationReport {
        if (chain.isEmpty()) return AttestationReport.None
        val certificates = runCatching {
            val factory = CertificateFactory.getInstance("X.509")
            chain.map { factory.generateCertificate(ByteArrayInputStream(it)) as X509Certificate }
        }.getOrElse { return AttestationReport.None.copy(chainLength = chain.size, wellFormed = false) }

        val linksValid = certificates.zipWithNext().all { (child, issuer) -> child.isSignedBy(issuer) }
        val rootSelfSigned = certificates.last().isSignedBy(certificates.last())
        val leaf = certificates.first()
        val extension = leaf.getExtensionValue(KEY_DESCRIPTION_OID)
        val description = extension
            ?.let { runCatching { KeyDescriptionParser.parse(Der.unwrapOctetString(it)) }.getOrNull() }

        return AttestationReport(
            chainLength = certificates.size,
            chainSignaturesValid = linksValid && rootSelfSigned,
            leafMatchesKey = leaf.publicKey.encoded.contentEquals(expectedPublicKey),
            challengeMatches = description?.attestationChallenge?.contentEquals(expectedChallenge) == true,
            description = description,
            rootKeyFingerprint = ReferenceSigningScheme.sha256Hex(certificates.last().publicKey.encoded).take(16),
            wellFormed = extension == null || description != null,
        )
    }

    private fun X509Certificate.isSignedBy(issuer: X509Certificate): Boolean =
        runCatching { verify(issuer.publicKey) }.isSuccess
}

/**
 * Reads KeyDescription (see the Android key attestation schema):
 * SEQUENCE { version, attestationSecurityLevel, keyMintVersion, keyMintSecurityLevel,
 * attestationChallenge, uniqueId, softwareEnforced, hardwareEnforced }.
 */
object KeyDescriptionParser {
    private const val TAG_NO_AUTH_REQUIRED = 503
    private const val TAG_USER_AUTH_TYPE = 504
    private const val TAG_ROOT_OF_TRUST = 704

    fun parse(der: ByteArray): KeyDescription {
        val fields = Der.Reader(der).readElement().expectSequence().children()
        require(fields.size >= 8) { "KeyDescription has ${fields.size} fields, expected 8." }
        val keymasterLevel = securityLevel(fields[3].integerValue())
        val softwareEnforced = authorizationList(fields[6])
        val hardwareEnforced = authorizationList(fields[7])
        val enforcing = if (keymasterLevel == SecurityLevel.SOFTWARE) softwareEnforced else hardwareEnforced

        return KeyDescription(
            attestationVersion = fields[0].integerValue(),
            attestationSecurityLevel = securityLevel(fields[1].integerValue()),
            keymasterSecurityLevel = keymasterLevel,
            attestationChallenge = fields[4].content,
            rootOfTrust = (hardwareEnforced[TAG_ROOT_OF_TRUST] ?: softwareEnforced[TAG_ROOT_OF_TRUST])?.let(::rootOfTrust),
            userAuthRequired = TAG_USER_AUTH_TYPE in enforcing && TAG_NO_AUTH_REQUIRED !in enforcing,
        )
    }

    /** AuthorizationList is a SEQUENCE of explicitly tagged fields; this maps tag number to its inner value. */
    private fun authorizationList(element: Der.Element): Map<Int, Der.Element> =
        element.expectSequence().children()
            .filter { it.tagClass == Der.CONTEXT_SPECIFIC }
            .associate { tagged -> tagged.tagNumber to Der.Reader(tagged.content).readElement() }

    private fun rootOfTrust(element: Der.Element): RootOfTrust {
        val fields = element.expectSequence().children()
        return RootOfTrust(
            deviceLocked = fields[1].booleanValue(),
            verifiedBootState = when (fields[2].integerValue()) {
                0 -> VerifiedBootState.VERIFIED
                1 -> VerifiedBootState.SELF_SIGNED
                2 -> VerifiedBootState.UNVERIFIED
                else -> VerifiedBootState.FAILED
            },
        )
    }

    private fun securityLevel(value: Int): SecurityLevel = when (value) {
        0 -> SecurityLevel.SOFTWARE
        1 -> SecurityLevel.TRUSTED_ENVIRONMENT
        2 -> SecurityLevel.STRONGBOX
        else -> SecurityLevel.UNKNOWN
    }
}

/** Just enough DER to read attestation records: tags (including high tag numbers), lengths, and primitives. */
internal object Der {
    const val UNIVERSAL = 0x00
    const val CONTEXT_SPECIFIC = 0x80
    private const val SEQUENCE = 0x10
    private const val OCTET_STRING = 0x04

    class Element(
        val tagClass: Int,
        val constructed: Boolean,
        val tagNumber: Int,
        val content: ByteArray,
    ) {
        fun expectSequence(): Element = apply {
            require(tagClass == UNIVERSAL && constructed && tagNumber == SEQUENCE) { "Expected a SEQUENCE." }
        }

        fun children(): List<Element> {
            val reader = Reader(content)
            return buildList { while (reader.hasMore()) add(reader.readElement()) }
        }

        /** INTEGER or ENUMERATED that fits in an Int. */
        fun integerValue(): Int {
            require(content.isNotEmpty() && content.size <= 4) { "Integer of ${content.size} bytes is out of range." }
            return content.fold(if (content[0] < 0) -1 else 0) { acc, byte -> (acc shl 8) or (byte.toInt() and 0xFF) }
        }

        fun booleanValue(): Boolean = content.singleOrNull()?.let { it.toInt() != 0 } ?: error("Malformed BOOLEAN.")
    }

    class Reader(private val bytes: ByteArray) {
        private var position = 0

        fun hasMore(): Boolean = position < bytes.size

        fun readElement(): Element {
            val first = next()
            val tagClass = first and 0xC0
            val constructed = first and 0x20 != 0
            var tagNumber = first and 0x1F
            if (tagNumber == 0x1F) {
                tagNumber = 0
                do {
                    val part = next()
                    tagNumber = (tagNumber shl 7) or (part and 0x7F)
                    require(tagNumber <= 0xFFFFFF) { "Tag number too large." }
                } while (part and 0x80 != 0)
            }
            val length = readLength()
            require(length <= bytes.size - position) { "Element runs past the end of its container." }
            val content = bytes.copyOfRange(position, position + length)
            position += length
            return Element(tagClass, constructed, tagNumber, content)
        }

        private fun readLength(): Int {
            val first = next()
            if (first < 0x80) return first
            val count = first and 0x7F
            require(count in 1..3) { "Unsupported length encoding." }
            var length = 0
            repeat(count) { length = (length shl 8) or next() }
            return length
        }

        private fun next(): Int {
            require(position < bytes.size) { "Unexpected end of DER data." }
            return bytes[position++].toInt() and 0xFF
        }
    }

    /** X509Certificate.getExtensionValue wraps the extension in one more OCTET STRING. */
    fun unwrapOctetString(der: ByteArray): ByteArray {
        val element = Reader(der).readElement()
        require(element.tagClass == UNIVERSAL && element.tagNumber == OCTET_STRING) { "Expected an OCTET STRING." }
        return element.content
    }
}
