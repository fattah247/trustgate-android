package id.fatarc.trustgate.backend.attestation

import id.fatarc.trustgate.domain.signing.ReferenceSigningScheme
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64

/** Google's published attestation roots, bundled so the backend pins them without a network call. */
object GoogleAttestationRoots {
    val certificates: List<X509Certificate> by lazy {
        val pem = checkNotNull(javaClass.getResource("/attestation/google-roots.pem")) { "Google attestation roots missing." }.readText()
        val factory = CertificateFactory.getInstance("X.509")
        Regex("-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----", RegexOption.DOT_MATCHES_ALL)
            .findAll(pem)
            .map { block -> Base64.getMimeDecoder().decode(block.groupValues[1]) }
            .map { der -> factory.generateCertificate(ByteArrayInputStream(der)) as X509Certificate }
            .toList()
    }

    /** SHA-256 of each root's public key. Rotated roots that keep their key share a fingerprint. */
    val keyFingerprints: Set<String> by lazy {
        certificates.mapTo(mutableSetOf()) { ReferenceSigningScheme.sha256Hex(it.publicKey.encoded) }
    }
}
