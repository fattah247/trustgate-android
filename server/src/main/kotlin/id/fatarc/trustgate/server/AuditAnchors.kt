package id.fatarc.trustgate.server

import id.fatarc.trustgate.backend.audit.AuditCheckpoint
import id.fatarc.trustgate.backend.audit.CheckpointSink
import id.fatarc.trustgate.backend.audit.Timestamper
import id.fatarc.trustgate.domain.api.TrustGateJson
import id.fatarc.trustgate.domain.signing.ReferenceSigningScheme
import java.io.File
import java.io.FileOutputStream
import java.math.BigInteger
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.security.KeyPair
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.SecureRandom
import java.time.Duration
import java.time.Instant
import java.util.Base64
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers
import org.bouncycastle.cms.CMSSignedData
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder
import org.bouncycastle.tsp.TSPAlgorithms
import org.bouncycastle.tsp.TimeStampRequestGenerator
import org.bouncycastle.tsp.TimeStampResponse
import org.bouncycastle.tsp.TimeStampToken
import org.slf4j.LoggerFactory

/**
 * Checkpoints as JSON lines appended to a file outside the database. Put it on storage the
 * database's owner can't rewrite, such as a write-once bucket, or ship each line to one.
 */
class FileCheckpointSink(private val file: File) : CheckpointSink {
    @Synchronized
    override fun append(checkpoint: AuditCheckpoint) {
        file.parentFile?.mkdirs()
        FileOutputStream(file, true).use { out ->
            out.write((TrustGateJson.encodeToString(AuditCheckpoint.serializer(), checkpoint) + "\n").toByteArray())
            out.fd.sync()
        }
    }

    @Synchronized
    override fun all(): List<AuditCheckpoint> =
        if (!file.exists()) emptyList() else file.readLines().filter { it.isNotBlank() }.map { TrustGateJson.decodeFromString(AuditCheckpoint.serializer(), it) }
}

/**
 * An RFC 3161 timestamping authority reached over HTTP. Only tokens signed by one of the
 * [trustedCertificates] (SHA-256 of each certificate, lowercase hex) count, so a token made with
 * any other key, however valid its signature, doesn't.
 */
class Rfc3161Timestamper(
    private val trustedCertificates: Set<String>,
    private val send: (request: ByteArray) -> ByteArray,
) : Timestamper {
    private val log = LoggerFactory.getLogger(Rfc3161Timestamper::class.java)

    init {
        require(trustedCertificates.isNotEmpty()) { "A timestamping authority needs at least one trusted certificate." }
    }

    override fun timestamp(digest: ByteArray): String? = runCatching {
        val request = TimeStampRequestGenerator().apply { setCertReq(true) }
            .generate(TSPAlgorithms.SHA256, digest, BigInteger(64, SecureRandom()))
        val response = TimeStampResponse(send(request.encoded))
        // Checks the status, and that the token answers this request's digest and nonce.
        response.validate(request)
        val token = Base64.getEncoder().encodeToString(checkNotNull(response.timeStampToken) { "No timestamp in the response." }.encoded)
        // A token that won't verify later is no use now either, for example after the authority changed certificates.
        checkNotNull(timeOf(token, digest)) { "The timestamp isn't signed by a trusted certificate." }
        token
    }.onFailure { log.warn("Couldn't get a timestamp: {}", it.message) }.getOrNull()

    override fun timeOf(token: String, digest: ByteArray): Instant? = runCatching {
        val stamp = TimeStampToken(CMSSignedData(Base64.getDecoder().decode(token)))
        val info = stamp.timeStampInfo
        check(info.hashAlgorithm.algorithm == NISTObjectIdentifiers.id_sha256) { "Not a SHA-256 timestamp." }
        check(MessageDigest.isEqual(info.messageImprintDigest, digest)) { "The timestamp is over another digest." }
        val certificate = stamp.certificates.getMatches(null).single { stamp.sid.match(it) }
        check(ReferenceSigningScheme.sha256Hex(certificate.encoded) in trustedCertificates) { "Signed by a certificate that isn't trusted." }
        // Verifies the signature, and that the certificate is for timestamping and was valid at the time.
        stamp.validate(JcaSimpleSignerInfoVerifierBuilder().build(certificate))
        info.genTime.toInstant()
    }.getOrNull()

    companion object {
        fun overHttp(url: String, trustedCertificates: Set<String>): Rfc3161Timestamper {
            val http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build()
            return Rfc3161Timestamper(trustedCertificates) { request ->
                val response = http.send(
                    HttpRequest.newBuilder(URI(url))
                        .header("Content-Type", "application/timestamp-query")
                        .timeout(Duration.ofSeconds(20))
                        .POST(HttpRequest.BodyPublishers.ofByteArray(request))
                        .build(),
                    HttpResponse.BodyHandlers.ofByteArray(),
                )
                check(response.statusCode() == 200) { "The timestamping authority answered ${response.statusCode()}" }
                response.body()
            }
        }
    }
}

/** The audit anchor key from its PKCS#12 file: the only entry in it. */
fun loadAnchorKey(keystore: File, password: String): KeyPair {
    val store = KeyStore.getInstance(keystore, password.toCharArray())
    val alias = store.aliases().toList().single()
    return KeyPair(store.getCertificate(alias).publicKey, store.getKey(alias, password.toCharArray()) as PrivateKey)
}
