package id.fatarc.trustgate.core.crypto

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * The one definition of how reference requests are signed, shared by the signer and the verifier
 * so the two sides cannot drift apart.
 */
internal object ReferenceSigningScheme {
    const val METHOD = "POST"
    const val PATH = "/payments/reference"

    const val HEADER_TIMESTAMP = "X-Request-Timestamp"
    const val HEADER_NONCE = "X-Request-Nonce"
    const val HEADER_SIGNATURE = "X-Request-Signature"

    /** Bundled on purpose so the limitation stays visible; production keys belong in managed custody. */
    const val REFERENCE_SECRET = "trustgate-reference-local-signing-key"

    fun signingInput(
        method: String,
        path: String,
        timestamp: String,
        nonce: String,
        bodyHash: String,
    ): String = listOf(method, path, timestamp, nonce, bodyHash).joinToString("\n")

    fun sha256Hex(value: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(value.toByteArray(StandardCharsets.UTF_8)).joinToString("") {
            "%02x".format(it)
        }
    }

    fun hmacSha256(secret: String, value: String): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(secret.toByteArray(StandardCharsets.UTF_8), "HmacSHA256"))
        return mac.doFinal(value.toByteArray(StandardCharsets.UTF_8))
    }

    fun encode(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)

    fun decodeOrNull(value: String): ByteArray? = runCatching { Base64.getDecoder().decode(value) }.getOrNull()
}
