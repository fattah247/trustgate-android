package id.fatarc.trustgate.core.crypto

import id.fatarc.trustgate.domain.signing.PaymentRequestPayload
import id.fatarc.trustgate.domain.signing.RequestSigner
import id.fatarc.trustgate.domain.signing.SignedRequest
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

class HmacRequestSigner(
    private val demoSecret: String = "trustgate-demo-local-signing-key",
) : RequestSigner {
    private val canonicalJson = Json {
        encodeDefaults = true
    }

    override fun sign(
        payload: PaymentRequestPayload,
        timestamp: String,
        nonce: String,
    ): SignedRequest {
        val canonicalBody = canonicalize(payload)
        val bodyHash = sha256Hex(canonicalBody)
        val signingInput = listOf(
            "POST",
            "/payments/demo",
            timestamp,
            nonce,
            bodyHash,
        ).joinToString("\n")
        val signature = hmacSha256Base64(signingInput)
        return SignedRequest(
            payload = payload,
            canonicalBody = canonicalBody,
            bodyHash = bodyHash,
            timestamp = timestamp,
            nonce = nonce,
            signature = signature,
            headers = mapOf(
                "X-Request-Timestamp" to timestamp,
                "X-Request-Nonce" to nonce,
                "X-Request-Signature" to signature,
            ),
        )
    }

    private fun canonicalize(payload: PaymentRequestPayload): String {
        return canonicalJson.encodeToString(payload)
    }

    private fun sha256Hex(value: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(value.toByteArray(StandardCharsets.UTF_8)).joinToString("") {
            "%02x".format(it)
        }
    }

    private fun hmacSha256Base64(value: String): String {
        val mac = Mac.getInstance("HmacSHA256")
        val secretKey = SecretKeySpec(demoSecret.toByteArray(StandardCharsets.UTF_8), "HmacSHA256")
        mac.init(secretKey)
        val signed = mac.doFinal(value.toByteArray(StandardCharsets.UTF_8))
        return Base64.getEncoder().encodeToString(signed)
    }
}
