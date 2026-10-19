package id.fatarc.trustgate.domain.signing

import kotlinx.serialization.Serializable

@Serializable
data class PaymentRequestPayload(
    val amountMinor: Long,
    val currency: String,
    val merchantReference: String,
)

/** Which device key signs a request. The backend decides which one a given request must use. */
enum class KeyRole {
    /** Signs ordinary requests without asking the person anything. */
    DEVICE,

    /** Signs only right after the person authenticates with biometrics or their screen lock. */
    STEP_UP,
}

/**
 * A request with every signed field settled and the exact bytes to sign. The private key never
 * passes through here: whoever holds it signs [signingInput] and hands back the signature.
 */
class PreparedRequest(
    val method: String,
    val path: String,
    val payload: PaymentRequestPayload,
    val canonicalBody: String,
    val bodyHash: String,
    val timestamp: String,
    val nonce: String,
    val keyId: String,
    val idempotencyKey: String?,
    val confirmation: String?,
    val signingInput: ByteArray,
) {
    fun signedWith(signature: ByteArray): SignedRequest {
        val encodedSignature = ReferenceSigningScheme.encode(signature)
        return SignedRequest(
            method = method,
            path = path,
            payload = payload,
            canonicalBody = canonicalBody,
            bodyHash = bodyHash,
            timestamp = timestamp,
            nonce = nonce,
            keyId = keyId,
            idempotencyKey = idempotencyKey,
            confirmation = confirmation,
            signature = encodedSignature,
            headers = buildMap {
                put(ReferenceSigningScheme.HEADER_TIMESTAMP, timestamp)
                put(ReferenceSigningScheme.HEADER_NONCE, nonce)
                put(ReferenceSigningScheme.HEADER_KEY_ID, keyId)
                idempotencyKey?.let { put(ReferenceSigningScheme.HEADER_IDEMPOTENCY_KEY, it) }
                confirmation?.let { put(ReferenceSigningScheme.HEADER_CONFIRMATION, it) }
                put(ReferenceSigningScheme.HEADER_SIGNATURE, encodedSignature)
            },
        )
    }
}

data class SignedRequest(
    val method: String,
    val path: String,
    val payload: PaymentRequestPayload,
    val canonicalBody: String,
    val bodyHash: String,
    val timestamp: String,
    val nonce: String,
    val keyId: String,
    val idempotencyKey: String?,
    val confirmation: String?,
    val signature: String,
    val headers: Map<String, String>,
)
