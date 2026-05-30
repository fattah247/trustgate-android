package id.fatarc.trustgate.domain.signing

data class PaymentRequestPayload(
    val amountMinor: Long,
    val currency: String,
    val merchantReference: String,
)

data class SignedRequest(
    val payload: PaymentRequestPayload,
    val canonicalBody: String,
    val bodyHash: String,
    val timestamp: String,
    val nonce: String,
    val signature: String,
    val headers: Map<String, String>,
)

