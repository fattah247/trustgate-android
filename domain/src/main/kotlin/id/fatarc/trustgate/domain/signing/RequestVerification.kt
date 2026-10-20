package id.fatarc.trustgate.domain.signing

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/** What a server actually receives: the wire request, without any of the signer's derived fields. */
data class ReceivedRequest(
    val method: String,
    val path: String,
    val headers: Map<String, String>,
    val body: String,
) {
    /** HTTP header names are case-insensitive. */
    fun header(name: String): String? = headers.entries.firstOrNull { it.key.equals(name, ignoreCase = true) }?.value
}

fun SignedRequest.asReceived(): ReceivedRequest = ReceivedRequest(
    method = method,
    path = path,
    headers = headers,
    body = canonicalBody,
)

@Serializable
sealed interface VerificationResult {
    @Serializable
    @SerialName("accepted")
    data object Accepted : VerificationResult

    @Serializable
    @SerialName("rejected")
    data class Rejected(val reason: RejectionReason) : VerificationResult
}

enum class RejectionReason {
    /** A required header is absent, or one contains a line break that could blur the signed fields. */
    MISSING_HEADERS,

    /** The timestamp header isn't an ISO-8601 instant. */
    MALFORMED_TIMESTAMP,

    /** Signed too long before, or too far after, the moment it arrived. */
    OUTSIDE_TIME_WINDOW,

    /** No registered key has this key ID. */
    UNKNOWN_KEY,

    /** The signature doesn't cover what arrived: something changed after signing, or another key signed it. */
    SIGNATURE_MISMATCH,

    /** The nonce wasn't issued by the backend, was issued to another device, or has expired. */
    UNKNOWN_CHALLENGE,

    /** The backend's one-time challenge was already used: a replay. */
    CHALLENGE_REUSED,

    /** The backend asked for step-up confirmation and the request doesn't carry it. */
    CONFIRMATION_REQUIRED,

    /** The idempotency key was already used for a different request. */
    IDEMPOTENCY_CONFLICT,

    /** The signature checks out, but the body isn't a payment the backend can process. */
    MALFORMED_BODY,

    /** This phone has made as many payments as the backend allows in a short time. */
    TOO_MANY_PAYMENTS,

    /** The payment would take this phone past its daily amount, or past what a new phone may pay. */
    OVER_LIMIT,

    /** The key was replaced, or the phone was removed, so the backend no longer accepts it. */
    KEY_REVOKED,
}
