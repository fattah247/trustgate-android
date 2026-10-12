package id.fatarc.trustgate.domain.signing

import java.time.Duration
import java.time.Instant

/** What a server actually receives: the wire request, without any of the signer's derived fields. */
data class ReceivedRequest(
    val method: String,
    val path: String,
    val headers: Map<String, String>,
    val body: String,
)

fun SignedRequest.asReceived(): ReceivedRequest = ReceivedRequest(
    method = method,
    path = path,
    headers = headers,
    body = canonicalBody,
)

sealed interface VerificationResult {
    data object Accepted : VerificationResult

    data class Rejected(val reason: RejectionReason) : VerificationResult
}

enum class RejectionReason {
    /** Timestamp, nonce, or signature header absent. */
    MISSING_HEADERS,

    /** The timestamp header isn't an ISO-8601 instant. */
    MALFORMED_TIMESTAMP,

    /** Signed too long before, or too far after, the moment it arrived. */
    OUTSIDE_TIME_WINDOW,

    /** The signature doesn't cover what arrived: the body, method, path, or headers changed, or a different key signed it. */
    SIGNATURE_MISMATCH,

    /** A correctly signed request whose nonce was already accepted once: a replay. */
    NONCE_REUSED,
}

interface RequestVerifier {
    /** How far a request's timestamp may sit from its arrival, in either direction. */
    val allowedClockSkew: Duration

    fun verify(request: ReceivedRequest, receivedAt: Instant = Instant.now()): VerificationResult
}
