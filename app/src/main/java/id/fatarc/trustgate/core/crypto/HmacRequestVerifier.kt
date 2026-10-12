package id.fatarc.trustgate.core.crypto

import id.fatarc.trustgate.domain.signing.ReceivedRequest
import id.fatarc.trustgate.domain.signing.RejectionReason
import id.fatarc.trustgate.domain.signing.RequestVerifier
import id.fatarc.trustgate.domain.signing.VerificationResult
import java.security.MessageDigest
import java.time.Duration
import java.time.Instant
import java.time.format.DateTimeParseException

/**
 * Plays the server's part for reference requests, using the same demo key as [HmacRequestSigner].
 * It runs on the device only to show what verification enforces; a real deployment verifies on the server.
 */
class HmacRequestVerifier(
    private val referenceSecret: String = ReferenceSigningScheme.REFERENCE_SECRET,
    override val allowedClockSkew: Duration = DEFAULT_CLOCK_SKEW,
    private val nonceLedger: NonceLedger = NonceLedger(retention = allowedClockSkew.multipliedBy(2)),
) : RequestVerifier {

    override fun verify(request: ReceivedRequest, receivedAt: Instant): VerificationResult {
        val timestamp = request.header(ReferenceSigningScheme.HEADER_TIMESTAMP)
        val nonce = request.header(ReferenceSigningScheme.HEADER_NONCE)
        val signature = request.header(ReferenceSigningScheme.HEADER_SIGNATURE)
        if (timestamp.isNullOrBlank() || nonce.isNullOrBlank() || signature.isNullOrBlank()) {
            return VerificationResult.Rejected(RejectionReason.MISSING_HEADERS)
        }

        val signedAt = try {
            Instant.parse(timestamp)
        } catch (_: DateTimeParseException) {
            return VerificationResult.Rejected(RejectionReason.MALFORMED_TIMESTAMP)
        }
        if (Duration.between(signedAt, receivedAt).abs() > allowedClockSkew) {
            return VerificationResult.Rejected(RejectionReason.OUTSIDE_TIME_WINDOW)
        }

        val expected = ReferenceSigningScheme.hmacSha256(
            secret = referenceSecret,
            value = ReferenceSigningScheme.signingInput(
                method = request.method,
                path = request.path,
                timestamp = timestamp,
                nonce = nonce,
                bodyHash = ReferenceSigningScheme.sha256Hex(request.body),
            ),
        )
        val presented = ReferenceSigningScheme.decodeOrNull(signature)
        // Constant-time comparison so response timing doesn't leak how much of a forged signature matched.
        if (presented == null || !MessageDigest.isEqual(expected, presented)) {
            return VerificationResult.Rejected(RejectionReason.SIGNATURE_MISMATCH)
        }

        // Claim the nonce only once everything else holds, so unsigned junk can't burn a genuine request's nonce.
        if (!nonceLedger.claim(nonce, receivedAt)) {
            return VerificationResult.Rejected(RejectionReason.NONCE_REUSED)
        }
        return VerificationResult.Accepted
    }

    private fun ReceivedRequest.header(name: String): String? =
        headers.entries.firstOrNull { it.key.equals(name, ignoreCase = true) }?.value

    companion object {
        val DEFAULT_CLOCK_SKEW: Duration = Duration.ofMinutes(5)
    }
}

/**
 * Remembers accepted nonces for [retention]. Anything older would already fail the time window,
 * so forgetting it keeps memory bounded without reopening a replay.
 */
class NonceLedger(
    private val retention: Duration,
) {
    private val seen = LinkedHashMap<String, Instant>()

    @Synchronized
    fun claim(nonce: String, at: Instant): Boolean {
        val cutoff = at.minus(retention)
        seen.entries.removeAll { (_, claimedAt) -> claimedAt.isBefore(cutoff) }
        if (nonce in seen) return false
        seen[nonce] = at
        return true
    }
}
