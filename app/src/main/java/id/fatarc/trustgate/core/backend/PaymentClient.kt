package id.fatarc.trustgate.core.backend

import id.fatarc.trustgate.domain.signing.ReceivedRequest
import id.fatarc.trustgate.domain.signing.ReferenceSigningScheme
import kotlinx.coroutines.delay
import java.io.IOException
import java.time.Clock
import kotlin.random.Random

/** The request reached the backend and was handled, but the answer never made it back. */
class ResponseLostException : IOException("The response was lost on the way back.")

fun interface PaymentTransport {
    suspend fun submit(request: ReceivedRequest): PaymentResponse
}

/**
 * Carries requests to the [ReferenceBackend]. With [loseFirstResponse] on, the first response for
 * each idempotency key is dropped after the backend has processed it, the way a timeout would.
 */
class ReferenceTransport(
    private val backend: ReferenceBackend,
    private val clock: Clock = Clock.systemUTC(),
) : PaymentTransport {
    @Volatile
    var loseFirstResponse: Boolean = false

    private val lostFor = HashSet<String>()

    override suspend fun submit(request: ReceivedRequest): PaymentResponse {
        val response = backend.submitPayment(request, clock.instant())
        val key = request.header(ReferenceSigningScheme.HEADER_IDEMPOTENCY_KEY)
        if (loseFirstResponse && key != null && synchronized(lostFor) { lostFor.add(key) }) {
            throw ResponseLostException()
        }
        return response
    }
}

/** [response] is null when every attempt went unanswered and the outcome is unknown. */
data class SubmitOutcome(
    val response: PaymentResponse?,
    val attempts: Int,
    val lostResponses: Int,
)

/**
 * Sends a signed payment and, when no answer comes back, sends the very same request again. The
 * idempotency key it carries is what makes that safe: the backend answers a repeat with the
 * original result instead of charging twice.
 */
class PaymentClient(
    private val transport: PaymentTransport,
    private val maxAttempts: Int = 3,
    private val baseDelayMillis: Long = 400,
    private val random: Random = Random.Default,
) {
    suspend fun submit(request: ReceivedRequest): SubmitOutcome {
        var lost = 0
        repeat(maxAttempts) { attempt ->
            try {
                return SubmitOutcome(transport.submit(request), attempts = attempt + 1, lostResponses = lost)
            } catch (_: IOException) {
                lost++
                if (attempt < maxAttempts - 1) delay(backoffMillis(attempt))
            }
        }
        return SubmitOutcome(response = null, attempts = maxAttempts, lostResponses = lost)
    }

    /** Exponential backoff with jitter, so many clients retrying at once don't arrive in lockstep. */
    private fun backoffMillis(attempt: Int): Long {
        val exponential = baseDelayMillis shl attempt
        return exponential + random.nextLong(baseDelayMillis / 2 + 1)
    }
}
