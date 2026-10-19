package id.fatarc.trustgate.core.integrity

import android.content.Context
import com.google.android.gms.tasks.Task
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.StandardIntegrityManager.PrepareIntegrityTokenRequest
import com.google.android.play.core.integrity.StandardIntegrityManager.StandardIntegrityTokenProvider
import com.google.android.play.core.integrity.StandardIntegrityManager.StandardIntegrityTokenRequest
import id.fatarc.trustgate.domain.api.MOCK_INTEGRITY_TOKEN_PREFIX
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/** Produces a Play Integrity token bound to a request hash, or null when this build has no way to get one. */
fun interface IntegrityTokenSource {
    suspend fun token(requestHash: String): String?
}

/**
 * Google Play's Standard integrity API. The token provider is prepared once and reused, which is
 * what keeps a request fast enough to make before every protected action.
 */
class PlayIntegrityTokenSource(
    context: Context,
    private val cloudProjectNumber: Long,
) : IntegrityTokenSource {
    private val manager = IntegrityManagerFactory.createStandard(context.applicationContext)
    private val lock = Mutex()
    private var provider: StandardIntegrityTokenProvider? = null

    override suspend fun token(requestHash: String): String {
        val ready = lock.withLock {
            provider ?: manager.prepareIntegrityToken(
                PrepareIntegrityTokenRequest.builder().setCloudProjectNumber(cloudProjectNumber).build(),
            ).await().also { provider = it }
        }
        return try {
            ready.request(StandardIntegrityTokenRequest.builder().setRequestHash(requestHash).build()).await().token()
        } catch (error: Exception) {
            // A provider can expire; the next request prepares a fresh one.
            lock.withLock { provider = null }
            throw error
        }
    }
}

/** For debug builds without Google Play set up: a token the development server knows to mark as a mock. */
object MockIntegrityTokenSource : IntegrityTokenSource {
    override suspend fun token(requestHash: String): String = MOCK_INTEGRITY_TOKEN_PREFIX + requestHash
}

private suspend fun <T> Task<T>.await(): T = suspendCancellableCoroutine { continuation ->
    addOnSuccessListener { continuation.resume(it) }
    addOnFailureListener { continuation.resumeWithException(it) }
    addOnCanceledListener { continuation.cancel() }
}
