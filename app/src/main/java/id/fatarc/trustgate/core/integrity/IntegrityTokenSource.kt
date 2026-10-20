package id.fatarc.trustgate.core.integrity

import android.app.Activity
import android.content.Context
import com.google.android.gms.tasks.Task
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.StandardIntegrityManager.PrepareIntegrityTokenRequest
import com.google.android.play.core.integrity.StandardIntegrityManager.StandardIntegrityToken
import com.google.android.play.core.integrity.StandardIntegrityManager.StandardIntegrityTokenProvider
import com.google.android.play.core.integrity.StandardIntegrityManager.StandardIntegrityTokenRequest
import com.google.android.play.core.integrity.model.IntegrityDialogResponseCode
import com.google.android.play.core.integrity.model.IntegrityDialogTypeCode
import id.fatarc.trustgate.domain.api.MockIntegrityClaims
import id.fatarc.trustgate.domain.api.PlayIntegrityLabels
import id.fatarc.trustgate.domain.api.Remedy
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/** Produces a Play Integrity token bound to a request hash, or null when this build has no way to get one. */
fun interface IntegrityTokenSource {
    suspend fun token(requestHash: String): String?

    /** Whether [showFix] can hand [remedy] to Google Play, which walks the person through it. */
    fun canShowFix(remedy: Remedy): Boolean = false

    /** Shows Google Play's dialog for [remedy]; true when the person fixed the problem. */
    suspend fun showFix(activity: Activity, remedy: Remedy): Boolean = false
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

    // Play's fix dialogs are opened from the token whose verdict found the problem.
    @Volatile
    private var lastToken: StandardIntegrityToken? = null

    override suspend fun token(requestHash: String): String {
        val ready = lock.withLock {
            provider ?: manager.prepareIntegrityToken(
                PrepareIntegrityTokenRequest.builder().setCloudProjectNumber(cloudProjectNumber).build(),
            ).await().also { provider = it }
        }
        return try {
            ready.request(StandardIntegrityTokenRequest.builder().setRequestHash(requestHash).build()).await()
                .also { lastToken = it }
                .token()
        } catch (error: Exception) {
            // A provider can expire; the next request prepares a fresh one.
            lock.withLock { provider = null }
            throw error
        }
    }

    override fun canShowFix(remedy: Remedy): Boolean = remedy.dialogType() != null && lastToken != null

    override suspend fun showFix(activity: Activity, remedy: Remedy): Boolean {
        val type = remedy.dialogType() ?: return false
        val token = lastToken ?: return false
        return token.showDialog(activity, type).await() == IntegrityDialogResponseCode.DIALOG_SUCCESSFUL
    }

    private fun Remedy.dialogType(): Int? = when (this) {
        Remedy.CLOSE_UNKNOWN_ACCESS_RISK -> IntegrityDialogTypeCode.CLOSE_UNKNOWN_ACCESS_RISK
        Remedy.CLOSE_ALL_ACCESS_RISK -> IntegrityDialogTypeCode.CLOSE_ALL_ACCESS_RISK
        Remedy.GET_LICENSED -> IntegrityDialogTypeCode.GET_LICENSED
        Remedy.FIX_PLAY_PROTECT, Remedy.UPDATE_APP -> null
    }
}

/** What a debug build can pretend Google Play found, to show how the server answers each verdict. */
enum class PretendVerdict(val claims: (requestHash: String) -> MockIntegrityClaims) {
    NOTHING({ MockIntegrityClaims(it) }),
    REMOTE_CONTROL({ MockIntegrityClaims(it, appsDetected = setOf(PlayIntegrityLabels.KNOWN_CONTROLLING)) }),
    UNKNOWN_SCREEN_READER({ MockIntegrityClaims(it, appsDetected = setOf(PlayIntegrityLabels.UNKNOWN_CAPTURING)) }),
    SCREEN_RECORDER({ MockIntegrityClaims(it, appsDetected = setOf(PlayIntegrityLabels.KNOWN_CAPTURING)) }),
    MALWARE({ MockIntegrityClaims(it, playProtect = PlayIntegrityLabels.PLAY_PROTECT_HIGH_RISK) }),
    PLAY_PROTECT_OFF({ MockIntegrityClaims(it, playProtect = PlayIntegrityLabels.PLAY_PROTECT_OFF) }),
    NOT_FROM_PLAY({ MockIntegrityClaims(it, appLicensing = PlayIntegrityLabels.UNLICENSED) }),
    TOKEN_FARMING({ MockIntegrityClaims(it, deviceActivity = PlayIntegrityLabels.ACTIVITY_LEVEL_4) }),
}

/**
 * For debug builds without Google Play set up: a token the development server knows to mark as a
 * mock, claiming whatever [pretend] says Google Play found.
 */
class MockIntegrityTokenSource : IntegrityTokenSource {
    @Volatile
    var pretend: PretendVerdict = PretendVerdict.NOTHING

    override suspend fun token(requestHash: String): String = pretend.claims(requestHash).encode()
}

private suspend fun <T> Task<T>.await(): T = suspendCancellableCoroutine { continuation ->
    addOnSuccessListener { continuation.resume(it) }
    addOnFailureListener { continuation.resumeWithException(it) }
    addOnCanceledListener { continuation.cancel() }
}
