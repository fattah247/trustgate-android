package id.fatarc.trustgate.backend.integrity

import id.fatarc.trustgate.domain.api.MOCK_INTEGRITY_TOKEN_PREFIX
import java.time.Clock

/** The fields of a decoded Play Integrity verdict the backend acts on. */
data class IntegrityVerdict(
    val requestPackageName: String,
    val requestHash: String,
    val timestampMillis: Long,
    /** PLAY_RECOGNIZED, UNRECOGNIZED_VERSION, or UNEVALUATED. */
    val appRecognition: String?,
    /** SHA-256 of the signing certificates Google Play saw, lowercase hex. */
    val certificateDigests: Set<String>,
    /** Labels such as MEETS_DEVICE_INTEGRITY and MEETS_STRONG_INTEGRITY. */
    val deviceRecognition: Set<String>,
    /** Made up on this machine for development rather than issued by Google. */
    val mock: Boolean = false,
)

/** Turns an integrity token into its verdict, or null when the token can't be verified. */
fun interface IntegrityVerifier {
    fun verify(token: String): IntegrityVerdict?
}

/**
 * Accepts the tokens a debug build makes up without Google Play, "mock:" followed by the request
 * hash, and marks each verdict as a mock so no policy mistakes it for Google's.
 */
class MockIntegrityVerifier(
    private val packageName: String,
    private val clock: Clock = Clock.systemUTC(),
) : IntegrityVerifier {
    override fun verify(token: String): IntegrityVerdict? {
        if (!token.startsWith(MOCK_INTEGRITY_TOKEN_PREFIX)) return null
        return IntegrityVerdict(
            requestPackageName = packageName,
            requestHash = token.removePrefix(MOCK_INTEGRITY_TOKEN_PREFIX),
            timestampMillis = clock.millis(),
            appRecognition = null,
            certificateDigests = emptySet(),
            deviceRecognition = emptySet(),
            mock = true,
        )
    }
}
