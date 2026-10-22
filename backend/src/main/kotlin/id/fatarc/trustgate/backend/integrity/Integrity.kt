package id.fatarc.trustgate.backend.integrity

import id.fatarc.trustgate.domain.api.MockIntegrityClaims
import id.fatarc.trustgate.domain.api.RecallBit
import java.time.Clock

/**
 * The fields of a decoded Play Integrity verdict the backend acts on. The optional verdicts are
 * null when the app's Play Console hasn't turned them on, which the backend reads as "not checked".
 */
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
    /** The version of the app that asked, as Google Play knows it. */
    val appVersionCode: Long? = null,
    /** LICENSED, UNLICENSED, or UNEVALUATED. */
    val appLicensing: String? = null,
    /** Apps running that could capture the screen, control the phone, or draw over it. */
    val appsDetected: Set<String>? = null,
    /** NO_ISSUES, NO_DATA, POSSIBLE_RISK (Play Protect off), MEDIUM_RISK, HIGH_RISK, or UNEVALUATED. */
    val playProtect: String? = null,
    /** How many integrity requests this phone made lately, LEVEL_1 to LEVEL_4. */
    val deviceActivity: String? = null,
    /** The device recall bits set for this phone; null when device recall isn't turned on. */
    val deviceRecall: Set<RecallBit>? = null,
    /** Made up on this machine for development rather than issued by Google. */
    val mock: Boolean = false,
)

/** Turns an integrity token into its verdict, or null when the token can't be verified. */
fun interface IntegrityVerifier {
    fun verify(token: String): IntegrityVerdict?
}

/**
 * Accepts the tokens a debug build makes up without Google Play, and marks each verdict as a mock
 * so no policy mistakes it for Google's. The token can claim the optional verdicts, so their
 * handling can be tried on an emulator.
 */
class MockIntegrityVerifier(
    private val packageName: String,
    private val clock: Clock = Clock.systemUTC(),
) : IntegrityVerifier {
    override fun verify(token: String): IntegrityVerdict? {
        val claims = MockIntegrityClaims.decode(token) ?: return null
        return IntegrityVerdict(
            requestPackageName = packageName,
            requestHash = claims.requestHash,
            timestampMillis = clock.millis(),
            appRecognition = null,
            certificateDigests = emptySet(),
            deviceRecognition = emptySet(),
            appLicensing = claims.appLicensing,
            appsDetected = claims.appsDetected,
            playProtect = claims.playProtect,
            deviceActivity = claims.deviceActivity,
            deviceRecall = claims.recall,
            mock = true,
        )
    }
}

/**
 * Sets device recall bits on Google's side for the phone an integrity [token] came from. Writes
 * happen after the change that called for them is committed, and must not hold anything up.
 */
fun interface DeviceRecallWriter {
    fun write(token: String, bits: Map<RecallBit, Boolean>)

    companion object {
        val NONE = DeviceRecallWriter { _, _ -> }
    }
}
