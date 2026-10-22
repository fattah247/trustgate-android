package id.fatarc.trustgate.domain.api

import kotlinx.serialization.Serializable

/** The labels Play Integrity uses in the verdict fields the backend acts on, as Google spells them. */
object PlayIntegrityLabels {
    // deviceIntegrity.deviceRecognitionVerdict
    const val MEETS_DEVICE_INTEGRITY = "MEETS_DEVICE_INTEGRITY"
    const val MEETS_STRONG_INTEGRITY = "MEETS_STRONG_INTEGRITY"

    // appIntegrity.appRecognitionVerdict
    const val PLAY_RECOGNIZED = "PLAY_RECOGNIZED"

    // accountDetails.appLicensingVerdict
    const val UNLICENSED = "UNLICENSED"

    // environmentDetails.appAccessRiskVerdict.appsDetected. "Known" apps came from Google Play or
    // the phone maker; "unknown" ones from anywhere else.
    const val KNOWN_CAPTURING = "KNOWN_CAPTURING"
    const val KNOWN_CONTROLLING = "KNOWN_CONTROLLING"
    const val KNOWN_OVERLAYS = "KNOWN_OVERLAYS"
    const val UNKNOWN_CAPTURING = "UNKNOWN_CAPTURING"
    const val UNKNOWN_CONTROLLING = "UNKNOWN_CONTROLLING"
    const val UNKNOWN_OVERLAYS = "UNKNOWN_OVERLAYS"

    // environmentDetails.playProtectVerdict
    const val PLAY_PROTECT_NO_DATA = "NO_DATA"
    const val PLAY_PROTECT_OFF = "POSSIBLE_RISK"
    const val PLAY_PROTECT_MEDIUM_RISK = "MEDIUM_RISK"
    const val PLAY_PROTECT_HIGH_RISK = "HIGH_RISK"

    // deviceIntegrity.recentDeviceActivity.deviceActivityLevel, from LEVEL_1 (fewest requests) to LEVEL_4.
    const val ACTIVITY_LEVEL_4 = "LEVEL_4"
}

/**
 * The three bits Play Integrity's device recall keeps per device for every app of one developer
 * account. They survive reinstalls and factory resets; the server decides what each one means.
 */
@Serializable
enum class RecallBit { FIRST, SECOND, THIRD }

/**
 * Something the person can do to clear a problem the server found. The first three map to the
 * dialogs Google Play shows for them; the app explains the rest in words.
 */
@Serializable
enum class Remedy {
    CLOSE_UNKNOWN_ACCESS_RISK,
    CLOSE_ALL_ACCESS_RISK,
    GET_LICENSED,
    FIX_PLAY_PROTECT,
    UPDATE_APP,
}

/**
 * What a debug build without Google Play can claim in the token it makes up, so the development
 * server's handling of each verdict can be tried on an emulator. Only a server that accepts mock
 * verdicts reads these, and it labels every one as a test.
 */
data class MockIntegrityClaims(
    val requestHash: String,
    val appsDetected: Set<String> = emptySet(),
    val playProtect: String? = null,
    val deviceActivity: String? = null,
    val appLicensing: String? = null,
    /** The device recall bits set for this phone. */
    val recall: Set<RecallBit> = emptySet(),
) {
    fun encode(): String = buildString {
        append(MOCK_INTEGRITY_TOKEN_PREFIX).append(requestHash)
        if (appsDetected.isNotEmpty()) append("|apps=").append(appsDetected.sorted().joinToString(","))
        playProtect?.let { append("|protect=").append(it) }
        deviceActivity?.let { append("|activity=").append(it) }
        appLicensing?.let { append("|licensing=").append(it) }
        if (recall.isNotEmpty()) append("|recall=").append(recall.sorted().joinToString(",") { it.name.lowercase() })
    }

    companion object {
        /** Null when [token] isn't a mock token. Unknown fields are ignored. */
        fun decode(token: String): MockIntegrityClaims? {
            if (!token.startsWith(MOCK_INTEGRITY_TOKEN_PREFIX)) return null
            val parts = token.removePrefix(MOCK_INTEGRITY_TOKEN_PREFIX).split('|')
            val fields = parts.drop(1).mapNotNull { part ->
                part.split('=', limit = 2).takeIf { it.size == 2 }?.let { (name, value) -> name to value }
            }.toMap()
            return MockIntegrityClaims(
                requestHash = parts.first(),
                appsDetected = fields["apps"]?.split(',')?.filter { it.isNotBlank() }?.toSet().orEmpty(),
                playProtect = fields["protect"],
                deviceActivity = fields["activity"],
                appLicensing = fields["licensing"],
                recall = fields["recall"]?.split(',')
                    ?.mapNotNull { name -> RecallBit.entries.firstOrNull { it.name.equals(name, ignoreCase = true) } }
                    ?.toSet().orEmpty(),
            )
        }
    }
}
