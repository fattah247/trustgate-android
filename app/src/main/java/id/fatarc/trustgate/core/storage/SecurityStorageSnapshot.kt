package id.fatarc.trustgate.core.storage

import id.fatarc.trustgate.domain.risk.DeviceRiskLevel

data class SecurityStorageSnapshot(
    val sessionToken: String? = null,
    val lastRiskLevel: DeviceRiskLevel? = null,
    val showSignalsOnHome: Boolean = true,
    /** Values that couldn't be decrypted, such as after a restore onto another device, and were removed. */
    val unreadableValuesCleared: Int = 0,
)

interface SecureValueStore {
    fun readSnapshot(): SecurityStorageSnapshot

    fun storeSessionToken(token: String)

    fun storeLastRiskLevel(level: DeviceRiskLevel)

    fun storeShowSignalsOnHome(enabled: Boolean)
}

/** Names of the stored values. Each is bound into its value's encryption, so renaming one loses the value. */
object SecureValueNames {
    const val SESSION_TOKEN = "session_token"
    const val LAST_RISK_LEVEL = "last_risk_level"
    const val SHOW_SIGNALS_ON_HOME = "show_signals_on_home"
}
