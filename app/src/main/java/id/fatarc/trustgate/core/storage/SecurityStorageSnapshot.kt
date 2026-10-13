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
