package id.fatarc.trustgate.core.storage

import id.fatarc.trustgate.domain.risk.DeviceRiskLevel

data class SecurityStorageSnapshot(
    val sessionToken: String? = null,
    val lastRiskLevel: DeviceRiskLevel? = null,
    val showSignalsOnHome: Boolean = true,
)

interface SecureValueStore {
    fun readSnapshot(): SecurityStorageSnapshot

    fun storeSessionToken(token: String)

    fun storeLastRiskLevel(level: DeviceRiskLevel)

    fun storeShowSignalsOnHome(enabled: Boolean)
}
