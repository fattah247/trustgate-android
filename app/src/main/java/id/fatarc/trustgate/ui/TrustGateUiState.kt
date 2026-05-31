package id.fatarc.trustgate.ui

import id.fatarc.trustgate.core.storage.SecurityStorageSnapshot
import id.fatarc.trustgate.domain.events.SecurityEvent
import id.fatarc.trustgate.domain.risk.DeviceRiskLevel
import id.fatarc.trustgate.domain.risk.DeviceRiskReport
import id.fatarc.trustgate.domain.signing.SignedRequest

data class TrustGateUiState(
    val riskReport: DeviceRiskReport? = null,
    val securityEvents: List<SecurityEvent> = emptyList(),
    val storageSnapshot: SecurityStorageSnapshot = SecurityStorageSnapshot(),
    val signedRequest: SignedRequest? = null,
    val actionMessage: String = "Sensitive action has not been attempted yet.",
    val signingMessage: String = "No request has been signed yet.",
    val storageMessage: String = "No secure values have been written yet.",
    val errorMessage: String? = null,
    val isAssessingRisk: Boolean = true,
    val isConfirmationRequired: Boolean = false,
    val pinningSummary: String = "",
    val selectedDemoRiskLevel: DeviceRiskLevel? = null,
)
