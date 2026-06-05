package id.fatarc.trustgate.ui

import id.fatarc.trustgate.core.storage.SecurityStorageSnapshot
import id.fatarc.trustgate.domain.actiongate.SensitiveActionDecision
import id.fatarc.trustgate.domain.events.SecurityEvent
import id.fatarc.trustgate.domain.risk.DeviceRiskLevel
import id.fatarc.trustgate.domain.risk.DeviceRiskReport
import id.fatarc.trustgate.domain.signing.SignedRequest

data class TrustGateUiState(
    val risk: RiskUiState = RiskUiState(),
    val securityEvents: List<SecurityEvent> = emptyList(),
    val payment: PaymentUiState = PaymentUiState(),
    val signing: SigningUiState = SigningUiState(),
    val storage: StorageUiState = StorageUiState(),
    val pinningSummary: String = "",
)

data class RiskUiState(
    val report: DeviceRiskReport? = null,
    val source: RiskReportSource = RiskReportSource.LIVE,
    val isLoading: Boolean = true,
    val errorMessage: String? = null,
)

enum class RiskReportSource {
    LIVE,
    DEMO,
}

data class PaymentUiState(
    val selectedDemoRiskLevel: DeviceRiskLevel? = null,
    val latestDecision: PaymentDecisionState = PaymentDecisionState.Idle,
)

sealed interface PaymentDecisionState {
    data object Idle : PaymentDecisionState

    data class Allowed(val riskLevel: DeviceRiskLevel) : PaymentDecisionState

    data class ConfirmationRequired(val riskLevel: DeviceRiskLevel) : PaymentDecisionState

    data class Confirmed(val riskLevel: DeviceRiskLevel) : PaymentDecisionState

    data class Blocked(val riskLevel: DeviceRiskLevel) : PaymentDecisionState

    data class Cancelled(val riskLevel: DeviceRiskLevel) : PaymentDecisionState
}

data class SigningUiState(
    val signedRequest: SignedRequest? = null,
    val status: SigningStatus = SigningStatus.Idle,
)

sealed interface SigningStatus {
    data object Idle : SigningStatus

    data class Signed(val merchantReference: String) : SigningStatus

    data class Failed(val message: String) : SigningStatus
}

data class StorageUiState(
    val snapshot: SecurityStorageSnapshot = SecurityStorageSnapshot(),
    val status: StorageStatus = StorageStatus.Idle,
)

sealed interface StorageStatus {
    data object Idle : StorageStatus

    data object Loaded : StorageStatus

    data class Stored(val keyCount: Int) : StorageStatus

    data class PreferenceUpdated(val showSignalsOnHome: Boolean) : StorageStatus

    data class Failed(val message: String) : StorageStatus
}

fun PaymentDecisionState.toDecision(): SensitiveActionDecision? = when (this) {
    is PaymentDecisionState.Allowed -> SensitiveActionDecision.ALLOW
    is PaymentDecisionState.ConfirmationRequired -> SensitiveActionDecision.REQUIRE_CONFIRMATION
    is PaymentDecisionState.Blocked -> SensitiveActionDecision.BLOCK
    is PaymentDecisionState.Cancelled,
    is PaymentDecisionState.Confirmed,
    PaymentDecisionState.Idle,
    -> null
}
