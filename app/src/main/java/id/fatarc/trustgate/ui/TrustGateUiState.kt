package id.fatarc.trustgate.ui

import id.fatarc.trustgate.core.keys.KeySet
import id.fatarc.trustgate.core.security.ConfirmationMethod
import id.fatarc.trustgate.core.storage.SecurityStorageSnapshot
import id.fatarc.trustgate.domain.events.SecurityEvent
import id.fatarc.trustgate.domain.risk.DeviceRiskLevel
import id.fatarc.trustgate.domain.risk.DeviceRiskReport
import id.fatarc.trustgate.domain.signing.KeyRole
import id.fatarc.trustgate.domain.signing.RejectionReason
import id.fatarc.trustgate.domain.signing.SignedRequest
import id.fatarc.trustgate.domain.signing.VerificationResult
import java.time.Instant

data class TrustGateUiState(
    val risk: RiskUiState = RiskUiState(),
    val securityEvents: List<SecurityEvent> = emptyList(),
    val payment: PaymentUiState = PaymentUiState(),
    val signing: SigningUiState = SigningUiState(),
    val storage: StorageUiState = StorageUiState(),
    val keys: KeysUiState = KeysUiState(),
    /** Drop the first response to each payment, as a timeout would, to show retries are safe. */
    val simulateLostResponse: Boolean = false,
    val pinningSummary: String = "",
    /** The reference backend's freshness window, shown where its rules are explained. */
    val verifierWindowMinutes: Long = 5,
    val userMessage: UserMessage? = null,
)

data class KeysUiState(
    val keys: KeySet? = null,
    val isPreparing: Boolean = true,
    val errorMessage: String? = null,
)

data class RiskUiState(
    val report: DeviceRiskReport? = null,
    val source: RiskReportSource = RiskReportSource.LIVE,
    /** When set, a simulated profile replaces live checks everywhere in the app. */
    val scenarioLevel: DeviceRiskLevel? = null,
    val isLoading: Boolean = true,
    val errorMessage: String? = null,
)

enum class RiskReportSource {
    LIVE,
    SCENARIO,
}

data class PaymentUiState(
    val latestDecision: PaymentDecisionState = PaymentDecisionState.Idle,
    /** When [latestDecision] was reached, so repeating the same outcome is still visible. */
    val decidedAt: Instant? = null,
    /** What happened to the request once the gate let the action through. */
    val submission: Submission? = null,
) {
    /** The gate let the action through and the payment hasn't come back yet. */
    val isSending: Boolean
        get() = submission == null &&
            (latestDecision is PaymentDecisionState.Allowed || latestDecision is PaymentDecisionState.Confirmed)
}

/** What happened to the payment a permitted action sent. */
sealed interface Submission {
    data class Charged(
        val paymentId: String,
        val signedWith: KeyRole,
        val attempts: Int,
        val lostResponses: Int,
    ) : Submission

    data class Refused(val reason: RejectionReason) : Submission

    /** Every attempt went unanswered; the idempotency key makes a later retry safe. */
    data class NoResponse(val attempts: Int) : Submission

    data class NotSent(val message: String) : Submission
}

sealed interface PaymentDecisionState {
    data object Idle : PaymentDecisionState

    data class Allowed(val riskLevel: DeviceRiskLevel) : PaymentDecisionState

    data class ConfirmationRequired(
        val riskLevel: DeviceRiskLevel,
        val method: ConfirmationMethod,
    ) : PaymentDecisionState

    data class Confirmed(val riskLevel: DeviceRiskLevel) : PaymentDecisionState

    data class Blocked(val riskLevel: DeviceRiskLevel) : PaymentDecisionState

    /** [problem] is set when the system ended the confirmation, for example after too many attempts. */
    data class Cancelled(val riskLevel: DeviceRiskLevel, val problem: String? = null) : PaymentDecisionState
}

data class SigningUiState(
    val signedRequest: SignedRequest? = null,
    val status: SigningStatus = SigningStatus.Idle,
    /** Attempts to get [signedRequest] past the verifier, newest first. */
    val verifications: List<VerificationRecord> = emptyList(),
)

/** Ways to send the latest request, from honest to deliberately broken. */
enum class VerificationAttempt(val metadataValue: String) {
    AS_SIGNED("as-signed"),
    CHANGED_AMOUNT("changed-amount"),
    DELIVERED_LATE("delivered-late"),
}

data class VerificationRecord(
    val attempt: VerificationAttempt,
    val result: VerificationResult,
    val at: Instant,
    val sentByProtectedAction: Boolean = false,
    /** Responses lost before this one arrived; the backend charged once regardless. */
    val lostResponses: Int = 0,
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

    data class Failed(val message: String) : StorageStatus
}

/** A one-off message for the snackbar. [id] keeps repeated identical messages distinct. */
data class UserMessage(
    val id: Long,
    val text: String,
)
