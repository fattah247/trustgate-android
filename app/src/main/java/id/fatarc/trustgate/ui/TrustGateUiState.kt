package id.fatarc.trustgate.ui

import id.fatarc.trustgate.core.integrity.PretendVerdict
import id.fatarc.trustgate.core.keys.KeySet
import id.fatarc.trustgate.core.security.ConfirmationMethod
import id.fatarc.trustgate.core.storage.SecurityStorageSnapshot
import id.fatarc.trustgate.domain.api.DecisionReason
import id.fatarc.trustgate.domain.api.Remedy
import id.fatarc.trustgate.domain.events.SecurityEvent
import id.fatarc.trustgate.domain.risk.DeviceRiskLevel
import id.fatarc.trustgate.domain.risk.DeviceRiskReport
import id.fatarc.trustgate.domain.signing.KeyRole
import id.fatarc.trustgate.domain.signing.Payee
import id.fatarc.trustgate.domain.signing.ReferencePayment
import id.fatarc.trustgate.domain.signing.RejectionReason
import id.fatarc.trustgate.domain.signing.SignedRequest
import id.fatarc.trustgate.domain.signing.VerificationResult
import java.time.Instant

data class TrustGateUiState(
    val risk: RiskUiState = RiskUiState(),
    val securityEvents: List<SecurityEvent> = emptyList(),
    val payment: PaymentUiState = PaymentUiState(),
    /** The request signed last, by a payment or a Lab test, for anyone who wants to see what was sent. */
    val lastRequest: SignedRequest? = null,
    val lab: LabUiState = LabUiState(),
    val storage: StorageUiState = StorageUiState(),
    val keys: KeysUiState = KeysUiState(),
    /** The payment the Pay button makes. */
    val checkout: Checkout = Checkout(),
    /** Drop the first response to each payment, as a timeout would, to show retries are safe. */
    val simulateLostResponse: Boolean = false,
    /** What the made-up integrity token claims; null when the build asks Google Play for real ones. */
    val pretendVerdict: PretendVerdict? = null,
    val userMessage: UserMessage? = null,
)

data class Checkout(
    val payee: Payee = ReferencePayment.STORE,
    val amountMinor: Long = ReferencePayment.AMOUNT_MINOR,
)

data class KeysUiState(
    val keys: KeySet? = null,
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

/** The steps a payment goes through, in order. */
enum class PaymentStage {
    CHECKING_DEVICE,
    ASKING_SERVER,
    CONFIRMING,
    PAYING,
    DONE,
}

data class PaymentUiState(
    /** Null until a payment is started. */
    val stage: PaymentStage? = null,
    val latestDecision: PaymentDecisionState = PaymentDecisionState.Idle,
    /** When [latestDecision] was reached, so repeating the same outcome is still visible. */
    val decidedAt: Instant? = null,
    /** What happened to the request once the gate let the action through. */
    val submission: Submission? = null,
    /** Why the backend decided as it did. */
    val reasons: List<DecisionReason> = emptyList(),
    /** What the person can do about the worst problem the server found. */
    val remedy: Remedy? = null,
    /** Whether Google Play can walk the person through [remedy]. */
    val canShowFix: Boolean = false,
    /** The server saw signs of someone talking the person into paying. */
    val scamWarning: Boolean = false,
    /** Why the payment stopped at [stage] before an outcome, such as the server being unreachable. */
    val problem: String? = null,
) {
    val isRunning: Boolean get() = stage != null && stage != PaymentStage.DONE && problem == null
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

    data class Confirmed(val riskLevel: DeviceRiskLevel, val method: ConfirmationMethod) : PaymentDecisionState

    data class Blocked(val riskLevel: DeviceRiskLevel) : PaymentDecisionState

    /** [problem] is set when the system ended the confirmation, for example after too many attempts. */
    data class Cancelled(val riskLevel: DeviceRiskLevel, val problem: String? = null) : PaymentDecisionState
}

/** Attacks the Lab runs against the real server. */
enum class LabTest(val metadataValue: String) {
    REPLAY("replay"),
    CHANGED_AMOUNT("changed-amount"),
    SENT_LATE("delivered-late"),
    RAPID_PAYMENTS("rapid-payments"),
}

/** How a Lab attack ended: [stopped] when the server refused it. [sends] holds each answer to a request attack. */
data class LabResult(
    val stopped: Boolean,
    val summary: String,
    val sends: List<VerificationResult> = emptyList(),
)

data class LabUiState(
    val running: LabTest? = null,
    val results: Map<LabTest, LabResult> = emptyMap(),
)

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
