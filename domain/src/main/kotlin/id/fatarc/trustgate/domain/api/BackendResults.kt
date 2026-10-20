package id.fatarc.trustgate.domain.api

import id.fatarc.trustgate.domain.actiongate.SensitiveActionDecision
import id.fatarc.trustgate.domain.risk.DeviceRiskLevel
import id.fatarc.trustgate.domain.signing.KeyRole
import id.fatarc.trustgate.domain.signing.RejectionReason
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
enum class RequiredConfirmation {
    NONE,

    /** The request must be signed by the device's step-up key, which only signs after the person authenticates. */
    STEP_UP_KEY,

    /** The device has no screen lock to step up to, so a signed tap confirmation is the weaker fallback. */
    TAP,
}

/** One thing the backend weighed, and how far it alone would push the risk level. LOW means it's fine. */
@Serializable
data class DecisionReason(
    val text: String,
    val level: DeviceRiskLevel = DeviceRiskLevel.LOW,
) {
    val isProblem: Boolean get() = level > DeviceRiskLevel.LOW
}

/** The backend's answer to a protected action: its own risk level, why, and what the request needs. */
@Serializable
sealed interface PaymentAuthorization {
    val decision: SensitiveActionDecision
    val level: DeviceRiskLevel
    val reasons: List<DecisionReason>

    /** What the person can do about the worst problem found, when there's something they can do. */
    val remedy: Remedy?

    /** What was found looks like someone talking the person into paying, so the app warns them. */
    val scamWarning: Boolean

    @Serializable
    @SerialName("proceed")
    data class Proceed(
        override val decision: SensitiveActionDecision,
        override val level: DeviceRiskLevel,
        val nonce: String,
        val signWith: KeyRole,
        val confirmation: RequiredConfirmation,
        override val reasons: List<DecisionReason> = emptyList(),
        override val remedy: Remedy? = null,
        override val scamWarning: Boolean = false,
        /** The device key has been in use long enough that the app should replace it. */
        val rotateKey: Boolean = false,
    ) : PaymentAuthorization

    @Serializable
    @SerialName("blocked")
    data class Blocked(
        override val level: DeviceRiskLevel,
        override val reasons: List<DecisionReason> = emptyList(),
        override val remedy: Remedy? = null,
        override val scamWarning: Boolean = false,
        /** The backend doesn't accept this phone's key, because it's unknown, replaced, or removed. */
        val keyRejected: Boolean = false,
    ) : PaymentAuthorization {
        override val decision: SensitiveActionDecision get() = SensitiveActionDecision.BLOCK
    }
}

@Serializable
sealed interface RegistrationResult {
    @Serializable
    @SerialName("registered")
    data class Registered(
        val keyId: String,
        val role: KeyRole,
        val attestation: AttestationSummary,
    ) : RegistrationResult

    @Serializable
    @SerialName("refused")
    data class Refused(val reason: String) : RegistrationResult
}

@Serializable
data class Payment(
    val id: String,
    val amountMinor: Long,
    val currency: String,
    val signedWith: KeyRole,
    val confirmation: RequiredConfirmation,
    /** ISO-8601 instant the backend charged it. */
    val processedAt: String,
)

@Serializable
sealed interface PaymentResponse {
    /** [replayed] means this exact request was processed before and nothing new was charged. */
    @Serializable
    @SerialName("processed")
    data class Processed(val payment: Payment, val replayed: Boolean) : PaymentResponse

    @Serializable
    @SerialName("rejected")
    data class Rejected(val reason: RejectionReason) : PaymentResponse
}
