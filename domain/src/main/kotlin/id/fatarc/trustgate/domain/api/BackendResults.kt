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

/** The backend's answer to a protected action: its own risk level, why, and what the request needs. */
@Serializable
sealed interface PaymentAuthorization {
    val decision: SensitiveActionDecision
    val level: DeviceRiskLevel
    val reasons: List<String>

    @Serializable
    @SerialName("proceed")
    data class Proceed(
        override val decision: SensitiveActionDecision,
        override val level: DeviceRiskLevel,
        val nonce: String,
        val signWith: KeyRole,
        val confirmation: RequiredConfirmation,
        override val reasons: List<String> = emptyList(),
    ) : PaymentAuthorization

    @Serializable
    @SerialName("blocked")
    data class Blocked(
        override val level: DeviceRiskLevel,
        override val reasons: List<String> = emptyList(),
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
