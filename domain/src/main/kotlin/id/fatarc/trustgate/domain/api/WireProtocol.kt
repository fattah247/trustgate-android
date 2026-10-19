package id.fatarc.trustgate.domain.api

import id.fatarc.trustgate.domain.risk.DeviceRiskLevel
import id.fatarc.trustgate.domain.signing.KeyRole
import id.fatarc.trustgate.domain.signing.ReferenceSigningScheme
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/** The server's HTTP routes. Signed requests go to the paths their signature covers. */
object TrustGateRoutes {
    const val HEALTH = "/v1/health"
    const val REGISTRATION_CHALLENGE = "/v1/keys/challenge"
    const val KEYS = "/v1/keys"
    const val REMOVE_STEP_UP = "/v1/keys/step-up/remove"
    const val VERIFICATION_CHALLENGE = "/v1/verification/challenge"
    const val AUTHORIZE_PAYMENT = "/v1/payments/authorize"
    const val PAYMENT = ReferenceSigningScheme.PATH

    /** Checks a signed payment request exactly as [PAYMENT] would, without charging anything. */
    const val PAYMENT_CHECK = "${ReferenceSigningScheme.PATH}/check"

    /** Every header a signed request may carry; anything else on the wire is ignored. */
    val SIGNING_HEADERS = listOf(
        ReferenceSigningScheme.HEADER_TIMESTAMP,
        ReferenceSigningScheme.HEADER_NONCE,
        ReferenceSigningScheme.HEADER_KEY_ID,
        ReferenceSigningScheme.HEADER_IDEMPOTENCY_KEY,
        ReferenceSigningScheme.HEADER_CONFIRMATION,
        ReferenceSigningScheme.HEADER_SIGNATURE,
    )
}

/** One JSON configuration for both ends, so a field added on one side is read the same on the other. */
val TrustGateJson: Json = Json {
    ignoreUnknownKeys = true
    encodeDefaults = true
    classDiscriminator = "type"
}

// Binary values travel as standard Base64.

@Serializable
data class RegistrationChallengeRequest(val deviceKeyId: String? = null)

@Serializable
data class RegistrationChallenge(val challenge: String)

@Serializable
data class KeyRegistrationRequest(
    val role: KeyRole,
    val publicKey: String,
    val certificateChain: List<String>,
    val challenge: String,
    val deviceKeyId: String? = null,
    val deviceKeyProof: String? = null,
)

@Serializable
data class StepUpRemovalRequest(
    val deviceKeyId: String,
    val challenge: String,
    val deviceKeyProof: String,
)

@Serializable
data class StepUpRemoval(val removed: Boolean)

@Serializable
data class VerificationChallengeRequest(val deviceKeyId: String)

@Serializable
data class VerificationChallenge(val nonce: String)

@Serializable
data class PaymentAuthorizationRequest(
    val deviceKeyId: String,
    val level: DeviceRiskLevel,
)

@Serializable
data class ServerHealth(
    val status: String,
    /** "strict" or "development", the attestation policy the server enforces. */
    val policy: String,
)

@Serializable
data class ErrorResponse(val error: String)
