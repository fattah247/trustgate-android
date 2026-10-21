package id.fatarc.trustgate.domain.api

import id.fatarc.trustgate.domain.signing.KeyRole
import id.fatarc.trustgate.domain.signing.PaymentRequestPayload
import id.fatarc.trustgate.domain.signing.ReferenceSigningScheme
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/** The server's HTTP routes. Signed requests go to the paths their signature covers. */
object TrustGateRoutes {
    const val HEALTH = "/v1/health"
    const val REGISTRATION_CHALLENGE = "/v1/keys/challenge"
    const val KEYS = "/v1/keys"
    const val REMOVE_STEP_UP = "/v1/keys/step-up/remove"
    const val ROTATE_DEVICE_KEY = "/v1/keys/rotate"
    const val REMOVE_DEVICE = "/v1/keys/remove"

    /** Operator routes, served only when the server has an admin token set. */
    const val ADMIN_REVOKE = "/admin/keys/revoke"
    const val ADMIN_AUDIT = "/admin/audit"
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

/** How a debug build without Google Play marks the integrity token it makes up: this, then the request hash. */
const val MOCK_INTEGRITY_TOKEN_PREFIX = "mock:"

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

/** A new device key, vouched for by the one it replaces: [proof] signs the rotate action for [challenge] and the new key's ID. */
@Serializable
data class KeyRotationRequest(
    val currentKeyId: String,
    val publicKey: String,
    val certificateChain: List<String>,
    val challenge: String,
    val proof: String,
)

/** The device key asking the backend to stop accepting this phone's keys. */
@Serializable
data class DeviceRemovalRequest(
    val deviceKeyId: String,
    val challenge: String,
    val proof: String,
)

@Serializable
data class DeviceRemoval(val removed: Boolean)

/** An operator revoking a phone, for example after fraud was reported. [keyId] may be either of its keys. */
@Serializable
data class AdminRevocationRequest(val keyId: String, val reason: String)

/** Whether the server's audit log is unbroken from its first entry to [headHash]. */
@Serializable
data class AuditStatus(
    val intact: Boolean,
    val entries: Long,
    val headHash: String?,
    /** The first entry whose hash doesn't follow from the one before, when there is one. */
    val brokenAt: Long? = null,
)

@Serializable
data class VerificationChallengeRequest(val deviceKeyId: String)

@Serializable
data class VerificationChallenge(val nonce: String)

@Serializable
data class ReportedSignal(val id: String, val detected: Boolean)

/** What the device reports about itself before a protected action. The server decides what it's worth. */
@Serializable
data class DeviceEvidence(
    val deviceKeyId: String,
    /** ISO-8601 instant; the server refuses evidence older than the protocol's time window. */
    val collectedAt: String,
    val signals: List<ReportedSignal>,
    /** The signals come from a simulated profile the person picked rather than from this device. */
    val simulated: Boolean = false,
    /**
     * The payment the person is about to make. The server binds the challenge it issues to these
     * exact details, so the payment that follows can't be for anything else.
     */
    val payment: PaymentRequestPayload? = null,
    /** The phone's offset from UTC, so the server can tell what time it is where the person is. */
    val utcOffsetMinutes: Int? = null,
)

@Serializable
data class PaymentAuthorizationRequest(
    val deviceKeyId: String,
    /** [DeviceEvidence] as the exact JSON the device key signed. */
    val evidence: String,
    /** The device key's signature over [evidence], Base64. */
    val signature: String,
    /** A Play Integrity token requested with the SHA-256 of [evidence] as its request hash. */
    val integrityToken: String? = null,
)

@Serializable
data class ServerHealth(
    val status: String,
    /** "strict" or "development", the attestation policy the server enforces. */
    val policy: String,
)

@Serializable
data class ErrorResponse(val error: String)
