package id.fatarc.trustgate.core.backend

import id.fatarc.trustgate.domain.api.PaymentAuthorization
import id.fatarc.trustgate.domain.api.PaymentResponse
import id.fatarc.trustgate.domain.api.RegistrationResult
import id.fatarc.trustgate.domain.risk.DeviceRiskLevel
import id.fatarc.trustgate.domain.signing.KeyRole
import id.fatarc.trustgate.domain.signing.ReceivedRequest
import id.fatarc.trustgate.domain.signing.VerificationResult

/** The TrustGate backend as the app reaches it. Any call can fail with an IOException. */
interface TrustGateApi {
    /** A one-time registration challenge; pass [deviceKeyId] to add or remove that device's step-up key. */
    suspend fun registrationChallenge(deviceKeyId: String? = null): ByteArray

    suspend fun registerKey(
        role: KeyRole,
        encodedPublicKey: ByteArray,
        attestationChain: List<ByteArray>,
        challenge: ByteArray,
        deviceKeyId: String? = null,
        deviceKeyProof: ByteArray? = null,
    ): RegistrationResult

    suspend fun removeStepUpKey(deviceKeyId: String, challenge: ByteArray, deviceKeyProof: ByteArray): Boolean

    suspend fun verificationChallenge(deviceKeyId: String): String

    suspend fun authorizePayment(deviceKeyId: String, level: DeviceRiskLevel): PaymentAuthorization

    /** Checks a signed request exactly as the payment endpoint would, without charging anything. */
    suspend fun checkRequest(request: ReceivedRequest): VerificationResult

    suspend fun submitPayment(request: ReceivedRequest): PaymentResponse
}
