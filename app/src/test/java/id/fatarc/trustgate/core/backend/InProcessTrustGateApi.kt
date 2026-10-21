package id.fatarc.trustgate.core.backend

import id.fatarc.trustgate.backend.ReferenceBackend
import id.fatarc.trustgate.domain.api.DecisionChallengeRequest
import id.fatarc.trustgate.domain.api.PaymentAuthorizationRequest
import id.fatarc.trustgate.domain.api.PhoneDecision
import id.fatarc.trustgate.domain.api.SignedAction
import id.fatarc.trustgate.domain.signing.KeyRole
import id.fatarc.trustgate.domain.signing.ReceivedRequest
import java.util.Base64

/** Runs the backend inside the app process, with no network in between. */
class InProcessTrustGateApi(private val backend: ReferenceBackend) : TrustGateApi {
    override suspend fun registrationChallenge(deviceKeyId: String?) = backend.issueRegistrationChallenge(deviceKeyId)

    override suspend fun registerKey(
        role: KeyRole,
        encodedPublicKey: ByteArray,
        attestationChain: List<ByteArray>,
        challenge: ByteArray,
        deviceKeyId: String?,
        deviceKeyProof: ByteArray?,
        phoneLabel: String?,
    ) = backend.registerKey(role, encodedPublicKey, attestationChain, challenge, deviceKeyId, deviceKeyProof, phoneLabel)

    override suspend fun removeStepUpKey(deviceKeyId: String, challenge: ByteArray, deviceKeyProof: ByteArray) =
        backend.removeStepUpKey(deviceKeyId, challenge, deviceKeyProof)

    override suspend fun rotateDeviceKey(
        currentKeyId: String,
        encodedPublicKey: ByteArray,
        attestationChain: List<ByteArray>,
        challenge: ByteArray,
        proof: ByteArray,
    ) = backend.rotateDeviceKey(currentKeyId, encodedPublicKey, attestationChain, challenge, proof)

    override suspend fun removeDevice(deviceKeyId: String, challenge: ByteArray, proof: ByteArray) =
        backend.removeDevice(deviceKeyId, challenge, proof)

    override suspend fun verificationChallenge(deviceKeyId: String) = backend.issueVerificationChallenge(deviceKeyId)

    override suspend fun authorizePayment(request: PaymentAuthorizationRequest) = backend.authorizePayment(
        deviceKeyId = request.deviceKeyId,
        evidence = request.evidence,
        signature = Base64.getDecoder().decode(request.signature),
        integrityToken = request.integrityToken,
    )

    override suspend fun checkRequest(request: ReceivedRequest) = backend.authenticate(request)

    override suspend fun submitPayment(request: ReceivedRequest) = backend.submitPayment(request)

    // The server answers a request it won't act on with HTTP 400; in process it's an exception.
    override suspend fun accountView(action: SignedAction) = backend.accountView(action) ?: throw BackendRequestException("Not allowed")

    override suspend fun createLinkCode(action: SignedAction) = backend.createLinkCode(action) ?: throw BackendRequestException("Not allowed")

    override suspend fun joinAccount(action: SignedAction) = backend.joinAccount(action)

    override suspend fun decisionChallenge(request: DecisionChallengeRequest) =
        backend.decisionChallenge(request) ?: throw BackendRequestException("Not allowed")

    override suspend fun decide(decision: PhoneDecision) = backend.decide(decision)
}
