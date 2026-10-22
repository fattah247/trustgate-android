package id.fatarc.trustgate.core.backend

import id.fatarc.trustgate.domain.api.AccountView
import id.fatarc.trustgate.domain.api.DecisionChallenge
import id.fatarc.trustgate.domain.api.DecisionChallengeRequest
import id.fatarc.trustgate.domain.api.DecisionResult
import id.fatarc.trustgate.domain.api.DeviceRemoval
import id.fatarc.trustgate.domain.api.DeviceRemovalRequest
import id.fatarc.trustgate.domain.api.JoinResult
import id.fatarc.trustgate.domain.api.KeyRegistrationRequest
import id.fatarc.trustgate.domain.api.KeyRotationRequest
import id.fatarc.trustgate.domain.api.LinkCode
import id.fatarc.trustgate.domain.api.PaymentAuthorization
import id.fatarc.trustgate.domain.api.PaymentAuthorizationRequest
import id.fatarc.trustgate.domain.api.PaymentResponse
import id.fatarc.trustgate.domain.api.PhoneDecision
import id.fatarc.trustgate.domain.api.RegistrationChallenge
import id.fatarc.trustgate.domain.api.RegistrationChallengeRequest
import id.fatarc.trustgate.domain.api.RegistrationResult
import id.fatarc.trustgate.domain.api.SignedAction
import id.fatarc.trustgate.domain.api.StepUpRemoval
import id.fatarc.trustgate.domain.api.StepUpRemovalRequest
import id.fatarc.trustgate.domain.api.TrustGateJson
import id.fatarc.trustgate.domain.api.TrustGateRoutes
import id.fatarc.trustgate.domain.api.VerificationChallenge
import id.fatarc.trustgate.domain.api.VerificationChallengeRequest
import id.fatarc.trustgate.domain.signing.KeyRole
import id.fatarc.trustgate.domain.signing.ReceivedRequest
import id.fatarc.trustgate.domain.signing.VerificationResult
import java.io.IOException
import java.util.Base64
import java.util.concurrent.TimeUnit
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.serialization.encodeToString
import okhttp3.Call
import okhttp3.Callback
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response

/** The server refused or couldn't handle a request; retrying the same request won't change that. */
class BackendRequestException(message: String) : Exception(message)

/**
 * Talks to the TrustGate server over HTTPS. Which certificates it trusts, and the key it pins the
 * server to, come from the network security config the build generates.
 */
class HttpTrustGateApi(
    private val baseUrl: String,
    private val client: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(5, TimeUnit.SECONDS)
        .readTimeout(10, TimeUnit.SECONDS)
        .build(),
) : TrustGateApi {
    override suspend fun registrationChallenge(deviceKeyId: String?): ByteArray =
        bytes(post<RegistrationChallengeRequest, RegistrationChallenge>(TrustGateRoutes.REGISTRATION_CHALLENGE, RegistrationChallengeRequest(deviceKeyId)).challenge)

    override suspend fun registerKey(
        role: KeyRole,
        encodedPublicKey: ByteArray,
        attestationChain: List<ByteArray>,
        challenge: ByteArray,
        deviceKeyId: String?,
        deviceKeyProof: ByteArray?,
        phoneLabel: String?,
    ): RegistrationResult = post(
        TrustGateRoutes.KEYS,
        KeyRegistrationRequest(
            role = role,
            publicKey = base64(encodedPublicKey),
            certificateChain = attestationChain.map(::base64),
            challenge = base64(challenge),
            deviceKeyId = deviceKeyId,
            deviceKeyProof = deviceKeyProof?.let(::base64),
            phoneLabel = phoneLabel,
        ),
    )

    override suspend fun removeStepUpKey(deviceKeyId: String, challenge: ByteArray, deviceKeyProof: ByteArray): Boolean =
        post<StepUpRemovalRequest, StepUpRemoval>(
            TrustGateRoutes.REMOVE_STEP_UP,
            StepUpRemovalRequest(deviceKeyId, base64(challenge), base64(deviceKeyProof)),
        ).removed

    override suspend fun rotateDeviceKey(
        currentKeyId: String,
        encodedPublicKey: ByteArray,
        attestationChain: List<ByteArray>,
        challenge: ByteArray,
        proof: ByteArray,
    ): RegistrationResult = post(
        TrustGateRoutes.ROTATE_DEVICE_KEY,
        KeyRotationRequest(currentKeyId, base64(encodedPublicKey), attestationChain.map(::base64), base64(challenge), base64(proof)),
    )

    override suspend fun removeDevice(deviceKeyId: String, challenge: ByteArray, proof: ByteArray): Boolean =
        post<DeviceRemovalRequest, DeviceRemoval>(
            TrustGateRoutes.REMOVE_DEVICE,
            DeviceRemovalRequest(deviceKeyId, base64(challenge), base64(proof)),
        ).removed

    override suspend fun verificationChallenge(deviceKeyId: String): String =
        post<VerificationChallengeRequest, VerificationChallenge>(TrustGateRoutes.VERIFICATION_CHALLENGE, VerificationChallengeRequest(deviceKeyId)).nonce

    override suspend fun authorizePayment(request: PaymentAuthorizationRequest): PaymentAuthorization =
        post(TrustGateRoutes.AUTHORIZE_PAYMENT, request)

    override suspend fun checkRequest(request: ReceivedRequest): VerificationResult = send(TrustGateRoutes.PAYMENT_CHECK, request)

    override suspend fun submitPayment(request: ReceivedRequest): PaymentResponse = send(TrustGateRoutes.PAYMENT, request)

    override suspend fun accountView(action: SignedAction): AccountView = post(TrustGateRoutes.ACCOUNT, action)

    override suspend fun createLinkCode(action: SignedAction): LinkCode = post(TrustGateRoutes.LINK_CODE, action)

    override suspend fun joinAccount(action: SignedAction): JoinResult = post(TrustGateRoutes.JOIN_ACCOUNT, action)

    override suspend fun decisionChallenge(request: DecisionChallengeRequest): DecisionChallenge = post(TrustGateRoutes.DECISION_CHALLENGE, request)

    override suspend fun decide(decision: PhoneDecision): DecisionResult = post(TrustGateRoutes.DECIDE, decision)

    private suspend inline fun <reified Req, reified Res> post(path: String, body: Req): Res =
        TrustGateJson.decodeFromString(execute(path, TrustGateJson.encodeToString(body), emptyMap()))

    /** Sends the exact body bytes and signing headers that were signed. */
    private suspend inline fun <reified Res> send(path: String, request: ReceivedRequest): Res =
        TrustGateJson.decodeFromString(execute(path, request.body, request.headers))

    private suspend fun execute(path: String, body: String, headers: Map<String, String>): String {
        val request = Request.Builder()
            .url(baseUrl.trimEnd('/') + path)
            .post(body.toRequestBody(JSON))
            .apply { headers.forEach { (name, value) -> header(name, value) } }
            .build()
        return client.newCall(request).await().use { response ->
            val text = response.body?.string().orEmpty()
            when {
                response.isSuccessful -> text
                // A server error may have happened after processing, so it's retried like a lost response.
                response.code >= 500 -> throw IOException("The TrustGate server answered ${response.code}.")
                response.code == 429 -> throw BackendRequestException("Too many tries. Wait a minute and try again.")
                else -> throw BackendRequestException("The TrustGate server refused the request (${response.code}).")
            }
        }
    }

    private suspend fun Call.await(): Response = suspendCancellableCoroutine { continuation ->
        continuation.invokeOnCancellation { cancel() }
        enqueue(
            object : Callback {
                override fun onResponse(call: Call, response: Response) = continuation.resume(response)

                override fun onFailure(call: Call, e: IOException) = continuation.resumeWithException(e)
            },
        )
    }

    private fun base64(value: ByteArray): String = Base64.getEncoder().encodeToString(value)

    private fun bytes(value: String): ByteArray = Base64.getDecoder().decode(value)

    private companion object {
        val JSON = "application/json".toMediaType()
    }
}
