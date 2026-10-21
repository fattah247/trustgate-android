package id.fatarc.trustgate.server

import id.fatarc.trustgate.backend.ReferenceBackend
import id.fatarc.trustgate.domain.api.AdminRevocationRequest
import id.fatarc.trustgate.domain.api.DecisionChallengeRequest
import id.fatarc.trustgate.domain.api.DeviceRemoval
import id.fatarc.trustgate.domain.api.DeviceRemovalRequest
import id.fatarc.trustgate.domain.api.ErrorResponse
import id.fatarc.trustgate.domain.api.KeyRegistrationRequest
import id.fatarc.trustgate.domain.api.KeyRotationRequest
import id.fatarc.trustgate.domain.api.PaymentAuthorization
import id.fatarc.trustgate.domain.api.PaymentAuthorizationRequest
import id.fatarc.trustgate.domain.api.PaymentResponse
import id.fatarc.trustgate.domain.api.PhoneDecision
import id.fatarc.trustgate.domain.api.RegistrationChallenge
import id.fatarc.trustgate.domain.api.RegistrationChallengeRequest
import id.fatarc.trustgate.domain.api.RegistrationResult
import id.fatarc.trustgate.domain.api.ServerHealth
import id.fatarc.trustgate.domain.api.SignedAction
import id.fatarc.trustgate.domain.api.StepUpRemoval
import id.fatarc.trustgate.domain.api.StepUpRemovalRequest
import id.fatarc.trustgate.domain.api.TrustGateJson
import id.fatarc.trustgate.domain.api.TrustGateRoutes
import id.fatarc.trustgate.domain.api.VerificationChallenge
import id.fatarc.trustgate.domain.api.VerificationChallengeRequest
import id.fatarc.trustgate.domain.signing.ReceivedRequest
import id.fatarc.trustgate.domain.signing.ReferenceSigningScheme
import id.fatarc.trustgate.domain.signing.VerificationResult
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.Application
import io.ktor.server.application.ApplicationCall
import io.ktor.server.application.call
import io.ktor.server.application.install
import io.ktor.server.application.log
import io.ktor.server.plugins.BadRequestException
import io.ktor.server.plugins.callloging.CallLogging
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.plugins.ratelimit.RateLimit
import io.ktor.server.plugins.ratelimit.RateLimitName
import io.ktor.server.plugins.ratelimit.rateLimit
import io.ktor.server.plugins.statuspages.StatusPages
import io.ktor.server.request.contentLength
import io.ktor.server.request.receive
import io.ktor.server.request.receiveText
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import java.security.MessageDigest
import java.util.Base64
import kotlin.time.Duration.Companion.minutes

/** Signed bodies are small payment payloads; anything bigger isn't one. */
private const val MAX_SIGNED_BODY_BYTES = 16 * 1024

/**
 * How many requests one client address may make per minute. Key and account requests are the
 * cheapest to flood, so they get the lower limit; payments have their own per-account limits too.
 */
class RequestLimits(val keysPerMinute: Int = 40, val paymentsPerMinute: Int = 60)

private val KEYS = RateLimitName("keys")
private val PAYMENTS = RateLimitName("payments")

fun Application.trustGateModule(
    backend: ReferenceBackend,
    health: ServerHealth,
    limits: RequestLimits = RequestLimits(),
    adminToken: String? = null,
) {
    install(ContentNegotiation) { json(TrustGateJson) }
    install(RateLimit) {
        // By connection address, not a forwarded header a client could set to anything.
        register(KEYS) {
            rateLimiter(limit = limits.keysPerMinute, refillPeriod = 1.minutes)
            requestKey { call -> call.request.local.remoteAddress }
        }
        register(PAYMENTS) {
            rateLimiter(limit = limits.paymentsPerMinute, refillPeriod = 1.minutes)
            requestKey { call -> call.request.local.remoteAddress }
        }
    }
    // Method, path, and status only: bodies and signing headers stay out of the log.
    install(CallLogging)
    install(StatusPages) {
        exception<BadRequestException> { call, _ -> call.respond(HttpStatusCode.BadRequest, ErrorResponse("The request couldn't be read.")) }
        exception<IllegalArgumentException> { call, _ -> call.respond(HttpStatusCode.BadRequest, ErrorResponse("The request couldn't be read.")) }
        exception<Throwable> { call, cause ->
            call.application.log.error("Request failed", cause)
            call.respond(HttpStatusCode.InternalServerError, ErrorResponse("The server couldn't complete the request."))
        }
    }

    routing {
        get(TrustGateRoutes.HEALTH) { call.respond(health) }

        rateLimit(KEYS) {
            keyRoutes(backend)
            if (adminToken != null) adminRoutes(backend, adminToken)
        }
        rateLimit(PAYMENTS) { paymentRoutes(backend) }
    }
}

/** For the people running the server: revoke a phone, and check the audit log's chain. */
private fun Route.adminRoutes(backend: ReferenceBackend, adminToken: String) {
    val expected = "Bearer $adminToken".toByteArray()
    suspend fun ApplicationCall.authorized(): Boolean {
        val presented = request.headers[HttpHeaders.Authorization].orEmpty().toByteArray()
        // Compared in constant time, so response timing doesn't reveal how much of a guess was right.
        if (MessageDigest.isEqual(presented, expected)) return true
        respond(HttpStatusCode.Unauthorized, ErrorResponse("Not allowed."))
        return false
    }

    post(TrustGateRoutes.ADMIN_REVOKE) {
        if (!call.authorized()) return@post
        val request = call.receive<AdminRevocationRequest>()
        call.respond(DeviceRemoval(backend.revokeByOperator(request.keyId, request.reason)))
    }

    get(TrustGateRoutes.ADMIN_AUDIT) {
        if (!call.authorized()) return@get
        call.respond(backend.auditStatus())
    }
}

private fun Route.keyRoutes(backend: ReferenceBackend) {
    post(TrustGateRoutes.REGISTRATION_CHALLENGE) {
        val request = call.receive<RegistrationChallengeRequest>()
        call.respond(RegistrationChallenge(base64(backend.issueRegistrationChallenge(request.deviceKeyId))))
    }

    post(TrustGateRoutes.KEYS) {
        val request = call.receive<KeyRegistrationRequest>()
        val result = backend.registerKey(
            role = request.role,
            encodedPublicKey = bytes(request.publicKey),
            attestationChain = request.certificateChain.map(::bytes),
            challenge = bytes(request.challenge),
            deviceKeyId = request.deviceKeyId,
            deviceKeyProof = request.deviceKeyProof?.let(::bytes),
            phoneLabel = request.phoneLabel,
        )
        call.respond<RegistrationResult>(result)
    }

    post(TrustGateRoutes.REMOVE_STEP_UP) {
        val request = call.receive<StepUpRemovalRequest>()
        val removed = backend.removeStepUpKey(request.deviceKeyId, bytes(request.challenge), bytes(request.deviceKeyProof))
        call.respond(StepUpRemoval(removed))
    }

    post(TrustGateRoutes.ROTATE_DEVICE_KEY) {
        val request = call.receive<KeyRotationRequest>()
        val result = backend.rotateDeviceKey(
            currentKeyId = request.currentKeyId,
            encodedPublicKey = bytes(request.publicKey),
            attestationChain = request.certificateChain.map(::bytes),
            challenge = bytes(request.challenge),
            proof = bytes(request.proof),
        )
        call.respond<RegistrationResult>(result)
    }

    post(TrustGateRoutes.REMOVE_DEVICE) {
        val request = call.receive<DeviceRemovalRequest>()
        call.respond(DeviceRemoval(backend.removeDevice(request.deviceKeyId, bytes(request.challenge), bytes(request.proof))))
    }

    // A phone's account: answered with 403 and nothing more when the signature or the phone doesn't check out.
    post(TrustGateRoutes.ACCOUNT) {
        call.respondOrForbid(backend.accountView(call.receive<SignedAction>()))
    }

    post(TrustGateRoutes.LINK_CODE) {
        call.respondOrForbid(backend.createLinkCode(call.receive<SignedAction>()))
    }

    post(TrustGateRoutes.JOIN_ACCOUNT) {
        call.respond(backend.joinAccount(call.receive<SignedAction>()))
    }

    post(TrustGateRoutes.DECISION_CHALLENGE) {
        call.respondOrForbid(backend.decisionChallenge(call.receive<DecisionChallengeRequest>()))
    }

    post(TrustGateRoutes.DECIDE) {
        call.respond(backend.decide(call.receive<PhoneDecision>()))
    }
}

private suspend inline fun <reified T : Any> ApplicationCall.respondOrForbid(value: T?) {
    if (value == null) respond(HttpStatusCode.Forbidden, ErrorResponse("Not allowed.")) else respond(value)
}

private fun Route.paymentRoutes(backend: ReferenceBackend) {
    post(TrustGateRoutes.VERIFICATION_CHALLENGE) {
        val request = call.receive<VerificationChallengeRequest>()
        call.respond(VerificationChallenge(backend.issueVerificationChallenge(request.deviceKeyId)))
    }

    post(TrustGateRoutes.AUTHORIZE_PAYMENT) {
        val request = call.receive<PaymentAuthorizationRequest>()
        val authorization = backend.authorizePayment(
            deviceKeyId = request.deviceKeyId,
            evidence = request.evidence,
            signature = bytes(request.signature),
            integrityToken = request.integrityToken,
        )
        call.respond<PaymentAuthorization>(authorization)
    }

    post(TrustGateRoutes.PAYMENT) {
        call.respond<PaymentResponse>(backend.submitPayment(call.signedRequest()))
    }

    post(TrustGateRoutes.PAYMENT_CHECK) {
        call.respond<VerificationResult>(backend.authenticate(call.signedRequest()))
    }
}

/**
 * The request as the payment endpoint would see it: its signing headers and exact body bytes. The
 * check endpoint uses the payment path too, so it judges the very request a payment would be.
 */
private suspend fun ApplicationCall.signedRequest(): ReceivedRequest {
    val length = request.contentLength()
    if (length == null || length > MAX_SIGNED_BODY_BYTES) throw BadRequestException("Signed body missing or too large.")
    return ReceivedRequest(
        method = "POST",
        path = ReferenceSigningScheme.PATH,
        headers = TrustGateRoutes.SIGNING_HEADERS.mapNotNull { name -> request.headers[name]?.let { name to it } }.toMap(),
        body = receiveText(),
    )
}

private fun base64(value: ByteArray): String = Base64.getEncoder().encodeToString(value)

private fun bytes(value: String): ByteArray = Base64.getDecoder().decode(value)
