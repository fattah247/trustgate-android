package id.fatarc.trustgate.server

import id.fatarc.trustgate.backend.ReferenceBackend
import id.fatarc.trustgate.domain.api.ErrorResponse
import id.fatarc.trustgate.domain.api.KeyRegistrationRequest
import id.fatarc.trustgate.domain.api.PaymentAuthorization
import id.fatarc.trustgate.domain.api.PaymentAuthorizationRequest
import id.fatarc.trustgate.domain.api.PaymentResponse
import id.fatarc.trustgate.domain.api.RegistrationChallenge
import id.fatarc.trustgate.domain.api.RegistrationChallengeRequest
import id.fatarc.trustgate.domain.api.RegistrationResult
import id.fatarc.trustgate.domain.api.ServerHealth
import id.fatarc.trustgate.domain.api.StepUpRemoval
import id.fatarc.trustgate.domain.api.StepUpRemovalRequest
import id.fatarc.trustgate.domain.api.TrustGateJson
import id.fatarc.trustgate.domain.api.TrustGateRoutes
import id.fatarc.trustgate.domain.api.VerificationChallenge
import id.fatarc.trustgate.domain.api.VerificationChallengeRequest
import id.fatarc.trustgate.domain.signing.ReceivedRequest
import id.fatarc.trustgate.domain.signing.ReferenceSigningScheme
import id.fatarc.trustgate.domain.signing.VerificationResult
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
import io.ktor.server.plugins.statuspages.StatusPages
import io.ktor.server.request.contentLength
import io.ktor.server.request.receive
import io.ktor.server.request.receiveText
import io.ktor.server.response.respond
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import java.util.Base64

/** Signed bodies are small payment payloads; anything bigger isn't one. */
private const val MAX_SIGNED_BODY_BYTES = 16 * 1024

fun Application.trustGateModule(backend: ReferenceBackend, health: ServerHealth) {
    install(ContentNegotiation) { json(TrustGateJson) }
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
            )
            call.respond<RegistrationResult>(result)
        }

        post(TrustGateRoutes.REMOVE_STEP_UP) {
            val request = call.receive<StepUpRemovalRequest>()
            val removed = backend.removeStepUpKey(request.deviceKeyId, bytes(request.challenge), bytes(request.deviceKeyProof))
            call.respond(StepUpRemoval(removed))
        }

        post(TrustGateRoutes.VERIFICATION_CHALLENGE) {
            val request = call.receive<VerificationChallengeRequest>()
            call.respond(VerificationChallenge(backend.issueVerificationChallenge(request.deviceKeyId)))
        }

        post(TrustGateRoutes.AUTHORIZE_PAYMENT) {
            val request = call.receive<PaymentAuthorizationRequest>()
            call.respond<PaymentAuthorization>(backend.beginPayment(request.deviceKeyId, request.level))
        }

        post(TrustGateRoutes.PAYMENT) {
            call.respond<PaymentResponse>(backend.submitPayment(call.signedRequest()))
        }

        post(TrustGateRoutes.PAYMENT_CHECK) {
            call.respond<VerificationResult>(backend.authenticate(call.signedRequest()))
        }
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
