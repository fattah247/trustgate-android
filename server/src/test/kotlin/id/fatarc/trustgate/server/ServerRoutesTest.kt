package id.fatarc.trustgate.server

import id.fatarc.trustgate.testing.TEST_PAYMENT
import com.google.common.truth.Truth.assertThat
import id.fatarc.trustgate.backend.ReferenceBackend
import id.fatarc.trustgate.domain.api.AdminRevocationRequest
import id.fatarc.trustgate.domain.api.AuditStatus
import id.fatarc.trustgate.domain.api.DeviceRemoval
import id.fatarc.trustgate.domain.api.KeyRegistrationRequest
import id.fatarc.trustgate.domain.api.PaymentAuthorization
import id.fatarc.trustgate.domain.api.PaymentAuthorizationRequest
import id.fatarc.trustgate.domain.api.PaymentResponse
import id.fatarc.trustgate.domain.api.RegistrationChallenge
import id.fatarc.trustgate.domain.api.RegistrationChallengeRequest
import id.fatarc.trustgate.domain.api.RegistrationResult
import id.fatarc.trustgate.domain.api.ServerHealth
import id.fatarc.trustgate.domain.api.TrustGateJson
import id.fatarc.trustgate.domain.api.TrustGateRoutes
import id.fatarc.trustgate.domain.api.VerificationChallenge
import id.fatarc.trustgate.domain.api.VerificationChallengeRequest
import id.fatarc.trustgate.domain.risk.DeviceRiskLevel
import id.fatarc.trustgate.domain.signing.KeyRole
import id.fatarc.trustgate.domain.signing.ReferencePayment
import id.fatarc.trustgate.domain.signing.ReferenceRequestSigner
import id.fatarc.trustgate.domain.signing.RejectionReason
import id.fatarc.trustgate.domain.signing.SignedRequest
import id.fatarc.trustgate.domain.signing.VerificationResult
import id.fatarc.trustgate.testing.TestKey
import id.fatarc.trustgate.testing.developmentPolicy
import id.fatarc.trustgate.testing.evidenceJson
import id.fatarc.trustgate.testing.selfSignedChain
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import java.time.Instant
import java.util.Base64
import kotlinx.serialization.encodeToString
import org.junit.Test

class ServerRoutesTest {
    private val backend = ReferenceBackend(developmentPolicy)
    private val device = TestKey()
    private val signer = ReferenceRequestSigner()

    private val adminToken = "a".repeat(40)

    private fun serve(limits: RequestLimits = RequestLimits(), test: suspend ApplicationTestBuilder.() -> Unit) = testApplication {
        application { trustGateModule(backend, ServerHealth(status = "ok", policy = "development"), limits, adminToken) }
        test()
    }

    private suspend inline fun <reified Req, reified Res> HttpClient.call(path: String, body: Req): Res {
        val response = post(path) {
            contentType(ContentType.Application.Json)
            setBody(TrustGateJson.encodeToString(body))
        }
        assertThat(response.status).isEqualTo(HttpStatusCode.OK)
        return TrustGateJson.decodeFromString(response.bodyAsText())
    }

    private suspend inline fun <reified Res> HttpClient.send(path: String, request: SignedRequest, body: String = request.canonicalBody): Res {
        val response = post(path) {
            request.headers.forEach { (name, value) -> header(name, value) }
            contentType(ContentType.Application.Json)
            setBody(body)
        }
        return TrustGateJson.decodeFromString(response.bodyAsText())
    }

    private suspend fun HttpClient.registerDevice() {
        val challenge = call<RegistrationChallengeRequest, RegistrationChallenge>(TrustGateRoutes.REGISTRATION_CHALLENGE, RegistrationChallengeRequest()).challenge
        val result = call<KeyRegistrationRequest, RegistrationResult>(
            TrustGateRoutes.KEYS,
            KeyRegistrationRequest(
                role = KeyRole.DEVICE,
                publicKey = base64(device.encodedPublicKey),
                certificateChain = selfSignedChain(device).map(::base64),
                challenge = challenge,
            ),
        )
        assertThat(result).isInstanceOf(RegistrationResult.Registered::class.java)
    }

    private suspend fun HttpClient.signedPayment(): SignedRequest {
        val authorization = call<PaymentAuthorizationRequest, PaymentAuthorization>(
            TrustGateRoutes.AUTHORIZE_PAYMENT,
            evidenceJson(device.keyId, DeviceRiskLevel.LOW, Instant.now()).let { evidence ->
                PaymentAuthorizationRequest(device.keyId, evidence, base64(device.sign(evidence.toByteArray())))
            },
        ) as PaymentAuthorization.Proceed
        return device.sign(
            signer.prepare(TEST_PAYMENT, authorization.nonce, device.keyId, Instant.now().toString(), idempotencyKey = "idem-1"),
        )
    }

    @Test
    fun `a payment is charged over HTTP once, and its repeat returns the same payment`() = serve {
        client.registerDevice()
        val payment = client.signedPayment()

        val first = client.send<PaymentResponse>(TrustGateRoutes.PAYMENT, payment) as PaymentResponse.Processed
        val repeat = client.send<PaymentResponse>(TrustGateRoutes.PAYMENT, payment) as PaymentResponse.Processed

        assertThat(first.replayed).isFalse()
        assertThat(repeat.replayed).isTrue()
        assertThat(repeat.payment.id).isEqualTo(first.payment.id)
        assertThat(backend.chargedPayments).isEqualTo(1)
    }

    @Test
    fun `a body changed in transit is refused`() = serve {
        client.registerDevice()
        val payment = client.signedPayment()

        val tampered = client.send<PaymentResponse>(TrustGateRoutes.PAYMENT, payment, body = payment.canonicalBody.replace("125000", "999999"))

        assertThat(tampered).isEqualTo(PaymentResponse.Rejected(RejectionReason.SIGNATURE_MISMATCH))
    }

    @Test
    fun `the check endpoint verifies a request once without charging`() = serve {
        client.registerDevice()
        val nonce = client.call<VerificationChallengeRequest, VerificationChallenge>(
            TrustGateRoutes.VERIFICATION_CHALLENGE,
            VerificationChallengeRequest(device.keyId),
        ).nonce
        val request = device.sign(signer.prepare(TEST_PAYMENT, nonce, device.keyId, Instant.now().toString()))

        val first = client.send<VerificationResult>(TrustGateRoutes.PAYMENT_CHECK, request)
        val replay = client.send<VerificationResult>(TrustGateRoutes.PAYMENT_CHECK, request)

        assertThat(first).isEqualTo(VerificationResult.Accepted)
        assertThat(replay).isEqualTo(VerificationResult.Rejected(RejectionReason.CHALLENGE_REUSED))
        assertThat(backend.chargedPayments).isEqualTo(0)
    }

    @Test
    fun `a request the server can't read is answered with 400, not an error page`() = serve {
        val response = client.post(TrustGateRoutes.KEYS) {
            contentType(ContentType.Application.Json)
            setBody("""{"role": "DEVICE", "publicKey": "not base64!", "certificateChain": [], "challenge": ""}""")
        }

        assertThat(response.status).isEqualTo(HttpStatusCode.BadRequest)
        assertThat(response.bodyAsText()).doesNotContain("Exception")
    }

    @Test
    fun `health reports the policy the server enforces`() = serve {
        val health = TrustGateJson.decodeFromString<ServerHealth>(client.get(TrustGateRoutes.HEALTH).bodyAsText())

        assertThat(health.policy).isEqualTo("development")
    }

    private fun base64(value: ByteArray): String = Base64.getEncoder().encodeToString(value)

    @Test
    fun `a client asking for too many registration challenges is told to slow down`() = serve(RequestLimits(keysPerMinute = 3)) {
        val statuses = List(4) {
            client.post(TrustGateRoutes.REGISTRATION_CHALLENGE) {
                contentType(ContentType.Application.Json)
                setBody(TrustGateJson.encodeToString(RegistrationChallengeRequest(null)))
            }.status
        }

        assertThat(statuses.take(3)).containsExactly(HttpStatusCode.OK, HttpStatusCode.OK, HttpStatusCode.OK)
        assertThat(statuses.last()).isEqualTo(HttpStatusCode.TooManyRequests)
    }

    @Test
    fun `admin routes need the operator's token`() = serve {
        val challenge = backend.issueRegistrationChallenge()
        backend.registerKey(KeyRole.DEVICE, device.encodedPublicKey, selfSignedChain(device), challenge)

        val withoutToken = client.get(TrustGateRoutes.ADMIN_AUDIT).status
        val wrongToken = client.get(TrustGateRoutes.ADMIN_AUDIT) { header(HttpHeaders.Authorization, "Bearer ${"b".repeat(40)}") }.status
        val revoked = client.post(TrustGateRoutes.ADMIN_REVOKE) {
            header(HttpHeaders.Authorization, "Bearer $adminToken")
            contentType(ContentType.Application.Json)
            setBody(TrustGateJson.encodeToString(AdminRevocationRequest(device.keyId, "fraud reported")))
        }
        val audit = client.get(TrustGateRoutes.ADMIN_AUDIT) { header(HttpHeaders.Authorization, "Bearer $adminToken") }

        assertThat(withoutToken).isEqualTo(HttpStatusCode.Unauthorized)
        assertThat(wrongToken).isEqualTo(HttpStatusCode.Unauthorized)
        assertThat(TrustGateJson.decodeFromString(DeviceRemoval.serializer(), revoked.bodyAsText()).removed).isTrue()
        assertThat(TrustGateJson.decodeFromString(AuditStatus.serializer(), audit.bodyAsText()).intact).isTrue()
    }
}
