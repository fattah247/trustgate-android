package id.fatarc.trustgate.attacklab

import id.fatarc.trustgate.domain.api.DeviceEvidence
import id.fatarc.trustgate.domain.api.KeyRegistrationRequest
import id.fatarc.trustgate.domain.api.KeyRotationRequest
import id.fatarc.trustgate.domain.api.MockIntegrityClaims
import id.fatarc.trustgate.domain.api.PaymentAuthorization
import id.fatarc.trustgate.domain.api.PaymentAuthorizationRequest
import id.fatarc.trustgate.domain.api.PaymentResponse
import id.fatarc.trustgate.domain.api.RegistrationChallenge
import id.fatarc.trustgate.domain.api.RegistrationChallengeRequest
import id.fatarc.trustgate.domain.api.RegistrationResult
import id.fatarc.trustgate.domain.api.ReportedSignal
import id.fatarc.trustgate.domain.api.TrustGateJson
import id.fatarc.trustgate.domain.api.TrustGateRoutes
import id.fatarc.trustgate.domain.api.VerificationChallenge
import id.fatarc.trustgate.domain.api.VerificationChallengeRequest
import id.fatarc.trustgate.domain.risk.SignalCatalog
import id.fatarc.trustgate.domain.signing.KeyRole
import id.fatarc.trustgate.domain.signing.PaymentRequestPayload
import id.fatarc.trustgate.domain.signing.ReferenceRequestSigner
import id.fatarc.trustgate.domain.signing.ReferenceSigningScheme
import id.fatarc.trustgate.domain.signing.SignedRequest
import id.fatarc.trustgate.domain.signing.VerificationResult
import id.fatarc.trustgate.domain.signing.asReceived
import id.fatarc.trustgate.testing.TestKey
import id.fatarc.trustgate.testing.selfSignedChain
import java.time.Clock
import java.time.Duration
import java.util.Base64
import java.util.UUID
import kotlinx.serialization.KSerializer

/** One HTTP exchange with the server under test. */
class Reply(val status: Int, val body: String)

/** How the lab reaches a server: over HTTPS from the command line, or in process from a test. */
interface Transport {
    fun post(path: String, body: String, headers: Map<String, String> = emptyMap()): Reply

    fun get(path: String): Reply
}

/** What one attack did, and whether the server stopped it. A [skipped] attack couldn't be tried at all. */
class AttackResult(val attack: String, val stopped: Boolean, val serverSaid: String, val skipped: Boolean = false)

/**
 * Attacks a TrustGate server through its public API, the way someone with a copy of the protocol
 * and a phone of their own would: replayed, edited, late, and forged requests, keys it never
 * registered, and requests for more than one phone may do. Every attack is aimed at the server,
 * whose answer is the only one that counts.
 */
class AttackLab(
    private val server: Transport,
    private val clock: Clock = Clock.systemUTC(),
) {
    private val signer = ReferenceRequestSigner()
    private val stranger = TestKey()

    fun run(): List<AttackResult> {
        val phone = TestKey()
        val registration = register(phone)
        if (registration !is RegistrationResult.Registered) {
            return listOf(
                AttackResult(
                    "Register a key with no hardware proof",
                    stopped = true,
                    serverSaid = (registration as RegistrationResult.Refused).reason,
                ),
                AttackResult(
                    "The attacks that need a registered key",
                    stopped = true,
                    serverSaid = "This server registers only hardware-attested keys",
                    skipped = true,
                ),
                readAuditWithoutToken(),
            )
        }
        return listOf(
            replayPayment(phone),
            changeAmount(phone),
            sendLate(phone),
            unknownKey(),
            borrowAnotherPhonesChallenge(phone),
            forgeDeviceReport(phone),
            reuseIntegrityToken(phone),
            skipConfirmation(phone),
            slipInStepUpKey(phone),
            hijackRotation(phone),
            useReplacedKey(),
            payPastTheLimit(),
            readAuditWithoutToken(),
            floodRegistration(),
        )
    }

    private fun replayPayment(phone: TestKey): AttackResult {
        val payment = signedPayment(phone, authorize(phone) as PaymentAuthorization.Proceed)
        val first = pay(payment)
        val again = pay(payment)
        val chargedOnce = first is PaymentResponse.Processed && again is PaymentResponse.Processed && again.replayed &&
            again.payment == first.payment
        return AttackResult(
            "Replay a payment",
            stopped = chargedOnce || again is PaymentResponse.Rejected,
            serverSaid = if (chargedOnce) "Same payment returned, charged once" else describe(again),
        )
    }

    private fun changeAmount(phone: TestKey): AttackResult {
        val request = verificationRequest(phone)
        val edited = request.asReceived().copy(body = signer.canonicalize(request.payload.copy(amountMinor = request.payload.amountMinor * 100)))
        return verdict("Raise the amount after signing", check(edited))
    }

    private fun sendLate(phone: TestKey): AttackResult {
        val nonce = verificationChallenge(phone.keyId)
        val signedEarlier = phone.sign(
            signer.prepare(
                payload = REFERENCE_PAYLOAD,
                nonce = nonce,
                keyId = phone.keyId,
                timestamp = clock.instant().minus(ReferenceSigningScheme.TIME_WINDOW).minus(Duration.ofMinutes(1)).toString(),
            ),
        )
        return verdict("Deliver a request after the time window", check(signedEarlier.asReceived()))
    }

    private fun unknownKey(): AttackResult {
        val request = stranger.sign(signer.prepare(REFERENCE_PAYLOAD, "made-up-nonce", stranger.keyId, clock.instant().toString()))
        return verdict("Sign with a key the server never registered", check(request.asReceived()))
    }

    private fun borrowAnotherPhonesChallenge(phone: TestKey): AttackResult {
        val victim = TestKey().also { register(it) }
        val victimsNonce = verificationChallenge(victim.keyId)
        val request = phone.sign(signer.prepare(REFERENCE_PAYLOAD, victimsNonce, phone.keyId, clock.instant().toString()))
        return verdict("Use a challenge issued to another phone", check(request.asReceived()))
    }

    private fun forgeDeviceReport(phone: TestKey): AttackResult {
        val evidence = evidence(phone.keyId)
        val authorization = authorize(phone.keyId, evidence, signature = stranger.sign(evidence.toByteArray()))
        return blockedVerdict("Send a clean device report signed by another key", authorization)
    }

    private fun reuseIntegrityToken(phone: TestKey): AttackResult {
        val otherReport = evidence(phone.keyId, signals = listOf(ReportedSignal(SignalCatalog.EMULATOR_FINGERPRINT.id, detected = false)))
        val tokenForOtherReport = MockIntegrityClaims(ReferenceSigningScheme.sha256Hex(otherReport)).encode()
        val evidence = evidence(phone.keyId)
        val authorization = authorize(phone.keyId, evidence, phone.sign(evidence.toByteArray()), tokenForOtherReport)
        return blockedVerdict("Reuse an integrity token issued for another report", authorization)
    }

    private fun skipConfirmation(phone: TestKey): AttackResult {
        val evidence = evidence(phone.keyId, signals = listOf(ReportedSignal(SignalCatalog.TEST_KEYS.id, detected = true)))
        val authorization = authorize(phone.keyId, evidence, phone.sign(evidence.toByteArray()))
        if (authorization !is PaymentAuthorization.Proceed) return blockedVerdict("Pay without the confirmation the server asked for", authorization)
        // Signed with the device key and no confirmation, as if the prompt had been skipped.
        val response = pay(phone.sign(signer.prepare(REFERENCE_PAYLOAD, authorization.nonce, phone.keyId, clock.instant().toString(), idempotencyKey = newKey())))
        return AttackResult("Pay without the confirmation the server asked for", response is PaymentResponse.Rejected, describe(response))
    }

    private fun slipInStepUpKey(phone: TestKey): AttackResult {
        val fake = TestKey()
        val challenge = registrationChallenge(phone.keyId)
        val proof = stranger.sign(ReferenceSigningScheme.keyBindingInput(ReferenceSigningScheme.ACTION_ADD_STEP_UP, challenge, fake.keyId))
        val result = post(
            TrustGateRoutes.KEYS,
            KeyRegistrationRequest(KeyRole.STEP_UP, base64(fake.encodedPublicKey), selfSignedChain(fake).map(::base64), base64(challenge), phone.keyId, base64(proof)),
            KeyRegistrationRequest.serializer(),
            RegistrationResult.serializer(),
        )
        return AttackResult("Add a confirmation key the phone didn't approve", result is RegistrationResult.Refused, describe(result))
    }

    private fun hijackRotation(phone: TestKey): AttackResult {
        val takeover = TestKey()
        val challenge = registrationChallenge(phone.keyId)
        val proof = stranger.sign(ReferenceSigningScheme.keyBindingInput(ReferenceSigningScheme.ACTION_ROTATE_DEVICE, challenge, takeover.keyId))
        val result = rotate(phone.keyId, takeover, challenge, proof)
        return AttackResult("Take over a phone by replacing its key", result is RegistrationResult.Refused, describe(result))
    }

    private fun useReplacedKey(): AttackResult {
        val old = TestKey().also { register(it) }
        val new = TestKey()
        val challenge = registrationChallenge(old.keyId)
        rotate(old.keyId, new, challenge, old.sign(ReferenceSigningScheme.keyBindingInput(ReferenceSigningScheme.ACTION_ROTATE_DEVICE, challenge, new.keyId)))
        val request = old.sign(signer.prepare(REFERENCE_PAYLOAD, verificationChallenge(old.keyId), old.keyId, clock.instant().toString()))
        return verdict("Keep using a key after it was replaced", check(request.asReceived()))
    }

    private fun payPastTheLimit(): AttackResult {
        val phone = TestKey().also { register(it) }
        // Authorizations first, payments after, so the limit can't be met one authorization at a time.
        val authorizations = List(RAPID_PAYMENTS) { authorize(phone) }.filterIsInstance<PaymentAuthorization.Proceed>()
        val responses = authorizations.map { pay(signedPayment(phone, it)) }
        val paid = responses.count { it is PaymentResponse.Processed }
        val refusal = responses.firstOrNull { it is PaymentResponse.Rejected }
        return AttackResult(
            "Pay $RAPID_PAYMENTS times as fast as possible",
            stopped = refusal != null,
            serverSaid = refusal?.let { "$paid paid, then ${describe(it).replaceFirstChar(Char::lowercase)}" } ?: "All $paid went through",
        )
    }

    private fun readAuditWithoutToken(): AttackResult {
        val status = server.get(TrustGateRoutes.ADMIN_AUDIT).status
        return AttackResult("Read the audit log without the operator token", status == 401 || status == 404, "HTTP $status")
    }

    private fun floodRegistration(): AttackResult {
        val statuses = (1..FLOOD_REQUESTS).map {
            server.post(TrustGateRoutes.REGISTRATION_CHALLENGE, json(RegistrationChallengeRequest(), RegistrationChallengeRequest.serializer())).status
        }
        val firstRefused = statuses.indexOfFirst { it == 429 }
        return AttackResult(
            "Flood key registration",
            stopped = firstRefused >= 0,
            serverSaid = if (firstRefused >= 0) "Slowed down after ${firstRefused + 1} requests (HTTP 429)" else "All $FLOOD_REQUESTS answered",
        )
    }

    // The protocol, as any client would speak it.

    private fun register(key: TestKey): RegistrationResult {
        val challenge = registrationChallenge(null)
        return post(
            TrustGateRoutes.KEYS,
            KeyRegistrationRequest(KeyRole.DEVICE, base64(key.encodedPublicKey), selfSignedChain(key).map(::base64), base64(challenge)),
            KeyRegistrationRequest.serializer(),
            RegistrationResult.serializer(),
        )
    }

    private fun rotate(currentKeyId: String, to: TestKey, challenge: ByteArray, proof: ByteArray): RegistrationResult = post(
        TrustGateRoutes.ROTATE_DEVICE_KEY,
        KeyRotationRequest(currentKeyId, base64(to.encodedPublicKey), selfSignedChain(to).map(::base64), base64(challenge), base64(proof)),
        KeyRotationRequest.serializer(),
        RegistrationResult.serializer(),
    )

    private fun registrationChallenge(deviceKeyId: String?): ByteArray = Base64.getDecoder().decode(
        post(
            TrustGateRoutes.REGISTRATION_CHALLENGE,
            RegistrationChallengeRequest(deviceKeyId),
            RegistrationChallengeRequest.serializer(),
            RegistrationChallenge.serializer(),
        ).challenge,
    )

    private fun verificationChallenge(deviceKeyId: String): String = post(
        TrustGateRoutes.VERIFICATION_CHALLENGE,
        VerificationChallengeRequest(deviceKeyId),
        VerificationChallengeRequest.serializer(),
        VerificationChallenge.serializer(),
    ).nonce

    private fun verificationRequest(key: TestKey): SignedRequest =
        key.sign(signer.prepare(REFERENCE_PAYLOAD, verificationChallenge(key.keyId), key.keyId, clock.instant().toString()))

    private fun evidence(deviceKeyId: String, signals: List<ReportedSignal> = emptyList()): String = TrustGateJson.encodeToString(
        DeviceEvidence.serializer(),
        DeviceEvidence(deviceKeyId, clock.instant().toString(), signals),
    )

    private fun authorize(phone: TestKey): PaymentAuthorization {
        val evidence = evidence(phone.keyId)
        return authorize(phone.keyId, evidence, phone.sign(evidence.toByteArray()))
    }

    private fun authorize(
        deviceKeyId: String,
        evidence: String,
        signature: ByteArray,
        integrityToken: String = MockIntegrityClaims(ReferenceSigningScheme.sha256Hex(evidence)).encode(),
    ): PaymentAuthorization = post(
        TrustGateRoutes.AUTHORIZE_PAYMENT,
        PaymentAuthorizationRequest(deviceKeyId, evidence, base64(signature), integrityToken),
        PaymentAuthorizationRequest.serializer(),
        PaymentAuthorization.serializer(),
    )

    private fun signedPayment(phone: TestKey, authorization: PaymentAuthorization.Proceed): SignedRequest =
        phone.sign(signer.prepare(REFERENCE_PAYLOAD, authorization.nonce, phone.keyId, clock.instant().toString(), idempotencyKey = newKey()))

    private fun pay(request: SignedRequest): PaymentResponse = signed(TrustGateRoutes.PAYMENT, request, PaymentResponse.serializer())

    private fun check(request: id.fatarc.trustgate.domain.signing.ReceivedRequest): VerificationResult =
        TrustGateJson.decodeFromString(VerificationResult.serializer(), server.post(TrustGateRoutes.PAYMENT_CHECK, request.body, request.headers).body)

    private fun <T> signed(path: String, request: SignedRequest, serializer: KSerializer<T>): T {
        val received = request.asReceived()
        return TrustGateJson.decodeFromString(serializer, server.post(path, received.body, received.headers).body)
    }

    private fun <Req, Res> post(path: String, body: Req, requestSerializer: KSerializer<Req>, responseSerializer: KSerializer<Res>): Res {
        val reply = server.post(path, json(body, requestSerializer))
        check(reply.status == 200) { "$path answered HTTP ${reply.status}: ${reply.body}" }
        return TrustGateJson.decodeFromString(responseSerializer, reply.body)
    }

    private fun <T> json(value: T, serializer: KSerializer<T>): String = TrustGateJson.encodeToString(serializer, value)

    private fun verdict(attack: String, result: VerificationResult) = AttackResult(attack, result is VerificationResult.Rejected, describe(result))

    private fun blockedVerdict(attack: String, authorization: PaymentAuthorization) = AttackResult(
        attack,
        stopped = authorization is PaymentAuthorization.Blocked,
        serverSaid = authorization.reasons.filter { it.isProblem }.joinToString("; ") { it.text }.ifEmpty { authorization.decision.name.lowercase() },
    )

    private fun describe(result: Any?): String = when (result) {
        is VerificationResult.Rejected -> "Refused: ${result.reason.name.lowercase()}"
        VerificationResult.Accepted -> "Accepted"
        is PaymentResponse.Rejected -> "Refused: ${result.reason.name.lowercase()}"
        is PaymentResponse.Processed -> "Charged ${result.payment.id}"
        is RegistrationResult.Refused -> "Refused: ${result.reason}"
        is RegistrationResult.Registered -> "Registered ${result.keyId}"
        else -> result.toString()
    }

    private fun base64(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)

    private fun newKey(): String = "lab_" + UUID.randomUUID().toString().replace("-", "")

    private companion object {
        val REFERENCE_PAYLOAD = PaymentRequestPayload(amountMinor = 125_000, currency = "IDR", merchantReference = "LAB-1")

        /** More than any policy's per-window payment count. */
        const val RAPID_PAYMENTS = 6

        /** More than the server's per-minute registration allowance. */
        const val FLOOD_REQUESTS = 40
    }
}
