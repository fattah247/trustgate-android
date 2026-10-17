package id.fatarc.trustgate.core.backend

import com.google.common.truth.Truth.assertThat
import id.fatarc.trustgate.domain.actiongate.SensitiveActionDecision
import id.fatarc.trustgate.domain.risk.DeviceRiskLevel
import id.fatarc.trustgate.domain.signing.KeyRole
import id.fatarc.trustgate.domain.signing.PaymentRequestPayload
import id.fatarc.trustgate.domain.signing.ReferenceRequestSigner
import id.fatarc.trustgate.domain.signing.ReferenceSigningScheme
import id.fatarc.trustgate.domain.signing.RejectionReason
import id.fatarc.trustgate.domain.signing.SignedRequest
import id.fatarc.trustgate.domain.signing.VerificationResult
import id.fatarc.trustgate.domain.signing.asReceived
import id.fatarc.trustgate.testing.MutableClock
import id.fatarc.trustgate.testing.TestAttestation
import id.fatarc.trustgate.testing.TestKey
import id.fatarc.trustgate.testing.selfSignedChain
import org.junit.Test

class ReferenceBackendTest {
    private val clock = MutableClock()
    private val backend = ReferenceBackend(clock = clock)
    private val signer = ReferenceRequestSigner()
    private val device = TestKey()
    private val stepUp = TestKey()
    private val payload = PaymentRequestPayload(amountMinor = 125_000, currency = "IDR", merchantReference = "REF-1001")

    private fun registerDevice(key: TestKey = device) {
        val challenge = backend.issueRegistrationChallenge()
        val result = backend.registerKey(KeyRole.DEVICE, key.encodedPublicKey, selfSignedChain(key), challenge)
        assertThat(result).isInstanceOf(RegistrationResult.Registered::class.java)
    }

    private fun registerStepUp(
        vouchedBy: TestKey = device,
        chainFor: (challenge: ByteArray) -> List<ByteArray> = { selfSignedChain(stepUp) },
    ): RegistrationResult {
        val challenge = backend.issueRegistrationChallenge(device.keyId)
        val proof = vouchedBy.sign(
            ReferenceSigningScheme.keyBindingInput(ReferenceSigningScheme.ACTION_ADD_STEP_UP, challenge, stepUp.keyId),
        )
        return backend.registerKey(KeyRole.STEP_UP, stepUp.encodedPublicKey, chainFor(challenge), challenge, device.keyId, proof)
    }

    private fun removeStepUp(vouchedBy: TestKey = device): Boolean {
        val challenge = backend.issueRegistrationChallenge(device.keyId)
        val proof = vouchedBy.sign(
            ReferenceSigningScheme.keyBindingInput(ReferenceSigningScheme.ACTION_REMOVE_STEP_UP, challenge, device.keyId),
        )
        return backend.removeStepUpKey(device.keyId, challenge, proof)
    }

    

    private fun paymentRequest(
        nonce: String,
        key: TestKey = device,
        idempotencyKey: String = "idem-1",
        confirmation: String? = null,
        body: PaymentRequestPayload = payload,
    ): SignedRequest = key.sign(
        signer.prepare(
            payload = body,
            nonce = nonce,
            keyId = key.keyId,
            timestamp = clock.now.toString(),
            idempotencyKey = idempotencyKey,
            confirmation = confirmation,
        ),
    )

    private fun allowedNonce(): String =
        (backend.beginPayment(device.keyId, DeviceRiskLevel.LOW) as PaymentAuthorization.Proceed).nonce

    private fun verificationRequest(key: TestKey = device): SignedRequest = key.sign(
        signer.prepare(
            payload = payload,
            nonce = backend.issueVerificationChallenge(device.keyId),
            keyId = key.keyId,
            timestamp = clock.now.toString(),
        ),
    )

    @Test
    fun `low risk payment signed by the device key is charged once`() {
        registerDevice()

        val response = backend.submitPayment(paymentRequest(allowedNonce()).asReceived())

        assertThat(response).isInstanceOf(PaymentResponse.Processed::class.java)
        assertThat((response as PaymentResponse.Processed).replayed).isFalse()
        assertThat(backend.chargedPayments).isEqualTo(1)
    }

    @Test
    fun `resending the same request returns the original payment without charging again`() {
        registerDevice()
        val request = paymentRequest(allowedNonce()).asReceived()
        val first = backend.submitPayment(request) as PaymentResponse.Processed

        clock.advanceSeconds(2)
        val retry = backend.submitPayment(request) as PaymentResponse.Processed

        assertThat(retry.replayed).isTrue()
        assertThat(retry.payment.id).isEqualTo(first.payment.id)
        assertThat(backend.chargedPayments).isEqualTo(1)
    }

    @Test
    fun `reusing an idempotency key for a different payment is a conflict`() {
        registerDevice()
        backend.submitPayment(paymentRequest(allowedNonce()).asReceived())

        val different = paymentRequest(allowedNonce(), body = payload.copy(amountMinor = 999)).asReceived()

        assertThat(backend.submitPayment(different))
            .isEqualTo(PaymentResponse.Rejected(RejectionReason.IDEMPOTENCY_CONFLICT))
        assertThat(backend.chargedPayments).isEqualTo(1)
    }

    @Test
    fun `high risk is blocked before any challenge is issued`() {
        registerDevice()

        val authorization = backend.beginPayment(device.keyId, DeviceRiskLevel.HIGH)

        assertThat(authorization).isEqualTo(PaymentAuthorization.Blocked(DeviceRiskLevel.HIGH))
    }

    @Test
    fun `medium risk with a step-up key must be signed by that key`() {
        registerDevice()
        assertThat(registerStepUp()).isInstanceOf(RegistrationResult.Registered::class.java)
        val authorization = backend.beginPayment(device.keyId, DeviceRiskLevel.MEDIUM) as PaymentAuthorization.Proceed

        val signedByDeviceKey = backend.submitPayment(paymentRequest(authorization.nonce).asReceived())
        val signedByStepUpKey = backend.submitPayment(paymentRequest(authorization.nonce, key = stepUp).asReceived())

        assertThat(authorization.decision).isEqualTo(SensitiveActionDecision.REQUIRE_CONFIRMATION)
        assertThat(authorization.confirmation).isEqualTo(RequiredConfirmation.STEP_UP_KEY)
        assertThat(signedByDeviceKey).isEqualTo(PaymentResponse.Rejected(RejectionReason.CONFIRMATION_REQUIRED))
        assertThat((signedByStepUpKey as PaymentResponse.Processed).payment.signedWith).isEqualTo(KeyRole.STEP_UP)
    }

    @Test
    fun `medium risk without a step-up key needs a signed tap confirmation`() {
        registerDevice()
        val authorization = backend.beginPayment(device.keyId, DeviceRiskLevel.MEDIUM) as PaymentAuthorization.Proceed

        val unconfirmed = backend.submitPayment(paymentRequest(authorization.nonce).asReceived())
        val tapped = backend.submitPayment(
            paymentRequest(authorization.nonce, idempotencyKey = "idem-2", confirmation = ReferenceSigningScheme.CONFIRMATION_TAP).asReceived(),
        )

        assertThat(authorization.confirmation).isEqualTo(RequiredConfirmation.TAP)
        assertThat(unconfirmed).isEqualTo(PaymentResponse.Rejected(RejectionReason.CONFIRMATION_REQUIRED))
        assertThat((tapped as PaymentResponse.Processed).payment.confirmation).isEqualTo(RequiredConfirmation.TAP)
    }

    @Test
    fun `adding the tap header after signing breaks the signature`() {
        registerDevice()
        val authorization = backend.beginPayment(device.keyId, DeviceRiskLevel.MEDIUM) as PaymentAuthorization.Proceed
        val request = paymentRequest(authorization.nonce).asReceived().let {
            it.copy(headers = it.headers + (ReferenceSigningScheme.HEADER_CONFIRMATION to ReferenceSigningScheme.CONFIRMATION_TAP))
        }

        assertThat(backend.submitPayment(request)).isEqualTo(PaymentResponse.Rejected(RejectionReason.SIGNATURE_MISMATCH))
    }

    @Test
    fun `verification spends the challenge so a replay is rejected`() {
        registerDevice()
        val request = verificationRequest().asReceived()

        val first = backend.authenticate(request)
        val replay = backend.authenticate(request)

        assertThat(first).isEqualTo(VerificationResult.Accepted)
        assertThat(replay).isEqualTo(VerificationResult.Rejected(RejectionReason.CHALLENGE_REUSED))
    }

    @Test
    fun `changing the body after signing breaks the signature`() {
        registerDevice()
        val tampered = verificationRequest().asReceived().copy(
            body = signer.canonicalize(payload.copy(amountMinor = 1_250_000)),
        )

        assertThat(backend.authenticate(tampered)).isEqualTo(VerificationResult.Rejected(RejectionReason.SIGNATURE_MISMATCH))
    }

    @Test
    fun `a rejected forgery does not use up the genuine request's challenge`() {
        registerDevice()
        val genuine = verificationRequest().asReceived()
        backend.authenticate(genuine.copy(body = "{}"))

        assertThat(backend.authenticate(genuine)).isEqualTo(VerificationResult.Accepted)
    }

    @Test
    fun `a request arriving after the time window is rejected`() {
        registerDevice()
        val request = verificationRequest().asReceived()

        val late = backend.authenticate(request, receivedAt = clock.now.plus(ReferenceBackend.ALLOWED_CLOCK_SKEW).plusSeconds(1))

        assertThat(late).isEqualTo(VerificationResult.Rejected(RejectionReason.OUTSIDE_TIME_WINDOW))
    }

    @Test
    fun `a key the backend never registered is rejected`() {
        registerDevice()

        val result = backend.authenticate(verificationRequest(key = TestKey()).asReceived())

        assertThat(result).isEqualTo(VerificationResult.Rejected(RejectionReason.UNKNOWN_KEY))
    }

    @Test
    fun `a nonce the backend never issued is rejected`() {
        registerDevice()
        val request = device.sign(signer.prepare(payload, nonce = "made-up", keyId = device.keyId, timestamp = clock.now.toString()))

        assertThat(backend.authenticate(request.asReceived()))
            .isEqualTo(VerificationResult.Rejected(RejectionReason.UNKNOWN_CHALLENGE))
    }

    @Test
    fun `a challenge issued to another device is rejected`() {
        val other = TestKey()
        registerDevice()
        registerDevice(other)
        val request = device.sign(
            signer.prepare(payload, nonce = backend.issueVerificationChallenge(other.keyId), keyId = device.keyId, timestamp = clock.now.toString()),
        )

        assertThat(backend.authenticate(request.asReceived()))
            .isEqualTo(VerificationResult.Rejected(RejectionReason.UNKNOWN_CHALLENGE))
    }

    @Test
    fun `an expired challenge is rejected`() {
        registerDevice()
        val nonce = backend.issueVerificationChallenge(device.keyId)
        clock.advanceSeconds(6 * 60)
        val request = device.sign(signer.prepare(payload, nonce = nonce, keyId = device.keyId, timestamp = clock.now.toString()))

        assertThat(backend.authenticate(request.asReceived()))
            .isEqualTo(VerificationResult.Rejected(RejectionReason.UNKNOWN_CHALLENGE))
    }

    @Test
    fun `a header containing a line break is rejected`() {
        registerDevice()
        val request = verificationRequest().asReceived().let {
            it.copy(headers = it.headers + (ReferenceSigningScheme.HEADER_IDEMPOTENCY_KEY to "a\nb"))
        }

        assertThat(backend.authenticate(request)).isEqualTo(VerificationResult.Rejected(RejectionReason.MISSING_HEADERS))
    }

    @Test
    fun `headers are matched case-insensitively like HTTP`() {
        registerDevice()
        val request = verificationRequest().asReceived().let { received ->
            received.copy(headers = received.headers.mapKeys { (name, _) -> name.lowercase() })
        }

        assertThat(backend.authenticate(request)).isEqualTo(VerificationResult.Accepted)
    }

    @Test
    fun `a registration challenge works only once`() {
        val challenge = backend.issueRegistrationChallenge()
        backend.registerKey(KeyRole.DEVICE, device.encodedPublicKey, selfSignedChain(device), challenge)
        val other = TestKey()

        val again = backend.registerKey(KeyRole.DEVICE, other.encodedPublicKey, selfSignedChain(other), challenge)

        assertThat(again).isInstanceOf(RegistrationResult.Refused::class.java)
    }

    @Test
    fun `a step-up key needs a registered device key`() {
        val result = backend.registerKey(
            KeyRole.STEP_UP,
            stepUp.encodedPublicKey,
            selfSignedChain(stepUp),
            backend.issueRegistrationChallenge("k_unknown"),
            deviceKeyId = "k_unknown",
        )

        assertThat(result).isInstanceOf(RegistrationResult.Refused::class.java)
    }

    @Test
    fun `a key with only its own self-signed certificate is registered as unattested`() {
        val result = backend.registerKey(KeyRole.DEVICE, device.encodedPublicKey, selfSignedChain(device), backend.issueRegistrationChallenge())

        assertThat((result as RegistrationResult.Registered).attestation.isAttested).isFalse()
    }

    @Test
    fun `a step-up key the device key did not vouch for is refused`() {
        registerDevice()

        val result = registerStepUp(vouchedBy = TestKey())

        assertThat(result).isInstanceOf(RegistrationResult.Refused::class.java)
        val authorization = backend.beginPayment(device.keyId, DeviceRiskLevel.MEDIUM) as PaymentAuthorization.Proceed
        assertThat(authorization.confirmation).isEqualTo(RequiredConfirmation.TAP)
    }

    @Test
    fun `only the device key can remove its step-up key`() {
        registerDevice()
        registerStepUp()

        val forged = removeStepUp(vouchedBy = TestKey())
        val stillStepUp = (backend.beginPayment(device.keyId, DeviceRiskLevel.MEDIUM) as PaymentAuthorization.Proceed).confirmation
        val genuine = removeStepUp()
        val afterRemoval = (backend.beginPayment(device.keyId, DeviceRiskLevel.MEDIUM) as PaymentAuthorization.Proceed).confirmation

        assertThat(forged).isFalse()
        assertThat(stillStepUp).isEqualTo(RequiredConfirmation.STEP_UP_KEY)
        assertThat(genuine).isTrue()
        assertThat(afterRemoval).isEqualTo(RequiredConfirmation.TAP)
    }

    @Test
    fun `a registered key cannot be registered again`() {
        registerDevice()

        val again = backend.registerKey(KeyRole.DEVICE, device.encodedPublicKey, selfSignedChain(device), backend.issueRegistrationChallenge())

        assertThat(again).isInstanceOf(RegistrationResult.Refused::class.java)
    }

    @Test
    fun `an unreadable attestation chain is refused`() {
        val chain = listOf(byteArrayOf(0x30, 0x03, 0x01, 0x02, 0x03))

        val result = backend.registerKey(KeyRole.DEVICE, device.encodedPublicKey, chain, backend.issueRegistrationChallenge())

        assertThat(result).isInstanceOf(RegistrationResult.Refused::class.java)
    }

    @Test
    fun `a payment challenge cannot be spent on verification`() {
        registerDevice()
        val nonce = allowedNonce()
        val asVerification = device.sign(signer.prepare(payload, nonce = nonce, keyId = device.keyId, timestamp = clock.now.toString()))

        val verified = backend.authenticate(asVerification.asReceived())
        val paid = backend.submitPayment(paymentRequest(nonce).asReceived())

        assertThat(verified).isEqualTo(VerificationResult.Rejected(RejectionReason.UNKNOWN_CHALLENGE))
        assertThat(paid).isInstanceOf(PaymentResponse.Processed::class.java)
    }

    @Test
    fun `an unusable payment body is refused without spending the challenge`() {
        registerDevice()
        val nonce = allowedNonce()

        val zero = backend.submitPayment(paymentRequest(nonce, body = payload.copy(amountMinor = 0)).asReceived())
        val valid = backend.submitPayment(paymentRequest(nonce, idempotencyKey = "idem-2").asReceived())

        assertThat(zero).isEqualTo(PaymentResponse.Rejected(RejectionReason.MALFORMED_BODY))
        assertThat(valid).isInstanceOf(PaymentResponse.Processed::class.java)
        assertThat(backend.chargedPayments).isEqualTo(1)
    }

    @Test
    fun `idempotency keys are scoped to the device`() {
        val other = TestKey()
        registerDevice()
        registerDevice(other)
        val otherNonce = (backend.beginPayment(other.keyId, DeviceRiskLevel.LOW) as PaymentAuthorization.Proceed).nonce

        backend.submitPayment(paymentRequest(allowedNonce()).asReceived())
        val fromOther = backend.submitPayment(paymentRequest(otherNonce, key = other).asReceived())

        assertThat((fromOther as PaymentResponse.Processed).replayed).isFalse()
        assertThat(backend.chargedPayments).isEqualTo(2)
    }

    @Test
    fun `a key without a certificate chain is refused`() {
        val result = backend.registerKey(KeyRole.DEVICE, device.encodedPublicKey, emptyList(), backend.issueRegistrationChallenge())

        assertThat(result).isInstanceOf(RegistrationResult.Refused::class.java)
    }

    @Test
    fun `an attested key is registered with its attestation`() {
        val challenge = backend.issueRegistrationChallenge()
        val chain = TestAttestation().chainFor(device.pair.public, challenge)

        val result = backend.registerKey(KeyRole.DEVICE, device.encodedPublicKey, chain, challenge)

        assertThat((result as RegistrationResult.Registered).attestation.isVerified).isTrue()
    }

    @Test
    fun `an attestation made for another challenge is refused`() {
        val chain = TestAttestation().chainFor(device.pair.public, backend.issueRegistrationChallenge())

        val result = backend.registerKey(KeyRole.DEVICE, device.encodedPublicKey, chain, backend.issueRegistrationChallenge())

        assertThat(result).isInstanceOf(RegistrationResult.Refused::class.java)
    }

    @Test
    fun `an attestation that certifies a different key is refused`() {
        val challenge = backend.issueRegistrationChallenge()
        val chain = TestAttestation().chainFor(TestKey().pair.public, challenge)

        val result = backend.registerKey(KeyRole.DEVICE, device.encodedPublicKey, chain, challenge)

        assertThat(result).isInstanceOf(RegistrationResult.Refused::class.java)
    }

    @Test
    fun `an attestation whose certificates don't chain up is refused`() {
        val challenge = backend.issueRegistrationChallenge()
        val leaf = TestAttestation().chainFor(device.pair.public, challenge).first()
        val unrelatedRoot = TestAttestation().chainFor(TestKey().pair.public, challenge).last()

        val result = backend.registerKey(KeyRole.DEVICE, device.encodedPublicKey, listOf(leaf, unrelatedRoot), challenge)

        assertThat(result).isInstanceOf(RegistrationResult.Refused::class.java)
    }

    @Test
    fun `an attested device's step-up key must be attested by the same root and require authentication`() {
        val attestation = TestAttestation()
        val deviceChallenge = backend.issueRegistrationChallenge()
        backend.registerKey(KeyRole.DEVICE, device.encodedPublicKey, attestation.chainFor(device.pair.public, deviceChallenge), deviceChallenge)

        val unattested = registerStepUp()
        val otherRoot = registerStepUp { challenge -> TestAttestation().chainFor(stepUp.pair.public, challenge, requiresAuthentication = true) }
        val noAuthentication = registerStepUp { challenge -> attestation.chainFor(stepUp.pair.public, challenge, requiresAuthentication = false) }
        val genuine = registerStepUp { challenge -> attestation.chainFor(stepUp.pair.public, challenge, requiresAuthentication = true) }

        assertThat(unattested).isInstanceOf(RegistrationResult.Refused::class.java)
        assertThat(otherRoot).isInstanceOf(RegistrationResult.Refused::class.java)
        assertThat(noAuthentication).isInstanceOf(RegistrationResult.Refused::class.java)
        assertThat(genuine).isInstanceOf(RegistrationResult.Registered::class.java)
    }

    @Test
    fun `registering a new step-up key retires the old one`() {
        registerDevice()
        registerStepUp()
        val oldStepUp = stepUp
        val newStepUp = TestKey()
        val challenge = backend.issueRegistrationChallenge(device.keyId)
        val proof = device.sign(ReferenceSigningScheme.keyBindingInput(ReferenceSigningScheme.ACTION_ADD_STEP_UP, challenge, newStepUp.keyId))
        backend.registerKey(KeyRole.STEP_UP, newStepUp.encodedPublicKey, selfSignedChain(newStepUp), challenge, device.keyId, proof)
        val nonce = (backend.beginPayment(device.keyId, DeviceRiskLevel.MEDIUM) as PaymentAuthorization.Proceed).nonce

        val signedByOldKey = backend.submitPayment(paymentRequest(nonce, key = oldStepUp).asReceived())

        assertThat(signedByOldKey).isEqualTo(PaymentResponse.Rejected(RejectionReason.UNKNOWN_KEY))
    }

    @Test
    fun `a timestamp that isn't an instant is rejected`() {
        registerDevice()
        val request = verificationRequest().asReceived().let {
            it.copy(headers = it.headers + (ReferenceSigningScheme.HEADER_TIMESTAMP to "yesterday"))
        }

        assertThat(backend.authenticate(request)).isEqualTo(VerificationResult.Rejected(RejectionReason.MALFORMED_TIMESTAMP))
    }

    @Test
    fun `a payment without an idempotency key is rejected`() {
        registerDevice()
        val unkeyed = device.sign(
            signer.prepare(payload, nonce = allowedNonce(), keyId = device.keyId, timestamp = clock.now.toString()),
        )

        assertThat(backend.submitPayment(unkeyed.asReceived())).isEqualTo(PaymentResponse.Rejected(RejectionReason.MISSING_HEADERS))
        assertThat(backend.chargedPayments).isEqualTo(0)
    }
}
