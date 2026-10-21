package id.fatarc.trustgate.backend

import com.google.common.truth.Truth.assertThat
import id.fatarc.trustgate.domain.actiongate.SensitiveActionDecision
import id.fatarc.trustgate.domain.api.DecisionChallengeRequest
import id.fatarc.trustgate.domain.api.PaymentAuthorization
import id.fatarc.trustgate.domain.api.PaymentResponse
import id.fatarc.trustgate.domain.api.PhoneDecision
import id.fatarc.trustgate.domain.api.PhoneStatus
import id.fatarc.trustgate.domain.api.RegistrationResult
import id.fatarc.trustgate.domain.api.SignedAction
import id.fatarc.trustgate.domain.risk.DeviceRiskLevel
import id.fatarc.trustgate.domain.signing.KeyRole
import id.fatarc.trustgate.domain.signing.PaymentRequestPayload
import id.fatarc.trustgate.domain.signing.ReferenceRequestSigner
import id.fatarc.trustgate.domain.signing.ReferenceSigningScheme
import id.fatarc.trustgate.domain.signing.RejectionReason
import id.fatarc.trustgate.domain.signing.asReceived
import id.fatarc.trustgate.testing.MutableClock
import id.fatarc.trustgate.testing.TEST_PAYMENT
import id.fatarc.trustgate.testing.TestKey
import id.fatarc.trustgate.testing.authorize
import id.fatarc.trustgate.testing.developmentPolicy
import id.fatarc.trustgate.testing.selfSignedChain
import java.time.Duration
import org.junit.Test

class AccountsTest {
    private val clock = MutableClock()
    private val signer = ReferenceRequestSigner()
    private val first = TestKey()
    private val second = TestKey()
    private var paymentsSent = 0

    private fun backend(limits: PaymentLimits = PaymentLimits.NONE) =
        ReferenceBackend(BackendPolicy(developmentPolicy.name, developmentPolicy.attestation, developmentPolicy.risk, limits), clock)

    private fun ReferenceBackend.register(key: TestKey, label: String = "Test phone"): ReferenceBackend = apply {
        val challenge = issueRegistrationChallenge()
        check(registerKey(KeyRole.DEVICE, key.encodedPublicKey, selfSignedChain(key), challenge, phoneLabel = label) is RegistrationResult.Registered)
    }

    private fun ReferenceBackend.addStepUp(device: TestKey, stepUp: TestKey) {
        val challenge = issueRegistrationChallenge(device.keyId)
        val proof = device.sign(ReferenceSigningScheme.keyBindingInput(ReferenceSigningScheme.ACTION_ADD_STEP_UP, challenge, stepUp.keyId))
        check(registerKey(KeyRole.STEP_UP, stepUp.encodedPublicKey, selfSignedChain(stepUp), challenge, device.keyId, proof) is RegistrationResult.Registered)
    }

    private fun ReferenceBackend.signed(key: TestKey, action: String, subject: String = ""): SignedAction {
        val challenge = issueRegistrationChallenge(key.keyId)
        val proof = key.sign(ReferenceSigningScheme.keyBindingInput(action, challenge, subject))
        return SignedAction(key.keyId, ReferenceSigningScheme.encode(challenge), ReferenceSigningScheme.encode(proof), subject)
    }

    private fun ReferenceBackend.linkCode(key: TestKey): String? = createLinkCode(signed(key, ReferenceSigningScheme.ACTION_LINK_CODE))?.code

    private fun ReferenceBackend.join(key: TestKey, code: String) = joinAccount(signed(key, ReferenceSigningScheme.ACTION_JOIN_ACCOUNT, code))

    private fun ReferenceBackend.view(key: TestKey) = checkNotNull(accountView(signed(key, ReferenceSigningScheme.ACTION_VIEW_ACCOUNT)))

    /** [decider] decides [action] about [phone]'s phone, signing with [signingKey], by tap when [tap]. */
    private fun ReferenceBackend.decideAbout(
        decider: TestKey,
        phone: TestKey,
        action: String,
        signingKey: TestKey = decider,
        tap: Boolean = true,
    ): Boolean {
        val challenge = decisionChallenge(DecisionChallengeRequest(decider.keyId, phone.keyId, action)) ?: return false
        val signature = signingKey.sign(ReferenceSigningScheme.decisionInput(action, challenge.nonce, phone.keyId, tap))
        return decide(PhoneDecision(signingKey.keyId, phone.keyId, action, challenge.nonce, ReferenceSigningScheme.encode(signature), tap)).done
    }

    private fun ReferenceBackend.pay(key: TestKey): PaymentResponse {
        val payment = PaymentRequestPayload(125_000, "IDR", "REF-${++paymentsSent}")
        val nonce = (authorize(key, DeviceRiskLevel.LOW, clock.now, payment) as PaymentAuthorization.Proceed).nonce
        return submitPayment(key.sign(signer.prepare(payment, nonce, key.keyId, clock.now.toString(), idempotencyKey = "idem-$paymentsSent")).asReceived(), clock.now)
    }

    @Test
    fun `a phone starts on an account of its own`() {
        val backend = backend().register(first, label = "Pixel 9")

        val view = backend.view(first)

        assertThat(view.phones.map { it.label }).containsExactly("Pixel 9")
        assertThat(view.phones.single().thisPhone).isTrue()
    }

    @Test
    fun `a phone joins with a code and gets in only once a phone on the account approves it`() {
        val backend = backend().register(first).register(second)
        val code = checkNotNull(backend.linkCode(first))

        val joined = backend.join(second, code)
        val whileWaiting = backend.view(first).phones.single { it.phoneId == second.keyId }
        val approved = backend.decideAbout(first, second, ReferenceSigningScheme.DECISION_APPROVE)

        assertThat(joined.waitingForApproval).isTrue()
        assertThat(whileWaiting.status).isEqualTo(PhoneStatus.WAITING_FOR_APPROVAL)
        assertThat(approved).isTrue()
        assertThat(backend.view(second).accountId).isEqualTo(backend.view(first).accountId)
    }

    @Test
    fun `a code works once, and a wrong or expired one gets nowhere`() {
        val backend = backend().register(first).register(second)
        val third = TestKey().also { backend.register(it) }
        val code = checkNotNull(backend.linkCode(first))

        backend.join(second, code)
        val reused = backend.join(third, code)
        val guessed = backend.join(third, "ABCD2345")
        val late = checkNotNull(backend.linkCode(first)).also { clock.advanceSeconds(Duration.ofMinutes(11).seconds) }

        assertThat(reused.waitingForApproval).isFalse()
        assertThat(guessed.waitingForApproval).isFalse()
        assertThat(backend.join(third, late).waitingForApproval).isFalse()
    }

    @Test
    fun `with a screen-lock key, only that key can approve a phone`() {
        val backend = backend().register(first).register(second)
        val firstStepUp = TestKey().also { backend.addStepUp(first, it) }
        backend.join(second, checkNotNull(backend.linkCode(first)))

        val byTap = backend.decideAbout(first, second, ReferenceSigningScheme.DECISION_APPROVE, signingKey = first, tap = true)
        val byScreenLock = backend.decideAbout(first, second, ReferenceSigningScheme.DECISION_APPROVE, signingKey = firstStepUp, tap = false)

        assertThat(byTap).isFalse()
        assertThat(byScreenLock).isTrue()
    }

    @Test
    fun `a phone off the account, or still waiting, can't decide for it`() {
        val backend = backend().register(first).register(second)
        val outsider = TestKey().also { backend.register(it) }
        backend.join(second, checkNotNull(backend.linkCode(first)))

        assertThat(backend.decideAbout(outsider, second, ReferenceSigningScheme.DECISION_APPROVE)).isFalse()
        assertThat(backend.decideAbout(second, second, ReferenceSigningScheme.DECISION_APPROVE)).isFalse()
        assertThat(backend.view(first).phones.single { it.phoneId == second.keyId }.status).isEqualTo(PhoneStatus.WAITING_FOR_APPROVAL)
    }

    @Test
    fun `a phone that's new on the account can't let others in yet`() {
        val limits = PaymentLimits(Int.MAX_VALUE, Duration.ofMinutes(1), null, newPhonePeriod = Duration.ofDays(1), newPhoneAmountMinor = null)
        val backend = backend(limits).register(first)

        val asNew = backend.linkCode(first)
        clock.advanceSeconds(Duration.ofDays(1).seconds + 1)

        assertThat(asNew).isNull()
        assertThat(backend.linkCode(first)).isNotNull()
    }

    @Test
    fun `phones on one account share its limits`() {
        val limits = PaymentLimits(maxPayments = 1, window = Duration.ofMinutes(10), dailyAmountMinor = null, newPhonePeriod = null, newPhoneAmountMinor = null)
        val backend = backend(limits).register(first).register(second)
        backend.join(second, checkNotNull(backend.linkCode(first)))
        backend.decideAbout(first, second, ReferenceSigningScheme.DECISION_APPROVE)

        backend.pay(first)

        assertThat(backend.authorize(second, DeviceRiskLevel.LOW, clock.now).decision).isEqualTo(SensitiveActionDecision.BLOCK)
    }

    @Test
    fun `removing a lost phone from the account stops it paying`() {
        val backend = backend().register(first).register(second)
        backend.join(second, checkNotNull(backend.linkCode(first)))
        backend.decideAbout(first, second, ReferenceSigningScheme.DECISION_APPROVE)

        val removed = backend.decideAbout(first, second, ReferenceSigningScheme.DECISION_REMOVE)

        assertThat(removed).isTrue()
        assertThat((backend.authorize(second, DeviceRiskLevel.LOW, clock.now) as PaymentAuthorization.Blocked).keyRejected).isTrue()
        assertThat(backend.view(first).phones.map { it.phoneId }).containsExactly(first.keyId)
        assertThat(backend.auditStatus().intact).isTrue()
    }

    @Test
    fun `a payment different from the one approved is refused`() {
        val backend = backend().register(first)
        val nonce = (backend.authorize(first, DeviceRiskLevel.LOW, clock.now, TEST_PAYMENT) as PaymentAuthorization.Proceed).nonce

        val toSomeoneElse = backend.submitPayment(
            first.sign(signer.prepare(TEST_PAYMENT.copy(payee = "someone-else"), nonce, first.keyId, clock.now.toString(), idempotencyKey = "idem-x")).asReceived(),
            clock.now,
        )

        assertThat(toSomeoneElse).isEqualTo(PaymentResponse.Rejected(RejectionReason.PAYMENT_CHANGED))
    }
}
