package id.fatarc.trustgate.ui

import com.google.common.truth.Truth.assertThat
import id.fatarc.trustgate.backend.ReferenceBackend
import id.fatarc.trustgate.core.backend.BackendTransport
import id.fatarc.trustgate.core.backend.InProcessTrustGateApi
import id.fatarc.trustgate.core.backend.PaymentClient
import id.fatarc.trustgate.core.integrity.MockIntegrityTokenSource
import id.fatarc.trustgate.core.integrity.PretendVerdict
import id.fatarc.trustgate.core.keys.KeyRegistrar
import id.fatarc.trustgate.core.security.ConfirmationMethod
import id.fatarc.trustgate.core.security.TrustGateSecurityService
import id.fatarc.trustgate.domain.api.PaymentAuthorization
import id.fatarc.trustgate.domain.api.PhoneStatus
import id.fatarc.trustgate.domain.api.Remedy
import id.fatarc.trustgate.domain.events.SecurityEventType
import id.fatarc.trustgate.domain.risk.DeviceRiskLevel
import id.fatarc.trustgate.domain.risk.RiskScorer
import id.fatarc.trustgate.domain.risk.SignalCategory
import id.fatarc.trustgate.domain.risk.SignalSeverity
import id.fatarc.trustgate.domain.signing.KeyRole
import id.fatarc.trustgate.domain.signing.ReferencePayment
import id.fatarc.trustgate.domain.signing.ReferenceRequestSigner
import id.fatarc.trustgate.domain.signing.ReferenceSigningScheme
import id.fatarc.trustgate.domain.signing.RejectionReason
import id.fatarc.trustgate.domain.signing.VerificationResult
import id.fatarc.trustgate.testing.InMemorySecureValueStore
import id.fatarc.trustgate.testing.InMemorySecurityEventRepository
import id.fatarc.trustgate.testing.MutableSignalCollector
import id.fatarc.trustgate.testing.SoftwareKeyProvider
import id.fatarc.trustgate.testing.TestKey
import id.fatarc.trustgate.testing.authorize
import id.fatarc.trustgate.testing.decideAbout
import id.fatarc.trustgate.testing.developmentPolicy
import id.fatarc.trustgate.testing.riskSignal
import id.fatarc.trustgate.testing.selfSignedChain
import id.fatarc.trustgate.testing.signedAction
import java.security.KeyStoreException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Before
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class TrustGateViewModelTest {
    private val dispatcher = StandardTestDispatcher()
    private val events = InMemorySecurityEventRepository()
    private val collector = MutableSignalCollector(emptyList())
    private val keys = SoftwareKeyProvider()
    private val backend = ReferenceBackend(developmentPolicy)
    private val api = InProcessTrustGateApi(backend)
    private val transport = BackendTransport(api)
    private val integrityTokens = MockIntegrityTokenSource()

    @Before
    fun setUp() {
        Dispatchers.setMain(dispatcher)
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }

    private fun TestScope.viewModel(): TrustGateViewModel = TrustGateViewModel(
        securityService = TrustGateSecurityService(collector, RiskScorer(), events),
        eventRepository = events,
        secureValueStore = InMemorySecureValueStore(),
        requestSigner = ReferenceRequestSigner(),
        api = api,
        keyProvider = keys,
        keyRegistrar = KeyRegistrar(keys, api, dispatcher),
        transport = transport,
        paymentClient = PaymentClient(transport, baseDelayMillis = 100),
        integrityTokens = integrityTokens,
        ioDispatcher = dispatcher,
    ).also { advanceUntilIdle() }

    private val payment: PaymentUiState get() = lastViewModel.uiState.value.payment
    private lateinit var lastViewModel: TrustGateViewModel

    private fun TestScope.start(): TrustGateViewModel = viewModel().also { lastViewModel = it }

    private fun mediumRisk() {
        collector.signals = listOf(riskSignal("test_keys", SignalSeverity.MEDIUM, SignalCategory.ROOT))
    }

    private fun highRisk() {
        collector.signals = listOf(riskSignal("debugger_connected", SignalSeverity.HIGH, SignalCategory.DEBUGGER))
    }

    @Test
    fun `low risk action is charged once and signed by the device key`() = runTest(dispatcher) {
        val viewModel = start()

        viewModel.attemptPayment()
        advanceUntilIdle()

        assertThat(payment.latestDecision).isEqualTo(PaymentDecisionState.Allowed(DeviceRiskLevel.LOW))
        val charged = payment.submission as Submission.Charged
        assertThat(charged.signedWith).isEqualTo(KeyRole.DEVICE)
        assertThat(backend.chargedPayments).isEqualTo(1)
    }

    @Test
    fun `an allowed payment shows the paying step until the server answers`() = runTest(dispatcher) {
        val viewModel = start()
        viewModel.setSimulateLostResponse(true)

        viewModel.attemptPayment()
        runCurrent() // The first response was lost; the retry is waiting out its backoff.
        val whileSending = payment
        advanceUntilIdle()

        assertThat(whileSending.latestDecision).isEqualTo(PaymentDecisionState.Allowed(DeviceRiskLevel.LOW))
        assertThat(whileSending.stage).isEqualTo(PaymentStage.PAYING)
        assertThat(payment.stage).isEqualTo(PaymentStage.DONE)
        assertThat(payment.isRunning).isFalse()
        assertThat(payment.submission).isInstanceOf(Submission.Charged::class.java)
    }

    @Test
    fun `checking the device while a payment is on its way keeps the payment's result`() = runTest(dispatcher) {
        val viewModel = start()
        viewModel.setSimulateLostResponse(true)

        viewModel.attemptPayment()
        runCurrent() // The retry is waiting out its backoff.
        viewModel.refreshRisk()
        advanceUntilIdle()

        assertThat(payment.submission).isInstanceOf(Submission.Charged::class.java)
        assertThat(backend.chargedPayments).isEqualTo(1)
    }

    @Test
    fun `keys that can't be confirmed are shown as an error, not as registered`() = runTest(dispatcher) {
        val viewModel = start()

        keys.keystoreError = KeyStoreException("Keystore is busy")
        viewModel.attemptPayment()
        advanceUntilIdle()

        assertThat(viewModel.uiState.value.keys.keys).isNull()
        assertThat(viewModel.uiState.value.keys.errorMessage).isEqualTo("Keystore is busy")
        assertThat(backend.chargedPayments).isEqualTo(0)
    }

    @Test
    fun `high risk is blocked and nothing is signed or charged`() = runTest(dispatcher) {
        highRisk()
        val viewModel = start()

        viewModel.attemptPayment()
        advanceUntilIdle()

        assertThat(payment.latestDecision).isEqualTo(PaymentDecisionState.Blocked(DeviceRiskLevel.HIGH))
        assertThat(backend.chargedPayments).isEqualTo(0)
        assertThat(events.events.value.map { it.type }).doesNotContain(SecurityEventType.REQUEST_SIGNED)
    }

    @Test
    fun `medium risk is charged only after the step-up key signs`() = runTest(dispatcher) {
        mediumRisk()
        val viewModel = start()

        viewModel.attemptPayment()
        advanceUntilIdle()
        val awaiting = payment.latestDecision
        val chargedBeforeConfirming = backend.chargedPayments
        viewModel.completeStepUp(requireNotNull(viewModel.stepUpSignatureForPrompt()))
        advanceUntilIdle()

        assertThat(awaiting).isEqualTo(
            PaymentDecisionState.ConfirmationRequired(DeviceRiskLevel.MEDIUM, ConfirmationMethod.DEVICE_CREDENTIAL),
        )
        assertThat(chargedBeforeConfirming).isEqualTo(0)
        assertThat(payment.latestDecision).isEqualTo(PaymentDecisionState.Confirmed(DeviceRiskLevel.MEDIUM, ConfirmationMethod.DEVICE_CREDENTIAL))
        assertThat((payment.submission as Submission.Charged).signedWith).isEqualTo(KeyRole.STEP_UP)
        assertThat(keys.stepUpSignaturesHandedOut).isEqualTo(1)
    }

    @Test
    fun `without a screen lock medium risk falls back to a signed tap`() = runTest(dispatcher) {
        mediumRisk()
        keys.screenLockSet = false
        val viewModel = start()

        viewModel.attemptPayment()
        advanceUntilIdle()
        val awaiting = payment.latestDecision
        viewModel.confirmWithTap()
        advanceUntilIdle()

        assertThat(awaiting).isEqualTo(PaymentDecisionState.ConfirmationRequired(DeviceRiskLevel.MEDIUM, ConfirmationMethod.TAP))
        assertThat((payment.submission as Submission.Charged).signedWith).isEqualTo(KeyRole.DEVICE)
        val confirmation = events.events.value.last { it.type == SecurityEventType.SENSITIVE_ACTION_ALLOWED_AFTER_CONFIRMATION }
        assertThat(confirmation.metadata["method"]).isEqualTo("tap")
    }

    @Test
    fun `a lost response is retried and the payment is charged once`() = runTest(dispatcher) {
        val viewModel = start()
        viewModel.setSimulateLostResponse(true)

        viewModel.attemptPayment()
        advanceUntilIdle()

        val charged = payment.submission as Submission.Charged
        assertThat(charged.attempts).isEqualTo(2)
        assertThat(charged.lostResponses).isEqualTo(1)
        assertThat(backend.chargedPayments).isEqualTo(1)
    }

    @Test
    fun `a device that turns high risk while confirming is blocked before anything is signed`() = runTest(dispatcher) {
        mediumRisk()
        val viewModel = start()
        viewModel.attemptPayment()
        advanceUntilIdle()
        val unlocked = requireNotNull(viewModel.stepUpSignatureForPrompt())

        highRisk()
        viewModel.completeStepUp(unlocked)
        advanceUntilIdle()

        assertThat(payment.latestDecision).isEqualTo(PaymentDecisionState.Blocked(DeviceRiskLevel.HIGH))
        assertThat(backend.chargedPayments).isEqualTo(0)
        val blocked = events.events.value.last { it.type == SecurityEventType.SENSITIVE_ACTION_BLOCKED }
        assertThat(blocked.metadata["decidedBy"]).isEqualTo("app")
    }

    @Test
    fun `switching profile mid-payment does not publish the old result`() = runTest(dispatcher) {
        val viewModel = start()
        viewModel.setScenarioRiskLevel(DeviceRiskLevel.LOW)
        advanceUntilIdle()
        viewModel.setSimulateLostResponse(true)

        viewModel.attemptPayment()
        runCurrent() // Now waiting to retry the lost response.
        viewModel.setScenarioRiskLevel(DeviceRiskLevel.HIGH)
        advanceUntilIdle()

        assertThat(payment.latestDecision).isEqualTo(PaymentDecisionState.Idle)
        assertThat(payment.submission).isNull()
        // The payment that was already sent still runs to an outcome and is logged.
        assertThat(backend.chargedPayments).isEqualTo(1)
        assertThat(events.events.value.map { it.type }).contains(SecurityEventType.PAYMENT_SUBMITTED)
    }

    @Test
    fun `an invalidated step-up key cancels the confirmation and is set up again`() = runTest(dispatcher) {
        mediumRisk()
        val viewModel = start()
        viewModel.attemptPayment()
        advanceUntilIdle()
        val oldStepUp = viewModel.uiState.value.keys.keys?.stepUp?.keyId

        keys.stepUpInvalidated = true
        val signature = viewModel.stepUpSignatureForPrompt()
        advanceUntilIdle()

        assertThat(signature).isNull()
        val cancelled = payment.latestDecision as PaymentDecisionState.Cancelled
        assertThat(cancelled.problem).contains("reset")
        val newStepUp = viewModel.uiState.value.keys.keys?.stepUp?.keyId
        assertThat(newStepUp).isNotNull()
        assertThat(newStepUp).isNotEqualTo(oldStepUp)
    }

    @Test
    fun `a replayed request is accepted once and then refused`() = runTest(dispatcher) {
        val viewModel = start()

        viewModel.runLabTest(LabTest.REPLAY)
        advanceUntilIdle()

        assertThat(viewModel.uiState.value.lab.results[LabTest.REPLAY]?.sends).containsExactly(
            VerificationResult.Accepted,
            VerificationResult.Rejected(RejectionReason.CHALLENGE_REUSED),
        ).inOrder()
        assertThat(viewModel.uiState.value.lastRequest).isNotNull()
    }

    @Test
    fun `a request with a changed amount or sent too late is refused`() = runTest(dispatcher) {
        val viewModel = start()

        viewModel.runLabTest(LabTest.CHANGED_AMOUNT)
        advanceUntilIdle()
        viewModel.runLabTest(LabTest.SENT_LATE)
        advanceUntilIdle()

        val results = viewModel.uiState.value.lab.results
        assertThat(results[LabTest.CHANGED_AMOUNT]?.sends).containsExactly(VerificationResult.Rejected(RejectionReason.SIGNATURE_MISMATCH))
        assertThat(results[LabTest.SENT_LATE]?.sends).containsExactly(VerificationResult.Rejected(RejectionReason.OUTSIDE_TIME_WINDOW))
        assertThat(results.values.all { it.stopped }).isTrue()
        assertThat(viewModel.uiState.value.lab.running).isNull()
    }

    @Test
    fun `a remote-control app reported by Play blocks the payment, warns of a scam, and says how to fix it`() = runTest(dispatcher) {
        val viewModel = start()
        viewModel.setPretendVerdict(PretendVerdict.REMOTE_CONTROL)

        viewModel.attemptPayment()
        advanceUntilIdle()

        assertThat(payment.latestDecision).isInstanceOf(PaymentDecisionState.Blocked::class.java)
        assertThat(payment.remedy).isEqualTo(Remedy.CLOSE_ALL_ACCESS_RISK)
        assertThat(payment.scamWarning).isTrue()
        assertThat(payment.reasons.filter { it.isProblem }.map { it.text }).containsExactly("Remote-control app running")
        assertThat(backend.chargedPayments).isEqualTo(0)
    }

    @Test
    fun `paying many times at once runs into the server's payment limit`() = runTest(dispatcher) {
        val viewModel = start()

        viewModel.runLabTest(LabTest.RAPID_PAYMENTS)
        advanceUntilIdle()

        val result = viewModel.uiState.value.lab.results[LabTest.RAPID_PAYMENTS]
        assertThat(result?.stopped).isTrue()
        assertThat(result?.summary).isEqualTo("3 paid, then refused: too many payments")
        assertThat(backend.chargedPayments).isEqualTo(3)
    }

    @Test
    fun `replacing the phone key keeps payments working and retires the old key`() = runTest(dispatcher) {
        val viewModel = start()
        val oldKey = viewModel.uiState.value.keys.keys?.device?.keyId

        viewModel.rotateDeviceKey()
        advanceUntilIdle()
        viewModel.attemptPayment()
        advanceUntilIdle()

        val newKey = viewModel.uiState.value.keys.keys?.device?.keyId
        assertThat(newKey).isNotEqualTo(oldKey)
        assertThat(viewModel.uiState.value.keys.keys?.stepUp).isNotNull()
        assertThat(payment.submission).isInstanceOf(Submission.Charged::class.java)
        assertThat(events.events.value.map { it.type }).contains(SecurityEventType.KEY_ROTATED)
    }

    @Test
    fun `a phone an operator revoked is told so and set up again as a new phone`() = runTest(dispatcher) {
        val viewModel = start()
        val revokedKey = requireNotNull(viewModel.uiState.value.keys.keys?.device?.keyId)
        backend.revokeByOperator(revokedKey, "fraud reported")

        viewModel.attemptPayment()
        advanceUntilIdle()

        assertThat(payment.latestDecision).isInstanceOf(PaymentDecisionState.Blocked::class.java)
        assertThat(payment.reasons.map { it.text }).containsExactly("Phone removed")
        assertThat(viewModel.uiState.value.keys.keys?.device?.keyId).isNotEqualTo(revokedKey)
        assertThat(events.events.value.map { it.type }).contains(SecurityEventType.PHONE_REMOVED)
    }

    @Test
    fun `removing the phone sets it up again with new keys`() = runTest(dispatcher) {
        val viewModel = start()
        val before = viewModel.uiState.value.keys.keys?.device?.keyId

        viewModel.removeThisPhone()
        advanceUntilIdle()

        assertThat(viewModel.uiState.value.keys.keys?.device?.keyId).isNotEqualTo(before)
        assertThat(backend.auditStatus().intact).isTrue()
    }

    @Test
    fun `the payment made is the one chosen at checkout`() = runTest(dispatcher) {
        val viewModel = start()
        val payee = ReferencePayment.PAYEES[1]

        viewModel.setCheckout(payee, ReferencePayment.AMOUNTS_MINOR[1])
        viewModel.attemptPayment()
        advanceUntilIdle()

        val signed = requireNotNull(viewModel.uiState.value.lastRequest)
        assertThat(payment.submission).isInstanceOf(Submission.Charged::class.java)
        assertThat(signed.payload.payee).isEqualTo(payee.id)
        assertThat(signed.payload.amountMinor).isEqualTo(ReferencePayment.AMOUNTS_MINOR[1])
    }

    /** Another phone, set up on its own as if on a second device. */
    private fun otherPhone(): TestKey = TestKey().also { other ->
        backend.registerKey(KeyRole.DEVICE, other.encodedPublicKey, selfSignedChain(other), backend.issueRegistrationChallenge(), phoneLabel = "Other phone")
    }

    /** This phone makes a code, [other] asks to join with it, and this phone sees the request. */
    private fun TestScope.letAskToJoin(viewModel: TrustGateViewModel, other: TestKey) {
        viewModel.createLinkCode()
        advanceUntilIdle()
        val code = requireNotNull(viewModel.uiState.value.account.linkCode).code
        backend.joinAccount(backend.signedAction(other, ReferenceSigningScheme.ACTION_JOIN_ACCOUNT, code))
        viewModel.refreshAccount()
        advanceUntilIdle()
    }

    /** Decides [action] about [other] from this phone, confirming with the screen lock. */
    private fun TestScope.decide(viewModel: TrustGateViewModel, other: TestKey, action: String) {
        viewModel.decideAboutPhone(other.keyId, action)
        advanceUntilIdle()
        viewModel.completeDecision(requireNotNull(viewModel.decisionSignatureForPrompt()))
        advanceUntilIdle()
    }

    private fun TrustGateViewModel.statusOf(other: TestKey): PhoneStatus? =
        uiState.value.account.view?.phones?.firstOrNull { it.phoneId == other.keyId }?.status

    @Test
    fun `a phone asking to join is approved from this phone, which confirms with its screen lock`() = runTest(dispatcher) {
        val viewModel = start()
        val other = otherPhone()
        letAskToJoin(viewModel, other)
        val waiting = viewModel.statusOf(other)

        viewModel.decideAboutPhone(other.keyId, ReferenceSigningScheme.DECISION_APPROVE)
        advanceUntilIdle()
        val asked = viewModel.uiState.value.account.deciding
        viewModel.completeDecision(requireNotNull(viewModel.decisionSignatureForPrompt()))
        advanceUntilIdle()

        assertThat(waiting).isEqualTo(PhoneStatus.WAITING_FOR_APPROVAL)
        assertThat(asked?.method).isEqualTo(ConfirmationMethod.DEVICE_CREDENTIAL)
        assertThat(viewModel.statusOf(other)).isEqualTo(PhoneStatus.ACTIVE)
        assertThat(keys.stepUpSignaturesHandedOut).isEqualTo(1)
    }

    @Test
    fun `without a screen lock, approving a phone is confirmed with a signed tap`() = runTest(dispatcher) {
        keys.screenLockSet = false
        val viewModel = start()
        val other = otherPhone()
        letAskToJoin(viewModel, other)

        viewModel.decideAboutPhone(other.keyId, ReferenceSigningScheme.DECISION_APPROVE)
        advanceUntilIdle()
        val asked = viewModel.uiState.value.account.deciding
        val prompt = viewModel.decisionSignatureForPrompt()
        viewModel.confirmDecisionWithTap()
        advanceUntilIdle()

        assertThat(asked?.method).isEqualTo(ConfirmationMethod.TAP)
        assertThat(prompt).isNull()
        assertThat(viewModel.statusOf(other)).isEqualTo(PhoneStatus.ACTIVE)
    }

    @Test
    fun `cancelling the prompt leaves the phone waiting, and declining keeps it off the account`() = runTest(dispatcher) {
        val viewModel = start()
        val other = otherPhone()
        letAskToJoin(viewModel, other)

        viewModel.decideAboutPhone(other.keyId, ReferenceSigningScheme.DECISION_APPROVE)
        advanceUntilIdle()
        viewModel.dismissDecision()
        viewModel.refreshAccount()
        advanceUntilIdle()
        val afterCancelling = viewModel.statusOf(other)
        decide(viewModel, other, ReferenceSigningScheme.DECISION_DECLINE)

        assertThat(afterCancelling).isEqualTo(PhoneStatus.WAITING_FOR_APPROVAL)
        assertThat(viewModel.statusOf(other)).isNull()
        assertThat(backend.accountView(backend.signedAction(other, ReferenceSigningScheme.ACTION_VIEW_ACCOUNT))?.waitingToJoin).isFalse()
    }

    @Test
    fun `a lost phone removed from the account can't pay from it any more`() = runTest(dispatcher) {
        val viewModel = start()
        val other = otherPhone()
        letAskToJoin(viewModel, other)
        decide(viewModel, other, ReferenceSigningScheme.DECISION_APPROVE)

        decide(viewModel, other, ReferenceSigningScheme.DECISION_REMOVE)

        val thisPhone = viewModel.uiState.value.keys.keys?.device?.keyId
        assertThat(viewModel.uiState.value.account.view?.phones?.map { it.phoneId }).containsExactly(thisPhone)
        assertThat((backend.authorize(other, DeviceRiskLevel.LOW) as PaymentAuthorization.Blocked).keyRejected).isTrue()
        assertThat(events.events.value.count { it.type == SecurityEventType.ACCOUNT_CHANGED }).isAtLeast(3)
    }

    @Test
    fun `this phone joins another account with the code from it, and pays from it once approved`() = runTest(dispatcher) {
        val viewModel = start()
        val other = otherPhone()
        val code = requireNotNull(backend.createLinkCode(backend.signedAction(other, ReferenceSigningScheme.ACTION_LINK_CODE))).code
        val thisPhone = requireNotNull(viewModel.uiState.value.keys.keys?.device?.keyId)

        // Typed the way a person might: lower case, in two groups.
        viewModel.joinAccount(code.lowercase().chunked(4).joinToString(" "))
        advanceUntilIdle()
        val waiting = viewModel.uiState.value.account.view?.waitingToJoin
        backend.decideAbout(other, thisPhone, ReferenceSigningScheme.DECISION_APPROVE)
        viewModel.refreshAccount()
        advanceUntilIdle()
        viewModel.attemptPayment()
        advanceUntilIdle()

        assertThat(waiting).isTrue()
        assertThat(viewModel.uiState.value.account.view?.phones?.map { it.phoneId }).containsExactly(other.keyId, thisPhone)
        assertThat(payment.submission).isInstanceOf(Submission.Charged::class.java)
    }

    @Test
    fun `a code that doesn't work says so, and this phone stays where it was`() = runTest(dispatcher) {
        val viewModel = start()

        viewModel.joinAccount("ABCD2345")
        advanceUntilIdle()

        assertThat(viewModel.uiState.value.userMessage?.text).contains("isn't valid")
        assertThat(viewModel.uiState.value.account.view?.waitingToJoin).isFalse()
        assertThat(viewModel.uiState.value.account.view?.phones).hasSize(1)
    }

    @Test
    fun `the first payment to someone this account hasn't paid asks for confirmation`() = runTest(dispatcher) {
        val viewModel = start()
        viewModel.attemptPayment()
        advanceUntilIdle()

        viewModel.setCheckout(ReferencePayment.PAYEES[2], ReferencePayment.AMOUNTS_MINOR[0])
        viewModel.attemptPayment()
        advanceUntilIdle()

        assertThat(payment.latestDecision).isEqualTo(
            PaymentDecisionState.ConfirmationRequired(DeviceRiskLevel.MEDIUM, ConfirmationMethod.DEVICE_CREDENTIAL),
        )
        assertThat(payment.reasons.filter { it.isProblem }.map { it.text }).containsExactly("First payment to this payee")
    }

    @Test
    fun `a phone Play remembers as blocked is blocked again, and one set up again must confirm`() = runTest(dispatcher) {
        val viewModel = start()

        viewModel.setPretendVerdict(PretendVerdict.BLOCKED_BEFORE)
        viewModel.attemptPayment()
        advanceUntilIdle()
        val blocked = payment
        viewModel.setPretendVerdict(PretendVerdict.SET_UP_BEFORE)
        viewModel.attemptPayment()
        advanceUntilIdle()

        assertThat(blocked.latestDecision).isInstanceOf(PaymentDecisionState.Blocked::class.java)
        assertThat(blocked.reasons.map { it.text }).contains("This phone was blocked before")
        assertThat(payment.latestDecision).isInstanceOf(PaymentDecisionState.ConfirmationRequired::class.java)
        assertThat(payment.reasons.filter { it.isProblem }.map { it.text }).containsExactly("Set up again on this phone")
        assertThat(backend.chargedPayments).isEqualTo(0)
    }

    @Test
    fun `keys are registered at launch with the step-up key when a lock is set`() = runTest(dispatcher) {
        val viewModel = start()

        val registered = viewModel.uiState.value.keys.keys
        assertThat(registered?.device).isNotNull()
        assertThat(registered?.stepUp).isNotNull()
        assertThat(events.events.value.count { it.type == SecurityEventType.KEY_REGISTERED }).isEqualTo(2)
    }

    @Test
    fun `setting a screen lock while away adds the step-up key on return`() = runTest(dispatcher) {
        keys.screenLockSet = false
        val viewModel = start()
        val before = viewModel.uiState.value.keys.keys

        keys.screenLockSet = true
        viewModel.onAppResumed()
        advanceUntilIdle()

        assertThat(before?.stepUp).isNull()
        assertThat(viewModel.uiState.value.keys.keys?.stepUp).isNotNull()
        mediumRisk()
        viewModel.attemptPayment()
        advanceUntilIdle()
        assertThat(payment.latestDecision).isEqualTo(
            PaymentDecisionState.ConfirmationRequired(DeviceRiskLevel.MEDIUM, ConfirmationMethod.DEVICE_CREDENTIAL),
        )
    }
}
