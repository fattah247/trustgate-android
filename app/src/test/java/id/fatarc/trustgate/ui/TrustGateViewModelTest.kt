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
import id.fatarc.trustgate.domain.api.Remedy
import id.fatarc.trustgate.domain.events.SecurityEventType
import id.fatarc.trustgate.domain.risk.DeviceRiskLevel
import id.fatarc.trustgate.domain.risk.RiskScorer
import id.fatarc.trustgate.domain.risk.SignalCategory
import id.fatarc.trustgate.domain.risk.SignalSeverity
import id.fatarc.trustgate.domain.signing.KeyRole
import id.fatarc.trustgate.domain.signing.ReferencePayment
import id.fatarc.trustgate.domain.signing.ReferenceRequestSigner
import id.fatarc.trustgate.domain.signing.RejectionReason
import id.fatarc.trustgate.domain.signing.VerificationResult
import id.fatarc.trustgate.testing.InMemorySecureValueStore
import id.fatarc.trustgate.testing.InMemorySecurityEventRepository
import id.fatarc.trustgate.testing.MutableSignalCollector
import id.fatarc.trustgate.testing.SoftwareKeyProvider
import id.fatarc.trustgate.testing.developmentPolicy
import id.fatarc.trustgate.testing.riskSignal
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
