package id.fatarc.trustgate.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import id.fatarc.trustgate.BuildConfig
import id.fatarc.trustgate.TrustGateAppContainer
import id.fatarc.trustgate.core.backend.BackendTransport
import id.fatarc.trustgate.core.backend.PaymentClient
import id.fatarc.trustgate.core.backend.TrustGateApi
import id.fatarc.trustgate.core.integrity.IntegrityTokenSource
import id.fatarc.trustgate.core.integrity.MockIntegrityTokenSource
import id.fatarc.trustgate.core.integrity.PretendVerdict
import id.fatarc.trustgate.core.keys.DeviceKeyProvider
import id.fatarc.trustgate.core.keys.KeyRegistrar
import id.fatarc.trustgate.core.keys.KeySet
import id.fatarc.trustgate.core.keys.StepUpKeyInvalidatedException
import id.fatarc.trustgate.core.security.AssessmentTrigger
import id.fatarc.trustgate.core.security.ConfirmationMethod
import id.fatarc.trustgate.core.security.TrustGateSecurityService
import id.fatarc.trustgate.core.storage.SecureValueNames
import id.fatarc.trustgate.core.storage.SecureValueStore
import id.fatarc.trustgate.core.storage.SecurityStorageSnapshot
import id.fatarc.trustgate.data.securityevent.AuditLogExport
import id.fatarc.trustgate.domain.api.DeviceEvidence
import id.fatarc.trustgate.domain.api.DecisionReason
import id.fatarc.trustgate.domain.api.PaymentAuthorization
import id.fatarc.trustgate.domain.api.PaymentAuthorizationRequest
import id.fatarc.trustgate.domain.api.PaymentResponse
import id.fatarc.trustgate.domain.api.ReportedSignal
import id.fatarc.trustgate.domain.api.RequiredConfirmation
import id.fatarc.trustgate.domain.api.TrustGateJson
import id.fatarc.trustgate.domain.events.SecurityEventRepository
import id.fatarc.trustgate.domain.risk.DeviceRiskLevel
import id.fatarc.trustgate.domain.risk.DeviceRiskReport
import id.fatarc.trustgate.domain.risk.scenarioRiskReport
import id.fatarc.trustgate.domain.signing.KeyRole
import id.fatarc.trustgate.domain.signing.ReferencePayment
import id.fatarc.trustgate.domain.signing.ReferenceRequestSigner
import id.fatarc.trustgate.domain.signing.ReferenceSigningScheme
import id.fatarc.trustgate.domain.signing.SignedRequest
import id.fatarc.trustgate.domain.signing.asReceived
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.IOException
import java.security.Signature
import java.time.Duration
import java.time.Instant
import java.util.UUID

class TrustGateViewModel(
    private val securityService: TrustGateSecurityService,
    private val eventRepository: SecurityEventRepository,
    private val secureValueStore: SecureValueStore,
    private val requestSigner: ReferenceRequestSigner,
    private val api: TrustGateApi,
    private val keyProvider: DeviceKeyProvider,
    private val keyRegistrar: KeyRegistrar,
    private val transport: BackendTransport,
    private val paymentClient: PaymentClient,
    private val integrityTokens: IntegrityTokenSource,
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
) : ViewModel() {
    private val _uiState = MutableStateFlow(
        TrustGateUiState(pretendVerdict = (integrityTokens as? MockIntegrityTokenSource)?.pretend),
    )
    val uiState: StateFlow<TrustGateUiState> = _uiState.asStateFlow()

    /** A payment the backend authorized that waits for the person to confirm it. */
    private class PendingPayment(
        val nonce: String,
        val keyId: String,
        val signWith: KeyRole,
        val confirmation: String?,
        val idempotencyKey: String,
    )

    private var assessmentJob: Job? = null
    private val storageLock = Mutex()
    private var actionJob: Job? = null
    private var pendingPayment: PendingPayment? = null
    private var nextMessageId = 0L

    init {
        viewModelScope.launch {
            eventRepository.events.collect { events ->
                _uiState.update { current -> current.copy(securityEvents = events) }
            }
        }
        loadStorageSnapshot()
        assessRisk(trigger = AssessmentTrigger.LAUNCH, announceResult = false)
        viewModelScope.launch { ensureKeys() }
    }

    fun refreshRisk() {
        assessRisk(trigger = AssessmentTrigger.MANUAL, announceResult = true)
    }

    /**
     * Brings the keys up to date and quietly re-checks a live verdict that has gone stale while the
     * app was in the background, so Overview never presents an old result as current. Only a changed
     * verdict is announced or logged.
     */
    fun onAppResumed() {
        // Returning from the confirmation prompt also resumes the app. The keys must stay put while
        // they're in use, and the action checks the device again itself.
        if (actionJob?.isActive == true || _uiState.value.payment.latestDecision is PaymentDecisionState.ConfirmationRequired) return
        // A screen lock set or removed in Settings adds or drops the step-up key.
        viewModelScope.launch { ensureKeys() }

        val risk = _uiState.value.risk
        val previous = risk.report ?: return
        if (risk.scenarioLevel != null || risk.isLoading || assessmentJob?.isActive == true) return
        if (Duration.between(previous.assessedAt, Instant.now()) < RESUME_RECHECK_AFTER) return

        assessmentJob = viewModelScope.launch {
            val report = runCatching {
                withContext(ioDispatcher) {
                    securityService.assessDeviceRisk(trigger = AssessmentTrigger.RESUME, previous = previous)
                }
            }.rethrowCancellation().getOrNull() ?: return@launch
            if (_uiState.value.risk.scenarioLevel != null) return@launch

            val levelChanged = report.level != previous.level
            applyRiskReport(report = report, source = RiskReportSource.LIVE, resetDecision = levelChanged)
            if (levelChanged) {
                showMessage("This phone is now ${report.level.label().lowercase()}")
            }
        }
    }

    /**
     * Runs the protected action end to end: check the device again, let the backend decide, and
     * when it allows the action, sign the payment with the key it asks for and submit it.
     */
    fun attemptPayment() {
        if (actionJob?.isActive == true || assessmentJob?.isActive == true) return
        pendingPayment = null
        _uiState.update { current -> current.copy(payment = PaymentUiState(stage = PaymentStage.CHECKING_DEVICE)) }
        actionJob = viewModelScope.launch {
            val report = reportForSensitiveAction() ?: return@launch abandonAction("Couldn't check this phone.")
            val keys = ensureKeys() ?: return@launch abandonAction(_uiState.value.keys.errorMessage ?: "This phone's key isn't ready.")
            _uiState.update { current -> current.copy(payment = current.payment.copy(stage = PaymentStage.ASKING_SERVER)) }
            val authorization = runCatching { withContext(ioDispatcher) { api.authorizePayment(authorizationRequest(report, keys.device.keyId)) } }
                .rethrowCancellation()
                .getOrElse { return@launch abandonAction("Couldn't reach the server.") }
            // The backend's own level counts from here on; the device's report was only evidence.
            val level = authorization.level
            runCatching { securityService.recordGateDecision(level, authorization.decision, authorization.reasons) }.rethrowCancellation()

            if (authorization !is PaymentAuthorization.Proceed) {
                updateDecision(PaymentDecisionState.Blocked(level), PaymentStage.DONE, authorization)
                return@launch
            }
            val keyId = when (authorization.signWith) {
                KeyRole.DEVICE -> keys.device.keyId
                KeyRole.STEP_UP -> keys.stepUp?.keyId
                    ?: return@launch abandonAction("This phone's screen-lock key isn't set up.")
            }
            val pending = PendingPayment(
                nonce = authorization.nonce,
                keyId = keyId,
                signWith = authorization.signWith,
                confirmation = ReferenceSigningScheme.CONFIRMATION_TAP.takeIf { authorization.confirmation == RequiredConfirmation.TAP },
                idempotencyKey = newIdempotencyKey(),
            )
            when (authorization.confirmation) {
                RequiredConfirmation.NONE -> {
                    updateDecision(PaymentDecisionState.Allowed(level), PaymentStage.PAYING, authorization)
                    val submission = signAndSubmit(pending, keyProvider::signWithDeviceKey)
                    // A profile switch cancels this job; don't publish a result for the old profile.
                    ensureActive()
                    publishSubmission(submission)
                }

                RequiredConfirmation.STEP_UP_KEY -> {
                    pendingPayment = pending
                    updateDecision(PaymentDecisionState.ConfirmationRequired(level, ConfirmationMethod.DEVICE_CREDENTIAL), PaymentStage.CONFIRMING, authorization)
                }

                RequiredConfirmation.TAP -> {
                    pendingPayment = pending
                    updateDecision(PaymentDecisionState.ConfirmationRequired(level, ConfirmationMethod.TAP), PaymentStage.CONFIRMING, authorization)
                }
            }
        }
    }

    /**
     * The step-up key's signature for the system prompt. It can't sign anything until the person
     * authenticates; the prompt hands it back unlocked through [completeStepUp].
     */
    fun stepUpSignatureForPrompt(): Signature? {
        if (pendingPayment?.signWith != KeyRole.STEP_UP) return null
        return try {
            keyProvider.stepUpSignature()
        } catch (error: StepUpKeyInvalidatedException) {
            viewModelScope.launch {
                keyRegistrar.invalidateStepUp()
                // Set up a replacement now, so the next attempt doesn't wait for key generation.
                ensureKeys()
            }
            dismissConfirmation("Your screen lock changed, so its key was reset. Pay again.")
            null
        } catch (error: Exception) {
            // Keystore reports trouble through several exception types; none should crash the confirmation.
            dismissConfirmation("Couldn't use the screen-lock key. Pay again.")
            null
        }
    }

    /** The person authenticated; [authenticated] can now sign exactly once. */
    fun completeStepUp(authenticated: Signature) {
        confirm(ConfirmationMethod.DEVICE_CREDENTIAL) { data ->
            authenticated.update(data)
            authenticated.sign()
        }
    }

    /** The fallback when the device has no screen lock: an explicit tap, signed into the request. */
    fun confirmWithTap() {
        confirm(ConfirmationMethod.TAP, keyProvider::signWithDeviceKey)
    }

    private fun confirm(method: ConfirmationMethod, sign: (ByteArray) -> ByteArray) {
        val decision = _uiState.value.payment.latestDecision as? PaymentDecisionState.ConfirmationRequired ?: return
        val pending = pendingPayment?.takeIf { decision.method == method } ?: return
        pendingPayment = null
        // Leave the confirmation state first so a second tap cannot record a second approval.
        updateDecision(PaymentDecisionState.Confirmed(decision.riskLevel, method), PaymentStage.PAYING)
        assessmentJob?.cancel()
        actionJob = viewModelScope.launch {
            // The device may have changed while the person was confirming, so check it again before approving.
            val report = reportForSensitiveAction() ?: return@launch abandonAction("Couldn't check this phone again.")
            if (report.level == DeviceRiskLevel.HIGH) {
                runCatching { securityService.recordBlockedAfterConfirmation(report) }.rethrowCancellation()
                val stopped = PaymentAuthorization.Blocked(report.level, listOf(DecisionReason("Turned high risk while you confirmed", report.level)))
                updateDecision(PaymentDecisionState.Blocked(report.level), PaymentStage.DONE, stopped)
                return@launch
            }
            val recorded = runCatching {
                securityService.confirmSensitiveAction(report, method)
            }.rethrowCancellation().isSuccess
            if (!recorded) return@launch abandonAction("Couldn't record your confirmation.")

            val submission = signAndSubmit(pending, sign)
            ensureActive()
            publishSubmission(submission)
        }
    }

    /** Ends the confirmation without approval: the person backed out, or [problem] stopped it. */
    fun dismissConfirmation(problem: String? = null) {
        val decision = _uiState.value.payment.latestDecision as? PaymentDecisionState.ConfirmationRequired ?: return
        val report = _uiState.value.risk.report
        pendingPayment = null
        updateDecision(PaymentDecisionState.Cancelled(decision.riskLevel, problem), PaymentStage.DONE)
        if (report != null) {
            viewModelScope.launch {
                runCatching { securityService.cancelSensitiveAction(report) }
            }
        }
    }

    /** What the made-up integrity token claims Google Play found. Only debug builds without Play have one. */
    fun setPretendVerdict(verdict: PretendVerdict) {
        val source = integrityTokens as? MockIntegrityTokenSource ?: return
        source.pretend = verdict
        _uiState.update { current -> current.copy(pretendVerdict = verdict) }
    }

    fun setSimulateLostResponse(enabled: Boolean) {
        _uiState.update { current -> current.copy(simulateLostResponse = enabled) }
    }

    fun setScenarioRiskLevel(level: DeviceRiskLevel?) {
        val risk = _uiState.value.risk
        if (risk.scenarioLevel == level && (risk.report != null || assessmentJob?.isActive == true)) return

        // A live check still in flight must not overwrite the profile that was just chosen.
        assessmentJob?.cancel()
        actionJob?.cancel()
        pendingPayment = null
        _uiState.update { current ->
            current.copy(
                risk = current.risk.copy(scenarioLevel = level, errorMessage = null),
                payment = PaymentUiState(),
            )
        }

        if (level == null) {
            assessRisk(trigger = AssessmentTrigger.MANUAL, announceResult = false)
            return
        }

        val report = scenarioRiskReport(level)
        applyRiskReport(report = report, source = RiskReportSource.SCENARIO)
        viewModelScope.launch {
            runCatching { securityService.recordScenarioApplied(report) }
        }
    }

    /**
     * Signs a fresh request against a verification challenge and attacks the server with it:
     * sends it twice, edits it after signing, or delivers a copy dated past the time window.
     */
    fun runLabTest(test: LabTest) {
        if (_uiState.value.lab.running != null) return
        _uiState.update { current -> current.copy(lab = current.lab.copy(running = test)) }
        viewModelScope.launch {
            val outcome = runCatching {
                val keys = checkNotNull(ensureKeys()) { _uiState.value.keys.errorMessage ?: "This phone's key isn't ready." }
                val request = withContext(ioDispatcher) {
                    val prepared = requestSigner.prepare(
                        payload = ReferencePayment.payload(),
                        nonce = api.verificationChallenge(keys.device.keyId),
                        keyId = keys.device.keyId,
                        timestamp = Instant.now().toString(),
                    )
                    prepared.signedWith(keyProvider.signWithDeviceKey(prepared.signingInput))
                }
                publishSigned(request, forProtectedAction = false)
                val sends = when (test) {
                    LabTest.REPLAY -> listOf(request.asReceived(), request.asReceived())
                    // The same canonical encoding with a bigger amount, as someone editing the body in transit would send.
                    LabTest.CHANGED_AMOUNT -> listOf(
                        request.asReceived().copy(
                            body = requestSigner.canonicalize(request.payload.copy(amountMinor = request.payload.amountMinor * 10)),
                        ),
                    )
                    // A server can't be told when a request arrived, so send a copy signed just past the
                    // window, which is exactly how a held-back request looks when it finally lands.
                    LabTest.SENT_LATE -> listOf(heldBackCopy(request).asReceived())
                }
                sends.map { sent -> withContext(ioDispatcher) { api.checkRequest(sent) } }.onEach { result ->
                    runCatching { securityService.recordVerification(request, result, test.metadataValue) }.rethrowCancellation()
                }
            }.rethrowCancellation()
            _uiState.update { current ->
                current.copy(
                    lab = current.lab.copy(
                        running = null,
                        results = outcome.getOrNull()?.let { current.lab.results + (test to it) } ?: current.lab.results,
                    ),
                )
            }
            outcome.exceptionOrNull()?.let { showMessage(if (it is IOException) "Couldn't reach the server." else it.message ?: "The test couldn't run.") }
        }
    }

    private fun heldBackCopy(request: SignedRequest): SignedRequest {
        val keyId = _uiState.value.keys.keys?.device?.keyId ?: request.keyId
        val prepared = requestSigner.prepare(
            payload = request.payload,
            nonce = request.nonce,
            keyId = keyId,
            timestamp = Instant.now().minus(ReferenceSigningScheme.TIME_WINDOW).minus(LATE_DELIVERY_MARGIN).toString(),
            idempotencyKey = request.idempotencyKey,
            confirmation = request.confirmation,
        )
        return prepared.signedWith(keyProvider.signWithDeviceKey(prepared.signingInput))
    }

    fun buildAuditExport(): String {
        val events = _uiState.value.securityEvents
        return AuditLogExport(
            app = "TrustGate ${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})",
            exportedAt = Instant.now().toString(),
            eventCount = events.size,
            events = events,
        ).toJson()
    }

    fun storeReferenceValues() {
        viewModelScope.launch {
            val report = _uiState.value.risk.report
            runCatching {
                withStorage {
                    secureValueStore.storeSessionToken("tg-session-${UUID.randomUUID().toString().take(8)}")
                    report?.let { secureValueStore.storeLastRiskLevel(it.level) }
                    secureValueStore.readSnapshot()
                }
            }.rethrowCancellation().onSuccess { snapshot ->
                val storedKeys = buildList {
                    add(SecureValueNames.SESSION_TOKEN)
                    if (report != null) add(SecureValueNames.LAST_RISK_LEVEL)
                }
                applyStorageSnapshot(snapshot)
                showMessage("Saved, encrypted")
                runCatching { securityService.recordSecureValueStored(keys = storedKeys) }
            }.onFailure { error ->
                updateStorageFailure(error.message ?: "Couldn't save.")
            }
        }
    }

    fun clearSecurityEvents() {
        viewModelScope.launch {
            runCatching { eventRepository.clear() }
                .rethrowCancellation()
                .onSuccess { showMessage("Activity cleared") }
                .onFailure { showMessage("Activity couldn't be cleared") }
        }
    }

    fun userMessageShown(id: Long) {
        _uiState.update { current ->
            if (current.userMessage?.id == id) current.copy(userMessage = null) else current
        }
    }

    private fun assessRisk(trigger: AssessmentTrigger, announceResult: Boolean) {
        if (assessmentJob?.isActive == true) return
        assessmentJob = viewModelScope.launch {
            // A payment already on its way keeps its result; the new verdict applies to the next action.
            val resetDecision = actionJob?.isActive != true
            val scenarioLevel = _uiState.value.risk.scenarioLevel
            if (scenarioLevel != null) {
                applyRiskReport(report = scenarioRiskReport(scenarioLevel), source = RiskReportSource.SCENARIO, resetDecision = resetDecision)
                return@launch
            }
            val report = assessLiveDevice(trigger = trigger, resetDecision = resetDecision) ?: return@launch
            if (announceResult) {
                showMessage("Checked · ${report.level.label()}")
            }
        }
    }

    /**
     * The report a protected action is judged against. Live checks run again every time so a
     * debugger or root tool attached after launch is still caught.
     */
    private suspend fun reportForSensitiveAction(): DeviceRiskReport? {
        val risk = _uiState.value.risk
        val scenarioLevel = risk.scenarioLevel
        // Choosing a profile applies its report at once, so there is always one to judge against.
        if (scenarioLevel != null) return risk.report
        return assessLiveDevice(trigger = AssessmentTrigger.BEFORE_ACTION, resetDecision = false)
    }

    private suspend fun assessLiveDevice(
        trigger: AssessmentTrigger,
        resetDecision: Boolean,
    ): DeviceRiskReport? {
        _uiState.update { current ->
            current.copy(risk = current.risk.copy(isLoading = true, errorMessage = null))
        }
        return runCatching {
            withContext(ioDispatcher) { securityService.assessDeviceRisk(trigger = trigger) }
        }.rethrowCancellation().onSuccess { report ->
            applyRiskReport(report = report, source = RiskReportSource.LIVE, resetDecision = resetDecision)
        }.onFailure { error ->
            applyRiskFailure(error.message ?: "The check couldn't finish.")
        }.getOrNull()
    }

    private fun loadStorageSnapshot() {
        viewModelScope.launch {
            runCatching {
                withStorage { secureValueStore.readSnapshot() }
            }.rethrowCancellation().onSuccess { snapshot ->
                applyStorageSnapshot(snapshot)
                if (snapshot.unreadableValuesCleared > 0) {
                    showMessage("${snapshot.unreadableValuesCleared} saved values couldn't be unlocked on this phone and were removed")
                }
            }.onFailure { error ->
                updateStorageFailure(error.message ?: "Secure storage isn't available.")
            }
        }
    }

    private fun applyRiskReport(
        report: DeviceRiskReport,
        source: RiskReportSource,
        resetDecision: Boolean = true,
    ) {
        _uiState.update { current ->
            current.copy(
                risk = current.risk.copy(
                    report = report,
                    source = source,
                    isLoading = false,
                    errorMessage = null,
                ),
                payment = if (resetDecision) PaymentUiState() else current.payment,
            )
        }
    }

    private fun applyRiskFailure(message: String) {
        _uiState.update { current ->
            current.copy(
                risk = current.risk.copy(
                    isLoading = false,
                    errorMessage = message,
                ),
            )
        }
    }

    private fun applyStorageSnapshot(snapshot: SecurityStorageSnapshot) {
        _uiState.update { current ->
            current.copy(
                storage = current.storage.copy(
                    snapshot = snapshot,
                    status = StorageStatus.Loaded,
                ),
            )
        }
    }

    private fun updateStorageFailure(message: String) {
        _uiState.update { current ->
            current.copy(
                storage = current.storage.copy(
                    status = StorageStatus.Failed(message),
                ),
            )
        }
    }

    /** Moves the payment on to [decision]; [from] is the server's answer that led there, if this step has one. */
    private fun updateDecision(decision: PaymentDecisionState, stage: PaymentStage, from: PaymentAuthorization? = null) {
        _uiState.update { current ->
            val previous = current.payment
            val remedy = if (from != null) from.remedy else previous.remedy
            current.copy(
                payment = PaymentUiState(
                    stage = stage,
                    latestDecision = decision,
                    decidedAt = Instant.now(),
                    reasons = from?.reasons ?: previous.reasons,
                    remedy = remedy,
                    canShowFix = remedy != null && integrityTokens.canShowFix(remedy),
                    scamWarning = from?.scamWarning ?: previous.scamWarning,
                ),
            )
        }
    }

    /**
     * What the device reports about itself, signed by its key, with a Play Integrity token bound to
     * that exact report. Without a token the backend weighs the signals alone.
     */
    private suspend fun authorizationRequest(report: DeviceRiskReport, deviceKeyId: String): PaymentAuthorizationRequest {
        val evidence = TrustGateJson.encodeToString(
            DeviceEvidence.serializer(),
            DeviceEvidence(
                deviceKeyId = deviceKeyId,
                collectedAt = Instant.now().toString(),
                signals = report.signals.map { ReportedSignal(it.id, it.detected) },
                simulated = _uiState.value.risk.source == RiskReportSource.SCENARIO,
            ),
        )
        val integrityToken = runCatching { integrityTokens.token(ReferenceSigningScheme.sha256Hex(evidence)) }.rethrowCancellation().getOrNull()
        return PaymentAuthorizationRequest(
            deviceKeyId = deviceKeyId,
            evidence = evidence,
            signature = ReferenceSigningScheme.encode(keyProvider.signWithDeviceKey(evidence.toByteArray())),
            integrityToken = integrityToken,
        )
    }

    /** Adds what happened to the payment to the decision that let it through, unless that was reset meanwhile. */
    private fun publishSubmission(submission: Submission) {
        _uiState.update { current ->
            if (current.payment.stage == PaymentStage.PAYING) {
                current.copy(payment = current.payment.copy(submission = submission, stage = PaymentStage.DONE))
            } else {
                current
            }
        }
    }

    /** Registers or refreshes the device's keys with the backend; null when they can't be prepared. */
    private suspend fun ensureKeys(): KeySet? {
        _uiState.update { current -> current.copy(keys = current.keys.copy(errorMessage = null)) }
        return runCatching { keyRegistrar.ensure() }
            .rethrowCancellation()
            .onSuccess { result ->
                _uiState.update { current -> current.copy(keys = KeysUiState(keys = result.keys)) }
                result.newlyRegistered.forEach { key ->
                    runCatching { securityService.recordKeyRegistered(key) }.rethrowCancellation()
                }
            }
            .onFailure { error ->
                _uiState.update { current ->
                    current.copy(keys = KeysUiState(errorMessage = keyProblem(error)))
                }
            }
            .getOrNull()
            ?.keys
    }

    /**
     * Signs the payment with a fresh timestamp and sends it. When a response is lost the client
     * resends the identical request; its idempotency key stops the backend charging twice.
     */
    private suspend fun signAndSubmit(pending: PendingPayment, sign: (ByteArray) -> ByteArray): Submission {
        val signed = runCatching {
            withContext(ioDispatcher) {
                val prepared = requestSigner.prepare(
                    payload = ReferencePayment.payload(),
                    nonce = pending.nonce,
                    keyId = pending.keyId,
                    timestamp = Instant.now().toString(),
                    idempotencyKey = pending.idempotencyKey,
                    confirmation = pending.confirmation,
                )
                prepared.signedWith(sign(prepared.signingInput))
            }
        }.rethrowCancellation().getOrElse { error ->
            return Submission.NotSent(error.message ?: "The request couldn't be signed.")
        }
        publishSigned(signed, forProtectedAction = true)

        transport.loseFirstResponse = _uiState.value.simulateLostResponse
        // Once a payment is sent it runs to an outcome and is logged, even if the screen moves on,
        // so a charge is never left without a record.
        val outcome = withContext(NonCancellable + ioDispatcher) {
            runCatching { paymentClient.submit(signed.asReceived()) }
                .onSuccess { outcome -> runCatching { securityService.recordPayment(signed, outcome) } }
        }.getOrElse { error ->
            // The server refused the request outright; resending the same one wouldn't change that.
            return Submission.NotSent(error.message ?: "The server refused the payment.")
        }

        return when (val response = outcome.response) {
            null -> Submission.NoResponse(outcome.attempts)
            is PaymentResponse.Rejected -> Submission.Refused(response.reason)
            is PaymentResponse.Processed -> {
                Submission.Charged(
                    paymentId = response.payment.id,
                    signedWith = response.payment.signedWith,
                    attempts = outcome.attempts,
                    lostResponses = outcome.lostResponses,
                )
            }
        }
    }

    private suspend fun publishSigned(signed: SignedRequest, forProtectedAction: Boolean) {
        _uiState.update { current -> current.copy(lastRequest = signed) }
        runCatching { securityService.recordSignedRequest(signed, forProtectedAction) }.rethrowCancellation()
    }

    /** Stops the payment at the step it reached, saying why there; nothing was charged. */
    private fun abandonAction(message: String) {
        pendingPayment = null
        _uiState.update { current ->
            current.copy(payment = current.payment.copy(stage = current.payment.stage ?: PaymentStage.CHECKING_DEVICE, problem = message))
        }
    }

    private fun keyProblem(error: Throwable): String = when (error) {
        is IOException -> if (BuildConfig.DEBUG) {
            "Can't reach the server at ${BuildConfig.SERVER_URL}. Start it with ./gradlew :server:run."
        } else {
            "Can't reach the server."
        }
        else -> error.message ?: "This phone's key couldn't be set up."
    }

    private fun newIdempotencyKey(): String = "pay_" + UUID.randomUUID().toString().replace("-", "")

    /** Storage calls run one at a time, in order, so a reload can't land between a toggle and its write. */
    private suspend fun <T> withStorage(block: () -> T): T = storageLock.withLock {
        withContext(ioDispatcher) { block() }
    }

    private fun showMessage(text: String) {
        val message = UserMessage(id = nextMessageId++, text = text)
        _uiState.update { current -> current.copy(userMessage = message) }
    }
}

private val RESUME_RECHECK_AFTER: Duration = Duration.ofSeconds(30)
private val LATE_DELIVERY_MARGIN: Duration = Duration.ofMinutes(1)

/** runCatching also catches cancellation; let it propagate so cancelled work doesn't report a failure. */
private fun <T> Result<T>.rethrowCancellation(): Result<T> = onFailure { error ->
    if (error is CancellationException) throw error
}

class TrustGateViewModelFactory(
    private val container: TrustGateAppContainer,
) : ViewModelProvider.Factory {
    @Suppress("UNCHECKED_CAST")
    override fun <T : ViewModel> create(modelClass: Class<T>): T {
        return TrustGateViewModel(
            securityService = container.securityService,
            eventRepository = container.securityEventRepository,
            secureValueStore = container.secureValueStore,
            requestSigner = container.requestSigner,
            api = container.api,
            keyProvider = container.keyProvider,
            keyRegistrar = container.keyRegistrar,
            transport = container.transport,
            paymentClient = container.paymentClient,
            integrityTokens = container.integrityTokens,
        ) as T
    }
}
