package id.fatarc.trustgate.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import id.fatarc.trustgate.BuildConfig
import id.fatarc.trustgate.TrustGateAppContainer
import id.fatarc.trustgate.core.crypto.PinningConfig
import id.fatarc.trustgate.core.security.AssessmentTrigger
import id.fatarc.trustgate.core.security.ConfirmationMethod
import id.fatarc.trustgate.core.security.TrustGateSecurityService
import id.fatarc.trustgate.core.storage.SecureValueStore
import id.fatarc.trustgate.core.storage.SecurityStorageSnapshot
import id.fatarc.trustgate.data.securityevent.AuditLogExport
import id.fatarc.trustgate.domain.actiongate.SensitiveActionDecision
import id.fatarc.trustgate.domain.events.SecurityEventRepository
import id.fatarc.trustgate.domain.risk.DeviceRiskLevel
import id.fatarc.trustgate.domain.risk.DeviceRiskReport
import id.fatarc.trustgate.domain.risk.scenarioRiskReport
import id.fatarc.trustgate.domain.signing.ReferencePayment
import id.fatarc.trustgate.domain.signing.RequestSigner
import id.fatarc.trustgate.domain.signing.RequestVerifier
import id.fatarc.trustgate.domain.signing.SignedRequest
import id.fatarc.trustgate.domain.signing.VerificationResult
import id.fatarc.trustgate.domain.signing.asReceived
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.time.Duration
import java.time.Instant
import java.util.UUID

class TrustGateViewModel(
    private val securityService: TrustGateSecurityService,
    private val eventRepository: SecurityEventRepository,
    private val secureValueStore: SecureValueStore,
    private val requestSigner: RequestSigner,
    private val requestVerifier: RequestVerifier,
    pinningConfig: PinningConfig,
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
) : ViewModel() {
    private val _uiState = MutableStateFlow(
        TrustGateUiState(
            pinningSummary = buildPinningSummary(pinningConfig),
            verifierWindowMinutes = requestVerifier.allowedClockSkew.toMinutes(),
        ),
    )
    val uiState: StateFlow<TrustGateUiState> = _uiState.asStateFlow()

    private var assessmentJob: Job? = null
    private val storageLock = Mutex()
    private var actionJob: Job? = null
    private var nextMessageId = 0L

    init {
        viewModelScope.launch {
            eventRepository.events.collect { events ->
                _uiState.update { current -> current.copy(securityEvents = events) }
            }
        }
        loadStorageSnapshot(announce = false)
        assessRisk(trigger = AssessmentTrigger.LAUNCH, announceResult = false)
    }

    fun refreshRisk() {
        assessRisk(trigger = AssessmentTrigger.MANUAL, announceResult = true)
    }

    /**
     * Quietly re-checks a live verdict that has gone stale while the app was in the background, so
     * Overview never presents an old result as current. Only a changed verdict is announced or logged.
     */
    fun onAppResumed() {
        val risk = _uiState.value.risk
        val previous = risk.report ?: return
        if (risk.scenarioLevel != null || risk.isLoading) return
        if (assessmentJob?.isActive == true || actionJob?.isActive == true) return
        // Returning from the system lock screen also resumes the app; the action's own re-check covers that.
        if (_uiState.value.payment.latestDecision is PaymentDecisionState.ConfirmationRequired) return
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
                showMessage("Device risk changed: ${previous.level.label()} to ${report.level.label().lowercase()}")
            }
        }
    }

    fun attemptPayment() {
        if (actionJob?.isActive == true || assessmentJob?.isActive == true) return
        actionJob = viewModelScope.launch {
            val report = reportForSensitiveAction()
            if (report == null) {
                // Never leave an earlier "allowed" result on screen when this attempt didn't run.
                _uiState.update { current -> current.copy(payment = PaymentUiState()) }
                showMessage("The device couldn't be checked, so the action didn't run.")
                return@launch
            }
            when (securityService.evaluateSensitiveAction(report)) {
                SensitiveActionDecision.ALLOW -> {
                    val submission = submitProtectedRequest()
                    // A profile switch cancels this job; don't publish a result for the old profile.
                    ensureActive()
                    updateDecision(decision = PaymentDecisionState.Allowed(report.level), submission = submission)
                }

                SensitiveActionDecision.REQUIRE_CONFIRMATION -> updateDecision(PaymentDecisionState.ConfirmationRequired(report.level))
                SensitiveActionDecision.BLOCK -> updateDecision(PaymentDecisionState.Blocked(report.level))
            }
        }
    }

    fun confirmPayment(method: ConfirmationMethod) {
        val decision = _uiState.value.payment.latestDecision as? PaymentDecisionState.ConfirmationRequired ?: return
        if (_uiState.value.risk.report == null) return
        // Leave the confirmation state first so a second tap cannot record a second approval.
        updateDecision(PaymentDecisionState.Confirmed(decision.riskLevel))
        assessmentJob?.cancel()
        actionJob = viewModelScope.launch {
            // The device may have changed while the person was confirming, so check it again before approving.
            val report = reportForSensitiveAction()
            if (report == null) {
                _uiState.update { current -> current.copy(payment = PaymentUiState()) }
                showMessage("The device couldn't be checked, so the action didn't run.")
                return@launch
            }
            if (report.level == DeviceRiskLevel.HIGH) {
                runCatching { securityService.evaluateSensitiveAction(report) }.rethrowCancellation()
                updateDecision(PaymentDecisionState.Blocked(report.level))
                return@launch
            }
            val recorded = runCatching {
                securityService.confirmSensitiveAction(report, method)
            }.rethrowCancellation().isSuccess
            if (!recorded) {
                _uiState.update { current -> current.copy(payment = PaymentUiState()) }
                showMessage("The confirmation couldn't be recorded, so the action didn't run.")
                return@launch
            }
            val submission = submitProtectedRequest()
            ensureActive()
            _uiState.update { current ->
                if (current.payment.latestDecision is PaymentDecisionState.Confirmed) {
                    current.copy(payment = current.payment.copy(submission = submission))
                } else {
                    current
                }
            }
        }
    }

    /** Ends the confirmation without approval: the person backed out, or [problem] stopped it. */
    fun dismissConfirmation(problem: String? = null) {
        val decision = _uiState.value.payment.latestDecision as? PaymentDecisionState.ConfirmationRequired ?: return
        val report = _uiState.value.risk.report
        updateDecision(PaymentDecisionState.Cancelled(decision.riskLevel, problem))
        if (report != null) {
            viewModelScope.launch {
                runCatching { securityService.cancelSensitiveAction(report) }
            }
        }
    }

    fun setScenarioRiskLevel(level: DeviceRiskLevel?) {
        val risk = _uiState.value.risk
        if (risk.scenarioLevel == level && (risk.report != null || assessmentJob?.isActive == true)) return

        // A live check still in flight must not overwrite the profile that was just chosen.
        assessmentJob?.cancel()
        actionJob?.cancel()
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

    fun signReferenceRequest() {
        viewModelScope.launch { signNewRequest(forProtectedAction = false) }
    }

    /** Sends the latest signed request to the reference verifier, honestly or deliberately altered. */
    fun verifyLatestRequest(attempt: VerificationAttempt) {
        val request = _uiState.value.signing.signedRequest ?: return
        viewModelScope.launch {
            val now = Instant.now()
            val (received, receivedAt) = when (attempt) {
                VerificationAttempt.AS_SIGNED -> request.asReceived() to now
                // The same canonical encoding with a bigger amount, as someone editing the body in transit would send.
                VerificationAttempt.CHANGED_AMOUNT -> request.asReceived().copy(
                    body = requestSigner.canonicalize(request.payload.copy(amountMinor = request.payload.amountMinor * 10)),
                ) to now
                // Arrives just past the window the verifier allows, as a delayed or captured request would.
                VerificationAttempt.DELIVERED_LATE ->
                    request.asReceived() to now.plus(requestVerifier.allowedClockSkew).plus(LATE_DELIVERY_MARGIN)
            }
            val result = requestVerifier.verify(received, receivedAt)
            recordVerification(request, attempt, result, sentByProtectedAction = false)
        }
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
            val showSignalsOnHome = _uiState.value.storage.snapshot.showSignalsOnHome
            runCatching {
                writeStorage {
                    secureValueStore.storeSessionToken("tg-session-${UUID.randomUUID().toString().take(8)}")
                    report?.let { secureValueStore.storeLastRiskLevel(it.level) }
                    secureValueStore.storeShowSignalsOnHome(showSignalsOnHome)
                    secureValueStore.readSnapshot()
                }
            }.rethrowCancellation().onSuccess { snapshot ->
                val storedKeys = buildList {
                    add("session_token")
                    if (report != null) add("last_risk_level")
                    add("show_signals_on_home")
                }
                applyStorageSnapshot(snapshot)
                showMessage("Saved ${storedKeys.size} values to encrypted storage")
                runCatching { securityService.recordSecureValueStored(keys = storedKeys) }
            }.onFailure { error ->
                updateStorageFailure(error.message ?: "Values couldn't be written to encrypted storage.")
            }
        }
    }

    fun refreshStorage() {
        loadStorageSnapshot(announce = true)
    }

    fun toggleShowSignalsOnHome(enabled: Boolean) {
        if (_uiState.value.storage.snapshot.showSignalsOnHome == enabled) return
        _uiState.update { current ->
            current.copy(
                storage = current.storage.copy(
                    snapshot = current.storage.snapshot.copy(showSignalsOnHome = enabled),
                ),
            )
        }
        viewModelScope.launch {
            runCatching {
                writeStorage { secureValueStore.storeShowSignalsOnHome(enabled) }
            }.rethrowCancellation().onFailure { error ->
                // Show what is actually stored rather than guessing at the previous value.
                val stored = runCatching { writeStorage { secureValueStore.readSnapshot() } }.getOrNull()
                _uiState.update { current ->
                    current.copy(
                        storage = current.storage.copy(
                            snapshot = stored ?: current.storage.snapshot.copy(showSignalsOnHome = !enabled),
                            status = StorageStatus.Failed(
                                error.message ?: "The display preference couldn't be saved.",
                            ),
                        ),
                    )
                }
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
            val scenarioLevel = _uiState.value.risk.scenarioLevel
            if (scenarioLevel != null) {
                applyRiskReport(report = scenarioRiskReport(scenarioLevel), source = RiskReportSource.SCENARIO)
                return@launch
            }
            val report = assessLiveDevice(trigger = trigger, resetDecision = true) ?: return@launch
            if (announceResult) {
                showMessage("Check complete · ${report.level.label()}")
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
        if (scenarioLevel != null) {
            return risk.report?.takeIf { risk.source == RiskReportSource.SCENARIO }
                ?: scenarioRiskReport(scenarioLevel).also { report ->
                    applyRiskReport(report = report, source = RiskReportSource.SCENARIO, resetDecision = false)
                }
        }
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
            applyRiskFailure(error.message ?: "The device check couldn't finish.")
        }.getOrNull()
    }

    private fun loadStorageSnapshot(announce: Boolean) {
        viewModelScope.launch {
            runCatching {
                withContext(ioDispatcher) { secureValueStore.readSnapshot() }
            }.rethrowCancellation().onSuccess { snapshot ->
                applyStorageSnapshot(snapshot)
                if (announce) showMessage("Reloaded from encrypted storage")
            }.onFailure { error ->
                updateStorageFailure(error.message ?: "Encrypted storage is unavailable.")
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

    private fun updateDecision(decision: PaymentDecisionState, submission: Submission? = null) {
        _uiState.update { current ->
            current.copy(
                payment = PaymentUiState(latestDecision = decision, decidedAt = Instant.now(), submission = submission),
            )
        }
    }

    /** Signs the request a permitted action carries and has the reference verifier check it, as a server would. */
    private suspend fun submitProtectedRequest(): Submission {
        val request = signNewRequest(forProtectedAction = true)
            ?: return Submission.NotSigned(
                (_uiState.value.signing.status as? SigningStatus.Failed)?.message ?: "The request couldn't be signed.",
            )
        val result = requestVerifier.verify(request.asReceived(), Instant.now())
        recordVerification(request, VerificationAttempt.AS_SIGNED, result, sentByProtectedAction = true)
        return Submission.Sent(
            merchantReference = request.payload.merchantReference,
            nonce = request.nonce,
            result = result,
        )
    }

    private suspend fun signNewRequest(forProtectedAction: Boolean): SignedRequest? {
        return runCatching {
            requestSigner.sign(
                payload = ReferencePayment.payload(),
                timestamp = Instant.now().toString(),
                nonce = UUID.randomUUID().toString().replace("-", "").take(16),
            )
        }.onSuccess { signedRequest ->
            _uiState.update { current ->
                current.copy(
                    signing = SigningUiState(
                        signedRequest = signedRequest,
                        status = SigningStatus.Signed(signedRequest.payload.merchantReference),
                    ),
                )
            }
            runCatching { securityService.recordSignedRequest(signedRequest, forProtectedAction) }.rethrowCancellation()
        }.onFailure { error ->
            _uiState.update { current ->
                current.copy(
                    signing = current.signing.copy(
                        status = SigningStatus.Failed(error.message ?: "The reference request couldn't be signed."),
                    ),
                )
            }
        }.getOrNull()
    }

    private suspend fun recordVerification(
        request: SignedRequest,
        attempt: VerificationAttempt,
        result: VerificationResult,
        sentByProtectedAction: Boolean,
    ) {
        val record = VerificationRecord(
            attempt = attempt,
            result = result,
            at = Instant.now(),
            sentByProtectedAction = sentByProtectedAction,
        )
        _uiState.update { current ->
            if (current.signing.signedRequest?.nonce != request.nonce) {
                current
            } else {
                current.copy(
                    signing = current.signing.copy(
                        verifications = (listOf(record) + current.signing.verifications).take(MAX_VERIFICATION_RECORDS),
                    ),
                )
            }
        }
        val attemptName = if (sentByProtectedAction) "protected-action" else attempt.metadataValue
        runCatching { securityService.recordVerification(request, result, attemptName) }.rethrowCancellation()
    }

    /** Storage calls run one at a time, in order, so quick toggles can't land out of order. */
    private suspend fun <T> writeStorage(block: () -> T): T = storageLock.withLock {
        withContext(ioDispatcher) { block() }
    }

    private fun showMessage(text: String) {
        val message = UserMessage(id = nextMessageId++, text = text)
        _uiState.update { current -> current.copy(userMessage = message) }
    }


    private fun buildPinningSummary(config: PinningConfig): String {
        return if (config.enabled) {
            "Pinning is on for ${config.host}. A real deployment also needs a plan for rotating pins."
        } else {
            "Pinning for ${config.host} is implemented but turned off, so this build works without a pinned server."
        }
    }
}

private val RESUME_RECHECK_AFTER: Duration = Duration.ofSeconds(30)
private val LATE_DELIVERY_MARGIN: Duration = Duration.ofMinutes(1)
private const val MAX_VERIFICATION_RECORDS = 6

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
            requestVerifier = container.requestVerifier,
            pinningConfig = container.pinningConfig,
        ) as T
    }
}
