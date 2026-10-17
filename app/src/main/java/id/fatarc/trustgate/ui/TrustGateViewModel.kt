package id.fatarc.trustgate.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import id.fatarc.trustgate.BuildConfig
import id.fatarc.trustgate.TrustGateAppContainer
import id.fatarc.trustgate.core.backend.PaymentAuthorization
import id.fatarc.trustgate.core.backend.PaymentClient
import id.fatarc.trustgate.core.backend.PaymentResponse
import id.fatarc.trustgate.core.backend.ReferenceBackend
import id.fatarc.trustgate.core.backend.ReferenceTransport
import id.fatarc.trustgate.core.backend.RequiredConfirmation
import id.fatarc.trustgate.core.crypto.PinningConfig
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
import id.fatarc.trustgate.domain.events.SecurityEventRepository
import id.fatarc.trustgate.domain.risk.DeviceRiskLevel
import id.fatarc.trustgate.domain.risk.DeviceRiskReport
import id.fatarc.trustgate.domain.risk.scenarioRiskReport
import id.fatarc.trustgate.domain.signing.KeyRole
import id.fatarc.trustgate.domain.signing.ReferencePayment
import id.fatarc.trustgate.domain.signing.ReferenceRequestSigner
import id.fatarc.trustgate.domain.signing.ReferenceSigningScheme
import id.fatarc.trustgate.domain.signing.SignedRequest
import id.fatarc.trustgate.domain.signing.VerificationResult
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
import java.security.Signature
import java.time.Duration
import java.time.Instant
import java.util.UUID

class TrustGateViewModel(
    private val securityService: TrustGateSecurityService,
    private val eventRepository: SecurityEventRepository,
    private val secureValueStore: SecureValueStore,
    private val requestSigner: ReferenceRequestSigner,
    private val backend: ReferenceBackend,
    private val keyProvider: DeviceKeyProvider,
    private val keyRegistrar: KeyRegistrar,
    private val transport: ReferenceTransport,
    private val paymentClient: PaymentClient,
    pinningConfig: PinningConfig,
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
) : ViewModel() {
    private val _uiState = MutableStateFlow(
        TrustGateUiState(pinning = pinningConfig),
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
        loadStorageSnapshot(announce = false)
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
                showMessage("Device risk changed: ${previous.level.label()} to ${report.level.label().lowercase()}")
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
        actionJob = viewModelScope.launch {
            val report = reportForSensitiveAction()
                ?: return@launch abandonAction("The device couldn't be checked, so the action didn't run.")
            val keys = ensureKeys()
                ?: return@launch abandonAction("The device key isn't ready, so the action didn't run.")
            val authorization = withContext(ioDispatcher) { backend.beginPayment(keys.device.keyId, report.level) }
            runCatching { securityService.recordGateDecision(report, authorization.decision) }.rethrowCancellation()

            if (authorization !is PaymentAuthorization.Proceed) {
                updateDecision(PaymentDecisionState.Blocked(report.level))
                return@launch
            }
            val keyId = when (authorization.signWith) {
                KeyRole.DEVICE -> keys.device.keyId
                KeyRole.STEP_UP -> keys.stepUp?.keyId
                    ?: return@launch abandonAction("The step-up key isn't registered, so the action didn't run.")
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
                    updateDecision(PaymentDecisionState.Allowed(report.level))
                    val submission = signAndSubmit(pending, keyProvider::signWithDeviceKey)
                    // A profile switch cancels this job; don't publish a result for the old profile.
                    ensureActive()
                    publishSubmission(submission)
                }

                RequiredConfirmation.STEP_UP_KEY -> {
                    pendingPayment = pending
                    updateDecision(PaymentDecisionState.ConfirmationRequired(report.level, ConfirmationMethod.DEVICE_CREDENTIAL))
                }

                RequiredConfirmation.TAP -> {
                    pendingPayment = pending
                    updateDecision(PaymentDecisionState.ConfirmationRequired(report.level, ConfirmationMethod.TAP))
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
            dismissConfirmation("Your screen lock or fingerprints changed, so the confirmation key was reset. Run the action again.")
            null
        } catch (error: Exception) {
            // Keystore reports trouble through several exception types; none should crash the confirmation.
            dismissConfirmation("The confirmation key couldn't be used. Run the action again.")
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
        updateDecision(PaymentDecisionState.Confirmed(decision.riskLevel))
        assessmentJob?.cancel()
        actionJob = viewModelScope.launch {
            // The device may have changed while the person was confirming, so check it again before approving.
            val report = reportForSensitiveAction()
                ?: return@launch abandonAction("The device couldn't be checked, so the action didn't run.")
            if (report.level == DeviceRiskLevel.HIGH) {
                runCatching { securityService.recordBlockedAfterConfirmation(report) }.rethrowCancellation()
                updateDecision(PaymentDecisionState.Blocked(report.level))
                return@launch
            }
            val recorded = runCatching {
                securityService.confirmSensitiveAction(report, method)
            }.rethrowCancellation().isSuccess
            if (!recorded) return@launch abandonAction("The confirmation couldn't be recorded, so the action didn't run.")

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
        updateDecision(PaymentDecisionState.Cancelled(decision.riskLevel, problem))
        if (report != null) {
            viewModelScope.launch {
                runCatching { securityService.cancelSensitiveAction(report) }
            }
        }
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

    /** Signs a request with the device key against a fresh verification challenge, charging nothing. */
    fun signReferenceRequest() {
        viewModelScope.launch {
            val keys = ensureKeys() ?: return@launch failSigning("The device key isn't ready.")
            runCatching {
                withContext(ioDispatcher) {
                    val nonce = backend.issueVerificationChallenge(keys.device.keyId)
                    val prepared = requestSigner.prepare(
                        payload = ReferencePayment.payload(),
                        nonce = nonce,
                        keyId = keys.device.keyId,
                        timestamp = Instant.now().toString(),
                    )
                    prepared.signedWith(keyProvider.signWithDeviceKey(prepared.signingInput))
                }
            }.rethrowCancellation()
                .onSuccess { publishSigned(it, forProtectedAction = false) }
                .onFailure { failSigning(it.message ?: "The reference request couldn't be signed.") }
        }
    }

    /** Sends the latest signed request to the reference backend, honestly or deliberately altered. */
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
                // Arrives just past the window the backend allows, as a delayed or captured request would.
                VerificationAttempt.DELIVERED_LATE ->
                    request.asReceived() to now.plus(ReferenceBackend.ALLOWED_CLOCK_SKEW).plus(LATE_DELIVERY_MARGIN)
            }
            val result = withContext(ioDispatcher) { backend.authenticate(received, receivedAt) }
            addVerificationRecord(request, VerificationRecord(attempt, result, at = Instant.now()))
            runCatching { securityService.recordVerification(request, result, attempt.metadataValue) }.rethrowCancellation()
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
                withStorage {
                    secureValueStore.storeSessionToken("tg-session-${UUID.randomUUID().toString().take(8)}")
                    report?.let { secureValueStore.storeLastRiskLevel(it.level) }
                    secureValueStore.storeShowSignalsOnHome(showSignalsOnHome)
                    secureValueStore.readSnapshot()
                }
            }.rethrowCancellation().onSuccess { snapshot ->
                val storedKeys = buildList {
                    add(SecureValueNames.SESSION_TOKEN)
                    if (report != null) add(SecureValueNames.LAST_RISK_LEVEL)
                    add(SecureValueNames.SHOW_SIGNALS_ON_HOME)
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
                withStorage { secureValueStore.storeShowSignalsOnHome(enabled) }
            }.rethrowCancellation().onFailure { error ->
                // Show what is actually stored rather than guessing at the previous value.
                val stored = runCatching { withStorage { secureValueStore.readSnapshot() } }.getOrNull()
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
            applyRiskFailure(error.message ?: "The device check couldn't finish.")
        }.getOrNull()
    }

    private fun loadStorageSnapshot(announce: Boolean) {
        viewModelScope.launch {
            runCatching {
                withStorage { secureValueStore.readSnapshot() }
            }.rethrowCancellation().onSuccess { snapshot ->
                applyStorageSnapshot(snapshot)
                when {
                    snapshot.unreadableValuesCleared > 0 -> showMessage(
                        "${snapshot.unreadableValuesCleared} stored values couldn't be decrypted on this device and were cleared",
                    )
                    announce -> showMessage("Reloaded from encrypted storage")
                }
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

    private fun updateDecision(decision: PaymentDecisionState) {
        _uiState.update { current ->
            current.copy(payment = PaymentUiState(latestDecision = decision, decidedAt = Instant.now()))
        }
    }

    /** Adds what happened to the payment to the decision that let it through, unless that was reset meanwhile. */
    private fun publishSubmission(submission: Submission) {
        _uiState.update { current ->
            if (current.payment.isSending) current.copy(payment = current.payment.copy(submission = submission)) else current
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
                    current.copy(keys = current.keys.copy(errorMessage = error.message ?: "The device key couldn't be prepared."))
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
            paymentClient.submit(signed.asReceived()).also { outcome ->
                runCatching { securityService.recordPayment(signed, outcome) }
            }
        }

        return when (val response = outcome.response) {
            null -> Submission.NoResponse(outcome.attempts)
            is PaymentResponse.Rejected -> {
                addVerificationRecord(signed, sentByProtectedAction(VerificationResult.Rejected(response.reason), outcome.lostResponses))
                Submission.Refused(response.reason)
            }

            is PaymentResponse.Processed -> {
                addVerificationRecord(signed, sentByProtectedAction(VerificationResult.Accepted, outcome.lostResponses))
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
        _uiState.update { current ->
            current.copy(
                signing = SigningUiState(
                    signedRequest = signed,
                    status = SigningStatus.Signed(signed.payload.merchantReference),
                ),
            )
        }
        runCatching { securityService.recordSignedRequest(signed, forProtectedAction) }.rethrowCancellation()
    }

    private fun failSigning(message: String) {
        _uiState.update { current ->
            current.copy(signing = current.signing.copy(status = SigningStatus.Failed(message)))
        }
    }

    private fun sentByProtectedAction(result: VerificationResult, lostResponses: Int) = VerificationRecord(
        attempt = VerificationAttempt.AS_SIGNED,
        result = result,
        at = Instant.now(),
        sentByProtectedAction = true,
        lostResponses = lostResponses,
    )

    /** Lists [record] under [request], unless another request was signed since and replaced it. */
    private fun addVerificationRecord(request: SignedRequest, record: VerificationRecord) {
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
    }

    /** Clears any earlier result so it can't be mistaken for this attempt's, and says why nothing ran. */
    private fun abandonAction(message: String) {
        pendingPayment = null
        _uiState.update { current -> current.copy(payment = PaymentUiState()) }
        showMessage(message)
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
            backend = container.backend,
            keyProvider = container.keyProvider,
            keyRegistrar = container.keyRegistrar,
            transport = container.transport,
            paymentClient = container.paymentClient,
            pinningConfig = container.pinningConfig,
        ) as T
    }
}
