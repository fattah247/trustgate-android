package id.fatarc.trustgate.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import id.fatarc.trustgate.TrustGateAppContainer
import id.fatarc.trustgate.core.crypto.PinningConfig
import id.fatarc.trustgate.core.security.TrustGateSecurityService
import id.fatarc.trustgate.core.storage.SecureValueStore
import id.fatarc.trustgate.domain.actiongate.SensitiveActionDecision
import id.fatarc.trustgate.domain.events.SecurityEvent
import id.fatarc.trustgate.domain.events.SecurityEventRepository
import id.fatarc.trustgate.domain.events.SecurityEventType
import id.fatarc.trustgate.domain.risk.DeviceRiskLevel
import id.fatarc.trustgate.domain.risk.DeviceRiskReport
import id.fatarc.trustgate.domain.risk.scenarioRiskReport
import id.fatarc.trustgate.domain.signing.PaymentRequestPayload
import id.fatarc.trustgate.domain.signing.RequestSigner
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.time.Instant
import java.time.LocalDate
import java.util.UUID

class TrustGateViewModel(
    private val securityService: TrustGateSecurityService,
    private val eventRepository: SecurityEventRepository,
    private val secureValueStore: SecureValueStore,
    private val requestSigner: RequestSigner,
    pinningConfig: PinningConfig,
) : ViewModel() {
    private val _uiState = MutableStateFlow(
        TrustGateUiState(
            pinningSummary = buildPinningSummary(pinningConfig),
        ),
    )
    val uiState: StateFlow<TrustGateUiState> = _uiState.asStateFlow()

    init {
        viewModelScope.launch {
            eventRepository.events.collect { events ->
                _uiState.update { current -> current.copy(securityEvents = events) }
            }
        }
        refreshStorage()
        refreshRisk()
    }

    fun refreshRisk() {
        viewModelScope.launch {
            val selectedScenarioRiskLevel = _uiState.value.payment.selectedScenarioRiskLevel
            _uiState.update { current ->
                current.copy(
                    risk = current.risk.copy(
                        isLoading = true,
                        errorMessage = null,
                    ),
                    payment = current.payment.copy(
                        latestDecision = PaymentDecisionState.Idle,
                    ),
                )
            }

            if (selectedScenarioRiskLevel != null) {
                applyRiskReport(
                    report = scenarioRiskReport(selectedScenarioRiskLevel),
                    source = RiskReportSource.SCENARIO,
                )
                return@launch
            }

            runCatching {
                securityService.assessDeviceRisk()
            }.onSuccess { report ->
                applyRiskReport(report = report, source = RiskReportSource.LIVE)
            }.onFailure { error ->
                applyRiskFailure(error.message ?: "Risk assessment failed.")
            }
        }
    }

    fun attemptPayment() {
        viewModelScope.launch {
            val report = currentReport() ?: return@launch
            val decision = securityService.evaluateSensitiveAction(report)
            _uiState.update { current ->
                current.copy(
                    payment = current.payment.copy(
                        latestDecision = decision.toPaymentDecisionState(report.level),
                    ),
                )
            }
        }
    }

    fun confirmPayment() {
        viewModelScope.launch {
            val report = currentReport() ?: return@launch
            runCatching {
                securityService.confirmSensitiveAction(report)
            }.onSuccess {
                _uiState.update { current ->
                    current.copy(
                        payment = current.payment.copy(
                            latestDecision = PaymentDecisionState.Confirmed(report.level),
                        ),
                    )
                }
            }.onFailure { error ->
                _uiState.update { current ->
                    current.copy(
                        payment = current.payment.copy(
                            latestDecision = PaymentDecisionState.Cancelled(report.level),
                        ),
                        risk = current.risk.copy(
                            errorMessage = error.message ?: "Unable to confirm the action.",
                        ),
                    )
                }
            }
        }
    }

    fun dismissConfirmation() {
        _uiState.update { current ->
            val decision = current.payment.latestDecision
            val nextDecision = if (decision is PaymentDecisionState.ConfirmationRequired) {
                PaymentDecisionState.Cancelled(decision.riskLevel)
            } else {
                decision
            }
            current.copy(
                payment = current.payment.copy(latestDecision = nextDecision),
            )
        }
    }

    fun setScenarioRiskLevel(level: DeviceRiskLevel?) {
        viewModelScope.launch {
            _uiState.update { current ->
                current.copy(
                    payment = current.payment.copy(
                        selectedScenarioRiskLevel = level,
                        latestDecision = PaymentDecisionState.Idle,
                    ),
                    risk = current.risk.copy(errorMessage = null),
                )
            }
            if (level == null) {
                refreshRisk()
                return@launch
            }

            val report = scenarioRiskReport(level)
            eventRepository.record(
                SecurityEvent(
                    type = SecurityEventType.DEVICE_RISK_ASSESSED,
                    riskLevel = report.level,
                    message = "Scenario risk state set to ${report.level.name}.",
                    metadata = mapOf("source" to "scenario-selector"),
                ),
            )
            applyRiskReport(report = report, source = RiskReportSource.SCENARIO)
        }
    }

    fun signReferenceRequest() {
        viewModelScope.launch {
            runCatching {
                val payload = PaymentRequestPayload(
                    amountMinor = 125_000,
                    currency = "IDR",
                    merchantReference = "TG-${LocalDate.now()}",
                )
                requestSigner.sign(
                    payload = payload,
                    timestamp = Instant.now().toString(),
                    nonce = UUID.randomUUID().toString().replace("-", "").take(16),
                )
            }.onSuccess { signedRequest ->
                securityService.recordSignedRequest(signedRequest)
                _uiState.update { current ->
                    current.copy(
                        signing = current.signing.copy(
                            signedRequest = signedRequest,
                            status = SigningStatus.Signed(signedRequest.payload.merchantReference),
                        ),
                    )
                }
            }.onFailure { error ->
                _uiState.update { current ->
                    current.copy(
                        signing = current.signing.copy(
                            status = SigningStatus.Failed(
                                error.message ?: "Unable to sign the reference request.",
                            ),
                        ),
                    )
                }
            }
        }
    }

    fun storeReferenceValues() {
        viewModelScope.launch {
            runCatching {
                val report = currentReport()
                secureValueStore.storeSessionToken("tg-session-${UUID.randomUUID().toString().take(8)}")
                report?.let { secureValueStore.storeLastRiskLevel(it.level) }
                secureValueStore.storeShowSignalsOnHome(_uiState.value.storage.snapshot.showSignalsOnHome)
            }.onSuccess {
                val storedKeys = listOf(
                    "session_token",
                    "last_risk_level",
                    "show_signals_on_home",
                )
                securityService.recordSecureValueStored(keys = storedKeys)
                loadStorageSnapshot(StorageStatus.Stored(storedKeys.size))
            }.onFailure { error ->
                updateStorageFailure(error.message ?: "Unable to write encrypted values.")
            }
        }
    }

    fun refreshStorage() {
        loadStorageSnapshot(StorageStatus.Loaded)
    }

    fun toggleShowSignalsOnHome(enabled: Boolean) {
        viewModelScope.launch {
            runCatching {
                secureValueStore.storeShowSignalsOnHome(enabled)
            }.onSuccess {
                loadStorageSnapshot(StorageStatus.PreferenceUpdated(enabled))
            }.onFailure { error ->
                updateStorageFailure(error.message ?: "Unable to update the display preference.")
            }
        }
    }

    private fun loadStorageSnapshot(status: StorageStatus) {
        viewModelScope.launch {
            runCatching {
                secureValueStore.readSnapshot()
            }.onSuccess { snapshot ->
                _uiState.update { current ->
                    current.copy(
                        storage = current.storage.copy(
                            snapshot = snapshot,
                            status = status,
                        ),
                    )
                }
            }.onFailure { error ->
                updateStorageFailure(error.message ?: "Encrypted storage is unavailable.")
            }
        }
    }

    private suspend fun currentReport(): DeviceRiskReport? {
        _uiState.value.risk.report?.let { return it }

        val selectedScenarioRiskLevel = _uiState.value.payment.selectedScenarioRiskLevel
        if (selectedScenarioRiskLevel != null) {
            val report = scenarioRiskReport(selectedScenarioRiskLevel)
            applyRiskReport(report = report, source = RiskReportSource.SCENARIO)
            return report
        }

        return runCatching {
            securityService.assessDeviceRisk()
        }.onSuccess { report ->
            applyRiskReport(report = report, source = RiskReportSource.LIVE)
        }.onFailure { error ->
            applyRiskFailure(error.message ?: "Risk assessment failed.")
        }.getOrNull()
    }

    private fun applyRiskReport(
        report: DeviceRiskReport,
        source: RiskReportSource,
    ) {
        _uiState.update { current ->
            current.copy(
                risk = current.risk.copy(
                    report = report,
                    source = source,
                    isLoading = false,
                    errorMessage = null,
                ),
                payment = current.payment.copy(
                    latestDecision = PaymentDecisionState.Idle,
                ),
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

    private fun updateStorageFailure(message: String) {
        _uiState.update { current ->
            current.copy(
                storage = current.storage.copy(
                    status = StorageStatus.Failed(message),
                ),
            )
        }
    }

    private fun SensitiveActionDecision.toPaymentDecisionState(
        riskLevel: DeviceRiskLevel,
    ): PaymentDecisionState = when (this) {
        SensitiveActionDecision.ALLOW -> PaymentDecisionState.Allowed(riskLevel)
        SensitiveActionDecision.REQUIRE_CONFIRMATION -> PaymentDecisionState.ConfirmationRequired(riskLevel)
        SensitiveActionDecision.BLOCK -> PaymentDecisionState.Blocked(riskLevel)
    }

    private fun buildPinningSummary(config: PinningConfig): String {
        return if (config.enabled) {
            "Certificate pinning is enabled for ${config.host}. Real deployments still need rotation planning."
        } else {
            "Certificate pinning is implemented for ${config.host}, but disabled by default so this build remains usable without a pinned endpoint."
        }
    }
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
            pinningConfig = container.pinningConfig,
        ) as T
    }
}
