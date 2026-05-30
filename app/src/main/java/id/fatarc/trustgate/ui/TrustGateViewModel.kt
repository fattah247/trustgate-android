package id.fatarc.trustgate.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import id.fatarc.trustgate.TrustGateAppContainer
import id.fatarc.trustgate.core.crypto.PinningConfig
import id.fatarc.trustgate.core.security.TrustGateSecurityService
import id.fatarc.trustgate.core.storage.SecureValueStore
import id.fatarc.trustgate.domain.actiongate.SensitiveActionDecision
import id.fatarc.trustgate.domain.events.SecurityEventRepository
import id.fatarc.trustgate.domain.risk.DeviceRiskReport
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
                _uiState.update { current ->
                    current.copy(securityEvents = events)
                }
            }
        }
        refreshStorage()
        refreshRisk()
    }

    fun refreshRisk() {
        viewModelScope.launch {
            _uiState.update {
                it.copy(
                    isAssessingRisk = true,
                    errorMessage = null,
                )
            }
            runCatching {
                securityService.assessDeviceRisk()
            }.onSuccess { report ->
                _uiState.update { current ->
                    current.copy(
                        riskReport = report,
                        isAssessingRisk = false,
                        errorMessage = null,
                    )
                }
            }.onFailure { error ->
                _uiState.update { current ->
                    current.copy(
                        isAssessingRisk = false,
                        errorMessage = error.message ?: "Risk assessment failed.",
                    )
                }
            }
        }
    }

    fun attemptPayment() {
        viewModelScope.launch {
            val report = currentReport() ?: return@launch
            when (securityService.evaluateSensitiveAction(report)) {
                SensitiveActionDecision.ALLOW -> {
                    _uiState.update { current ->
                        current.copy(
                            actionMessage = "Payment-like action allowed for the current device state.",
                            isConfirmationRequired = false,
                        )
                    }
                }

                SensitiveActionDecision.REQUIRE_CONFIRMATION -> {
                    _uiState.update { current ->
                        current.copy(
                            actionMessage = "Medium-risk state detected. Confirm to continue.",
                            isConfirmationRequired = true,
                        )
                    }
                }

                SensitiveActionDecision.BLOCK -> {
                    _uiState.update { current ->
                        current.copy(
                            actionMessage = "Payment-like action blocked because the device is high risk.",
                            isConfirmationRequired = false,
                        )
                    }
                }
            }
        }
    }

    fun confirmPayment() {
        viewModelScope.launch {
            val report = currentReport() ?: return@launch
            securityService.confirmSensitiveAction(report)
            _uiState.update { current ->
                current.copy(
                    actionMessage = "Payment-like action allowed after explicit confirmation.",
                    isConfirmationRequired = false,
                )
            }
        }
    }

    fun dismissConfirmation() {
        _uiState.update { current ->
            current.copy(isConfirmationRequired = false)
        }
    }

    fun signDemoRequest() {
        viewModelScope.launch {
            val payload = PaymentRequestPayload(
                amountMinor = 125_000,
                currency = "IDR",
                merchantReference = "TG-${LocalDate.now()}",
            )
            val signedRequest = requestSigner.sign(
                payload = payload,
                timestamp = Instant.now().toString(),
                nonce = UUID.randomUUID().toString().replace("-", "").take(16),
            )
            securityService.recordSignedRequest(signedRequest)
            _uiState.update { current ->
                current.copy(
                    signedRequest = signedRequest,
                    signingMessage = "Signed a demo request with deterministic canonicalization and HMAC-SHA256.",
                )
            }
        }
    }

    fun storeDemoValues() {
        viewModelScope.launch {
            val report = currentReport()
            secureValueStore.storeSessionToken("demo-session-${UUID.randomUUID().toString().take(8)}")
            report?.let { secureValueStore.storeLastRiskLevel(it.level) }
            secureValueStore.storeShowSignalsOnHome(_uiState.value.storageSnapshot.showSignalsOnHome)
            securityService.recordSecureValueStored(
                keys = listOf(
                    "session_token",
                    "last_risk_level",
                    "show_signals_on_home",
                ),
            )
            loadStorageSnapshot("Stored demo values in encrypted local storage.")
        }
    }

    fun refreshStorage() {
        loadStorageSnapshot("Loaded encrypted local values.")
    }

    fun toggleShowSignalsOnHome(enabled: Boolean) {
        viewModelScope.launch {
            secureValueStore.storeShowSignalsOnHome(enabled)
            loadStorageSnapshot("Updated local display preference.")
        }
    }

    private fun loadStorageSnapshot(message: String) {
        viewModelScope.launch {
            runCatching {
                secureValueStore.readSnapshot()
            }.onSuccess { snapshot ->
                _uiState.update { current ->
                    current.copy(
                        storageSnapshot = snapshot,
                        storageMessage = message,
                        errorMessage = null,
                    )
                }
            }.onFailure { error ->
                _uiState.update { current ->
                    current.copy(
                        errorMessage = error.message ?: "Encrypted storage is unavailable.",
                    )
                }
            }
        }
    }

    private suspend fun currentReport(): DeviceRiskReport? {
        return _uiState.value.riskReport ?: securityService.assessDeviceRisk().also { report ->
            _uiState.update { current ->
                current.copy(
                    riskReport = report,
                    isAssessingRisk = false,
                )
            }
        }
    }

    private fun buildPinningSummary(config: PinningConfig): String {
        return if (config.enabled) {
            "Certificate pinning is enabled for ${config.host}. Real deployments still need rotation planning."
        } else {
            "Certificate pinning is implemented as an example for ${config.host}, but disabled by default so the demo app stays usable."
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

