package id.fatarc.trustgate

import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.getValue
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.viewmodel.compose.viewModel
import id.fatarc.trustgate.ui.TrustGateApp
import id.fatarc.trustgate.ui.TrustGateViewModel
import id.fatarc.trustgate.ui.TrustGateViewModelFactory
import id.fatarc.trustgate.ui.theme.TrustGateTheme
import kotlinx.coroutines.launch

// A FragmentActivity so the system biometric prompt can host itself for step-up confirmation.
class MainActivity : FragmentActivity() {
    private val container get() = (application as TrustGateApplication).container

    override fun onStart() {
        super.onStart()
        container.screenRecording.watch(this)
    }

    override fun onStop() {
        container.screenRecording.stop(this)
        super.onStop()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        val appContainer = (application as TrustGateApplication).container
        setContent {
            TrustGateTheme {
                val viewModel: TrustGateViewModel = viewModel(
                    factory = TrustGateViewModelFactory(appContainer),
                )
                val uiState by viewModel.uiState.collectAsStateWithLifecycle()
                TrustGateApp(
                    uiState = uiState,
                    onRefreshRisk = viewModel::refreshRisk,
                    onAttemptPayment = viewModel::attemptPayment,
                    onStepUpSignature = viewModel::stepUpSignatureForPrompt,
                    onStepUpAuthenticated = viewModel::completeStepUp,
                    onConfirmWithTap = viewModel::confirmWithTap,
                    onDismissConfirmation = viewModel::dismissConfirmation,
                    onSetSimulateLostResponse = viewModel::setSimulateLostResponse,
                    onRunLabTest = viewModel::runLabTest,
                    onSetPretendVerdict = viewModel::setPretendVerdict,
                    onRotateKey = viewModel::rotateDeviceKey,
                    onRemovePhone = viewModel::removeThisPhone,
                    onFixWithPlay = { remedy ->
                        lifecycleScope.launch {
                            // Google Play walks the person through it; once fixed, the payment runs again.
                            val fixed = runCatching { appContainer.integrityTokens.showFix(this@MainActivity, remedy) }.getOrDefault(false)
                            if (fixed) viewModel.attemptPayment()
                        }
                    },
                    onStoreReferenceValues = viewModel::storeReferenceValues,
                    onSetScenarioRiskLevel = viewModel::setScenarioRiskLevel,
                    onSetCheckout = viewModel::setCheckout,
                    onClearEvents = viewModel::clearSecurityEvents,
                    onExportEvents = viewModel::buildAuditExport,
                    onAppResumed = viewModel::onAppResumed,
                    onUserMessageShown = viewModel::userMessageShown,
                )
            }
        }
    }
}
