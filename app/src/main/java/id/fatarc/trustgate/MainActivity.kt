package id.fatarc.trustgate

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.getValue
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import id.fatarc.trustgate.ui.TrustGateApp
import id.fatarc.trustgate.ui.TrustGateViewModel
import id.fatarc.trustgate.ui.TrustGateViewModelFactory
import id.fatarc.trustgate.ui.theme.TrustGateTheme

class MainActivity : ComponentActivity() {
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
                    onConfirmPayment = viewModel::confirmPayment,
                    onDismissConfirmation = viewModel::dismissConfirmation,
                    onSignDemoRequest = viewModel::signDemoRequest,
                    onStoreDemoValues = viewModel::storeDemoValues,
                    onRefreshStorage = viewModel::refreshStorage,
                    onToggleShowSignalsOnHome = viewModel::toggleShowSignalsOnHome,
                )
            }
        }
    }
}
