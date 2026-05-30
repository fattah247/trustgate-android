package id.fatarc.trustgate.ui

import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.IconButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.navigation.NavDestination.Companion.hierarchy
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import id.fatarc.trustgate.ui.about.AboutScreen
import id.fatarc.trustgate.ui.events.SecurityEventLogScreen
import id.fatarc.trustgate.ui.home.HomeScreen
import id.fatarc.trustgate.ui.payment.PaymentActionScreen
import id.fatarc.trustgate.ui.risk.DeviceRiskDetailsScreen
import id.fatarc.trustgate.ui.signing.RequestSigningScreen
import id.fatarc.trustgate.ui.storage.SecureStorageScreen

private enum class TrustGateScreen(val route: String, val title: String) {
    Home("home", "Trust Overview"),
    Risk("risk", "Device Risk Details"),
    Payment("payment", "Payment Action Demo"),
    Signing("signing", "Request Signing Demo"),
    Storage("storage", "Secure Storage Demo"),
    Events("events", "Security Event Log"),
    About("about", "About and Limitations"),
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TrustGateApp(
    uiState: TrustGateUiState,
    onRefreshRisk: () -> Unit,
    onAttemptPayment: () -> Unit,
    onConfirmPayment: () -> Unit,
    onDismissConfirmation: () -> Unit,
    onSignDemoRequest: () -> Unit,
    onStoreDemoValues: () -> Unit,
    onRefreshStorage: () -> Unit,
    onToggleShowSignalsOnHome: (Boolean) -> Unit,
) {
    val navController = rememberNavController()
    val backStackEntry by navController.currentBackStackEntryAsState()
    val currentDestination = backStackEntry?.destination
    val currentScreen = TrustGateScreen.entries.firstOrNull { screen ->
        currentDestination?.hierarchy?.any { it.route == screen.route } == true
    } ?: TrustGateScreen.Home

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(currentScreen.title) },
                navigationIcon = {
                    if (currentScreen != TrustGateScreen.Home) {
                        IconButton(onClick = { navController.popBackStack() }) {
                            Text("<")
                        }
                    }
                },
            )
        },
    ) { innerPadding ->
        NavHost(
            navController = navController,
            startDestination = TrustGateScreen.Home.route,
            modifier = Modifier.padding(innerPadding),
        ) {
            composable(TrustGateScreen.Home.route) {
                HomeScreen(
                    uiState = uiState,
                    onRefreshRisk = onRefreshRisk,
                    onOpenRiskDetails = { navController.navigate(TrustGateScreen.Risk.route) },
                    onOpenPaymentDemo = { navController.navigate(TrustGateScreen.Payment.route) },
                    onOpenSigningDemo = { navController.navigate(TrustGateScreen.Signing.route) },
                    onOpenStorageDemo = { navController.navigate(TrustGateScreen.Storage.route) },
                    onOpenEvents = { navController.navigate(TrustGateScreen.Events.route) },
                    onOpenAbout = { navController.navigate(TrustGateScreen.About.route) },
                )
            }
            composable(TrustGateScreen.Risk.route) {
                DeviceRiskDetailsScreen(uiState = uiState)
            }
            composable(TrustGateScreen.Payment.route) {
                PaymentActionScreen(
                    uiState = uiState,
                    onAttemptPayment = onAttemptPayment,
                )
            }
            composable(TrustGateScreen.Signing.route) {
                RequestSigningScreen(
                    uiState = uiState,
                    onSignDemoRequest = onSignDemoRequest,
                )
            }
            composable(TrustGateScreen.Storage.route) {
                SecureStorageScreen(
                    uiState = uiState,
                    onStoreDemoValues = onStoreDemoValues,
                    onRefreshStorage = onRefreshStorage,
                    onToggleShowSignalsOnHome = onToggleShowSignalsOnHome,
                )
            }
            composable(TrustGateScreen.Events.route) {
                SecurityEventLogScreen(uiState = uiState)
            }
            composable(TrustGateScreen.About.route) {
                AboutScreen(uiState = uiState)
            }
        }
    }

    if (uiState.isConfirmationRequired) {
        AlertDialog(
            onDismissRequest = onDismissConfirmation,
            title = { Text("Confirm medium-risk action") },
            text = {
                Text("The app treats this device state as medium risk. Continue only for this demo action.")
            },
            confirmButton = {
                TextButton(onClick = onConfirmPayment) {
                    Text("Continue")
                }
            },
            dismissButton = {
                TextButton(onClick = onDismissConfirmation) {
                    Text("Cancel")
                }
            },
        )
    }
}
