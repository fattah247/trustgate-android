package id.fatarc.trustgate.ui

import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Payment
import androidx.compose.material.icons.filled.Security
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.dp
import androidx.navigation.NavDestination.Companion.hierarchy
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import id.fatarc.trustgate.domain.risk.DeviceRiskLevel
import id.fatarc.trustgate.ui.about.AboutScreen
import id.fatarc.trustgate.ui.events.SecurityEventLogScreen
import id.fatarc.trustgate.ui.home.HomeScreen
import id.fatarc.trustgate.ui.payment.PaymentActionScreen
import id.fatarc.trustgate.ui.risk.DeviceRiskDetailsScreen
import id.fatarc.trustgate.ui.signing.RequestSigningScreen
import id.fatarc.trustgate.ui.storage.SecureStorageScreen

private enum class TrustGateScreen(val route: String, val title: String) {
    Home("home", "TrustGate"),
    Risk("risk", "Risk Signals"),
    Payment("payment", "Sensitive Action Gate"),
    Signing("signing", "Request Signing"),
    Storage("storage", "Secure Storage"),
    Events("events", "Security Event Log"),
    About("about", "Scope and Limits"),
}

private data class TopLevelDestination(
    val screen: TrustGateScreen,
    val label: String,
    val icon: ImageVector,
)

private val TopLevelDestinations = listOf(
    TopLevelDestination(TrustGateScreen.Home, "Overview", Icons.Filled.Home),
    TopLevelDestination(TrustGateScreen.Risk, "Signals", Icons.Filled.Security),
    TopLevelDestination(TrustGateScreen.Payment, "Gate", Icons.Filled.Payment),
    TopLevelDestination(TrustGateScreen.Events, "Log", Icons.Filled.History),
    TopLevelDestination(TrustGateScreen.About, "Info", Icons.Filled.Info),
)

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
    onSetDemoRiskLevel: (DeviceRiskLevel?) -> Unit,
) {
    val navController = rememberNavController()
    val backStackEntry by navController.currentBackStackEntryAsState()
    val currentDestination = backStackEntry?.destination
    val currentScreen = TrustGateScreen.entries.firstOrNull { screen ->
        currentDestination?.hierarchy?.any { it.route == screen.route } == true
    } ?: TrustGateScreen.Home
    val selectedTopLevelScreen = currentScreen.asTopLevelScreen()

    TrustGateBackdrop {
        Scaffold(
            containerColor = Color.Transparent,
            contentColor = MaterialTheme.colorScheme.onSurface,
            topBar = {
                TopAppBar(
                    colors = TopAppBarDefaults.topAppBarColors(
                        containerColor = MaterialTheme.colorScheme.background.copy(alpha = 0.72f),
                        scrolledContainerColor = MaterialTheme.colorScheme.background.copy(alpha = 0.86f),
                        titleContentColor = androidx.compose.material3.MaterialTheme.colorScheme.onBackground,
                    ),
                    title = { Text(currentScreen.title) },
                    navigationIcon = {
                        if (currentScreen != selectedTopLevelScreen) {
                            IconButton(onClick = { navController.popBackStack() }) {
                                Icon(
                                    imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                                    contentDescription = "Back",
                                    tint = MaterialTheme.colorScheme.onBackground,
                                )
                            }
                        }
                    },
                )
            },
            bottomBar = {
                NavigationBar(
                    containerColor = MaterialTheme.colorScheme.surface.copy(alpha = 0.82f),
                    contentColor = MaterialTheme.colorScheme.onSurface,
                    tonalElevation = 0.dp,
                ) {
                    TopLevelDestinations.forEach { destination ->
                        val selected = currentScreen == destination.screen
                        NavigationBarItem(
                            selected = selected,
                            onClick = {
                                navController.navigate(destination.screen.route) {
                                    popUpTo(navController.graph.findStartDestination().id) {
                                        saveState = true
                                    }
                                    launchSingleTop = true
                                    restoreState = currentScreen == selectedTopLevelScreen
                                }
                            },
                            icon = {
                                Icon(
                                    imageVector = destination.icon,
                                    contentDescription = null,
                                )
                            },
                            label = { Text(destination.label) },
                            colors = NavigationBarItemDefaults.colors(
                                selectedIconColor = MaterialTheme.colorScheme.primary,
                                selectedTextColor = MaterialTheme.colorScheme.primary,
                                indicatorColor = MaterialTheme.colorScheme.primary.copy(alpha = 0.14f),
                                unselectedIconColor = MaterialTheme.colorScheme.onSurfaceVariant,
                                unselectedTextColor = MaterialTheme.colorScheme.onSurfaceVariant,
                            ),
                        )
                    }
                }
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
                        onOpenSigningDemo = { navController.navigate(TrustGateScreen.Signing.route) },
                        onOpenStorageDemo = { navController.navigate(TrustGateScreen.Storage.route) },
                        onOpenEvents = { navController.navigate(TrustGateScreen.Events.route) },
                    )
                }
                composable(TrustGateScreen.Risk.route) {
                    DeviceRiskDetailsScreen(uiState = uiState)
                }
                composable(TrustGateScreen.Payment.route) {
                    PaymentActionScreen(
                        uiState = uiState,
                        onAttemptPayment = onAttemptPayment,
                        onSetDemoRiskLevel = onSetDemoRiskLevel,
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
    }

    if (uiState.payment.latestDecision is PaymentDecisionState.ConfirmationRequired) {
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

private fun TrustGateScreen.asTopLevelScreen(): TrustGateScreen = when (this) {
    TrustGateScreen.Signing,
    TrustGateScreen.Storage,
    -> TrustGateScreen.Payment

    else -> this
}
