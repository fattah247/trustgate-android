package id.fatarc.trustgate.ui

import androidx.compose.animation.AnimatedContentTransitionScope
import androidx.compose.animation.AnimatedContentTransitionScope.SlideDirection
import androidx.compose.animation.EnterTransition
import androidx.compose.animation.ExitTransition
import androidx.compose.animation.core.CubicBezierEasing
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.consumeWindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Radar
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.outlined.History
import androidx.compose.material.icons.outlined.Home
import androidx.compose.material.icons.outlined.Radar
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationRail
import androidx.compose.material3.NavigationRailItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.LifecycleResumeEffect
import androidx.lifecycle.compose.dropUnlessResumed
import androidx.navigation.NavBackStackEntry
import androidx.navigation.NavDestination.Companion.hierarchy
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.NavHostController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.navigation
import androidx.navigation.compose.rememberNavController
import id.fatarc.trustgate.core.security.ConfirmationMethod
import id.fatarc.trustgate.domain.risk.DeviceRiskLevel
import id.fatarc.trustgate.ui.about.AboutScreen
import id.fatarc.trustgate.ui.events.SecurityEventLogScreen
import id.fatarc.trustgate.ui.gate.GateHubScreen
import id.fatarc.trustgate.ui.home.HomeScreen
import id.fatarc.trustgate.ui.payment.PaymentActionScreen
import id.fatarc.trustgate.ui.payment.StepUpConfirmation
import id.fatarc.trustgate.ui.risk.DeviceRiskDetailsScreen
import id.fatarc.trustgate.ui.signing.RequestSigningScreen
import id.fatarc.trustgate.ui.storage.SecureStorageScreen

private object Routes {
    const val OVERVIEW = "overview"
    const val ABOUT = "overview/about"
    const val SIGNALS = "signals"
    const val GATE = "gate"
    const val SENSITIVE_ACTION = "gate/sensitive-action"
    const val SIGNING = "gate/signing"
    const val STORAGE = "gate/storage"
    const val GATE_SIGNALS = "gate/signals"
    const val ACTIVITY = "activity"
}

/** Each tab owns a nested graph so its back stack survives switching tabs. */
private enum class Tab(
    val graphRoute: String,
    val startRoute: String,
    val label: String,
    val selectedIcon: ImageVector,
    val unselectedIcon: ImageVector,
) {
    Overview("overview-tab", Routes.OVERVIEW, "Overview", Icons.Filled.Home, Icons.Outlined.Home),
    Signals("signals-tab", Routes.SIGNALS, "Signals", Icons.Filled.Radar, Icons.Outlined.Radar),
    Gate("gate-tab", Routes.GATE, "Gate", Icons.Filled.Shield, Icons.Outlined.Shield),
    Activity("activity-tab", Routes.ACTIVITY, "Activity", Icons.Filled.History, Icons.Outlined.History),
}

@Composable
fun TrustGateApp(
    uiState: TrustGateUiState,
    onRefreshRisk: () -> Unit,
    onAttemptPayment: () -> Unit,
    onConfirmPayment: (ConfirmationMethod) -> Unit,
    onDismissConfirmation: (problem: String?) -> Unit,
    onSignReferenceRequest: () -> Unit,
    onStoreReferenceValues: () -> Unit,
    onRefreshStorage: () -> Unit,
    onToggleShowSignalsOnHome: (Boolean) -> Unit,
    onSetScenarioRiskLevel: (DeviceRiskLevel?) -> Unit,
    onClearEvents: () -> Unit,
    onVerifyRequest: (VerificationAttempt) -> Unit,
    onExportEvents: () -> String,
    onAppResumed: () -> Unit,
    onUserMessageShown: (Long) -> Unit,
) {
    val navController = rememberNavController()
    val backStackEntry by navController.currentBackStackEntryAsState()
    val selectedTab = backStackEntry?.tab() ?: Tab.Overview
    val snackbarHostState = remember { SnackbarHostState() }

    uiState.userMessage?.let { message ->
        LaunchedEffect(message.id) {
            snackbarHostState.showSnackbar(message.text)
            onUserMessageShown(message.id)
        }
    }

    // Coming back to the app re-checks a stale verdict so nothing old is presented as current.
    LifecycleResumeEffect(Unit) {
        onAppResumed()
        onPauseOrDispose { }
    }

    val selectTab: (Tab) -> Unit = { tab ->
        if (tab == selectedTab) {
            // Re-selecting the current tab returns to its first screen.
            navController.popBackStack(tab.startRoute, inclusive = false)
        } else {
            navController.navigateToTab(tab)
        }
    }
    val resumeLiveChecks: () -> Unit = { onSetScenarioRiskLevel(null) }

    CompositionLocalProvider(LocalSnackbarHostState provides snackbarHostState) {
        Surface(
            modifier = Modifier.fillMaxSize(),
            color = MaterialTheme.colorScheme.background,
        ) {
            BoxWithConstraints(modifier = Modifier.fillMaxSize()) {
                val useRail = maxWidth >= 600.dp
                Row(modifier = Modifier.fillMaxSize()) {
                    if (useRail) {
                        NavigationRail(
                            windowInsets = WindowInsets.safeDrawing.only(WindowInsetsSides.Vertical + WindowInsetsSides.Start),
                        ) {
                            Tab.entries.forEach { tab ->
                                val selected = tab == selectedTab
                                NavigationRailItem(
                                    selected = selected,
                                    onClick = { selectTab(tab) },
                                    icon = { Icon(tab.icon(selected), contentDescription = null) },
                                    label = { Text(tab.label) },
                                )
                            }
                        }
                    }
                    Scaffold(
                        modifier = if (useRail) {
                            Modifier.consumeWindowInsets(WindowInsets.safeDrawing.only(WindowInsetsSides.Start))
                        } else {
                            Modifier
                        },
                        containerColor = MaterialTheme.colorScheme.background,
                        contentWindowInsets = WindowInsets(0, 0, 0, 0),
                        snackbarHost = {
                            SnackbarHost(
                                hostState = snackbarHostState,
                                modifier = if (useRail) Modifier.navigationBarsPadding() else Modifier,
                            )
                        },
                        bottomBar = {
                            if (!useRail) {
                                NavigationBar {
                                    Tab.entries.forEach { tab ->
                                        val selected = tab == selectedTab
                                        NavigationBarItem(
                                            selected = selected,
                                            onClick = { selectTab(tab) },
                                            icon = { Icon(tab.icon(selected), contentDescription = null) },
                                            label = { Text(tab.label) },
                                        )
                                    }
                                }
                            }
                        },
                    ) { innerPadding ->
                        NavHost(
                            navController = navController,
                            startDestination = Tab.Overview.graphRoute,
                            modifier = Modifier
                                .padding(innerPadding)
                                .consumeWindowInsets(innerPadding),
                            enterTransition = { if (isTabSwitch()) FadeThroughIn else pushEnter(SlideDirection.Start) },
                            exitTransition = { if (isTabSwitch()) FadeThroughOut else pushExit(SlideDirection.Start) },
                            popEnterTransition = { if (isTabSwitch()) FadeThroughIn else pushEnter(SlideDirection.End) },
                            popExitTransition = { if (isTabSwitch()) FadeThroughOut else pushExit(SlideDirection.End) },
                        ) {
                            navigation(startDestination = Routes.OVERVIEW, route = Tab.Overview.graphRoute) {
                                composable(Routes.OVERVIEW) {
                                    HomeScreen(
                                        uiState = uiState,
                                        onRefreshRisk = onRefreshRisk,
                                        onResumeLiveChecks = resumeLiveChecks,
                                        onOpenSignals = dropUnlessResumed { navController.navigateToTab(Tab.Signals) },
                                        onOpenActivity = dropUnlessResumed { navController.navigateToTab(Tab.Activity) },
                                        onOpenAbout = dropUnlessResumed { navController.navigate(Routes.ABOUT) },
                                    )
                                }
                                composable(Routes.ABOUT) {
                                    AboutScreen(
                                        uiState = uiState,
                                        onNavigateUp = dropUnlessResumed { navController.navigateUp() },
                                    )
                                }
                            }
                            navigation(startDestination = Routes.SIGNALS, route = Tab.Signals.graphRoute) {
                                composable(Routes.SIGNALS) {
                                    DeviceRiskDetailsScreen(
                                        uiState = uiState,
                                        onRefreshRisk = onRefreshRisk,
                                        onResumeLiveChecks = resumeLiveChecks,
                                    )
                                }
                            }
                            navigation(startDestination = Routes.GATE, route = Tab.Gate.graphRoute) {
                                composable(Routes.GATE) {
                                    GateHubScreen(
                                        uiState = uiState,
                                        onResumeLiveChecks = resumeLiveChecks,
                                        onOpenPaymentAction = dropUnlessResumed { navController.navigate(Routes.SENSITIVE_ACTION) },
                                        onOpenSigning = dropUnlessResumed { navController.navigate(Routes.SIGNING) },
                                        onOpenStorage = dropUnlessResumed { navController.navigate(Routes.STORAGE) },
                                    )
                                }
                                composable(Routes.SENSITIVE_ACTION) {
                                    PaymentActionScreen(
                                        uiState = uiState,
                                        onNavigateUp = dropUnlessResumed { navController.navigateUp() },
                                        onAttemptPayment = onAttemptPayment,
                                        onSetScenarioRiskLevel = onSetScenarioRiskLevel,
                                        // Pushed within Gate so back returns to the action, not Overview.
                                        onOpenSignals = dropUnlessResumed { navController.navigate(Routes.GATE_SIGNALS) },
                                        onInspectRequest = dropUnlessResumed { navController.navigate(Routes.SIGNING) },
                                    )
                                }
                                composable(Routes.GATE_SIGNALS) {
                                    DeviceRiskDetailsScreen(
                                        uiState = uiState,
                                        onRefreshRisk = onRefreshRisk,
                                        onResumeLiveChecks = resumeLiveChecks,
                                        onNavigateUp = dropUnlessResumed { navController.navigateUp() },
                                    )
                                }
                                composable(Routes.SIGNING) {
                                    RequestSigningScreen(
                                        uiState = uiState,
                                        onNavigateUp = dropUnlessResumed { navController.navigateUp() },
                                        onSignReferenceRequest = onSignReferenceRequest,
                                        onVerifyRequest = onVerifyRequest,
                                    )
                                }
                                composable(Routes.STORAGE) {
                                    SecureStorageScreen(
                                        uiState = uiState,
                                        onNavigateUp = dropUnlessResumed { navController.navigateUp() },
                                        onStoreReferenceValues = onStoreReferenceValues,
                                        onRefreshStorage = onRefreshStorage,
                                        onToggleShowSignalsOnHome = onToggleShowSignalsOnHome,
                                    )
                                }
                            }
                            navigation(startDestination = Routes.ACTIVITY, route = Tab.Activity.graphRoute) {
                                composable(Routes.ACTIVITY) {
                                    SecurityEventLogScreen(
                                        uiState = uiState,
                                        onClearEvents = onClearEvents,
                                        onExportEvents = onExportEvents,
                                        onCheckDevice = onRefreshRisk,
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }

        if (uiState.payment.latestDecision is PaymentDecisionState.ConfirmationRequired) {
            StepUpConfirmation(
                requestedAt = uiState.payment.decidedAt,
                signalNames = uiState.risk.report?.flaggedSignals().orEmpty().map { it.name },
                onConfirm = onConfirmPayment,
                onDismiss = onDismissConfirmation,
            )
        }
    }
}


private fun Tab.icon(selected: Boolean): ImageVector = if (selected) selectedIcon else unselectedIcon

private fun NavBackStackEntry.tab(): Tab? = Tab.entries.firstOrNull { tab ->
    destination.hierarchy.any { it.route == tab.graphRoute }
}

private fun NavHostController.navigateToTab(tab: Tab) {
    navigate(tab.graphRoute) {
        popUpTo(graph.findStartDestination().id) {
            saveState = true
        }
        launchSingleTop = true
        restoreState = true
    }
}

// Motion follows the Material patterns: fade through between tabs, a short shared-axis slide
// for screens pushed within a tab. Pop transitions also drive the predictive back preview.
private val EmphasizedDecelerate = CubicBezierEasing(0.05f, 0.7f, 0.1f, 1f)
private val FadeThroughIn = fadeIn(tween(durationMillis = 210, delayMillis = 90))
private val FadeThroughOut = fadeOut(tween(durationMillis = 90))

private fun AnimatedContentTransitionScope<NavBackStackEntry>.isTabSwitch(): Boolean =
    initialState.tab() != targetState.tab()

private fun AnimatedContentTransitionScope<NavBackStackEntry>.pushEnter(towards: SlideDirection): EnterTransition =
    slideIntoContainer(towards, tween(durationMillis = 300, easing = EmphasizedDecelerate)) { it / 8 } +
        fadeIn(tween(durationMillis = 210, delayMillis = 60))

private fun AnimatedContentTransitionScope<NavBackStackEntry>.pushExit(towards: SlideDirection): ExitTransition =
    slideOutOfContainer(towards, tween(durationMillis = 300, easing = EmphasizedDecelerate)) { it / 8 } +
        fadeOut(tween(durationMillis = 90))
