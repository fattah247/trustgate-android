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
import androidx.compose.material.icons.filled.GppGood
import androidx.compose.material.icons.filled.Science
import androidx.compose.material.icons.outlined.History
import androidx.compose.material.icons.outlined.Home
import androidx.compose.material.icons.outlined.GppGood
import androidx.compose.material.icons.outlined.Science
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
import id.fatarc.trustgate.domain.risk.DeviceRiskLevel
import id.fatarc.trustgate.ui.about.AboutScreen
import id.fatarc.trustgate.ui.events.SecurityEventLogScreen
import id.fatarc.trustgate.ui.home.HomeScreen
import id.fatarc.trustgate.ui.lab.LabScreen
import id.fatarc.trustgate.ui.lab.RequestDetailsScreen
import id.fatarc.trustgate.ui.payment.PayScreen
import id.fatarc.trustgate.ui.payment.StepUpConfirmation
import id.fatarc.trustgate.ui.risk.ChecksScreen
import java.security.Signature

private object Routes {
    const val HOME = "home"
    const val PAY = "home/pay"
    const val PAY_CHECKS = "home/pay/checks"
    const val PAY_REQUEST = "home/pay/request"
    const val ABOUT = "home/about"
    const val CHECKS = "checks"
    const val LAB = "lab"
    const val LAB_REQUEST = "lab/request"
    const val LAB_ABOUT = "lab/about"
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
    Home("home-tab", Routes.HOME, "Home", Icons.Filled.Home, Icons.Outlined.Home),
    Checks("checks-tab", Routes.CHECKS, "Checks", Icons.Filled.GppGood, Icons.Outlined.GppGood),
    Lab("lab-tab", Routes.LAB, "Lab", Icons.Filled.Science, Icons.Outlined.Science),
    Activity("activity-tab", Routes.ACTIVITY, "Activity", Icons.Filled.History, Icons.Outlined.History),
}

@Composable
fun TrustGateApp(
    uiState: TrustGateUiState,
    onRefreshRisk: () -> Unit,
    onAttemptPayment: () -> Unit,
    onStepUpSignature: () -> Signature?,
    onStepUpAuthenticated: (Signature) -> Unit,
    onConfirmWithTap: () -> Unit,
    onDismissConfirmation: (problem: String?) -> Unit,
    onSetSimulateLostResponse: (Boolean) -> Unit,
    onRunLabTest: (LabTest) -> Unit,
    onStoreReferenceValues: () -> Unit,
    onSetScenarioRiskLevel: (DeviceRiskLevel?) -> Unit,
    onClearEvents: () -> Unit,
    onExportEvents: () -> String,
    onAppResumed: () -> Unit,
    onUserMessageShown: (Long) -> Unit,
) {
    val navController = rememberNavController()
    val backStackEntry by navController.currentBackStackEntryAsState()
    val selectedTab = backStackEntry?.tab() ?: Tab.Home
    val snackbarHostState = remember { SnackbarHostState() }

    uiState.userMessage?.let { message ->
        LaunchedEffect(message.id) {
            snackbarHostState.showSnackbar(message.text)
            onUserMessageShown(message.id)
        }
    }

    // Coming back to the app refreshes the keys and re-checks a stale verdict.
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
    val useThisPhone: () -> Unit = { onSetScenarioRiskLevel(null) }

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
                            startDestination = Tab.Home.graphRoute,
                            modifier = Modifier
                                .padding(innerPadding)
                                .consumeWindowInsets(innerPadding),
                            enterTransition = { if (isTabSwitch()) FadeThroughIn else pushEnter(SlideDirection.Start) },
                            exitTransition = { if (isTabSwitch()) FadeThroughOut else pushExit(SlideDirection.Start) },
                            popEnterTransition = { if (isTabSwitch()) FadeThroughIn else pushEnter(SlideDirection.End) },
                            popExitTransition = { if (isTabSwitch()) FadeThroughOut else pushExit(SlideDirection.End) },
                        ) {
                            val navigateUp = { navController.navigateUp(); Unit }
                            navigation(startDestination = Routes.HOME, route = Tab.Home.graphRoute) {
                                composable(Routes.HOME) {
                                    HomeScreen(
                                        uiState = uiState,
                                        onRefreshRisk = onRefreshRisk,
                                        onPay = dropUnlessResumed {
                                            onAttemptPayment()
                                            navController.navigate(Routes.PAY)
                                        },
                                        onSelectDemoPhone = onSetScenarioRiskLevel,
                                        onOpenActivity = dropUnlessResumed { navController.navigateToTab(Tab.Activity) },
                                        onOpenAbout = dropUnlessResumed { navController.navigate(Routes.ABOUT) },
                                    )
                                }
                                composable(Routes.PAY) {
                                    PayScreen(
                                        uiState = uiState,
                                        onNavigateUp = dropUnlessResumed(block = navigateUp),
                                        onPay = onAttemptPayment,
                                        // Pushed within Home so back returns to the payment.
                                        onOpenChecks = dropUnlessResumed { navController.navigate(Routes.PAY_CHECKS) },
                                        onOpenRequest = dropUnlessResumed { navController.navigate(Routes.PAY_REQUEST) },
                                    )
                                }
                                composable(Routes.PAY_CHECKS) {
                                    ChecksScreen(
                                        uiState = uiState,
                                        onRefreshRisk = onRefreshRisk,
                                        onUseThisPhone = useThisPhone,
                                        onNavigateUp = dropUnlessResumed(block = navigateUp),
                                    )
                                }
                                composable(Routes.PAY_REQUEST) {
                                    RequestDetailsScreen(request = uiState.lastRequest, onNavigateUp = dropUnlessResumed(block = navigateUp))
                                }
                                composable(Routes.ABOUT) {
                                    AboutScreen(onNavigateUp = dropUnlessResumed(block = navigateUp))
                                }
                            }
                            navigation(startDestination = Routes.CHECKS, route = Tab.Checks.graphRoute) {
                                composable(Routes.CHECKS) {
                                    ChecksScreen(uiState = uiState, onRefreshRisk = onRefreshRisk, onUseThisPhone = useThisPhone)
                                }
                            }
                            navigation(startDestination = Routes.LAB, route = Tab.Lab.graphRoute) {
                                composable(Routes.LAB) {
                                    LabScreen(
                                        uiState = uiState,
                                        onRunTest = onRunLabTest,
                                        onSetSimulateLostResponse = onSetSimulateLostResponse,
                                        onStoreTestValues = onStoreReferenceValues,
                                        onOpenRequest = dropUnlessResumed { navController.navigate(Routes.LAB_REQUEST) },
                                        onOpenAbout = dropUnlessResumed { navController.navigate(Routes.LAB_ABOUT) },
                                    )
                                }
                                composable(Routes.LAB_REQUEST) {
                                    RequestDetailsScreen(request = uiState.lastRequest, onNavigateUp = dropUnlessResumed(block = navigateUp))
                                }
                                composable(Routes.LAB_ABOUT) {
                                    AboutScreen(onNavigateUp = dropUnlessResumed(block = navigateUp))
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

        val pendingConfirmation = uiState.payment.latestDecision as? PaymentDecisionState.ConfirmationRequired
        if (pendingConfirmation != null) {
            StepUpConfirmation(
                method = pendingConfirmation.method,
                requestedAt = uiState.payment.decidedAt,
                signalNames = uiState.risk.report?.flaggedSignals().orEmpty().map { it.name },
                onRequestSignature = onStepUpSignature,
                onAuthenticated = onStepUpAuthenticated,
                onConfirmTap = onConfirmWithTap,
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
