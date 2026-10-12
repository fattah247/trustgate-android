package id.fatarc.trustgate.ui.home

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.ErrorOutline
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.outlined.Refresh
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import id.fatarc.trustgate.domain.events.SecurityEvent
import id.fatarc.trustgate.domain.risk.DeviceRiskLevel
import id.fatarc.trustgate.ui.GateMark
import id.fatarc.trustgate.ui.GateState
import id.fatarc.trustgate.ui.GroupedSurface
import id.fatarc.trustgate.ui.gateState
import id.fatarc.trustgate.ui.reasonSentence
import id.fatarc.trustgate.ui.InfoRow
import id.fatarc.trustgate.ui.ListRow
import id.fatarc.trustgate.ui.NoticeCard
import id.fatarc.trustgate.ui.RiskReportSource
import id.fatarc.trustgate.ui.RiskUiState
import id.fatarc.trustgate.ui.RowDivider
import id.fatarc.trustgate.ui.ScreenScaffold
import id.fatarc.trustgate.ui.Section
import id.fatarc.trustgate.ui.SimulationBanner
import id.fatarc.trustgate.ui.TimeFormats
import id.fatarc.trustgate.ui.Tone
import id.fatarc.trustgate.ui.TrustGateSpacing
import id.fatarc.trustgate.ui.TrustGateUiState
import id.fatarc.trustgate.ui.contentColor
import id.fatarc.trustgate.ui.events.headline
import id.fatarc.trustgate.ui.events.icon
import id.fatarc.trustgate.ui.events.isSignalDetail
import id.fatarc.trustgate.ui.events.tone
import id.fatarc.trustgate.ui.flaggedSignals
import id.fatarc.trustgate.ui.label
import id.fatarc.trustgate.ui.parseInstantOrNull
import id.fatarc.trustgate.ui.rememberTimeFormats
import id.fatarc.trustgate.ui.tone
import id.fatarc.trustgate.ui.verdict

@Composable
fun HomeScreen(
    uiState: TrustGateUiState,
    onRefreshRisk: () -> Unit,
    onResumeLiveChecks: () -> Unit,
    onOpenSignals: () -> Unit,
    onOpenActivity: () -> Unit,
    onOpenAbout: () -> Unit,
) {
    val formats = rememberTimeFormats()
    val risk = uiState.risk
    val flaggedSignals = risk.report?.flaggedSignals().orEmpty()
    val recentEvents = uiState.securityEvents
        .asReversed()
        .asSequence()
        .filterNot { it.isSignalDetail }
        .take(4)
        .toList()

    ScreenScaffold(
        title = "Overview",
        actions = {
            IconButton(onClick = onOpenAbout) {
                Icon(Icons.Outlined.Info, contentDescription = "About TrustGate")
            }
        },
    ) {
        risk.scenarioLevel?.let { level ->
            item(key = "simulation") {
                SimulationBanner(level = level, onResumeLiveChecks = onResumeLiveChecks)
            }
        }

        item(key = "status") {
            DeviceStatusCard(
                risk = risk,
                flaggedCount = flaggedSignals.size,
                formats = formats,
                onRefreshRisk = onRefreshRisk,
            )
        }

        // Below the status card: an item inserted above the first visible one would land off screen.
        if (risk.report != null && risk.errorMessage != null) {
            item(key = "stale") {
                NoticeCard(
                    title = "The last check didn't finish",
                    body = "Showing the previous result. ${risk.errorMessage}",
                    tone = Tone.CRITICAL,
                    icon = Icons.Outlined.ErrorOutline,
                )
            }
        }

        if (uiState.storage.snapshot.showSignalsOnHome && flaggedSignals.isNotEmpty()) {
            item(key = "signals") {
                Section(
                    title = "Detected signals",
                    action = {
                        TextButton(onClick = onOpenSignals) { Text("See all") }
                    },
                ) {
                    val shown = flaggedSignals.take(3)
                    shown.forEachIndexed { index, signal ->
                        ListRow(
                            headline = signal.name,
                            supporting = signal.category.label(),
                            trailing = {
                                Text(
                                    text = signal.severity.label(),
                                    style = MaterialTheme.typography.labelLarge,
                                    color = signal.severity.tone().contentColor(),
                                )
                            },
                        )
                        if (index != shown.lastIndex) RowDivider()
                    }
                }
            }
        }

        item(key = "activity") {
            Section(
                title = "Recent activity",
                action = if (uiState.securityEvents.isNotEmpty()) {
                    { TextButton(onClick = onOpenActivity) { Text("See all") } }
                } else {
                    null
                },
            ) {
                if (recentEvents.isEmpty()) {
                    ListRow(
                        headline = "No activity yet",
                        supporting = "Checks and workflow results will show up here.",
                        supportingColor = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                } else {
                    recentEvents.forEachIndexed { index, event ->
                        RecentEventRow(event = event, formats = formats)
                        if (index != recentEvents.lastIndex) RowDivider(startIndent = TrustGateSpacing.listIconInset)
                    }
                }
            }
        }
    }
}

@Composable
private fun DeviceStatusCard(
    risk: RiskUiState,
    flaggedCount: Int,
    formats: TimeFormats,
    onRefreshRisk: () -> Unit,
) {
    val report = risk.report
    val status = deviceStatus(risk)

    GroupedSurface(shape = MaterialTheme.shapes.large) {
        // Fade only when the verdict itself changes, not on every re-check.
        AnimatedContent(
            targetState = status,
            contentKey = { it.key },
            transitionSpec = {
                fadeIn(tween(durationMillis = 220, delayMillis = 90)) togetherWith fadeOut(tween(durationMillis = 90))
            },
            label = "deviceStatus",
        ) { current ->
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(start = 16.dp, top = 20.dp, end = 16.dp, bottom = 16.dp)
                    .semantics(mergeDescendants = true) { liveRegion = LiveRegionMode.Polite },
                horizontalArrangement = Arrangement.spacedBy(16.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                GateMark(
                    state = current.gate,
                    tone = current.tone,
                    contentDescription = null,
                    size = 64.dp,
                )
                Column(
                    modifier = Modifier.weight(1f),
                    verticalArrangement = Arrangement.spacedBy(4.dp),
                ) {
                    Text(text = current.title, style = MaterialTheme.typography.headlineSmall)
                    Text(
                        text = current.body,
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }

        if (report != null) {
            RowDivider()
            InfoRow(
                label = "Protected actions",
                value = report.level.actionOutcome(),
                valueColor = report.level.tone().contentColor(),
            )
            RowDivider()
            InfoRow(
                label = "Signals found",
                value = "$flaggedCount of ${report.signals.size}",
            )
            RowDivider()
            InfoRow(
                label = if (risk.source == RiskReportSource.SCENARIO) "Profile applied" else "Last checked",
                value = formats.dayAndTime(report.assessedAt),
            )
        }

        if (risk.scenarioLevel == null) {
            Row(modifier = Modifier.padding(start = 16.dp, top = 8.dp, end = 16.dp, bottom = 16.dp)) {
                FilledTonalButton(
                    onClick = onRefreshRisk,
                    enabled = !risk.isLoading,
                    contentPadding = ButtonDefaults.ButtonWithIconContentPadding,
                ) {
                    Icon(
                        imageVector = Icons.Outlined.Refresh,
                        contentDescription = null,
                        modifier = Modifier.size(ButtonDefaults.IconSize),
                    )
                    Spacer(Modifier.width(ButtonDefaults.IconSpacing))
                    Text(if (report == null && risk.errorMessage != null) "Try again" else "Check again")
                }
            }
        }
    }
}

@Composable
private fun RecentEventRow(
    event: SecurityEvent,
    formats: TimeFormats,
) {
    val tone = event.tone()
    ListRow(
        headline = event.headline(),
        supporting = event.message,
        supportingMaxLines = 1,
        leadingIcon = event.icon,
        leadingTint = tone.contentColor(),
        trailing = {
            parseInstantOrNull(event.timestamp)?.let { instant ->
                Text(
                    text = formats.compact(instant),
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        },
    )
}

private data class DeviceStatus(
    val key: String,
    val title: String,
    val body: String,
    val tone: Tone,
    val gate: GateState,
)

private fun deviceStatus(risk: RiskUiState): DeviceStatus {
    val report = risk.report
    return when {
        report == null && risk.errorMessage != null -> DeviceStatus(
            key = "error",
            title = "Couldn't check this device",
            body = risk.errorMessage,
            tone = Tone.CRITICAL,
            gate = GateState.SHUT,
        )

        report == null -> DeviceStatus(
            key = "loading",
            title = "Checking this device",
            body = "Looking for root, emulator, and debugging signals.",
            tone = Tone.NEUTRAL,
            gate = GateState.CHECKING,
        )

        else -> DeviceStatus(
            key = report.level.name,
            title = report.level.verdict(),
            body = report.reasonSentence(),
            tone = report.level.tone(),
            gate = report.level.gateState(),
        )
    }
}

private fun DeviceRiskLevel.actionOutcome(): String = when (this) {
    DeviceRiskLevel.LOW -> "Allowed"
    DeviceRiskLevel.MEDIUM -> "Need confirmation"
    DeviceRiskLevel.HIGH -> "Blocked"
}
