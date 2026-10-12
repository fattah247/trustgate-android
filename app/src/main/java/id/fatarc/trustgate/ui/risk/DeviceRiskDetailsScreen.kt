package id.fatarc.trustgate.ui.risk

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material.icons.outlined.ErrorOutline
import androidx.compose.material.icons.outlined.Flag
import androidx.compose.material.icons.outlined.Refresh
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import id.fatarc.trustgate.domain.risk.DeviceRiskReport
import id.fatarc.trustgate.domain.risk.RiskScorer
import id.fatarc.trustgate.domain.risk.RiskSignal
import id.fatarc.trustgate.domain.risk.SignalCategory
import id.fatarc.trustgate.domain.risk.SignalSeverity
import id.fatarc.trustgate.ui.GateMark
import id.fatarc.trustgate.ui.GroupedSurface
import id.fatarc.trustgate.ui.InfoRow
import id.fatarc.trustgate.ui.flaggedSignals
import id.fatarc.trustgate.ui.gateState
import id.fatarc.trustgate.ui.points
import id.fatarc.trustgate.ui.reasonSentence
import id.fatarc.trustgate.ui.ListRow
import id.fatarc.trustgate.ui.NoticeAction
import id.fatarc.trustgate.ui.NoticeCard
import id.fatarc.trustgate.ui.RiskReportSource
import id.fatarc.trustgate.ui.RowDivider
import id.fatarc.trustgate.ui.ScreenScaffold
import id.fatarc.trustgate.ui.Section
import id.fatarc.trustgate.ui.SimulationBanner
import id.fatarc.trustgate.ui.TimeFormats
import id.fatarc.trustgate.ui.Tone
import id.fatarc.trustgate.ui.TrustGateSpacing
import id.fatarc.trustgate.ui.TrustGateUiState
import id.fatarc.trustgate.ui.contentColor
import id.fatarc.trustgate.ui.label
import id.fatarc.trustgate.ui.rememberTimeFormats
import id.fatarc.trustgate.ui.tone

@Composable
fun DeviceRiskDetailsScreen(
    uiState: TrustGateUiState,
    onRefreshRisk: () -> Unit,
    onResumeLiveChecks: () -> Unit,
    onNavigateUp: (() -> Unit)? = null,
) {
    val formats = rememberTimeFormats()
    val risk = uiState.risk
    val report = risk.report

    ScreenScaffold(
        title = "Signals",
        onNavigateUp = onNavigateUp,
        actions = {
            if (risk.scenarioLevel == null) {
                IconButton(onClick = onRefreshRisk, enabled = !risk.isLoading) {
                    Icon(Icons.Outlined.Refresh, contentDescription = "Check again")
                }
            }
        },
    ) {
        risk.scenarioLevel?.let { level ->
            item(key = "simulation") {
                SimulationBanner(level = level, onResumeLiveChecks = onResumeLiveChecks)
            }
        }

        when {
            report != null -> {
                item(key = "summary") {
                    SignalsSummary(report = report, source = risk.source, formats = formats)
                }
                item(key = "reason") {
                    ReasonSection(report = report)
                }
                SignalCategory.entries.forEach { category ->
                    val signals = report.signals
                        .filter { it.category == category }
                        .sortedWith(compareByDescending<RiskSignal> { it.detected }.thenByDescending { it.severity.weight })
                    if (signals.isNotEmpty()) {
                        item(key = category.name) {
                            Section(
                                title = category.label(),
                                footer = category.footer(),
                            ) {
                                signals.forEachIndexed { index, signal ->
                                    SignalRow(signal = signal)
                                    if (index != signals.lastIndex) {
                                        RowDivider(startIndent = TrustGateSpacing.listIconInset)
                                    }
                                }
                            }
                        }
                    }
                }
            }

            risk.errorMessage != null -> item(key = "error") {
                NoticeCard(
                    title = "Couldn't check this device",
                    body = risk.errorMessage,
                    tone = Tone.CRITICAL,
                    icon = Icons.Outlined.ErrorOutline,
                    action = NoticeAction(label = "Try again", onClick = onRefreshRisk),
                )
            }

            else -> item(key = "loading") {
                GroupedSurface {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(16.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(16.dp),
                    ) {
                        CircularProgressIndicator(modifier = Modifier.size(24.dp), strokeWidth = 3.dp)
                        Text("Checking this device", style = MaterialTheme.typography.bodyLarge)
                    }
                }
            }
        }
    }
}

@Composable
private fun SignalsSummary(
    report: DeviceRiskReport,
    source: RiskReportSource,
    formats: TimeFormats,
) {
    val flagged = report.signals.count { it.detected }
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp)
            .semantics(mergeDescendants = true) {},
        horizontalArrangement = Arrangement.spacedBy(16.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        GateMark(
            state = report.level.gateState(),
            tone = report.level.tone(),
            contentDescription = null,
            size = 48.dp,
        )
        Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(
                text = when (flagged) {
                    0 -> "No signals found"
                    else -> "$flagged of ${report.signals.size} checks flagged"
                },
                style = MaterialTheme.typography.titleLarge,
            )
            Text(
                text = buildString {
                    append(report.level.label())
                    append(" · score ")
                    append(report.score)
                    append(" · ")
                    append(
                        when (source) {
                            RiskReportSource.LIVE -> formats.dayAndTime(report.assessedAt)
                            RiskReportSource.SCENARIO -> "simulated"
                        },
                    )
                },
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

/** Shows the rule that produced the level and the points behind it, so the verdict can be checked by hand. */
@Composable
private fun ReasonSection(report: DeviceRiskReport) {
    val contributing = report.flaggedSignals()
    Section(
        title = "Why ${report.level.label().lowercase()}",
        footer = "Medium risk starts at ${RiskScorer.MEDIUM_SCORE_THRESHOLD} points. High risk starts at " +
            "${RiskScorer.HIGH_SCORE_THRESHOLD} points, or with any single high-severity signal.",
    ) {
        Text(
            text = report.reasonSentence(),
            modifier = Modifier.padding(16.dp),
            style = MaterialTheme.typography.bodyLarge,
        )
        if (contributing.isNotEmpty()) {
            RowDivider()
            contributing.forEach { signal ->
                InfoRow(
                    label = signal.name,
                    value = "+${signal.severity.weight}",
                    valueColor = signal.severity.tone().contentColor(),
                )
            }
            RowDivider()
            InfoRow(
                label = "Total",
                value = report.score.points(),
                valueColor = MaterialTheme.colorScheme.onSurface,
            )
        }
    }
}

@Composable
private fun SignalRow(signal: RiskSignal) {
    ListRow(
        headline = signal.name,
        supporting = if (signal.detected) signal.explanation else "Not detected",
        supportingColor = MaterialTheme.colorScheme.onSurfaceVariant,
        leadingIcon = if (signal.detected) Icons.Outlined.Flag else Icons.Outlined.CheckCircle,
        leadingTint = if (signal.detected) {
            if (signal.severity == SignalSeverity.HIGH) Tone.CRITICAL.contentColor() else Tone.CAUTION.contentColor()
        } else {
            MaterialTheme.colorScheme.outline
        },
        leadingIconDescription = if (signal.detected) "Detected" else "Not detected",
        trailing = if (signal.detected) {
            {
                Text(
                    text = signal.severity.label(),
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        } else {
            null
        },
    )
}

/** Only where the group needs context its rows don't already give. */
private fun SignalCategory.footer(): String? = when (this) {
    SignalCategory.ROOT -> "Root access or a modified system means the app can't rely on platform protections."
    SignalCategory.INSTALLER -> "Install source is reviewed, but never blocks on its own."
    SignalCategory.EMULATOR,
    SignalCategory.DEBUGGER,
    -> null
}
