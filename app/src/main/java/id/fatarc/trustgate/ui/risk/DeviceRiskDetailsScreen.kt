package id.fatarc.trustgate.ui.risk

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import id.fatarc.trustgate.domain.risk.DeviceRiskLevel
import id.fatarc.trustgate.domain.risk.DeviceRiskReport
import id.fatarc.trustgate.domain.risk.RiskSignal
import id.fatarc.trustgate.domain.risk.SignalCategory
import id.fatarc.trustgate.ui.CalloutTone
import id.fatarc.trustgate.ui.DetailSurface
import id.fatarc.trustgate.ui.DividerList
import id.fatarc.trustgate.ui.EvidenceRow
import id.fatarc.trustgate.ui.KeyValueRow
import id.fatarc.trustgate.ui.RiskBadge
import id.fatarc.trustgate.ui.SectionBlock
import id.fatarc.trustgate.ui.SectionDivider
import id.fatarc.trustgate.ui.StatusCallout
import id.fatarc.trustgate.ui.StatusCalloutState
import id.fatarc.trustgate.ui.SummaryPanel
import id.fatarc.trustgate.ui.TrustGateScreen
import id.fatarc.trustgate.ui.TrustGateUiState
import id.fatarc.trustgate.ui.asHumanLabel

@Composable
fun DeviceRiskDetailsScreen(
    uiState: TrustGateUiState,
) {
    val report = uiState.risk.report
    TrustGateScreen {
        item {
            if (report == null) {
                SummaryPanel(
                    eyebrow = "Risk details",
                    title = "No risk report available",
                    supporting = uiState.risk.errorMessage
                        ?: "Run the device checks from the overview screen to populate the signal list.",
                    tone = if (uiState.risk.errorMessage == null) CalloutTone.NEUTRAL else CalloutTone.ERROR,
                )
            } else {
                SummaryPanel(
                    eyebrow = "Risk details",
                    title = report.level.summaryTitle(),
                    supporting = "This screen groups the current device signals by meaning so the verdict can be reviewed without scanning unrelated detail.",
                    tone = report.level.summaryTone(),
                ) {
                    RiskBadge(level = report.level)
                    KeyValueRow(label = "Risk score", value = report.score.toString())
                    KeyValueRow(label = "Total signals", value = report.signals.size.toString())
                    KeyValueRow(
                        label = "Detected signals",
                        value = report.signals.count { it.detected }.toString(),
                    )
                    KeyValueRow(
                        label = "Assessed at",
                        value = report.assessedAt.toString(),
                        monospace = true,
                    )
                }
            }
        }

        if (report != null) {
            orderedCategories.forEach { category ->
                item {
                    CategorySection(
                        category = category,
                        signals = report.signals.filter { it.category == category },
                    )
                }
            }
        }
    }
}

@Composable
private fun CategorySection(
    category: SignalCategory,
    signals: List<RiskSignal>,
) {
    SectionBlock(
        title = category.sectionTitle(),
        description = category.sectionDescription(),
    ) {
        DetailSurface {
            if (signals.isEmpty()) {
                StatusCallout(
                    state = StatusCalloutState(
                        title = "No checks in this group",
                        body = "This build does not currently expose signals for this category.",
                    ),
                )
            } else {
                DividerList {
                    signals.forEachIndexed { index, signal ->
                        EvidenceRow(
                            title = signal.name,
                            summary = if (signal.detected) signal.explanation else "No evidence for this signal was detected.",
                            supporting = "Severity: ${signal.severity.name.asHumanLabel()} \u00b7 Id: ${signal.id}",
                            trailing = {
                                Text(
                                    text = if (signal.detected) "Detected" else "Clear",
                                    style = MaterialTheme.typography.labelLarge,
                                    color = if (signal.detected) {
                                        MaterialTheme.colorScheme.error
                                    } else {
                                        MaterialTheme.colorScheme.primary
                                    },
                                )
                            },
                        )
                        if (index != signals.lastIndex) {
                            SectionDivider()
                        }
                    }
                }
            }
        }
    }
}

private fun DeviceRiskLevel.summaryTitle(): String = when (this) {
    DeviceRiskLevel.LOW -> "No strong trust blockers detected"
    DeviceRiskLevel.MEDIUM -> "Some checks need operator review"
    DeviceRiskLevel.HIGH -> "The current signal set indicates a high-risk environment"
}

private fun DeviceRiskLevel.summaryTone(): CalloutTone = when (this) {
    DeviceRiskLevel.LOW -> CalloutTone.SUCCESS
    DeviceRiskLevel.MEDIUM -> CalloutTone.WARNING
    DeviceRiskLevel.HIGH -> CalloutTone.ERROR
}

private fun SignalCategory.sectionTitle(): String = when (this) {
    SignalCategory.ROOT -> "Root indicators"
    SignalCategory.EMULATOR -> "Emulator indicators"
    SignalCategory.DEBUGGER -> "Debugger and tamper indicators"
    SignalCategory.INSTALLER -> "Environment indicators"
}

private fun SignalCategory.sectionDescription(): String = when (this) {
    SignalCategory.ROOT -> "Checks that suggest root access, writable system state, or privileged management tools."
    SignalCategory.EMULATOR -> "Checks that look for build and hardware patterns commonly associated with emulators."
    SignalCategory.DEBUGGER -> "Checks that suggest the runtime is attached to a debugger or built for debugging."
    SignalCategory.INSTALLER -> "Context checks that help explain how the app arrived on the device without forcing a hard block."
}

private val orderedCategories = listOf(
    SignalCategory.ROOT,
    SignalCategory.EMULATOR,
    SignalCategory.DEBUGGER,
    SignalCategory.INSTALLER,
)
