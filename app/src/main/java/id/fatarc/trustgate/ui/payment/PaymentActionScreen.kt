package id.fatarc.trustgate.ui.payment

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.unit.dp
import id.fatarc.trustgate.domain.risk.DeviceRiskLevel
import id.fatarc.trustgate.ui.CalloutTone
import id.fatarc.trustgate.ui.DetailSurface
import id.fatarc.trustgate.ui.DividerList
import id.fatarc.trustgate.ui.EvidenceRow
import id.fatarc.trustgate.ui.KeyValueRow
import id.fatarc.trustgate.ui.PaymentDecisionState
import id.fatarc.trustgate.ui.PrimaryActionButton
import id.fatarc.trustgate.ui.RiskBadge
import id.fatarc.trustgate.ui.RiskReportSource
import id.fatarc.trustgate.ui.SectionBlock
import id.fatarc.trustgate.ui.SectionDivider
import id.fatarc.trustgate.ui.StatusCallout
import id.fatarc.trustgate.ui.StatusCalloutState
import id.fatarc.trustgate.ui.SummaryPanel
import id.fatarc.trustgate.ui.TrustGateScreen
import id.fatarc.trustgate.ui.TrustGateUiState
import id.fatarc.trustgate.ui.asLabel

@Composable
fun PaymentActionScreen(
    uiState: TrustGateUiState,
    onAttemptPayment: () -> Unit,
    onSetDemoRiskLevel: (DeviceRiskLevel?) -> Unit,
) {
    TrustGateScreen {
        item {
            SummaryPanel(
                eyebrow = "Protected action",
                title = latestDecisionSummary(uiState.payment.latestDecision).title,
                supporting = latestDecisionSummary(uiState.payment.latestDecision).body,
                tone = latestDecisionSummary(uiState.payment.latestDecision).tone,
            ) {
                uiState.risk.report?.let { report ->
                    RiskBadge(level = report.level)
                    KeyValueRow(label = "Current risk", value = report.level.asLabel())
                    KeyValueRow(
                        label = "Risk source",
                        value = when (uiState.risk.source) {
                            RiskReportSource.LIVE -> "Live assessment"
                            RiskReportSource.DEMO -> "Demo profile"
                        },
                    )
                }
                PrimaryActionButton(
                    label = "Run protected action",
                    onClick = onAttemptPayment,
                )
            }
        }

        item {
            SectionBlock(
                title = "Decision policy",
                description = "The app uses the current trust result to decide whether a protected action should proceed, require confirmation, or stop.",
            ) {
                DetailSurface {
                    DividerList {
                        PolicyRow(
                            title = "Low risk",
                            summary = "Allow the action without additional confirmation.",
                        )
                        SectionDivider()
                        PolicyRow(
                            title = "Medium risk",
                            summary = "Require an explicit confirmation step before continuing.",
                        )
                        SectionDivider()
                        PolicyRow(
                            title = "High risk",
                            summary = "Block the action until the environment is reviewed.",
                        )
                    }
                }
            }
        }

        item {
            SectionBlock(
                title = "Risk source",
                description = "Use live device checks for real validation or a sample profile to exercise a specific path on demand.",
            ) {
                DemoRiskSelector(
                    selectedLevel = uiState.payment.selectedDemoRiskLevel,
                    onSelectLevel = onSetDemoRiskLevel,
                )
                uiState.risk.errorMessage?.let { message ->
                    StatusCallout(
                        state = StatusCalloutState(
                            title = "Risk state unavailable",
                            body = message,
                            tone = CalloutTone.ERROR,
                        ),
                    )
                }
            }
        }
    }
}

@Composable
private fun PolicyRow(
    title: String,
    summary: String,
) {
    EvidenceRow(
        title = title,
        summary = summary,
    )
}

@Composable
private fun DemoRiskSelector(
    selectedLevel: DeviceRiskLevel?,
    onSelectLevel: (DeviceRiskLevel?) -> Unit,
) {
    Column(
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            FilterChip(
                selected = selectedLevel == null,
                onClick = { onSelectLevel(null) },
                label = { Text("Live device") },
            )
            FilterChip(
                selected = selectedLevel == DeviceRiskLevel.LOW,
                onClick = { onSelectLevel(DeviceRiskLevel.LOW) },
                label = { Text("Low risk") },
            )
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            FilterChip(
                selected = selectedLevel == DeviceRiskLevel.MEDIUM,
                onClick = { onSelectLevel(DeviceRiskLevel.MEDIUM) },
                label = { Text("Medium risk") },
            )
            FilterChip(
                selected = selectedLevel == DeviceRiskLevel.HIGH,
                onClick = { onSelectLevel(DeviceRiskLevel.HIGH) },
                label = { Text("High risk") },
            )
        }
    }
}

private fun latestDecisionSummary(decision: PaymentDecisionState): StatusCalloutState {
    return when (decision) {
        PaymentDecisionState.Idle -> StatusCalloutState(
            title = "Awaiting a protected action",
            body = "Run the action to confirm whether the current trust result allows, escalates, or blocks it.",
        )

        is PaymentDecisionState.Allowed -> StatusCalloutState(
            title = "Protected action allowed",
            body = "The current trust result allowed the action because the device was ${decision.riskLevel.asLabel()}.",
            tone = CalloutTone.SUCCESS,
        )

        is PaymentDecisionState.ConfirmationRequired -> StatusCalloutState(
            title = "Confirmation required",
            body = "The app stopped at the confirmation step because the current risk state requires operator review.",
            tone = CalloutTone.WARNING,
        )

        is PaymentDecisionState.Confirmed -> StatusCalloutState(
            title = "Action allowed after confirmation",
            body = "A medium-risk action was explicitly confirmed and then allowed for the current session.",
            tone = CalloutTone.SUCCESS,
        )

        is PaymentDecisionState.Blocked -> StatusCalloutState(
            title = "Protected action blocked",
            body = "The current trust result blocked the action because the device was ${decision.riskLevel.asLabel()}.",
            tone = CalloutTone.ERROR,
        )

        is PaymentDecisionState.Cancelled -> StatusCalloutState(
            title = "Action cancelled",
            body = "The confirmation step was dismissed, so the protected action did not continue.",
        )
    }
}
