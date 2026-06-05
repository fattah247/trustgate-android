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
import id.fatarc.trustgate.ui.KeyValueRow
import id.fatarc.trustgate.ui.PaymentDecisionState
import id.fatarc.trustgate.ui.PrimaryActionButton
import id.fatarc.trustgate.ui.RiskBadge
import id.fatarc.trustgate.ui.RiskReportSource
import id.fatarc.trustgate.ui.SectionCard
import id.fatarc.trustgate.ui.StatusCallout
import id.fatarc.trustgate.ui.StatusCalloutState
import id.fatarc.trustgate.ui.TrustGateScreen
import id.fatarc.trustgate.ui.TrustGateSpacing
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
            SectionCard(title = "Gate policy") {
                Text(
                    text = "This demo runs one sensitive action through a simple policy: low risk is allowed, medium risk requires confirmation, and high risk is blocked.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                PolicySummary()
            }
        }

        item {
            SectionCard(title = "Choose the risk source") {
                Text(
                    text = "Use the live assessment for realism or a demo profile to force a specific path without fabricating the decision logic.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                DemoRiskSelector(
                    selectedLevel = uiState.payment.selectedDemoRiskLevel,
                    onSelectLevel = onSetDemoRiskLevel,
                )
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

        item {
            SectionCard(title = "Run the action") {
                Text(
                    text = "The button below uses the current risk state. If the app has no report yet, it will assess first and then continue.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                PrimaryActionButton(
                    label = "Create demo payment",
                    onClick = onAttemptPayment,
                )
                StatusCallout(state = latestDecisionSummary(uiState.payment.latestDecision))
            }
        }
    }
}

@Composable
private fun PolicySummary() {
    Column(verticalArrangement = Arrangement.spacedBy(TrustGateSpacing.compactGap)) {
        KeyValueRow(label = "Low risk", value = "Allow")
        KeyValueRow(label = "Medium risk", value = "Require explicit confirmation")
        KeyValueRow(label = "High risk", value = "Block")
    }
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
            title = "Awaiting a payment attempt",
            body = "No action has been attempted since the current risk state was loaded.",
        )

        is PaymentDecisionState.Allowed -> StatusCalloutState(
            title = "Action allowed",
            body = "The app allowed the payment-like action because the device was ${decision.riskLevel.asLabel()}.",
            tone = CalloutTone.SUCCESS,
        )

        is PaymentDecisionState.ConfirmationRequired -> StatusCalloutState(
            title = "Confirmation required",
            body = "The app paused at the confirmation step because the device was ${decision.riskLevel.asLabel()}.",
            tone = CalloutTone.WARNING,
        )

        is PaymentDecisionState.Confirmed -> StatusCalloutState(
            title = "Action allowed after confirmation",
            body = "The user explicitly confirmed a medium-risk action and the app recorded that decision.",
            tone = CalloutTone.SUCCESS,
        )

        is PaymentDecisionState.Blocked -> StatusCalloutState(
            title = "Action blocked",
            body = "The app blocked the payment-like action because the device was ${decision.riskLevel.asLabel()}.",
            tone = CalloutTone.ERROR,
        )

        is PaymentDecisionState.Cancelled -> StatusCalloutState(
            title = "Action cancelled",
            body = "The confirmation step was dismissed, so the medium-risk action did not continue.",
        )
    }
}
