package id.fatarc.trustgate.ui.home

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import id.fatarc.trustgate.ui.CalloutTone
import id.fatarc.trustgate.ui.KeyValueRow
import id.fatarc.trustgate.ui.PrimaryActionButton
import id.fatarc.trustgate.ui.PaymentDecisionState
import id.fatarc.trustgate.ui.RiskBadge
import id.fatarc.trustgate.ui.RiskReportSource
import id.fatarc.trustgate.ui.SectionCard
import id.fatarc.trustgate.ui.SecondaryActionButton
import id.fatarc.trustgate.ui.SigningStatus
import id.fatarc.trustgate.ui.StatusCallout
import id.fatarc.trustgate.ui.StatusCalloutState
import id.fatarc.trustgate.ui.StorageStatus
import id.fatarc.trustgate.ui.TrustGateScreen
import id.fatarc.trustgate.ui.TrustGateSpacing
import id.fatarc.trustgate.ui.TrustGateUiState
import id.fatarc.trustgate.ui.asLabel

@Composable
fun HomeScreen(
    uiState: TrustGateUiState,
    onRefreshRisk: () -> Unit,
    onOpenRiskDetails: () -> Unit,
    onOpenPaymentDemo: () -> Unit,
    onOpenSigningDemo: () -> Unit,
    onOpenStorageDemo: () -> Unit,
    onOpenEvents: () -> Unit,
    onOpenAbout: () -> Unit,
) {
    TrustGateScreen {
        item {
            SectionCard(title = "Current trust state") {
                Text(
                    text = "TrustGate treats client checks as signals, then uses that risk picture to shape sensitive actions and local audit output.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                RiskSummary(uiState)
                PrimaryActionButton(
                    label = if (uiState.risk.isLoading) "Assessing device risk" else "Refresh live assessment",
                    onClick = onRefreshRisk,
                    enabled = !uiState.risk.isLoading,
                )
                uiState.risk.errorMessage?.let { message ->
                    StatusCallout(
                        state = StatusCalloutState(
                            title = "Risk assessment failed",
                            body = message,
                            tone = CalloutTone.ERROR,
                        ),
                    )
                }
            }
        }

        item {
            SectionCard(title = "Primary demos") {
                Text(
                    text = "Each destination answers one concrete question about the client-side security model.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                DemoDestinationButton(
                    title = "Inspect risk signals",
                    description = "See which heuristics are present, their severity, and how they affect the score.",
                    onClick = onOpenRiskDetails,
                )
                DemoDestinationButton(
                    title = "Run the sensitive action gate",
                    description = "Exercise the allow, confirm, and block paths with live or demo risk states.",
                    onClick = onOpenPaymentDemo,
                )
                DemoDestinationButton(
                    title = "Review request signing",
                    description = "Generate a deterministic signed request and inspect the canonical body and headers.",
                    onClick = onOpenSigningDemo,
                )
                DemoDestinationButton(
                    title = "Inspect secure storage",
                    description = "Check what the app persists locally and how the encrypted snapshot changes.",
                    onClick = onOpenStorageDemo,
                )
                DemoDestinationButton(
                    title = "Read the security event log",
                    description = "Review the local event trail that explains each assessment and action outcome.",
                    onClick = onOpenEvents,
                )
                DemoDestinationButton(
                    title = "Read scope and limits",
                    description = "See what the demo proves, what it does not prove, and why.",
                    onClick = onOpenAbout,
                )
            }
        }

        item {
            SectionCard(title = "Latest outcomes") {
                StatusCallout(state = paymentSummary(uiState))
                StatusCallout(state = signingSummary(uiState))
                StatusCallout(state = storageSummary(uiState))
                KeyValueRow(
                    label = "Recorded security events",
                    value = uiState.securityEvents.size.toString(),
                )
            }
        }
    }
}

@Composable
private fun RiskSummary(uiState: TrustGateUiState) {
    val report = uiState.risk.report
    when {
        uiState.risk.isLoading && report == null -> {
            StatusCallout(
                state = StatusCalloutState(
                    title = "Assessment in progress",
                    body = "The app is collecting runtime signals and rebuilding the current device-risk view.",
                ),
            )
        }

        report == null -> {
            StatusCallout(
                state = StatusCalloutState(
                    title = "No assessment available",
                    body = "Run a live assessment to populate the current trust state.",
                ),
            )
        }

        else -> {
            RiskBadge(level = report.level)
            KeyValueRow(label = "Risk level", value = report.level.asLabel())
            KeyValueRow(label = "Risk score", value = report.score.toString())
            KeyValueRow(
                label = "Signal source",
                value = when (uiState.risk.source) {
                    RiskReportSource.LIVE -> "Live device assessment"
                    RiskReportSource.DEMO -> "Demo profile"
                },
            )
            KeyValueRow(
                label = "Detected signals",
                value = report.signals.count { it.detected }.toString(),
            )
            KeyValueRow(
                label = "Assessed at",
                value = report.assessedAt.toString(),
                monospace = true,
            )
            if (uiState.storage.snapshot.showSignalsOnHome) {
                Column(verticalArrangement = Arrangement.spacedBy(TrustGateSpacing.compactGap)) {
                    report.signals.take(4).forEach { signal ->
                        Text(
                            text = if (signal.detected) "Active signal: ${signal.name}" else "Clear signal: ${signal.name}",
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun DemoDestinationButton(
    title: String,
    description: String,
    onClick: () -> Unit,
) {
    SecondaryActionButton(
        title = title,
        description = description,
        onClick = onClick,
    )
}

private fun paymentSummary(uiState: TrustGateUiState): StatusCalloutState {
    return when (val decision = uiState.payment.latestDecision) {
        PaymentDecisionState.Idle -> StatusCalloutState(
            title = "Sensitive action not attempted",
            body = "Open the gate screen to run the action flow against the current risk state.",
        )

        is PaymentDecisionState.Allowed -> StatusCalloutState(
            title = "Action allowed",
            body = "The last payment-like action was allowed because the device evaluated as ${decision.riskLevel.asLabel()}.",
            tone = CalloutTone.SUCCESS,
        )

        is PaymentDecisionState.ConfirmationRequired -> StatusCalloutState(
            title = "Confirmation required",
            body = "The current state is ${decision.riskLevel.asLabel()}, so the app requires an explicit confirmation step.",
            tone = CalloutTone.WARNING,
        )

        is PaymentDecisionState.Confirmed -> StatusCalloutState(
            title = "Action allowed after confirmation",
            body = "A medium-risk action was explicitly confirmed and then allowed for the demo flow.",
            tone = CalloutTone.SUCCESS,
        )

        is PaymentDecisionState.Blocked -> StatusCalloutState(
            title = "Action blocked",
            body = "The last payment-like action was blocked because the device evaluated as ${decision.riskLevel.asLabel()}.",
            tone = CalloutTone.ERROR,
        )

        is PaymentDecisionState.Cancelled -> StatusCalloutState(
            title = "Confirmation dismissed",
            body = "The pending medium-risk action was cancelled instead of being forced through.",
            tone = CalloutTone.NEUTRAL,
        )
    }
}

private fun signingSummary(uiState: TrustGateUiState): StatusCalloutState {
    return when (val status = uiState.signing.status) {
        SigningStatus.Idle -> StatusCalloutState(
            title = "No request signed yet",
            body = "Generate a demo request to inspect the canonical body, hash, and signature headers.",
        )

        is SigningStatus.Signed -> StatusCalloutState(
            title = "Request signed",
            body = "The latest demo request for ${status.merchantReference} was canonicalized and signed locally.",
            tone = CalloutTone.SUCCESS,
        )

        is SigningStatus.Failed -> StatusCalloutState(
            title = "Signing failed",
            body = status.message,
            tone = CalloutTone.ERROR,
        )
    }
}

private fun storageSummary(uiState: TrustGateUiState): StatusCalloutState {
    return when (val status = uiState.storage.status) {
        StorageStatus.Idle -> StatusCalloutState(
            title = "Encrypted storage untouched",
            body = "No demo values have been written or reloaded yet.",
        )

        StorageStatus.Loaded -> StatusCalloutState(
            title = "Encrypted snapshot reloaded",
            body = "The current view reflects the latest values read back from local encrypted storage.",
            tone = CalloutTone.SUCCESS,
        )

        is StorageStatus.Stored -> StatusCalloutState(
            title = "Encrypted values stored",
            body = "${status.keyCount} demo values were written to encrypted local storage.",
            tone = CalloutTone.SUCCESS,
        )

        is StorageStatus.PreferenceUpdated -> StatusCalloutState(
            title = "Display preference updated",
            body = if (status.showSignalsOnHome) {
                "Signal previews will appear on the overview screen."
            } else {
                "Signal previews are hidden from the overview screen."
            },
            tone = CalloutTone.SUCCESS,
        )

        is StorageStatus.Failed -> StatusCalloutState(
            title = "Encrypted storage failed",
            body = status.message,
            tone = CalloutTone.ERROR,
        )
    }
}
