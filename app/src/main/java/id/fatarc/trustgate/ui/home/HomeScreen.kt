package id.fatarc.trustgate.ui.home

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import id.fatarc.trustgate.domain.risk.DeviceRiskLevel
import id.fatarc.trustgate.domain.risk.DeviceRiskReport
import id.fatarc.trustgate.domain.risk.RiskSignal
import id.fatarc.trustgate.domain.risk.SignalCategory
import id.fatarc.trustgate.domain.risk.SignalSeverity
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
import id.fatarc.trustgate.ui.SecondaryActionButton
import id.fatarc.trustgate.ui.SigningStatus
import id.fatarc.trustgate.ui.StatusCallout
import id.fatarc.trustgate.ui.StatusCalloutState
import id.fatarc.trustgate.ui.StorageStatus
import id.fatarc.trustgate.ui.SummaryPanel
import id.fatarc.trustgate.ui.TrustGateScreen
import id.fatarc.trustgate.ui.TrustGateSpacing
import id.fatarc.trustgate.ui.TrustGateUiState
import id.fatarc.trustgate.ui.asHumanLabel
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
    val overview = buildOverviewState(uiState)
    val strongestSignals = uiState.risk.report.strongestSignals()

    TrustGateScreen {
        item {
            SummaryPanel(
                eyebrow = "Current verdict",
                title = overview.title,
                supporting = overview.body,
                tone = overview.tone,
            ) {
                uiState.risk.report?.let { report ->
                    RiskBadge(level = report.level)
                    KeyValueRow(label = "Risk level", value = report.level.asLabel())
                    KeyValueRow(label = "Risk score", value = report.score.toString())
                    KeyValueRow(
                        label = "Assessment source",
                        value = when (uiState.risk.source) {
                            RiskReportSource.LIVE -> "Live device checks"
                            RiskReportSource.DEMO -> "Sample risk profile"
                        },
                    )
                    KeyValueRow(
                        label = "Assessed at",
                        value = report.assessedAt.toString(),
                        monospace = true,
                    )
                }
                PrimaryActionButton(
                    label = if (uiState.risk.isLoading) "Running device checks" else "Run device checks again",
                    onClick = onRefreshRisk,
                    enabled = !uiState.risk.isLoading,
                )
                uiState.risk.errorMessage?.let { message ->
                    StatusCallout(
                        state = StatusCalloutState(
                            title = "Assessment error",
                            body = message,
                            tone = CalloutTone.ERROR,
                        ),
                    )
                }
            }
        }

        item {
            SectionBlock(
                title = "Strongest reasons",
                description = "The overview focuses on the signals that most affect the current verdict.",
            ) {
                DetailSurface {
                    if (strongestSignals.isEmpty()) {
                        StatusCallout(
                            state = StatusCalloutState(
                                title = "No strong indicators detected",
                                body = "The current result does not show root, emulator, or debugger signals strong enough to raise the trust level.",
                                tone = CalloutTone.SUCCESS,
                            ),
                        )
                    } else {
                        DividerList {
                            strongestSignals.forEachIndexed { index, signal ->
                                SignalRow(signal = signal)
                                if (index != strongestSignals.lastIndex) {
                                    SectionDivider()
                                }
                            }
                        }
                    }
                }
            }
        }

        item {
            SectionBlock(
                title = "What to do next",
                description = "The next step depends on whether this result is acceptable for the policy you are testing.",
            ) {
                StatusCallout(state = nextStepState(uiState))
                DividerList {
                    DemoDestinationButton(
                        title = "Inspect risk signals",
                        description = "Review every check grouped by root, emulator, debugger, and installer context.",
                        onClick = onOpenRiskDetails,
                    )
                    DemoDestinationButton(
                        title = "Run the sensitive action gate",
                        description = "Exercise the allow, confirm, and block paths against the current risk result.",
                        onClick = onOpenPaymentDemo,
                    )
                    DemoDestinationButton(
                        title = "Review request signing",
                        description = "Generate a deterministic request and inspect the canonical payload and headers.",
                        onClick = onOpenSigningDemo,
                    )
                    DemoDestinationButton(
                        title = "Inspect secure storage",
                        description = "Confirm which demo values are written locally and which are deliberately omitted.",
                        onClick = onOpenStorageDemo,
                    )
                    DemoDestinationButton(
                        title = "Read the security event log",
                        description = "See the local audit trail for assessments and action outcomes.",
                        onClick = onOpenEvents,
                    )
                    DemoDestinationButton(
                        title = "Read scope and limits",
                        description = "Review what the app demonstrates and where server-side controls are still required.",
                        onClick = onOpenAbout,
                    )
                }
            }
        }

        item {
            SectionBlock(
                title = "Recent activity",
                description = "These summaries show the last meaningful outcomes from the supporting demo workflows.",
            ) {
                DetailSurface {
                    DividerList {
                        ActivityRow(state = paymentSummary(uiState))
                        SectionDivider()
                        ActivityRow(state = signingSummary(uiState))
                        SectionDivider()
                        ActivityRow(state = storageSummary(uiState))
                        SectionDivider()
                        KeyValueRow(
                            label = "Recorded security events",
                            value = uiState.securityEvents.size.toString(),
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun SignalRow(signal: RiskSignal) {
    EvidenceRow(
        title = signal.name,
        summary = if (signal.detected) {
            signal.explanation
        } else {
            "This indicator is currently clear."
        },
        supporting = "${signal.category.name.asHumanLabel()} \u00b7 ${signal.severity.name.asHumanLabel()} severity",
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
}

@Composable
private fun ActivityRow(state: StatusCalloutState) {
    EvidenceRow(
        title = state.title,
        summary = state.body,
        trailing = {
            Text(
                text = when (state.tone) {
                    CalloutTone.NEUTRAL -> "Info"
                    CalloutTone.SUCCESS -> "OK"
                    CalloutTone.WARNING -> "Review"
                    CalloutTone.ERROR -> "Blocked"
                },
                style = MaterialTheme.typography.labelLarge,
                color = when (state.tone) {
                    CalloutTone.NEUTRAL -> MaterialTheme.colorScheme.onSurfaceVariant
                    CalloutTone.SUCCESS -> MaterialTheme.colorScheme.primary
                    CalloutTone.WARNING -> MaterialTheme.colorScheme.tertiary
                    CalloutTone.ERROR -> MaterialTheme.colorScheme.error
                },
            )
        },
    )
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

private fun DeviceRiskReport?.strongestSignals(): List<RiskSignal> {
    return this?.signals
        ?.filter { it.detected }
        ?.sortedWith(
            compareByDescending<RiskSignal> { it.severity.weight }
                .thenBy { categoryPriority(it.category) }
                .thenBy { it.name },
        )
        ?.take(3)
        .orEmpty()
}

private fun categoryPriority(category: SignalCategory): Int = when (category) {
    SignalCategory.ROOT -> 0
    SignalCategory.DEBUGGER -> 1
    SignalCategory.EMULATOR -> 2
    SignalCategory.INSTALLER -> 3
}

private fun buildOverviewState(uiState: TrustGateUiState): OverviewState {
    val report = uiState.risk.report
    return when {
        uiState.risk.isLoading && report == null -> OverviewState(
            title = "Running device checks",
            body = "The app is collecting device signals and building the current trust result.",
            tone = CalloutTone.NEUTRAL,
        )

        report == null && uiState.risk.errorMessage != null -> OverviewState(
            title = "Assessment unavailable",
            body = "The last attempt did not complete. Review the error and retry the device checks.",
            tone = CalloutTone.ERROR,
        )

        report == null -> OverviewState(
            title = "No current result",
            body = "Run the device checks to produce a trust verdict and supporting evidence.",
            tone = CalloutTone.NEUTRAL,
        )

        report.level == DeviceRiskLevel.LOW -> OverviewState(
            title = "Device currently meets this policy",
            body = "No strong root, emulator, or debugger signals were detected in the current assessment.",
            tone = CalloutTone.SUCCESS,
        )

        report.level == DeviceRiskLevel.MEDIUM -> OverviewState(
            title = "Device needs review before protected actions",
            body = "Some signals were detected. The app would require explicit confirmation before allowing the protected demo action.",
            tone = CalloutTone.WARNING,
        )

        else -> OverviewState(
            title = "Device does not meet this policy",
            body = "The current signal set is strong enough to block the protected demo action until the environment is reviewed.",
            tone = CalloutTone.ERROR,
        )
    }
}

private fun nextStepState(uiState: TrustGateUiState): StatusCalloutState {
    val report = uiState.risk.report
    if (report == null) {
        return StatusCalloutState(
            title = "Run a fresh assessment",
            body = "The app needs a current result before it can explain whether the device should be trusted.",
        )
    }

    return when (report.level) {
        DeviceRiskLevel.LOW -> StatusCalloutState(
            title = "Proceed with validation",
            body = if (uiState.risk.source == RiskReportSource.DEMO) {
                "Switch back to live device checks when you are ready to validate the actual environment."
            } else {
                "If you are validating a production-like path, the current device result is suitable for the protected demo flow."
            },
            tone = CalloutTone.SUCCESS,
        )

        DeviceRiskLevel.MEDIUM -> StatusCalloutState(
            title = "Review the detected signals",
            body = "Check whether the result is expected for this test environment, then use the gate screen to confirm the medium-risk path.",
            tone = CalloutTone.WARNING,
        )

        DeviceRiskLevel.HIGH -> StatusCalloutState(
            title = "Investigate before continuing",
            body = "A high-risk result usually means root, debugger, or equivalent signals are present. Resolve those conditions or keep the device limited to non-protected flows.",
            tone = CalloutTone.ERROR,
        )
    }
}

private data class OverviewState(
    val title: String,
    val body: String,
    val tone: CalloutTone,
)

private fun paymentSummary(uiState: TrustGateUiState): StatusCalloutState {
    return when (val decision = uiState.payment.latestDecision) {
        PaymentDecisionState.Idle -> StatusCalloutState(
            title = "Sensitive action not attempted",
            body = "Open the gate screen to test the current trust result against the protected action policy.",
        )

        is PaymentDecisionState.Allowed -> StatusCalloutState(
            title = "Protected action allowed",
            body = "The last payment-like action was allowed because the device evaluated as ${decision.riskLevel.asLabel()}.",
            tone = CalloutTone.SUCCESS,
        )

        is PaymentDecisionState.ConfirmationRequired -> StatusCalloutState(
            title = "Confirmation required",
            body = "The app paused because the current trust result requires explicit operator confirmation.",
            tone = CalloutTone.WARNING,
        )

        is PaymentDecisionState.Confirmed -> StatusCalloutState(
            title = "Protected action confirmed",
            body = "The last medium-risk action was explicitly confirmed and then allowed.",
            tone = CalloutTone.SUCCESS,
        )

        is PaymentDecisionState.Blocked -> StatusCalloutState(
            title = "Protected action blocked",
            body = "The last payment-like action was blocked because the device evaluated as ${decision.riskLevel.asLabel()}.",
            tone = CalloutTone.ERROR,
        )

        is PaymentDecisionState.Cancelled -> StatusCalloutState(
            title = "Confirmation dismissed",
            body = "The pending medium-risk action was cancelled instead of being forced through.",
        )
    }
}

private fun signingSummary(uiState: TrustGateUiState): StatusCalloutState {
    return when (val status = uiState.signing.status) {
        SigningStatus.Idle -> StatusCalloutState(
            title = "No request signed yet",
            body = "Generate a demo request to inspect the canonical payload, hash, and signature headers.",
        )

        is SigningStatus.Signed -> StatusCalloutState(
            title = "Request signed",
            body = "The latest request for ${status.merchantReference} was canonicalized and signed locally.",
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
            body = "The current screen reflects the latest values read back from encrypted storage.",
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
                "Signal previews are visible on the overview screen."
            } else {
                "Signal previews are hidden on the overview screen."
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
