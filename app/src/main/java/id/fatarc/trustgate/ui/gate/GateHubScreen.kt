package id.fatarc.trustgate.ui.gate

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowForward
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import id.fatarc.trustgate.ui.CalloutTone
import id.fatarc.trustgate.ui.DetailSurface
import id.fatarc.trustgate.ui.DividerList
import id.fatarc.trustgate.ui.EvidenceRow
import id.fatarc.trustgate.ui.PaymentDecisionState
import id.fatarc.trustgate.ui.SectionBlock
import id.fatarc.trustgate.ui.SectionDivider
import id.fatarc.trustgate.ui.SigningStatus
import id.fatarc.trustgate.ui.StatusCalloutState
import id.fatarc.trustgate.ui.StorageStatus
import id.fatarc.trustgate.ui.TrustGateScreen
import id.fatarc.trustgate.ui.TrustGateUiState
import id.fatarc.trustgate.ui.WorkflowSummaryPanel

@Composable
fun GateHubScreen(
    uiState: TrustGateUiState,
    onOpenPaymentAction: () -> Unit,
    onOpenSigning: () -> Unit,
    onOpenStorage: () -> Unit,
) {
    val gateState = gateSummary(uiState)

    TrustGateScreen {
        item {
            WorkflowSummaryPanel(
                eyebrow = "Gate",
                title = gateState.title,
                supporting = gateState.body,
                tone = gateState.tone,
            )
        }

        item {
            SectionBlock(
                title = "Workflows",
                description = "Run the protected action, inspect request signing, or verify local storage.",
            ) {
                DetailSurface {
                    DividerList {
                        GateWorkflowRow(
                            title = "Sensitive Action Gate",
                            summary = "Exercise allow, review, and block behavior using the current device result.",
                            state = paymentStateLabel(uiState.payment.latestDecision),
                            onClick = onOpenPaymentAction,
                        )
                        SectionDivider()
                        GateWorkflowRow(
                            title = "Request Signing",
                            summary = "Generate a deterministic request and inspect payload headers.",
                            state = signingStateLabel(uiState.signing.status),
                            onClick = onOpenSigning,
                        )
                        SectionDivider()
                        GateWorkflowRow(
                            title = "Secure Storage",
                            summary = "Review encrypted values stored locally for the current session.",
                            state = storageStateLabel(uiState.storage.status),
                            onClick = onOpenStorage,
                        )
                    }
                }
            }
        }

        item {
            SectionBlock(
                title = "Latest workflow state",
                description = "Current result from each gate-related workflow.",
            ) {
                DetailSurface {
                    DividerList {
                        EvidenceRow(
                            title = "Protected action",
                            summary = paymentStateLabel(uiState.payment.latestDecision),
                        )
                        SectionDivider()
                        EvidenceRow(
                            title = "Request signing",
                            summary = signingStateLabel(uiState.signing.status),
                        )
                        SectionDivider()
                        EvidenceRow(
                            title = "Secure storage",
                            summary = storageStateLabel(uiState.storage.status),
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun GateWorkflowRow(
    title: String,
    summary: String,
    state: String,
    onClick: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(vertical = 2.dp),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(
            modifier = Modifier.weight(1f),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleSmall,
            )
            Text(
                text = summary,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                text = state,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.primary,
            )
        }
        Icon(
            imageVector = Icons.AutoMirrored.Filled.ArrowForward,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.primary,
        )
    }
}

private fun gateSummary(uiState: TrustGateUiState): StatusCalloutState {
    return when (uiState.payment.latestDecision) {
        is PaymentDecisionState.Blocked -> StatusCalloutState(
            title = "Protected action blocked",
            body = "The current device result stops the protected action. Review Signals before continuing.",
            tone = CalloutTone.ERROR,
        )

        is PaymentDecisionState.ConfirmationRequired -> StatusCalloutState(
            title = "Review required",
            body = "The current device result requires explicit confirmation for protected actions.",
            tone = CalloutTone.WARNING,
        )

        is PaymentDecisionState.Allowed,
        is PaymentDecisionState.Confirmed,
        -> StatusCalloutState(
            title = "Gate recently allowed",
            body = "The protected action flow completed with the current device result.",
            tone = CalloutTone.SUCCESS,
        )

        else -> StatusCalloutState(
            title = "Gate ready",
            body = "Choose a workflow to run protected action policy, signing, or encrypted storage.",
        )
    }
}

private fun paymentStateLabel(decision: PaymentDecisionState): String = when (decision) {
    PaymentDecisionState.Idle -> "Not run yet"
    is PaymentDecisionState.Allowed -> "Allowed"
    is PaymentDecisionState.ConfirmationRequired -> "Waiting for confirmation"
    is PaymentDecisionState.Confirmed -> "Allowed after confirmation"
    is PaymentDecisionState.Blocked -> "Blocked"
    is PaymentDecisionState.Cancelled -> "Confirmation cancelled"
}

private fun signingStateLabel(status: SigningStatus): String = when (status) {
    SigningStatus.Idle -> "No request signed"
    is SigningStatus.Signed -> "Signed ${status.merchantReference}"
    is SigningStatus.Failed -> "Signing failed"
}

private fun storageStateLabel(status: StorageStatus): String = when (status) {
    StorageStatus.Idle -> "No encrypted write"
    StorageStatus.Loaded -> "Snapshot loaded"
    is StorageStatus.Stored -> "${status.keyCount} values stored"
    is StorageStatus.PreferenceUpdated -> "Display preference updated"
    is StorageStatus.Failed -> "Storage failed"
}
