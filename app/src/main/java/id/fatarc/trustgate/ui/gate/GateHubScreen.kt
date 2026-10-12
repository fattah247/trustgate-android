package id.fatarc.trustgate.ui.gate

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.KeyboardArrowRight
import androidx.compose.material.icons.outlined.Key
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.Payments
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import id.fatarc.trustgate.domain.risk.DeviceRiskLevel
import id.fatarc.trustgate.ui.GateMark
import id.fatarc.trustgate.ui.GateState
import id.fatarc.trustgate.ui.GroupedSurface
import id.fatarc.trustgate.ui.gateState
import id.fatarc.trustgate.ui.ListRow
import id.fatarc.trustgate.ui.PaymentDecisionState
import id.fatarc.trustgate.ui.RiskReportSource
import id.fatarc.trustgate.ui.RiskUiState
import id.fatarc.trustgate.ui.RowDivider
import id.fatarc.trustgate.ui.ScreenScaffold
import id.fatarc.trustgate.ui.Section
import id.fatarc.trustgate.ui.SigningStatus
import id.fatarc.trustgate.ui.SimulationBanner
import id.fatarc.trustgate.ui.StorageStatus
import id.fatarc.trustgate.ui.StorageUiState
import id.fatarc.trustgate.ui.TimeFormats
import id.fatarc.trustgate.ui.Tone
import id.fatarc.trustgate.ui.TrustGateSpacing
import id.fatarc.trustgate.ui.TrustGateUiState
import id.fatarc.trustgate.ui.contentColor
import id.fatarc.trustgate.ui.label
import id.fatarc.trustgate.ui.rememberTimeFormats
import id.fatarc.trustgate.ui.tone

@Composable
fun GateHubScreen(
    uiState: TrustGateUiState,
    onResumeLiveChecks: () -> Unit,
    onOpenPaymentAction: () -> Unit,
    onOpenSigning: () -> Unit,
    onOpenStorage: () -> Unit,
) {
    val formats = rememberTimeFormats()

    ScreenScaffold(title = "Gate") {
        uiState.risk.scenarioLevel?.let { level ->
            item(key = "simulation") {
                SimulationBanner(level = level, onResumeLiveChecks = onResumeLiveChecks)
            }
        }

        item(key = "policy") {
            PolicyCard(risk = uiState.risk, formats = formats)
        }

        item(key = "workflows") {
            Section(title = "Workflows") {
                val payment = paymentState(uiState.payment.latestDecision)
                WorkflowRow(
                    title = "Sensitive action",
                    state = payment.first,
                    stateTone = payment.second,
                    icon = Icons.Outlined.Payments,
                    onClick = onOpenPaymentAction,
                )
                RowDivider(startIndent = TrustGateSpacing.listIconInset)
                val signing = signingState(uiState.signing.status)
                WorkflowRow(
                    title = "Request signing",
                    state = signing.first,
                    stateTone = signing.second,
                    icon = Icons.Outlined.Key,
                    onClick = onOpenSigning,
                )
                RowDivider(startIndent = TrustGateSpacing.listIconInset)
                val storage = storageState(uiState.storage)
                WorkflowRow(
                    title = "Secure storage",
                    state = storage.first,
                    stateTone = storage.second,
                    icon = Icons.Outlined.Lock,
                    onClick = onOpenStorage,
                )
            }
        }
    }
}

@Composable
private fun PolicyCard(
    risk: RiskUiState,
    formats: TimeFormats,
) {
    val report = risk.report
    GroupedSurface {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp)
                .semantics(mergeDescendants = true) {},
            horizontalArrangement = Arrangement.spacedBy(16.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            GateMark(
                state = when {
                    report != null -> report.level.gateState()
                    risk.errorMessage != null -> GateState.SHUT
                    else -> GateState.CHECKING
                },
                tone = when {
                    report != null -> report.level.tone()
                    risk.errorMessage != null -> Tone.CRITICAL
                    else -> Tone.NEUTRAL
                },
                contentDescription = null,
                size = 48.dp,
            )
            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                Text(
                    text = when {
                        report != null -> report.level.policySentence()
                        risk.errorMessage != null -> "Protected actions are unavailable"
                        else -> "Checking this device"
                    },
                    style = MaterialTheme.typography.titleMedium,
                )
                Text(
                    text = when {
                        report == null && risk.errorMessage != null -> "The device check failed. It runs again when you check from Overview or start an action."
                        report == null -> "The policy appears once the check finishes."
                        risk.source == RiskReportSource.SCENARIO -> "${report.level.label()} \u00b7 simulated profile"
                        else -> "${report.level.label()} \u00b7 Live check \u00b7 ${formats.dayAndTime(report.assessedAt)}"
                    },
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun WorkflowRow(
    title: String,
    state: String,
    stateTone: Tone,
    icon: ImageVector,
    onClick: () -> Unit,
) {
    ListRow(
        headline = title,
        supporting = state,
        supportingColor = if (stateTone == Tone.NEUTRAL) Color.Unspecified else stateTone.contentColor(),
        leadingIcon = icon,
        trailing = {
            Icon(
                imageVector = Icons.AutoMirrored.Outlined.KeyboardArrowRight,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        },
        onClickLabel = "Open",
        onClick = onClick,
    )
}

private fun DeviceRiskLevel.policySentence(): String = when (this) {
    DeviceRiskLevel.LOW -> "Protected actions are allowed"
    DeviceRiskLevel.MEDIUM -> "Protected actions need confirmation"
    DeviceRiskLevel.HIGH -> "Protected actions are blocked"
}

private fun paymentState(decision: PaymentDecisionState): Pair<String, Tone> = when (decision) {
    PaymentDecisionState.Idle -> "Not run yet" to Tone.NEUTRAL
    is PaymentDecisionState.Allowed -> "Last run: allowed" to Tone.POSITIVE
    is PaymentDecisionState.ConfirmationRequired -> "Waiting for confirmation" to Tone.CAUTION
    is PaymentDecisionState.Confirmed -> "Last run: allowed after confirmation" to Tone.POSITIVE
    is PaymentDecisionState.Blocked -> "Last run: blocked" to Tone.CRITICAL
    is PaymentDecisionState.Cancelled -> "Last run: cancelled" to Tone.NEUTRAL
}

private fun signingState(status: SigningStatus): Pair<String, Tone> = when (status) {
    SigningStatus.Idle -> "No request signed yet" to Tone.NEUTRAL
    is SigningStatus.Signed -> "Signed ${status.merchantReference}" to Tone.NEUTRAL
    is SigningStatus.Failed -> "Signing failed" to Tone.CRITICAL
}

private fun storageState(storage: StorageUiState): Pair<String, Tone> = when {
    storage.status is StorageStatus.Failed -> "Encrypted storage unavailable" to Tone.CRITICAL
    storage.snapshot.sessionToken != null -> "Reference values saved" to Tone.NEUTRAL
    else -> "Nothing saved yet" to Tone.NEUTRAL
}
