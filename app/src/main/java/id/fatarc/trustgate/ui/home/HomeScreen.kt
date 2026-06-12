package id.fatarc.trustgate.ui.home

import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import id.fatarc.trustgate.domain.events.SecurityEvent
import id.fatarc.trustgate.domain.events.SecurityEventType
import id.fatarc.trustgate.domain.risk.DeviceRiskLevel
import id.fatarc.trustgate.domain.risk.DeviceRiskReport
import id.fatarc.trustgate.domain.risk.RiskSignal
import id.fatarc.trustgate.domain.risk.SignalCategory
import id.fatarc.trustgate.ui.CalloutTone
import id.fatarc.trustgate.ui.DetailSurface
import id.fatarc.trustgate.ui.DividerList
import id.fatarc.trustgate.ui.EvidenceRow
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
import id.fatarc.trustgate.ui.TrustGateScreen
import id.fatarc.trustgate.ui.TrustGateUiState
import id.fatarc.trustgate.ui.asLabel
import id.fatarc.trustgate.ui.formatAuditTimestamp
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

@Composable
fun HomeScreen(
    uiState: TrustGateUiState,
    onRefreshRisk: () -> Unit,
    onOpenEvents: () -> Unit,
) {
    val overview = buildOverviewState(uiState)
    val strongestSignals = uiState.risk.report.strongestSignals()
    val recentEvents = uiState.securityEvents.asReversed().take(8)

    TrustGateScreen {
        item {
            AnimatedVerdictPanel(
                uiState = uiState,
                overview = overview,
                strongestSignals = strongestSignals,
                onRefreshRisk = onRefreshRisk,
            )
        }

        item {
            SectionBlock(
                title = "Audit log",
                description = "Latest events recorded on this device.",
            ) {
                if (recentEvents.isEmpty()) {
                    StatusCallout(
                        state = StatusCalloutState(
                            title = "No local history yet",
                            body = "Run the device checks or complete one of the workflows to populate the local audit timeline.",
                        ),
                    )
                } else {
                    DetailSurface {
                        recentEvents.take(4).forEachIndexed { index, event ->
                            ActivityHistoryRow(event = event)
                            if (index != recentEvents.take(4).lastIndex) {
                                SectionDivider()
                            }
                        }
                    }
                    SecondaryActionButton(
                        title = "Open full event history",
                        description = "Go to the dedicated Security Event Log screen for the complete audit trail.",
                        onClick = onOpenEvents,
                    )
                }
            }
        }

        item {
            SectionBlock(
                title = "Workflow status",
                description = "Last known result from each gate workflow.",
            ) {
                DetailSurface {
                    DividerList {
                        ActivityRow(state = paymentSummary(uiState))
                        SectionDivider()
                        ActivityRow(state = signingSummary(uiState))
                        SectionDivider()
                        ActivityRow(state = storageSummary(uiState))
                    }
                }
            }
        }
    }
}

@Composable
private fun AnimatedVerdictPanel(
    uiState: TrustGateUiState,
    overview: OverviewState,
    strongestSignals: List<RiskSignal>,
    onRefreshRisk: () -> Unit,
) {
    val report = uiState.risk.report
    val accent = toneAccentColor(overview.tone)
    val reveal = remember { Animatable(0f) }

    LaunchedEffect(uiState.risk.isLoading, report?.assessedAt, uiState.risk.errorMessage) {
        reveal.snapTo(0f)
        reveal.animateTo(
            targetValue = 1f,
            animationSpec = tween(durationMillis = 520, easing = FastOutSlowInEasing),
        )
    }

    Column(
        modifier = Modifier.graphicsLayer {
            alpha = reveal.value
            translationY = (1f - reveal.value) * 24f
        }
            .fillMaxWidth()
            .clip(MaterialTheme.shapes.large)
            .background(MaterialTheme.colorScheme.surfaceContainerHigh)
            .border(
                width = 1.dp,
                color = MaterialTheme.colorScheme.outline.copy(alpha = 0.55f),
                shape = MaterialTheme.shapes.large,
            )
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.Top,
        ) {
            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                Text(
                    text = "Device status",
                    style = MaterialTheme.typography.labelLarge,
                    color = accent,
                )
                Text(
                    text = overview.title,
                    style = MaterialTheme.typography.titleLarge,
                )
                Text(
                    text = overview.body,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            report?.let { RiskBadge(level = it.level) }
        }

        SectionDivider()

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            VerdictDataRow(
                modifier = Modifier.weight(1f),
                label = "Score",
                value = report?.score?.toString() ?: "--",
            )
            VerdictDataRow(
                modifier = Modifier.weight(1f),
                label = "Signals",
                value = report?.signals?.count { it.detected }?.toString() ?: "--",
            )
            VerdictDataRow(
                modifier = Modifier.weight(1f),
                label = "Protected flow",
                value = report.actionPolicyLabel(),
                valueColor = accent,
            )
        }

        if (uiState.risk.isLoading) {
            LinearProgressIndicator(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(4.dp)
                    .clip(MaterialTheme.shapes.small),
                color = accent,
                trackColor = accent.copy(alpha = 0.18f),
            )
        } else {
            Text(
                text = buildMetaLine(uiState),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        if (strongestSignals.isNotEmpty()) {
            SectionDivider()
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text(
                    text = "Risk indicators",
                    style = MaterialTheme.typography.titleSmall,
                )
                Text(
                    text = strongestSignals.joinToString(separator = ", ") { it.name },
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }

        PrimaryActionButton(
            label = if (uiState.risk.isLoading) "Running device checks" else "Run device checks again",
            onClick = onRefreshRisk,
            enabled = !uiState.risk.isLoading,
        )
    }
}

@Composable
private fun VerdictDataRow(
    label: String,
    value: String,
    modifier: Modifier = Modifier,
    valueColor: Color = MaterialTheme.colorScheme.onSurface,
) {
    Column(
        modifier = modifier,
        verticalArrangement = Arrangement.spacedBy(2.dp),
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(
            text = value,
            style = MaterialTheme.typography.titleMedium,
            color = valueColor,
        )
    }
}

private fun buildMetaLine(uiState: TrustGateUiState): String {
    val assessedAt = uiState.risk.report?.assessedAt?.toString()?.let(::formatAuditTimestamp) ?: "No result yet"
    val source = when (uiState.risk.source) {
        RiskReportSource.LIVE -> "Live device checks"
        RiskReportSource.SCENARIO -> "Scenario profile"
    }
    return "$assessedAt · $source"
}

@Composable
private fun ActivityHistoryRow(event: SecurityEvent) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 2.dp),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
        verticalAlignment = Alignment.Top,
    ) {
        Column(
            modifier = Modifier.width(54.dp),
            verticalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            Text(
                text = event.dateStamp(),
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.onSurface,
            )
            Text(
                text = event.timeStamp(),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Column(
            modifier = Modifier.weight(1f),
            verticalArrangement = Arrangement.spacedBy(5.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.Top,
            ) {
                Column(
                    modifier = Modifier.weight(1f),
                    verticalArrangement = Arrangement.spacedBy(3.dp),
                ) {
                    Text(
                        text = event.historyLabel(),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Text(
                        text = event.headline(),
                        style = MaterialTheme.typography.titleSmall,
                    )
                }
                event.riskLevel?.let { RiskBadge(level = it) }
            }
            Text(
                text = event.message,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
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
                    CalloutTone.SUCCESS -> "Ready"
                    CalloutTone.WARNING -> "Review"
                    CalloutTone.ERROR -> "Blocked"
                },
                style = MaterialTheme.typography.labelLarge,
                color = toneAccentColor(state.tone),
            )
        },
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
        ?.take(2)
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
            title = "Checking this device",
            body = "Collecting local signals before deciding whether protected actions can run.",
            tone = CalloutTone.NEUTRAL,
        )

        report == null && uiState.risk.errorMessage != null -> OverviewState(
            title = "Check failed",
            body = "The last attempt did not complete. Review the error and run the checks again.",
            tone = CalloutTone.ERROR,
        )

        report == null -> OverviewState(
            title = "No device result",
            body = "Run the checks to evaluate this device before using protected workflows.",
            tone = CalloutTone.NEUTRAL,
        )

        report.level == DeviceRiskLevel.LOW -> OverviewState(
            title = "Device trusted",
            body = "No strong root, emulator, or debugger signals were found in this check.",
            tone = CalloutTone.SUCCESS,
        )

        report.level == DeviceRiskLevel.MEDIUM -> OverviewState(
            title = "Review required",
            body = "Some signals were found. Sensitive actions should ask for confirmation.",
            tone = CalloutTone.WARNING,
        )

        else -> OverviewState(
            title = "High risk device",
            body = "Detected signals are strong enough to block protected actions.",
            tone = CalloutTone.ERROR,
        )
    }
}

private data class OverviewState(
    val title: String,
    val body: String,
    val tone: CalloutTone,
)

private fun DeviceRiskReport?.actionPolicyLabel(): String = when (this?.level) {
    DeviceRiskLevel.LOW -> "Allow"
    DeviceRiskLevel.MEDIUM -> "Confirm"
    DeviceRiskLevel.HIGH -> "Block"
    null -> "--"
}

private fun SecurityEvent.historyLabel(): String = when (type) {
    SecurityEventType.DEVICE_RISK_ASSESSED,
    SecurityEventType.ROOT_SIGNAL_FOUND,
    SecurityEventType.EMULATOR_SIGNAL_FOUND,
    SecurityEventType.DEBUGGER_ATTACHED,
    -> "Assessment history"

    SecurityEventType.SENSITIVE_ACTION_ALLOWED,
    SecurityEventType.SENSITIVE_ACTION_REQUIRES_CONFIRMATION,
    SecurityEventType.SENSITIVE_ACTION_ALLOWED_AFTER_CONFIRMATION,
    SecurityEventType.SENSITIVE_ACTION_BLOCKED,
    -> "Protected action history"

    SecurityEventType.REQUEST_SIGNED -> "Signing history"
    SecurityEventType.SECURE_VALUE_STORED -> "Storage history"
}

private fun SecurityEvent.headline(): String = when (type) {
    SecurityEventType.DEVICE_RISK_ASSESSED -> "Device assessment completed"
    SecurityEventType.ROOT_SIGNAL_FOUND -> "Root signal detected"
    SecurityEventType.EMULATOR_SIGNAL_FOUND -> "Emulator signal detected"
    SecurityEventType.DEBUGGER_ATTACHED -> "Debugger attached"
    SecurityEventType.SENSITIVE_ACTION_ALLOWED -> "Protected action allowed"
    SecurityEventType.SENSITIVE_ACTION_REQUIRES_CONFIRMATION -> "Protected action paused for confirmation"
    SecurityEventType.SENSITIVE_ACTION_ALLOWED_AFTER_CONFIRMATION -> "Protected action allowed after confirmation"
    SecurityEventType.SENSITIVE_ACTION_BLOCKED -> "Protected action blocked"
    SecurityEventType.REQUEST_SIGNED -> "Request signed locally"
    SecurityEventType.SECURE_VALUE_STORED -> "Encrypted values stored"
}

private fun SecurityEvent.calloutTone(): CalloutTone = when (type) {
    SecurityEventType.SENSITIVE_ACTION_BLOCKED -> CalloutTone.ERROR
    SecurityEventType.SENSITIVE_ACTION_REQUIRES_CONFIRMATION -> CalloutTone.WARNING
    SecurityEventType.ROOT_SIGNAL_FOUND,
    SecurityEventType.EMULATOR_SIGNAL_FOUND,
    SecurityEventType.DEBUGGER_ATTACHED,
    -> if (riskLevel == DeviceRiskLevel.HIGH) CalloutTone.ERROR else CalloutTone.WARNING

    else -> CalloutTone.SUCCESS
}

private fun toneAccentColor(tone: CalloutTone): Color = when (tone) {
    CalloutTone.NEUTRAL -> Color(0xFFE06E98)
    CalloutTone.SUCCESS -> Color(0xFF76C98E)
    CalloutTone.WARNING -> Color(0xFFF18F7E)
    CalloutTone.ERROR -> Color(0xFFE96F63)
}

private fun SecurityEvent.dateStamp(): String = formatInstantPart(timestamp, DateFormatter)

private fun SecurityEvent.timeStamp(): String = formatInstantPart(timestamp, TimeFormatter)

private fun formatInstantPart(
    rawTimestamp: String,
    formatter: DateTimeFormatter,
): String {
    return runCatching {
        Instant.parse(rawTimestamp)
            .atZone(ZoneId.systemDefault())
            .format(formatter)
    }.getOrDefault("--")
}

private val DateFormatter: DateTimeFormatter = DateTimeFormatter.ofPattern("dd MMM")
private val TimeFormatter: DateTimeFormatter = DateTimeFormatter.ofPattern("HH:mm")

private fun paymentSummary(uiState: TrustGateUiState): StatusCalloutState {
    return when (val decision = uiState.payment.latestDecision) {
        PaymentDecisionState.Idle -> StatusCalloutState(
            title = "No protected action attempted",
            body = "The gate screen has not been used since the current trust result was loaded.",
        )

        is PaymentDecisionState.Allowed -> StatusCalloutState(
            title = "Protected action allowed",
            body = "The current trust result allowed the protected action because the device evaluated as ${decision.riskLevel.asLabel()}.",
            tone = CalloutTone.SUCCESS,
        )

        is PaymentDecisionState.ConfirmationRequired -> StatusCalloutState(
            title = "Confirmation required",
            body = "The current trust result paused the action for explicit operator confirmation.",
            tone = CalloutTone.WARNING,
        )

        is PaymentDecisionState.Confirmed -> StatusCalloutState(
            title = "Protected action confirmed",
            body = "The last medium-risk action was explicitly confirmed and then allowed.",
            tone = CalloutTone.SUCCESS,
        )

        is PaymentDecisionState.Blocked -> StatusCalloutState(
            title = "Protected action blocked",
            body = "The current trust result blocked the action because the device evaluated as ${decision.riskLevel.asLabel()}.",
            tone = CalloutTone.ERROR,
        )

        is PaymentDecisionState.Cancelled -> StatusCalloutState(
            title = "Protected action cancelled",
            body = "The confirmation step was dismissed, so the protected action did not continue.",
        )
    }
}

private fun signingSummary(uiState: TrustGateUiState): StatusCalloutState {
    return when (val status = uiState.signing.status) {
        SigningStatus.Idle -> StatusCalloutState(
            title = "No request signed yet",
            body = "The signing screen has not generated a request since the current session began.",
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
            title = "No encrypted write yet",
            body = "The storage workflow has not written or reloaded reference values in this session.",
        )

        StorageStatus.Loaded -> StatusCalloutState(
            title = "Encrypted snapshot reloaded",
            body = "The storage screen last read back the current encrypted values from local storage.",
            tone = CalloutTone.SUCCESS,
        )

        is StorageStatus.Stored -> StatusCalloutState(
            title = "Encrypted values stored",
            body = "${status.keyCount} reference values were written to local encrypted storage.",
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
