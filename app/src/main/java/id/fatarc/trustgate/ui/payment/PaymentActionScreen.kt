package id.fatarc.trustgate.ui.payment

import android.os.Build
import android.view.HapticFeedbackConstants
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
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Block
import androidx.compose.material.icons.outlined.Cancel
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material.icons.outlined.ErrorOutline
import androidx.compose.material.icons.outlined.PendingActions
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.os.ConfigurationCompat
import id.fatarc.trustgate.domain.risk.DeviceRiskLevel
import id.fatarc.trustgate.domain.signing.ReferencePayment
import id.fatarc.trustgate.domain.signing.KeyRole
import id.fatarc.trustgate.ui.GateMark
import id.fatarc.trustgate.ui.GateState
import id.fatarc.trustgate.ui.GroupedSurface
import id.fatarc.trustgate.ui.InfoRow
import id.fatarc.trustgate.ui.ListRow
import id.fatarc.trustgate.ui.NoticeAction
import id.fatarc.trustgate.ui.NoticeCard
import id.fatarc.trustgate.ui.PaymentDecisionState
import id.fatarc.trustgate.ui.PaymentUiState
import id.fatarc.trustgate.ui.RiskReportSource
import id.fatarc.trustgate.ui.RiskUiState
import id.fatarc.trustgate.ui.RowDivider
import id.fatarc.trustgate.ui.ScreenScaffold
import id.fatarc.trustgate.ui.Section
import id.fatarc.trustgate.ui.SectionFooter
import id.fatarc.trustgate.ui.SectionHeader
import id.fatarc.trustgate.ui.SensitiveScreen
import id.fatarc.trustgate.ui.Submission
import id.fatarc.trustgate.ui.SwitchRow
import id.fatarc.trustgate.ui.TimeFormats
import id.fatarc.trustgate.ui.Tone
import id.fatarc.trustgate.ui.TrustGateSpacing
import id.fatarc.trustgate.ui.TrustGateUiState
import id.fatarc.trustgate.ui.contentColor
import id.fatarc.trustgate.ui.formatMinorAmount
import id.fatarc.trustgate.ui.icon
import id.fatarc.trustgate.ui.label
import id.fatarc.trustgate.ui.policyLabel
import id.fatarc.trustgate.ui.rememberTimeFormats
import id.fatarc.trustgate.ui.signing.sentence
import id.fatarc.trustgate.ui.tone
import java.util.Locale

@Composable
fun PaymentActionScreen(
    uiState: TrustGateUiState,
    onNavigateUp: () -> Unit,
    onAttemptPayment: () -> Unit,
    onSetScenarioRiskLevel: (DeviceRiskLevel?) -> Unit,
    onSetSimulateLostResponse: (Boolean) -> Unit,
    onOpenSignals: () -> Unit,
    onInspectRequest: () -> Unit,
) {
    val formats = rememberTimeFormats()
    val risk = uiState.risk

    SensitiveScreen()
    DecisionHaptics(payment = uiState.payment)

    ScreenScaffold(
        title = "Sensitive action",
        onNavigateUp = onNavigateUp,
    ) {
        // No simulation banner here: the risk source control below already shows it, and an item
        // inserted above the first visible one would land off screen.
        item(key = "action") {
            ActionCard(risk = risk, payment = uiState.payment, onAttemptPayment = onAttemptPayment)
        }

        if (uiState.payment.latestDecision != PaymentDecisionState.Idle) {
            item(key = "result") {
                DecisionResult(
                    payment = uiState.payment,
                    formats = formats,
                    onOpenSignals = onOpenSignals,
                    onInspectRequest = onInspectRequest,
                    modifier = Modifier.animateItem(),
                )
            }
        }

        item(key = "source") {
            RiskSourcePicker(
                selectedLevel = risk.scenarioLevel,
                onSelectLevel = onSetScenarioRiskLevel,
            )
        }

        item(key = "reliability") {
            Section(
                title = "Network",
                footer = "Each payment carries an idempotency key. When a response is lost, the app sends the same " +
                    "signed request again and the backend answers with the original payment instead of charging twice.",
            ) {
                SwitchRow(
                    title = "Lose the first response",
                    supporting = "The backend processes the payment, but its reply never arrives.",
                    checked = uiState.simulateLostResponse,
                    onCheckedChange = onSetSimulateLostResponse,
                )
            }
        }

        item(key = "policy") {
            Section(
                title = "Policy",
                footer = "The reference backend makes this decision, not the app, and says which key must sign the request.",
            ) {
                DeviceRiskLevel.entries.forEachIndexed { index, level ->
                    val isCurrent = risk.report?.level == level
                    ListRow(
                        headline = "${level.label()}: ${level.policyLabel().lowercase()}",
                        supporting = level.policyDescription(),
                        supportingColor = MaterialTheme.colorScheme.onSurfaceVariant,
                        leadingIcon = level.icon,
                        leadingTint = level.tone().contentColor(),
                        trailing = if (isCurrent) {
                            {
                                Text(
                                    text = "Current",
                                    style = MaterialTheme.typography.labelMedium,
                                    color = MaterialTheme.colorScheme.primary,
                                )
                            }
                        } else {
                            null
                        },
                    )
                    if (index != DeviceRiskLevel.entries.lastIndex) {
                        RowDivider(startIndent = TrustGateSpacing.listIconInset)
                    }
                }
            }
        }
    }
}

@Composable
private fun ActionCard(
    risk: RiskUiState,
    payment: PaymentUiState,
    onAttemptPayment: () -> Unit,
) {
    val report = risk.report
    val locale = ConfigurationCompat.getLocales(LocalConfiguration.current)[0] ?: Locale.getDefault()
    val gate = payment.latestDecision.gateState()
    GroupedSurface(shape = MaterialTheme.shapes.large) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(start = 16.dp, top = 20.dp, end = 16.dp, bottom = 12.dp),
            horizontalArrangement = Arrangement.spacedBy(16.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            // The gate acts out the decision: it swings open, waits ajar, or locks.
            GateMark(
                state = gate,
                tone = payment.latestDecision.tone() ?: report?.level?.tone() ?: Tone.NEUTRAL,
                contentDescription = null,
                size = 64.dp,
            )
            Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(
                    text = formatMinorAmount(ReferencePayment.AMOUNT_MINOR, ReferencePayment.CURRENCY, locale),
                    style = MaterialTheme.typography.headlineSmall,
                )
                Text(
                    text = "Reference payment · ${ReferencePayment.payload().merchantReference}",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        Text(
            text = "Running it checks the device again and asks the backend to decide. If it's allowed, the app " +
                "signs the payment with a key held in Android Keystore and submits it.",
            modifier = Modifier.padding(start = 16.dp, end = 16.dp, bottom = 16.dp),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        RowDivider()
        InfoRow(
            label = "This device",
            value = when {
                risk.errorMessage != null -> "Check failed"
                report != null && risk.source == RiskReportSource.SCENARIO -> "${report.level.label()} (simulated)"
                report != null -> report.level.label()
                else -> "Checking…"
            },
            valueColor = when {
                risk.errorMessage != null -> Tone.CRITICAL.contentColor()
                report != null -> report.level.tone().contentColor()
                else -> MaterialTheme.colorScheme.onSurfaceVariant
            },
        )
        RowDivider()
        InfoRow(
            label = "Gate response",
            value = report?.level?.takeIf { risk.errorMessage == null }?.policyLabel() ?: "—",
        )
        Button(
            onClick = onAttemptPayment,
            enabled = !risk.isLoading && payment.latestDecision !is PaymentDecisionState.ConfirmationRequired,
            modifier = Modifier
                .fillMaxWidth()
                .padding(start = 16.dp, top = 8.dp, end = 16.dp, bottom = 16.dp),
        ) {
            Text("Run protected action")
        }
    }
}

@Composable
private fun DecisionResult(
    payment: PaymentUiState,
    formats: TimeFormats,
    onOpenSignals: () -> Unit,
    onInspectRequest: () -> Unit,
    modifier: Modifier = Modifier,
) {
    AnimatedContent(
        targetState = payment,
        contentKey = { it.decidedAt to (it.submission != null) },
        transitionSpec = { fadeIn(tween(220, delayMillis = 60)) togetherWith fadeOut(tween(60)) },
        modifier = modifier.semantics { liveRegion = LiveRegionMode.Polite },
        label = "decisionResult",
    ) { current ->
        val outcome = current.outcome() ?: return@AnimatedContent
        NoticeCard(
            title = outcome.title,
            body = outcome.body,
            caption = current.decidedAt?.let(formats::preciseTime),
            tone = outcome.tone,
            icon = outcome.icon,
            action = when {
                current.latestDecision is PaymentDecisionState.Blocked ->
                    NoticeAction(label = "View signals", onClick = onOpenSignals)

                current.submission is Submission.Charged || current.submission is Submission.Refused ->
                    NoticeAction(label = "Inspect request", onClick = onInspectRequest)

                else -> null
            },
        )
    }
}

/** A light confirm or reject tap when the gate decides, the way a physical latch would feel. */
@Composable
private fun DecisionHaptics(payment: PaymentUiState) {
    val view = LocalView.current
    // Saved so returning to the screen or rotating doesn't replay the tap for an old decision.
    var lastFelt by rememberSaveable { mutableStateOf<String?>(null) }
    LaunchedEffect(payment.decidedAt) {
        val key = payment.decidedAt?.toString() ?: return@LaunchedEffect
        if (key == lastFelt) return@LaunchedEffect
        lastFelt = key
        val confirm = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) HapticFeedbackConstants.CONFIRM else HapticFeedbackConstants.VIRTUAL_KEY
        val reject = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) HapticFeedbackConstants.REJECT else HapticFeedbackConstants.LONG_PRESS
        when (payment.latestDecision) {
            is PaymentDecisionState.Allowed,
            is PaymentDecisionState.Confirmed,
            -> view.performHapticFeedback(confirm)

            is PaymentDecisionState.Blocked -> view.performHapticFeedback(reject)
            else -> Unit
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun RiskSourcePicker(
    selectedLevel: DeviceRiskLevel?,
    onSelectLevel: (DeviceRiskLevel?) -> Unit,
) {
    val options: List<Pair<DeviceRiskLevel?, String>> = listOf(
        null to "Live",
        DeviceRiskLevel.LOW to "Low",
        DeviceRiskLevel.MEDIUM to "Medium",
        DeviceRiskLevel.HIGH to "High",
    )
    Column {
        SectionHeader(title = "Risk source")
        Spacer(Modifier.height(4.dp))
        SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
            options.forEachIndexed { index, (level, label) ->
                SegmentedButton(
                    selected = selectedLevel == level,
                    onClick = { onSelectLevel(level) },
                    shape = SegmentedButtonDefaults.itemShape(index = index, count = options.size),
                    // The check mark doesn't fit four segments on a phone; the fill marks the selection.
                    icon = {},
                    label = { Text(label, maxLines = 1, overflow = TextOverflow.Ellipsis) },
                )
            }
        }
        SectionFooter(
            text = "Low, Medium, and High simulate a device profile across the app until you switch back to Live.",
        )
    }
}

private fun PaymentDecisionState.gateState(): GateState = when (this) {
    PaymentDecisionState.Idle,
    is PaymentDecisionState.Cancelled,
    -> GateState.SHUT

    is PaymentDecisionState.Allowed,
    is PaymentDecisionState.Confirmed,
    -> GateState.OPEN

    is PaymentDecisionState.ConfirmationRequired -> GateState.AJAR
    is PaymentDecisionState.Blocked -> GateState.LOCKED
}

private fun PaymentDecisionState.tone(): Tone? = when (this) {
    PaymentDecisionState.Idle -> null
    is PaymentDecisionState.Allowed,
    is PaymentDecisionState.Confirmed,
    -> Tone.POSITIVE

    is PaymentDecisionState.ConfirmationRequired -> Tone.CAUTION
    is PaymentDecisionState.Blocked -> Tone.CRITICAL
    is PaymentDecisionState.Cancelled -> Tone.NEUTRAL
}

private data class Outcome(
    val title: String,
    val body: String,
    val tone: Tone,
    val icon: ImageVector,
)

private fun PaymentUiState.outcome(): Outcome? = when (val decision = latestDecision) {
    PaymentDecisionState.Idle -> null

    is PaymentDecisionState.Allowed -> allowedOutcome(
        title = "Action allowed",
        reason = "The device was ${decision.riskLevel.label().lowercase()}, so no extra step was needed.",
    )

    is PaymentDecisionState.ConfirmationRequired -> Outcome(
        title = "Waiting for confirmation",
        body = "The device was ${decision.riskLevel.label().lowercase()}, so the action is paused until you confirm.",
        tone = Tone.CAUTION,
        icon = Icons.Outlined.PendingActions,
    )

    is PaymentDecisionState.Confirmed -> allowedOutcome(
        title = "Allowed after confirmation",
        reason = "You confirmed the action on a ${decision.riskLevel.label().lowercase()} device.",
    )

    is PaymentDecisionState.Blocked -> Outcome(
        title = "Action blocked",
        body = "The device was ${decision.riskLevel.label().lowercase()}, so nothing was signed or sent.",
        tone = Tone.CRITICAL,
        icon = Icons.Outlined.Block,
    )

    is PaymentDecisionState.Cancelled -> Outcome(
        title = "Action cancelled",
        body = decision.problem?.let { "The confirmation stopped: $it Nothing was signed or sent." }
            ?: "You cancelled at the confirmation step, so nothing was signed or sent.",
        tone = Tone.NEUTRAL,
        icon = Icons.Outlined.Cancel,
    )
}

/** The gate let the action through; what matters next is whether the payment it sent was charged. */
private fun PaymentUiState.allowedOutcome(title: String, reason: String): Outcome = when (val sent = submission) {
    null -> Outcome(
        title = title,
        body = "$reason Signing and sending the payment\u2026",
        tone = Tone.POSITIVE,
        icon = Icons.Outlined.CheckCircle,
    )

    is Submission.NotSent -> Outcome(
        title = "Allowed, but not sent",
        body = "$reason The payment couldn't be signed: ${sent.message}",
        tone = Tone.CRITICAL,
        icon = Icons.Outlined.ErrorOutline,
    )

    is Submission.Charged -> Outcome(
        title = title,
        body = buildString {
            append(reason)
            append(" Payment ${sent.paymentId} was accepted, signed by the ")
            append(if (sent.signedWith == KeyRole.STEP_UP) "step-up key your confirmation unlocked." else "device key.")
            if (sent.lostResponses > 0) {
                append(" The first response was lost; the retry returned the same payment, so it was charged once.")
            }
        },
        tone = Tone.POSITIVE,
        icon = Icons.Outlined.CheckCircle,
    )

    is Submission.Refused -> Outcome(
        title = "Allowed, but refused on arrival",
        body = "$reason The backend refused the payment: ${sent.reason.sentence()}",
        tone = Tone.CRITICAL,
        icon = Icons.Outlined.ErrorOutline,
    )

    is Submission.NoResponse -> Outcome(
        title = "No response",
        body = "$reason No answer came back after ${sent.attempts} tries, so the outcome is unknown. Retrying is " +
            "safe: the same idempotency key can never be charged twice.",
        tone = Tone.CAUTION,
        icon = Icons.Outlined.ErrorOutline,
    )
}

private fun DeviceRiskLevel.policyDescription(): String = when (this) {
    DeviceRiskLevel.LOW -> "Runs without an extra step."
    DeviceRiskLevel.MEDIUM -> "Signed only after the person unlocks the step-up key with their screen lock or biometrics."
    DeviceRiskLevel.HIGH -> "Stopped until the device is reviewed."
}
