package id.fatarc.trustgate.ui.payment

import android.os.Build
import android.view.HapticFeedbackConstants
import androidx.compose.animation.animateContentSize
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Block
import androidx.compose.material.icons.outlined.Cancel
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material.icons.outlined.ErrorOutline
import androidx.compose.material.icons.outlined.RadioButtonUnchecked
import androidx.compose.material.icons.outlined.RemoveCircleOutline
import androidx.compose.material.icons.outlined.WifiOff
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.core.os.ConfigurationCompat
import id.fatarc.trustgate.core.security.ConfirmationMethod
import id.fatarc.trustgate.domain.signing.KeyRole
import id.fatarc.trustgate.domain.signing.ReferencePayment
import id.fatarc.trustgate.ui.ChipFlow
import id.fatarc.trustgate.ui.PaymentDecisionState
import id.fatarc.trustgate.ui.PaymentStage
import id.fatarc.trustgate.ui.PaymentUiState
import id.fatarc.trustgate.ui.RiskUiState
import id.fatarc.trustgate.ui.ScreenScaffold
import id.fatarc.trustgate.ui.SensitiveScreen
import id.fatarc.trustgate.ui.Submission
import id.fatarc.trustgate.ui.Tone
import id.fatarc.trustgate.ui.TrustGateUiState
import id.fatarc.trustgate.ui.containerColor
import id.fatarc.trustgate.ui.contentColor
import id.fatarc.trustgate.ui.flaggedSignals
import id.fatarc.trustgate.ui.formatMinorAmount
import id.fatarc.trustgate.ui.home.MerchantBadge
import id.fatarc.trustgate.ui.onContainerColor
import id.fatarc.trustgate.ui.signing.shortLabel
import id.fatarc.trustgate.ui.theme.TrustGateTheme
import java.util.Locale

@Composable
fun PayScreen(
    uiState: TrustGateUiState,
    onNavigateUp: () -> Unit,
    onPay: () -> Unit,
    onOpenChecks: () -> Unit,
    onOpenRequest: () -> Unit,
) {
    SensitiveScreen()
    DecisionHaptics(uiState.payment)
    val locale = ConfigurationCompat.getLocales(LocalConfiguration.current)[0] ?: Locale.getDefault()
    val amount = formatMinorAmount(ReferencePayment.AMOUNT_MINOR, ReferencePayment.CURRENCY, locale)
    val payment = uiState.payment
    val result = payment.result(amount)

    ScreenScaffold(title = "Pay", onNavigateUp = onNavigateUp) {
        item(key = "order") { OrderSummary(amount) }

        // The outcome goes above the steps so it's the first thing seen when the payment finishes.
        if (result != null) {
            item(key = "result") {
                ResultCard(result = result, reasons = payment.reasons, onOpenChecks = onOpenChecks)
            }
        }

        if (payment.stage == null) {
            // Home starts the payment on the way here; this only shows if that state was lost.
            item(key = "start") {
                Button(onClick = onPay, enabled = uiState.risk.report != null, modifier = Modifier.fillMaxWidth().heightIn(min = 56.dp)) {
                    Text("Pay $amount", style = MaterialTheme.typography.titleMedium)
                }
            }
        } else {
            item(key = "steps") {
                Steps(steps = payment.steps(uiState.risk), modifier = Modifier.animateContentSize())
            }
        }

        if (result != null) {
            item(key = "after") {
                Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.fillMaxWidth()) {
                    FilledTonalButton(onClick = onPay, modifier = Modifier.fillMaxWidth().heightIn(min = 52.dp)) {
                        Text(if (payment.submission is Submission.Charged) "Pay again" else "Try again")
                    }
                    if (uiState.lastRequest != null) {
                        TextButton(onClick = onOpenRequest) { Text("See what was sent") }
                    }
                }
            }
        }
    }
}

@Composable
private fun OrderSummary(amount: String) {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(28.dp),
        color = TrustGateTheme.colors.groupedSurface,
    ) {
        Column(modifier = Modifier.padding(20.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                MerchantBadge()
                Column {
                    Text("TrustGate Store", style = MaterialTheme.typography.titleMedium)
                    Text(
                        "Order ${ReferencePayment.payload().merchantReference}",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            Spacer(Modifier.height(16.dp))
            Text(amount, style = MaterialTheme.typography.displaySmall, fontWeight = FontWeight.SemiBold)
        }
    }
}

private enum class StepState { WAITING, ACTIVE, DONE, FAILED, SKIPPED }

private class Step(val title: String, val state: StepState, val detail: String? = null)

@Composable
private fun Steps(
    steps: List<Step>,
    modifier: Modifier = Modifier,
) {
    Surface(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(28.dp),
        color = TrustGateTheme.colors.groupedSurface,
    ) {
        Column(modifier = Modifier.padding(vertical = 12.dp).semantics { liveRegion = LiveRegionMode.Polite }) {
            steps.forEach { step -> StepRow(step) }
        }
    }
}

@Composable
private fun StepRow(step: Step) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 56.dp)
            .padding(horizontal = 20.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Box(modifier = Modifier.size(24.dp), contentAlignment = Alignment.Center) {
            when (step.state) {
                StepState.ACTIVE -> CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.5.dp)
                else -> Icon(step.state.icon, contentDescription = null, tint = step.state.tint())
            }
        }
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = step.title,
                style = MaterialTheme.typography.titleMedium,
                color = if (step.state == StepState.WAITING || step.state == StepState.SKIPPED) {
                    MaterialTheme.colorScheme.onSurfaceVariant
                } else {
                    MaterialTheme.colorScheme.onSurface
                },
            )
            step.detail?.let {
                Text(it, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}

private val StepState.icon: ImageVector
    get() = when (this) {
        StepState.WAITING, StepState.ACTIVE -> Icons.Outlined.RadioButtonUnchecked
        StepState.DONE -> Icons.Outlined.CheckCircle
        StepState.FAILED -> Icons.Outlined.Cancel
        StepState.SKIPPED -> Icons.Outlined.RemoveCircleOutline
    }

@Composable
private fun StepState.tint() = when (this) {
    StepState.DONE -> Tone.POSITIVE.contentColor()
    StepState.FAILED -> Tone.CRITICAL.contentColor()
    else -> MaterialTheme.colorScheme.outline
}

/** The four steps, read from how far the payment got and what each step answered. */
private fun PaymentUiState.steps(risk: RiskUiState): List<Step> {
    val reached = stage?.ordinal ?: -1
    fun stateOf(step: PaymentStage) = when {
        problem != null && stage == step -> StepState.FAILED
        stage == step -> StepState.ACTIVE
        reached > step.ordinal -> StepState.DONE
        else -> StepState.WAITING
    }
    val decision = latestDecision
    val found = risk.report?.flaggedSignals().orEmpty().map { it.name }

    val check = Step(
        title = "Check this phone",
        state = stateOf(PaymentStage.CHECKING_DEVICE),
        detail = when {
            stage == PaymentStage.CHECKING_DEVICE -> problem
            reached > PaymentStage.CHECKING_DEVICE.ordinal -> if (found.isEmpty()) "No problems found" else found.joinToString()
            else -> null
        },
    )
    val ask = when (decision) {
        is PaymentDecisionState.Blocked -> Step("Ask the server", StepState.FAILED, "Blocked")
        is PaymentDecisionState.Allowed -> Step("Ask the server", StepState.DONE, "Approved")
        is PaymentDecisionState.ConfirmationRequired,
        is PaymentDecisionState.Confirmed,
        is PaymentDecisionState.Cancelled,
        -> Step("Ask the server", StepState.DONE, "Asks you to confirm")
        PaymentDecisionState.Idle -> Step("Ask the server", stateOf(PaymentStage.ASKING_SERVER), problem.takeIf { stage == PaymentStage.ASKING_SERVER })
    }
    val confirm = when (decision) {
        is PaymentDecisionState.ConfirmationRequired -> Step("Confirm it's you", StepState.ACTIVE, decision.method.prompt())
        is PaymentDecisionState.Confirmed -> Step("Confirm it's you", StepState.DONE, decision.method.done())
        is PaymentDecisionState.Cancelled -> Step("Confirm it's you", StepState.FAILED, decision.problem ?: "Cancelled")
        is PaymentDecisionState.Allowed -> Step("Confirm it's you", StepState.SKIPPED, "Not needed")
        else -> Step("Confirm it's you", if (decision is PaymentDecisionState.Blocked) StepState.SKIPPED else StepState.WAITING)
    }
    val pay = when (val sent = submission) {
        is Submission.Charged -> Step("Pay", StepState.DONE, "Paid")
        is Submission.Refused -> Step("Pay", StepState.FAILED, "Refused")
        is Submission.NoResponse -> Step("Pay", StepState.FAILED, "No answer")
        is Submission.NotSent -> Step("Pay", StepState.FAILED, sent.message)
        null -> when {
            decision is PaymentDecisionState.Blocked || decision is PaymentDecisionState.Cancelled -> Step("Pay", StepState.SKIPPED)
            stage == PaymentStage.PAYING -> Step("Pay", StepState.ACTIVE, "Sending…")
            else -> Step("Pay", StepState.WAITING)
        }
    }
    return listOf(check, ask, confirm, pay)
}

private fun ConfirmationMethod.prompt(): String = when (this) {
    ConfirmationMethod.DEVICE_CREDENTIAL -> "Use your fingerprint or screen lock"
    ConfirmationMethod.TAP -> "Tap to confirm"
}

private fun ConfirmationMethod.done(): String = when (this) {
    ConfirmationMethod.DEVICE_CREDENTIAL -> "Confirmed with your screen lock"
    ConfirmationMethod.TAP -> "Confirmed with a tap"
}

private class PayResult(
    val title: String,
    val body: String,
    val tone: Tone,
    val icon: ImageVector,
    val note: String? = null,
    val offerChecks: Boolean = false,
)

private fun PaymentUiState.result(amount: String): PayResult? {
    problem?.let { return PayResult("Couldn't pay", "$it Nothing was charged.", Tone.CRITICAL, Icons.Outlined.ErrorOutline) }
    return when (latestDecision) {
        is PaymentDecisionState.Blocked -> PayResult(
            title = "Payment blocked",
            body = "This phone isn't safe enough to pay from. Nothing was charged.",
            tone = Tone.CRITICAL,
            icon = Icons.Outlined.Block,
            offerChecks = true,
        )
        is PaymentDecisionState.Cancelled -> PayResult("Payment cancelled", "Nothing was charged.", Tone.NEUTRAL, Icons.Outlined.Cancel)
        else -> when (val sent = submission) {
            is Submission.Charged -> PayResult(
                title = "Paid",
                body = "$amount to TrustGate Store · ${sent.paymentId}",
                tone = Tone.POSITIVE,
                icon = Icons.Outlined.CheckCircle,
                note = listOfNotNull(
                    "The connection dropped, so the app tried again. You were charged once.".takeIf { sent.lostResponses > 0 },
                    "Signed with the key your screen lock unlocks.".takeIf { sent.signedWith == KeyRole.STEP_UP },
                ).joinToString(" ").ifEmpty { null },
            )
            is Submission.Refused -> PayResult(
                title = "Payment refused",
                body = "The server refused it: ${sent.reason.shortLabel()}. Nothing was charged.",
                tone = Tone.CRITICAL,
                icon = Icons.Outlined.ErrorOutline,
            )
            is Submission.NoResponse -> PayResult(
                title = "No answer from the server",
                body = "You may not have been charged. Paying again is safe: it can't charge twice.",
                tone = Tone.CAUTION,
                icon = Icons.Outlined.WifiOff,
            )
            is Submission.NotSent -> PayResult("Couldn't pay", "${sent.message} Nothing was charged.", Tone.CRITICAL, Icons.Outlined.ErrorOutline)
            null -> null
        }
    }
}

@Composable
private fun ResultCard(
    result: PayResult,
    reasons: List<String>,
    onOpenChecks: () -> Unit,
) {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(28.dp),
        color = result.tone.containerColor(),
        contentColor = result.tone.onContainerColor(),
    ) {
        Column(modifier = Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Icon(result.icon, contentDescription = null, modifier = Modifier.size(28.dp))
                Text(result.title, style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.SemiBold)
            }
            Text(result.body, style = MaterialTheme.typography.bodyLarge)
            result.note?.let { Text(it, style = MaterialTheme.typography.bodyMedium) }
            if (reasons.isNotEmpty()) {
                Spacer(Modifier.height(4.dp))
                Text("What the server saw", style = MaterialTheme.typography.labelLarge)
                ChipFlow(reasons, tone = result.tone)
            }
            if (result.offerChecks) {
                TextButton(onClick = onOpenChecks, modifier = Modifier.padding(top = 4.dp)) { Text("See what's wrong") }
            }
        }
    }
}

/** A light confirm or reject tap when the server answers, the way a physical latch would feel. */
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
            is PaymentDecisionState.Allowed, is PaymentDecisionState.Confirmed -> view.performHapticFeedback(confirm)
            is PaymentDecisionState.Blocked -> view.performHapticFeedback(reject)
            else -> Unit
        }
    }
}
