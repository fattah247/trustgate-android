package id.fatarc.trustgate.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.ExpandMore
import androidx.compose.material.icons.outlined.PhoneAndroid
import androidx.compose.material.icons.outlined.Science
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import id.fatarc.trustgate.domain.risk.DeviceRiskLevel

/** How the person should read this phone's state, in the words every screen uses. */
data class PhoneStatus(
    val headline: String,
    val detail: String,
    val tone: Tone,
    val gate: GateState,
)

fun RiskUiState.phoneStatus(): PhoneStatus {
    val report = report
    return when {
        report == null && errorMessage != null -> PhoneStatus("Couldn't check this phone", errorMessage, Tone.CAUTION, GateState.SHUT)
        report == null || isLoading -> PhoneStatus("Checking this phone…", "This takes a moment.", Tone.NEUTRAL, GateState.CHECKING)
        else -> when (report.level) {
            DeviceRiskLevel.LOW -> PhoneStatus("Ready to pay", "No problems found.", Tone.POSITIVE, GateState.OPEN)
            DeviceRiskLevel.MEDIUM -> PhoneStatus("Payments need your OK", "You'll confirm each payment.", Tone.CAUTION, GateState.AJAR)
            DeviceRiskLevel.HIGH -> PhoneStatus("Payments blocked", "This phone isn't safe to pay from.", Tone.CRITICAL, GateState.LOCKED)
        }
    }
}

/** The big state card: gate, headline, one line of detail, and what was found. */
@Composable
fun StatusHero(
    status: PhoneStatus,
    findings: List<String>,
    modifier: Modifier = Modifier,
    footer: (@Composable () -> Unit)? = null,
) {
    Surface(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(28.dp),
        color = status.tone.containerColor(),
        contentColor = status.tone.onContainerColor(),
    ) {
        Column(modifier = Modifier.padding(start = 20.dp, top = 20.dp, end = 20.dp, bottom = if (footer != null) 8.dp else 20.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                GateMark(state = status.gate, tone = status.tone, contentDescription = null, size = 72.dp)
                Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(status.headline, style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.SemiBold)
                    Text(status.detail, style = MaterialTheme.typography.bodyLarge)
                }
            }
            if (findings.isNotEmpty()) {
                Spacer(Modifier.height(16.dp))
                ChipFlow(findings, tone = status.tone)
            }
            footer?.let {
                Spacer(Modifier.height(8.dp))
                it()
            }
        }
    }
}

/** Short facts, such as what a check found, laid out as chips that wrap. */
@OptIn(ExperimentalLayoutApi::class)
@Composable
fun ChipFlow(
    items: List<String>,
    tone: Tone,
    modifier: Modifier = Modifier,
) {
    FlowRow(
        modifier = modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        items.forEach { item -> Pill(text = item, tone = tone, onTinted = true) }
    }
}

/** A small rounded label. [onTinted] is for pills that sit on a tone's container colour. */
@Composable
fun Pill(
    text: String,
    tone: Tone,
    modifier: Modifier = Modifier,
    onTinted: Boolean = false,
    leadingIcon: ImageVector? = null,
) {
    Surface(
        modifier = modifier,
        shape = CircleShape,
        color = if (onTinted) MaterialTheme.colorScheme.surfaceContainerLowest.copy(alpha = 0.7f) else tone.containerColor(),
        contentColor = tone.onContainerColor(),
    ) {
        Row(
            modifier = Modifier.padding(start = if (leadingIcon != null) 8.dp else 12.dp, end = 12.dp, top = 6.dp, bottom = 6.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            leadingIcon?.let { Icon(it, contentDescription = null, modifier = Modifier.size(16.dp)) }
            Text(text = text, style = MaterialTheme.typography.labelLarge)
        }
    }
}

/** The phones the demo can pretend to be, each showing one path through a payment. */
enum class DemoPhone(val level: DeviceRiskLevel?, val title: String, val description: String) {
    REAL(null, "This phone", "Use the real checks"),
    SAFE(DeviceRiskLevel.LOW, "A safe phone", "Payments go straight through"),
    RISKY(DeviceRiskLevel.MEDIUM, "A risky phone", "Payments need your OK"),
    COMPROMISED(DeviceRiskLevel.HIGH, "A compromised phone", "Payments are blocked"),
    ;

    companion object {
        fun of(level: DeviceRiskLevel?): DemoPhone = entries.first { it.level == level }
    }
}

/** Says which phone the app is acting as, and opens the picker. */
@Composable
fun DemoPhoneButton(
    selected: DemoPhone,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val demo = selected != DemoPhone.REAL
    Surface(
        onClick = onClick,
        modifier = modifier.heightIn(min = 40.dp),
        shape = CircleShape,
        color = if (demo) MaterialTheme.colorScheme.tertiaryContainer else MaterialTheme.colorScheme.surfaceContainerHigh,
        contentColor = if (demo) MaterialTheme.colorScheme.onTertiaryContainer else MaterialTheme.colorScheme.onSurface,
    ) {
        Row(
            modifier = Modifier.padding(start = 12.dp, end = 8.dp, top = 8.dp, bottom = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Icon(if (demo) Icons.Outlined.Science else Icons.Outlined.PhoneAndroid, contentDescription = null, modifier = Modifier.size(18.dp))
            Text(if (demo) "Demo: ${selected.title.lowercase()}" else "Testing on this phone", style = MaterialTheme.typography.labelLarge)
            Icon(Icons.Outlined.ExpandMore, contentDescription = null, modifier = Modifier.size(18.dp))
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DemoPhoneSheet(
    selected: DemoPhone,
    onSelect: (DemoPhone) -> Unit,
    onDismiss: () -> Unit,
) {
    ModalBottomSheet(onDismissRequest = onDismiss) {
        Column(modifier = Modifier.navigationBarsPadding().padding(bottom = 16.dp)) {
            Text(
                text = "Pretend this phone is…",
                modifier = Modifier.padding(horizontal = 24.dp),
                style = MaterialTheme.typography.titleLarge,
            )
            Text(
                text = "Try each path a payment can take. Everything else stays real.",
                modifier = Modifier.padding(start = 24.dp, end = 24.dp, top = 4.dp, bottom = 8.dp),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Column(modifier = Modifier.selectableGroup()) {
                DemoPhone.entries.forEach { phone ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .selectable(selected = phone == selected, role = Role.RadioButton, onClick = { onSelect(phone) })
                            .padding(horizontal = 16.dp, vertical = 8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        RadioButton(selected = phone == selected, onClick = null)
                        Column {
                            Text(phone.title, style = MaterialTheme.typography.bodyLarge)
                            Text(phone.description, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                    }
                }
            }
        }
    }
}
