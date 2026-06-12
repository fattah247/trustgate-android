package id.fatarc.trustgate.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.foundation.BorderStroke
import id.fatarc.trustgate.domain.risk.DeviceRiskLevel
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

object TrustGateSpacing {
    val screenHorizontal = 20.dp
    val screenVertical = 20.dp
    val sectionGap = 28.dp
    val blockGap = 18.dp
    val itemGap = 14.dp
    val compactGap = 8.dp
    val summaryPadding = 22.dp
    val insetPadding = 18.dp
}

enum class CalloutTone {
    NEUTRAL,
    SUCCESS,
    WARNING,
    ERROR,
}

data class StatusCalloutState(
    val title: String,
    val body: String,
    val tone: CalloutTone = CalloutTone.NEUTRAL,
)

@Composable
fun TrustGateBackdrop(
    content: @Composable () -> Unit,
) {
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background),
    ) {
        content()
    }
}

@Composable
fun TrustGateScreen(
    content: LazyListScope.() -> Unit,
) {
    LazyColumn(
        contentPadding = PaddingValues(
            start = TrustGateSpacing.screenHorizontal,
            top = TrustGateSpacing.screenVertical,
            end = TrustGateSpacing.screenHorizontal,
            bottom = TrustGateSpacing.screenVertical,
        ),
        verticalArrangement = Arrangement.spacedBy(TrustGateSpacing.sectionGap),
        content = content,
    )
}

@Composable
fun SummaryPanel(
    eyebrow: String,
    title: String,
    supporting: String,
    tone: CalloutTone = CalloutTone.NEUTRAL,
    modifier: Modifier = Modifier,
    content: @Composable ColumnScope.() -> Unit = {},
) {
    val accentColor = toneAccentColor(tone)
    SurfacePanel(
        modifier = modifier,
        contentPadding = TrustGateSpacing.summaryPadding,
    ) {
        Text(
            text = eyebrow.uppercase(),
            style = MaterialTheme.typography.labelMedium,
            color = accentColor,
        )
        Text(
            text = title,
            style = MaterialTheme.typography.headlineLarge,
        )
        Text(
            text = supporting,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.95f),
        )
        content()
    }
}

@Composable
fun SectionBlock(
    title: String,
    description: String? = null,
    modifier: Modifier = Modifier,
    content: @Composable ColumnScope.() -> Unit,
) {
    Column(
        modifier = modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(TrustGateSpacing.blockGap),
    ) {
        Column(
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Text(
                text = title,
                style = MaterialTheme.typography.headlineSmall,
            )
            if (description != null) {
                Text(
                    text = description,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        content()
    }
}

@Composable
fun DetailSurface(
    modifier: Modifier = Modifier,
    content: @Composable ColumnScope.() -> Unit,
) {
    SurfacePanel(
        modifier = modifier,
        contentPadding = TrustGateSpacing.insetPadding,
        content = content,
    )
}

@Composable
fun DividerList(
    modifier: Modifier = Modifier,
    content: @Composable ColumnScope.() -> Unit,
) {
    Column(
        modifier = modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(TrustGateSpacing.itemGap),
        content = content,
    )
}

@Composable
fun SectionDivider() {
    HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.38f))
}

@Composable
fun StatusCallout(
    state: StatusCalloutState,
    modifier: Modifier = Modifier,
) {
    val tone = state.tone
    val accent = toneAccentColor(tone)
    SurfacePanel(
        modifier = modifier,
        contentPadding = TrustGateSpacing.insetPadding,
    ) {
        Text(
            text = state.title,
            style = MaterialTheme.typography.titleSmall,
            color = accent.copy(alpha = 0.98f),
        )
        Text(
            text = state.body,
            style = MaterialTheme.typography.bodyMedium,
        )
    }
}

@Composable
fun RiskBadge(level: DeviceRiskLevel) {
    val accentColor = when (level) {
        DeviceRiskLevel.LOW -> Color(0xFF76C98E)
        DeviceRiskLevel.MEDIUM -> Color(0xFFF18F7E)
        DeviceRiskLevel.HIGH -> Color(0xFFE96F63)
    }
    Box(
        modifier = Modifier
            .clip(MaterialTheme.shapes.small)
            .background(accentColor.copy(alpha = 0.16f))
            .border(
                width = 1.dp,
                color = accentColor.copy(alpha = 0.32f),
                shape = MaterialTheme.shapes.small,
            )
            .padding(horizontal = 10.dp, vertical = 6.dp),
    ) {
        Text(
            text = level.asLabel(),
            style = MaterialTheme.typography.labelLarge,
            color = accentColor,
        )
    }
}

@Composable
fun KeyValueRow(
    label: String,
    value: String,
    monospace: Boolean = false,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
        verticalAlignment = Alignment.Top,
    ) {
        Text(
            text = label,
            modifier = Modifier.weight(1f),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(
            text = value,
            modifier = Modifier.weight(1.25f),
            textAlign = TextAlign.End,
            style = MaterialTheme.typography.bodyMedium,
            fontFamily = if (monospace) FontFamily.Monospace else null,
        )
    }
}

@Composable
fun EvidenceRow(
    title: String,
    summary: String,
    modifier: Modifier = Modifier,
    supporting: String? = null,
    trailing: @Composable (() -> Unit)? = null,
) {
    Row(
        modifier = modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
        verticalAlignment = Alignment.Top,
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
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.95f),
            )
            if (supporting != null) {
                Text(
                    text = supporting,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        if (trailing != null) {
            trailing()
        }
    }
}

@Composable
fun PrimaryActionButton(
    label: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
) {
    Button(
        onClick = onClick,
        modifier = modifier.fillMaxWidth(),
        enabled = enabled,
        shape = MaterialTheme.shapes.medium,
        colors = ButtonDefaults.buttonColors(
            containerColor = MaterialTheme.colorScheme.primary,
            contentColor = MaterialTheme.colorScheme.onPrimary,
            disabledContainerColor = MaterialTheme.colorScheme.surfaceContainerHigh,
            disabledContentColor = MaterialTheme.colorScheme.onSurfaceVariant,
        ),
    ) {
        Text(label)
    }
}

@Composable
fun SecondaryActionButton(
    title: String,
    description: String? = null,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    OutlinedButton(
        onClick = onClick,
        modifier = modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.medium,
        colors = ButtonDefaults.outlinedButtonColors(
            contentColor = MaterialTheme.colorScheme.onSurface,
        ),
        border = BorderStroke(
            width = 1.dp,
            color = MaterialTheme.colorScheme.outline.copy(alpha = 0.6f),
        ),
    ) {
        Column(
            modifier = Modifier.fillMaxWidth(),
            verticalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            Text(
                text = title,
                style = MaterialTheme.typography.labelLarge,
            )
            if (description != null) {
                Text(
                    text = description,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
fun ToggleRow(
    label: String,
    description: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(
            modifier = Modifier.weight(1f),
            verticalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            Text(text = label, style = MaterialTheme.typography.titleSmall)
            Text(
                text = description,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Switch(
            checked = checked,
            onCheckedChange = onCheckedChange,
            colors = SwitchDefaults.colors(
                checkedThumbColor = MaterialTheme.colorScheme.primary,
                checkedTrackColor = MaterialTheme.colorScheme.primary.copy(alpha = 0.35f),
            ),
        )
    }
}

@Composable
fun BulletLine(text: String) {
    Text(
        text = "\u2022 $text",
        style = MaterialTheme.typography.bodyMedium,
    )
}

fun DeviceRiskLevel.asLabel(): String = when (this) {
    DeviceRiskLevel.LOW -> "Low risk"
    DeviceRiskLevel.MEDIUM -> "Needs review"
    DeviceRiskLevel.HIGH -> "High risk"
}

fun String.asHumanLabel(): String {
    return lowercase()
        .split("_")
        .joinToString(" ") { part ->
            part.replaceFirstChar { char ->
                if (char.isLowerCase()) {
                    char.titlecase()
                } else {
                    char.toString()
                }
            }
        }
}

fun maskToken(token: String?): String {
    if (token.isNullOrBlank()) return "Not stored"
    return if (token.length <= 8) "Stored" else "${token.take(6)}...${token.takeLast(4)}"
}

fun formatAuditTimestamp(rawTimestamp: String): String {
    return runCatching {
        Instant.parse(rawTimestamp)
            .atZone(ZoneId.systemDefault())
            .format(AuditTimestampFormatter)
    }.getOrDefault(rawTimestamp)
}

private val AuditTimestampFormatter: DateTimeFormatter =
    DateTimeFormatter.ofPattern("dd MMM yyyy \u00b7 HH:mm")

@Composable
private fun SurfacePanel(
    modifier: Modifier = Modifier,
    contentPadding: androidx.compose.ui.unit.Dp,
    content: @Composable ColumnScope.() -> Unit,
) {
    Box(
        modifier = modifier
            .fillMaxWidth()
            .clip(MaterialTheme.shapes.large)
            .background(MaterialTheme.colorScheme.surfaceContainerHigh)
            .border(
                width = 1.dp,
                color = MaterialTheme.colorScheme.outline.copy(alpha = 0.55f),
                shape = MaterialTheme.shapes.large,
            )
            .padding(contentPadding),
    ) {
        Column(
            verticalArrangement = Arrangement.spacedBy(TrustGateSpacing.itemGap),
        ) {
            content()
        }
    }
}

@Composable
private fun toneAccentColor(tone: CalloutTone): Color = when (tone) {
    CalloutTone.NEUTRAL -> MaterialTheme.colorScheme.primary
    CalloutTone.SUCCESS -> Color(0xFF76C98E)
    CalloutTone.WARNING -> Color(0xFFF18F7E)
    CalloutTone.ERROR -> Color(0xFFE96F63)
}
