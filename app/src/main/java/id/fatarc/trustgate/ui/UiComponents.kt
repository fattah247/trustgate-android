package id.fatarc.trustgate.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import id.fatarc.trustgate.domain.risk.DeviceRiskLevel

object TrustGateSpacing {
    val screenHorizontal = 20.dp
    val screenVertical = 20.dp
    val sectionGap = 24.dp
    val blockGap = 16.dp
    val itemGap = 12.dp
    val compactGap = 8.dp
    val summaryPadding = 20.dp
    val insetPadding = 16.dp
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
    val (containerColor, contentColor) = summaryToneColors(tone)
    Surface(
        modifier = modifier.fillMaxWidth(),
        color = containerColor,
        contentColor = contentColor,
        shape = MaterialTheme.shapes.large,
    ) {
        Column(
            modifier = Modifier.padding(TrustGateSpacing.summaryPadding),
            verticalArrangement = Arrangement.spacedBy(TrustGateSpacing.itemGap),
            content = {
                Text(
                    text = eyebrow,
                    style = MaterialTheme.typography.labelLarge,
                    color = contentColor.copy(alpha = 0.82f),
                )
                Text(
                    text = title,
                    style = MaterialTheme.typography.headlineMedium,
                )
                Text(
                    text = supporting,
                    style = MaterialTheme.typography.bodyMedium,
                    color = contentColor.copy(alpha = 0.9f),
                )
                content()
            },
        )
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
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleLarge,
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
    Surface(
        modifier = modifier.fillMaxWidth(),
        color = MaterialTheme.colorScheme.surface,
        shape = MaterialTheme.shapes.medium,
    ) {
        Column(
            modifier = Modifier.padding(TrustGateSpacing.insetPadding),
            verticalArrangement = Arrangement.spacedBy(TrustGateSpacing.itemGap),
            content = content,
        )
    }
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
    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.55f))
}

@Composable
fun StatusCallout(
    state: StatusCalloutState,
    modifier: Modifier = Modifier,
) {
    val (containerColor, contentColor) = when (state.tone) {
        CalloutTone.NEUTRAL -> MaterialTheme.colorScheme.surfaceContainerHigh to MaterialTheme.colorScheme.onSurface
        CalloutTone.SUCCESS -> TrustGateSuccessContainer to TrustGateSuccessContent
        CalloutTone.WARNING -> TrustGateWarningContainer to TrustGateWarningContent
        CalloutTone.ERROR -> MaterialTheme.colorScheme.errorContainer to MaterialTheme.colorScheme.onErrorContainer
    }

    Surface(
        modifier = modifier.fillMaxWidth(),
        color = containerColor,
        contentColor = contentColor,
        shape = MaterialTheme.shapes.medium,
    ) {
        Column(
            modifier = Modifier.padding(TrustGateSpacing.insetPadding),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text(
                text = state.title,
                style = MaterialTheme.typography.labelLarge,
            )
            Text(
                text = state.body,
                style = MaterialTheme.typography.bodyMedium,
            )
        }
    }
}

@Composable
fun RiskBadge(level: DeviceRiskLevel) {
    val containerColor = when (level) {
        DeviceRiskLevel.LOW -> TrustGateSuccessContainer
        DeviceRiskLevel.MEDIUM -> TrustGateWarningContainer
        DeviceRiskLevel.HIGH -> MaterialTheme.colorScheme.errorContainer
    }
    val contentColor = when (level) {
        DeviceRiskLevel.LOW -> TrustGateSuccessContent
        DeviceRiskLevel.MEDIUM -> TrustGateWarningContent
        DeviceRiskLevel.HIGH -> MaterialTheme.colorScheme.onErrorContainer
    }

    Surface(
        color = containerColor,
        contentColor = contentColor,
        shape = MaterialTheme.shapes.small,
    ) {
        Text(
            text = level.asLabel(),
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp),
            style = MaterialTheme.typography.labelLarge,
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
            modifier = Modifier.weight(1.2f),
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
        colors = ButtonDefaults.outlinedButtonColors(
            contentColor = MaterialTheme.colorScheme.onSurface,
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
    DeviceRiskLevel.MEDIUM -> "Medium risk"
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

@Composable
private fun summaryToneColors(tone: CalloutTone): Pair<Color, Color> = when (tone) {
    CalloutTone.NEUTRAL -> MaterialTheme.colorScheme.surface to MaterialTheme.colorScheme.onSurface
    CalloutTone.SUCCESS -> TrustGateSuccessContainer to TrustGateSuccessContent
    CalloutTone.WARNING -> TrustGateWarningContainer to TrustGateWarningContent
    CalloutTone.ERROR -> MaterialTheme.colorScheme.errorContainer to MaterialTheme.colorScheme.onErrorContainer
}

private val TrustGateSuccessContainer = Color(0xFFDCEEDF)
private val TrustGateSuccessContent = Color(0xFF1E5D31)
private val TrustGateWarningContainer = Color(0xFFF6E1B7)
private val TrustGateWarningContent = Color(0xFF6A4A00)
