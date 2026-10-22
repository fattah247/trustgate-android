package id.fatarc.trustgate.ui.risk

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material.icons.outlined.Refresh
import androidx.compose.material.icons.outlined.Science
import androidx.compose.material.icons.outlined.WarningAmber
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import id.fatarc.trustgate.domain.risk.RiskSignal
import id.fatarc.trustgate.domain.risk.SignalCatalog
import id.fatarc.trustgate.ui.BulletItem
import id.fatarc.trustgate.ui.ListRow
import id.fatarc.trustgate.ui.Pill
import id.fatarc.trustgate.ui.RowDivider
import id.fatarc.trustgate.ui.ScreenScaffold
import id.fatarc.trustgate.ui.Section
import id.fatarc.trustgate.ui.Tone
import id.fatarc.trustgate.ui.TrustGateSpacing
import id.fatarc.trustgate.ui.TrustGateUiState
import id.fatarc.trustgate.ui.contentColor
import id.fatarc.trustgate.ui.flaggedSignals
import id.fatarc.trustgate.ui.label
import id.fatarc.trustgate.ui.rememberTimeFormats
import id.fatarc.trustgate.ui.tone

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ChecksScreen(
    uiState: TrustGateUiState,
    onRefreshRisk: () -> Unit,
    onUseThisPhone: () -> Unit,
    onNavigateUp: (() -> Unit)? = null,
) {
    val formats = rememberTimeFormats()
    val risk = uiState.risk
    val report = risk.report
    val found = report?.flaggedSignals().orEmpty()
    val passed = report?.signals.orEmpty().filterNot { it.detected }
    var openSignalId by rememberSaveable { mutableStateOf<String?>(null) }
    var explainingScore by rememberSaveable { mutableStateOf(false) }

    ScreenScaffold(
        title = "Checks",
        onNavigateUp = onNavigateUp,
        actions = {
            IconButton(onClick = onRefreshRisk, enabled = !risk.isLoading) {
                Icon(Icons.Outlined.Refresh, contentDescription = "Check again")
            }
        },
    ) {
        if (risk.scenarioLevel != null) {
            item(key = "demo") { DemoNotice(onUseThisPhone) }
        }

        item(key = "summary") {
            Column(modifier = Modifier.padding(horizontal = 4.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    text = when {
                        report == null -> if (risk.isLoading) "Checking this phone…" else "Couldn't check this phone"
                        found.isEmpty() -> "All ${report.signals.size} checks passed"
                        else -> "${found.size} of ${report.signals.size} checks found a problem"
                    },
                    style = MaterialTheme.typography.headlineSmall,
                    fontWeight = FontWeight.SemiBold,
                )
                if (report != null) {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                        Pill(text = report.level.label(), tone = report.level.tone())
                        Text(
                            "Checked ${formats.time(report.assessedAt)}",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                } else if (risk.errorMessage != null) {
                    Text(risk.errorMessage, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }

        if (found.isNotEmpty()) {
            item(key = "found") {
                Section(title = "Found") {
                    found.forEachIndexed { index, signal ->
                        ListRow(
                            headline = signal.name,
                            leadingIcon = Icons.Outlined.WarningAmber,
                            leadingTint = signal.severity.tone().contentColor(),
                            trailing = { Pill(text = signal.severity.label(), tone = signal.severity.tone()) },
                            onClickLabel = "Explain",
                            onClick = { openSignalId = signal.id },
                        )
                        if (index != found.lastIndex) RowDivider(startIndent = TrustGateSpacing.listIconInset)
                    }
                }
            }
        }

        if (passed.isNotEmpty()) {
            item(key = "passed") {
                Section(title = "Passed") {
                    passed.forEachIndexed { index, signal ->
                        ListRow(
                            headline = SignalCatalog.passedName(signal),
                            leadingIcon = Icons.Outlined.CheckCircle,
                            leadingTint = Tone.POSITIVE.contentColor(),
                            onClickLabel = "Explain",
                            onClick = { openSignalId = signal.id },
                        )
                        if (index != passed.lastIndex) RowDivider(startIndent = TrustGateSpacing.listIconInset)
                    }
                }
            }
        }

        if (report != null) {
            item(key = "score") {
                TextButton(onClick = { explainingScore = true }) { Text("How the score works") }
            }
        }
    }

    report?.signals?.firstOrNull { it.id == openSignalId }?.let { signal ->
        ModalBottomSheet(onDismissRequest = { openSignalId = null }) {
            SignalExplanation(signal)
        }
    }
    if (explainingScore) {
        ModalBottomSheet(onDismissRequest = { explainingScore = false }) {
            ScoreExplanation()
        }
    }
}

@Composable
private fun DemoNotice(onUseThisPhone: () -> Unit) {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.large,
        color = MaterialTheme.colorScheme.tertiaryContainer,
        contentColor = MaterialTheme.colorScheme.onTertiaryContainer,
    ) {
        Row(
            modifier = Modifier.padding(start = 16.dp, top = 4.dp, end = 4.dp, bottom = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Icon(Icons.Outlined.Science, contentDescription = null)
            Text("These are a demo phone's results.", style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
            TextButton(onClick = onUseThisPhone) { Text("Use this phone") }
        }
    }
}

@Composable
private fun SignalExplanation(signal: RiskSignal) {
    Column(
        modifier = Modifier.navigationBarsPadding().padding(start = 24.dp, end = 24.dp, bottom = 24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(if (signal.detected) signal.name else SignalCatalog.passedName(signal), style = MaterialTheme.typography.titleLarge)
        Pill(
            text = if (signal.detected) "Found · ${signal.severity.label()} risk" else "Not found",
            tone = if (signal.detected) signal.severity.tone() else Tone.POSITIVE,
        )
        Text(signal.explanation, style = MaterialTheme.typography.bodyLarge)
    }
}

@Composable
private fun ScoreExplanation() {
    Column(modifier = Modifier.navigationBarsPadding().padding(bottom = 24.dp)) {
        Text(
            "How the score works",
            modifier = Modifier.padding(start = 24.dp, end = 24.dp, bottom = 8.dp),
            style = MaterialTheme.typography.titleLarge,
        )
        BulletItem("Each problem adds points: low 1, medium 2, high 3.")
        BulletItem("2 points or more: you confirm each payment.")
        BulletItem("5 points or more, or any high problem: payments are blocked.")
        BulletItem("The server scores what the phone reports itself, so a tampered app can't lower it.")
    }
}
