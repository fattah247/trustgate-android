package id.fatarc.trustgate.ui.risk

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import id.fatarc.trustgate.ui.RiskBadge
import id.fatarc.trustgate.ui.SectionCard
import id.fatarc.trustgate.ui.TrustGateUiState

@Composable
fun DeviceRiskDetailsScreen(
    uiState: TrustGateUiState,
) {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        item {
            SectionCard(
                title = "Assessment notes",
                modifier = Modifier.padding(top = 16.dp),
            ) {
                Text(
                    text = "These checks are heuristics gathered from the client runtime. They can guide a trust decision, but they are not bypass-proof.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                uiState.riskReport?.let { report ->
                    RiskBadge(level = report.level)
                    Text("Score: ${report.score}", style = MaterialTheme.typography.bodyMedium)
                }
            }
        }
        val report = uiState.riskReport
        if (report == null) {
            item {
                Text(
                    text = "No risk report available yet.",
                    modifier = Modifier.padding(bottom = 24.dp),
                )
            }
        } else {
            items(report.signals.size) { index ->
                val signal = report.signals[index]
                SectionCard(title = signal.name) {
                    Text(
                        text = if (signal.detected) "Detected" else "Not detected",
                        color = if (signal.detected) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary,
                    )
                    Text(
                        text = "Severity: ${signal.severity.name}",
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    Text(
                        text = signal.explanation,
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    Text(
                        text = "Signal id: ${signal.id}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
    }
}

