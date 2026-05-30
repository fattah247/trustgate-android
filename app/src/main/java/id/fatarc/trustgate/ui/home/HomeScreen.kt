package id.fatarc.trustgate.ui.home

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import id.fatarc.trustgate.ui.KeyValueRow
import id.fatarc.trustgate.ui.RiskBadge
import id.fatarc.trustgate.ui.SectionCard
import id.fatarc.trustgate.ui.TrustGateUiState

@Composable
fun HomeScreen(
    uiState: TrustGateUiState,
    onRefreshRisk: () -> Unit,
    onOpenRiskDetails: () -> Unit,
    onOpenPaymentDemo: () -> Unit,
    onOpenSigningDemo: () -> Unit,
    onOpenStorageDemo: () -> Unit,
    onOpenEvents: () -> Unit,
    onOpenAbout: () -> Unit,
) {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        item {
            SectionCard(
                title = "Trust state",
                modifier = Modifier.padding(top = 16.dp),
            ) {
                Text(
                    text = "This lab treats device checks as risk signals, not guarantees. Sensitive actions use that risk level before moving forward.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                uiState.riskReport?.let { report ->
                    RiskBadge(level = report.level)
                    KeyValueRow(label = "Risk score", value = report.score.toString())
                    KeyValueRow(label = "Detected signals", value = report.signals.count { it.detected }.toString())
                    KeyValueRow(label = "Assessed at", value = report.assessedAt.toString(), monospace = true)
                    if (uiState.storageSnapshot.showSignalsOnHome) {
                        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                            report.signals.take(4).forEach { signal ->
                                Text(
                                    text = if (signal.detected) "Active: ${signal.name}" else "Clear: ${signal.name}",
                                    style = MaterialTheme.typography.bodySmall,
                                )
                            }
                        }
                    }
                } ?: Text("Run the assessment to populate current risk state.")
                Button(
                    onClick = onRefreshRisk,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(if (uiState.isAssessingRisk) "Assessing..." else "Refresh assessment")
                }
                if (uiState.errorMessage != null) {
                    Text(
                        text = uiState.errorMessage,
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }
        }

        item {
            SectionCard(title = "Demo flows") {
                Text(
                    text = "Each screen focuses on one part of the mobile-client security story.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                OutlinedButton(onClick = onOpenRiskDetails, modifier = Modifier.fillMaxWidth()) {
                    Text("Open device risk details")
                }
                OutlinedButton(onClick = onOpenPaymentDemo, modifier = Modifier.fillMaxWidth()) {
                    Text("Open payment action demo")
                }
                OutlinedButton(onClick = onOpenSigningDemo, modifier = Modifier.fillMaxWidth()) {
                    Text("Open request signing demo")
                }
                OutlinedButton(onClick = onOpenStorageDemo, modifier = Modifier.fillMaxWidth()) {
                    Text("Open secure storage demo")
                }
                OutlinedButton(onClick = onOpenEvents, modifier = Modifier.fillMaxWidth()) {
                    Text("Open security event log")
                }
                OutlinedButton(onClick = onOpenAbout, modifier = Modifier.fillMaxWidth()) {
                    Text("Open about and limitations")
                }
            }
        }

        item {
            SectionCard(
                title = "Latest state",
                modifier = Modifier.padding(bottom = 24.dp),
            ) {
                Text(uiState.actionMessage, style = MaterialTheme.typography.bodyMedium)
                Text(uiState.signingMessage, style = MaterialTheme.typography.bodyMedium)
                Text(uiState.storageMessage, style = MaterialTheme.typography.bodyMedium)
                KeyValueRow(
                    label = "Security events",
                    value = uiState.securityEvents.size.toString(),
                )
            }
        }
    }
}

