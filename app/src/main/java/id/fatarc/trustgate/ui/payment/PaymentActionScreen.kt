package id.fatarc.trustgate.ui.payment

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import id.fatarc.trustgate.ui.KeyValueRow
import id.fatarc.trustgate.ui.RiskBadge
import id.fatarc.trustgate.ui.SectionCard
import id.fatarc.trustgate.ui.TrustGateUiState

@Composable
fun PaymentActionScreen(
    uiState: TrustGateUiState,
    onAttemptPayment: () -> Unit,
) {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        item {
            SectionCard(
                title = "Sensitive action gate",
                modifier = Modifier.padding(top = 16.dp),
            ) {
                Text(
                    text = "This screen simulates a payment approval. The app only uses the current risk level to decide whether to allow, require confirmation, or block.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                uiState.riskReport?.let { report ->
                    RiskBadge(level = report.level)
                    KeyValueRow(label = "Current risk", value = report.level.name)
                }
                KeyValueRow(label = "LOW", value = "Allow action")
                KeyValueRow(label = "MEDIUM", value = "Require confirmation")
                KeyValueRow(label = "HIGH", value = "Block action")
                Button(
                    onClick = onAttemptPayment,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text("Create demo payment")
                }
            }
        }

        item {
            SectionCard(
                title = "Latest decision",
                modifier = Modifier.padding(bottom = 24.dp),
            ) {
                Text(uiState.actionMessage, style = MaterialTheme.typography.bodyMedium)
            }
        }
    }
}

