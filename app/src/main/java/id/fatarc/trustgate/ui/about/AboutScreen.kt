package id.fatarc.trustgate.ui.about

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import id.fatarc.trustgate.ui.SectionCard
import id.fatarc.trustgate.ui.TrustGateUiState

@Composable
fun AboutScreen(
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
                title = "What this app is",
                modifier = Modifier.padding(top = 16.dp),
            ) {
                Text(
                    text = "TrustGate Android is a public-safe mobile security lab. It shows how a client can collect risk signals, gate sensitive actions, sign requests, and keep a local security event log.",
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
        }
        item {
            SectionCard(title = "Limitations") {
                Text("Client-side checks are signals, not guarantees.", style = MaterialTheme.typography.bodyMedium)
                Text("The request signing key is hardcoded for demo purposes only.", style = MaterialTheme.typography.bodyMedium)
                Text("There is no real payment processor or fraud engine behind this app.", style = MaterialTheme.typography.bodyMedium)
                Text("Advanced bypass frameworks and kernel-level compromise are out of scope.", style = MaterialTheme.typography.bodyMedium)
            }
        }
        item {
            SectionCard(
                title = "Certificate pinning note",
                modifier = Modifier.padding(bottom = 24.dp),
            ) {
                Text(uiState.pinningSummary, style = MaterialTheme.typography.bodyMedium)
                Text(
                    text = "Pinning can reduce some man-in-the-middle risk, but it still needs certificate rotation planning and server-side controls.",
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
        }
    }
}

