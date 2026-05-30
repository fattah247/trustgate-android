package id.fatarc.trustgate.ui.events

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import id.fatarc.trustgate.domain.events.SecurityEvent
import id.fatarc.trustgate.ui.SectionCard
import id.fatarc.trustgate.ui.TrustGateUiState

@Composable
fun SecurityEventLogScreen(
    uiState: TrustGateUiState,
) {
    val events = uiState.securityEvents.reversed()
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        item {
            SectionCard(
                title = "Local event log",
                modifier = Modifier.padding(top = 16.dp),
            ) {
                Text(
                    text = "The log is local to the device. It helps explain why the app allowed, escalated, or blocked a demo action.",
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
        }
        if (events.isEmpty()) {
            item {
                Text(
                    text = "No security events recorded yet.",
                    modifier = Modifier.padding(bottom = 24.dp),
                )
            }
        } else {
            items(events.size) { index ->
                EventCard(event = events[index])
            }
        }
    }
}

@Composable
private fun EventCard(event: SecurityEvent) {
    SectionCard(title = event.type.name) {
        Text(
            text = event.message,
            style = MaterialTheme.typography.bodyMedium,
        )
        Text(
            text = event.timestamp,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        if (event.riskLevel != null) {
            Text(
                text = "Risk level: ${event.riskLevel.name}",
                style = MaterialTheme.typography.bodySmall,
            )
        }
        if (event.metadata.isNotEmpty()) {
            event.metadata.entries.sortedBy { it.key }.forEach { entry ->
                Text(
                    text = "${entry.key}: ${entry.value}",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }
    }
}

