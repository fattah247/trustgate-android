package id.fatarc.trustgate.ui.events

import androidx.compose.foundation.lazy.items
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import id.fatarc.trustgate.domain.events.SecurityEvent
import id.fatarc.trustgate.ui.KeyValueRow
import id.fatarc.trustgate.ui.RiskBadge
import id.fatarc.trustgate.ui.SectionCard
import id.fatarc.trustgate.ui.StatusCallout
import id.fatarc.trustgate.ui.StatusCalloutState
import id.fatarc.trustgate.ui.TrustGateScreen
import id.fatarc.trustgate.ui.TrustGateUiState
import id.fatarc.trustgate.ui.asHumanLabel

@Composable
fun SecurityEventLogScreen(
    uiState: TrustGateUiState,
) {
    val events = uiState.securityEvents.asReversed()
    TrustGateScreen {
        item {
            SectionCard(title = "Local event log") {
                Text(
                    text = "The log is device-local. It explains which assessments and action decisions the demo app recorded over time.",
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
        }

        if (events.isEmpty()) {
            item {
                StatusCallout(
                    state = StatusCalloutState(
                        title = "No events recorded yet",
                        body = "Run an assessment or complete one of the demo flows to populate the log.",
                    ),
                )
            }
        } else {
            items(events, key = { "${it.timestamp}-${it.type}" }) { event ->
                EventCard(event = event)
            }
        }
    }
}

@Composable
private fun EventCard(event: SecurityEvent) {
    SectionCard(title = event.type.name.asHumanLabel()) {
        Text(
            text = event.message,
            style = MaterialTheme.typography.bodyMedium,
        )
        KeyValueRow(label = "Recorded at", value = event.timestamp, monospace = true)
        event.riskLevel?.let { riskLevel ->
            RiskBadge(level = riskLevel)
        }
        event.metadata.toSortedMap().forEach { (key, value) ->
            KeyValueRow(
                label = key.asHumanLabel(),
                value = value,
                monospace = key.contains("nonce", ignoreCase = true) || key.contains("signature", ignoreCase = true),
            )
        }
    }
}
