package id.fatarc.trustgate.ui.storage

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import id.fatarc.trustgate.ui.BulletLine
import id.fatarc.trustgate.ui.CalloutTone
import id.fatarc.trustgate.ui.KeyValueRow
import id.fatarc.trustgate.ui.PrimaryActionButton
import id.fatarc.trustgate.ui.SectionCard
import id.fatarc.trustgate.ui.SecondaryActionButton
import id.fatarc.trustgate.ui.StatusCallout
import id.fatarc.trustgate.ui.StatusCalloutState
import id.fatarc.trustgate.ui.StorageStatus
import id.fatarc.trustgate.ui.ToggleRow
import id.fatarc.trustgate.ui.TrustGateScreen
import id.fatarc.trustgate.ui.TrustGateUiState
import id.fatarc.trustgate.ui.maskToken

@Composable
fun SecureStorageScreen(
    uiState: TrustGateUiState,
    onStoreDemoValues: () -> Unit,
    onRefreshStorage: () -> Unit,
    onToggleShowSignalsOnHome: (Boolean) -> Unit,
) {
    TrustGateScreen {
        item {
            SectionCard(title = "Encrypted values") {
                Text(
                    text = "This demo stores a mock session token, the last risk decision, and one harmless UI preference in encrypted local storage.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                KeyValueRow(
                    label = "Session token",
                    value = maskToken(uiState.storage.snapshot.sessionToken),
                )
                KeyValueRow(
                    label = "Last risk level",
                    value = uiState.storage.snapshot.lastRiskLevel?.name ?: "Not stored",
                )
                KeyValueRow(
                    label = "Signal preview on overview",
                    value = if (uiState.storage.snapshot.showSignalsOnHome) "Enabled" else "Disabled",
                )
                ToggleRow(
                    label = "Show signal preview on overview",
                    description = "This toggle changes only a local display preference. It does not affect scoring.",
                    checked = uiState.storage.snapshot.showSignalsOnHome,
                    onCheckedChange = onToggleShowSignalsOnHome,
                )
                PrimaryActionButton(
                    label = "Store demo values",
                    onClick = onStoreDemoValues,
                )
                SecondaryActionButton(
                    title = "Reload encrypted values",
                    description = "Read the latest encrypted snapshot without writing new demo data.",
                    onClick = onRefreshStorage,
                )
                StatusCallout(state = storageStateSummary(uiState.storage.status))
            }
        }

        item {
            SectionCard(title = "Deliberately not stored") {
                BulletLine("No real card data or payment credentials are written to this device.")
                BulletLine("No backend secrets or production signing keys live in app storage.")
                BulletLine("The stored values are only enough to demonstrate encrypted local persistence.")
            }
        }
    }
}

private fun storageStateSummary(status: StorageStatus): StatusCalloutState {
    return when (status) {
        StorageStatus.Idle -> StatusCalloutState(
            title = "No writes yet",
            body = "The screen is showing the default encrypted snapshot.",
        )

        StorageStatus.Loaded -> StatusCalloutState(
            title = "Snapshot reloaded",
            body = "The values shown above were read back from encrypted storage.",
            tone = CalloutTone.SUCCESS,
        )

        is StorageStatus.Stored -> StatusCalloutState(
            title = "Values stored",
            body = "${status.keyCount} demo values were written to encrypted storage and read back.",
            tone = CalloutTone.SUCCESS,
        )

        is StorageStatus.PreferenceUpdated -> StatusCalloutState(
            title = "Preference updated",
            body = if (status.showSignalsOnHome) {
                "Signal previews are now visible on the overview screen."
            } else {
                "Signal previews are now hidden on the overview screen."
            },
            tone = CalloutTone.SUCCESS,
        )

        is StorageStatus.Failed -> StatusCalloutState(
            title = "Encrypted storage failed",
            body = status.message,
            tone = CalloutTone.ERROR,
        )
    }
}
