package id.fatarc.trustgate.ui.storage

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import id.fatarc.trustgate.ui.BulletLine
import id.fatarc.trustgate.ui.CalloutTone
import id.fatarc.trustgate.ui.DetailSurface
import id.fatarc.trustgate.ui.DividerList
import id.fatarc.trustgate.ui.KeyValueRow
import id.fatarc.trustgate.ui.PrimaryActionButton
import id.fatarc.trustgate.ui.SectionBlock
import id.fatarc.trustgate.ui.SectionDivider
import id.fatarc.trustgate.ui.SecondaryActionButton
import id.fatarc.trustgate.ui.StatusCalloutState
import id.fatarc.trustgate.ui.StorageStatus
import id.fatarc.trustgate.ui.SummaryPanel
import id.fatarc.trustgate.ui.ToggleRow
import id.fatarc.trustgate.ui.TrustGateScreen
import id.fatarc.trustgate.ui.TrustGateUiState
import id.fatarc.trustgate.ui.asLabel
import id.fatarc.trustgate.ui.maskToken

@Composable
fun SecureStorageScreen(
    uiState: TrustGateUiState,
    onStoreDemoValues: () -> Unit,
    onRefreshStorage: () -> Unit,
    onToggleShowSignalsOnHome: (Boolean) -> Unit,
) {
    val storageState = storageStateSummary(uiState.storage.status)
    TrustGateScreen {
        item {
            SummaryPanel(
                eyebrow = "Secure storage",
                title = storageState.title,
                supporting = storageState.body,
                tone = storageState.tone,
            ) {
                PrimaryActionButton(
                    label = "Store demo values",
                    onClick = onStoreDemoValues,
                )
                SecondaryActionButton(
                    title = "Reload encrypted values",
                    description = "Read the latest encrypted snapshot without writing new demo data.",
                    onClick = onRefreshStorage,
                )
            }
        }

        item {
            SectionBlock(
                title = "Stored values",
                description = "These values are safe demo data used to exercise local encrypted persistence.",
            ) {
                DetailSurface {
                    DividerList {
                        KeyValueRow(
                            label = "Session token",
                            value = maskToken(uiState.storage.snapshot.sessionToken),
                        )
                        SectionDivider()
                        KeyValueRow(
                            label = "Last risk level",
                            value = uiState.storage.snapshot.lastRiskLevel?.asLabel() ?: "Not stored",
                        )
                        SectionDivider()
                        KeyValueRow(
                            label = "Signal preview on overview",
                            value = if (uiState.storage.snapshot.showSignalsOnHome) "Enabled" else "Disabled",
                        )
                        SectionDivider()
                        ToggleRow(
                            label = "Show signal preview on overview",
                            description = "This toggle changes only a local display preference. It does not affect scoring.",
                            checked = uiState.storage.snapshot.showSignalsOnHome,
                            onCheckedChange = onToggleShowSignalsOnHome,
                        )
                    }
                }
            }
        }

        item {
            SectionBlock(
                title = "Deliberately excluded",
                description = "The storage demo is intentionally narrow so the app does not imply that sensitive production data belongs on the device.",
            ) {
                DetailSurface {
                    BulletLine("No real card data or payment credentials are written to this device.")
                    BulletLine("No backend secrets or production signing keys live in app storage.")
                    BulletLine("The stored values exist only to demonstrate encrypted local persistence.")
                }
            }
        }
    }
}

private fun storageStateSummary(status: StorageStatus): StatusCalloutState {
    return when (status) {
        StorageStatus.Idle -> StatusCalloutState(
            title = "No encrypted writes yet",
            body = "The screen is showing the default encrypted snapshot.",
        )

        StorageStatus.Loaded -> StatusCalloutState(
            title = "Encrypted snapshot reloaded",
            body = "The values shown here were read back from local encrypted storage.",
            tone = CalloutTone.SUCCESS,
        )

        is StorageStatus.Stored -> StatusCalloutState(
            title = "Encrypted values stored",
            body = "${status.keyCount} demo values were written to local encrypted storage and read back.",
            tone = CalloutTone.SUCCESS,
        )

        is StorageStatus.PreferenceUpdated -> StatusCalloutState(
            title = "Display preference updated",
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
