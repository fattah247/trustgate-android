package id.fatarc.trustgate.ui.storage

import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.ErrorOutline
import androidx.compose.material.icons.outlined.Refresh
import androidx.compose.material.icons.outlined.Visibility
import androidx.compose.material.icons.outlined.VisibilityOff
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import id.fatarc.trustgate.ui.GroupedSurface
import id.fatarc.trustgate.ui.InfoRow
import id.fatarc.trustgate.ui.NoticeCard
import id.fatarc.trustgate.ui.RowDivider
import id.fatarc.trustgate.ui.ScreenScaffold
import id.fatarc.trustgate.ui.Section
import id.fatarc.trustgate.ui.SectionFooter
import id.fatarc.trustgate.ui.StorageStatus
import id.fatarc.trustgate.ui.SwitchRow
import id.fatarc.trustgate.ui.Tone
import id.fatarc.trustgate.ui.TrustGateUiState
import id.fatarc.trustgate.ui.label
import id.fatarc.trustgate.ui.maskToken

@Composable
fun SecureStorageScreen(
    uiState: TrustGateUiState,
    onNavigateUp: () -> Unit,
    onStoreReferenceValues: () -> Unit,
    onRefreshStorage: () -> Unit,
    onToggleShowSignalsOnHome: (Boolean) -> Unit,
) {
    val snapshot = uiState.storage.snapshot
    var revealToken by rememberSaveable { mutableStateOf(false) }

    ScreenScaffold(
        title = "Secure storage",
        onNavigateUp = onNavigateUp,
        actions = {
            IconButton(onClick = onRefreshStorage) {
                Icon(Icons.Outlined.Refresh, contentDescription = "Reload stored values")
            }
        },
    ) {
        item(key = "intro") {
            GroupedSurface {
                Text(
                    text = "Keys and values are encrypted with AES-256 (SIV for keys, GCM for values) under a " +
                        "master key held in Android Keystore.",
                    modifier = Modifier.padding(16.dp),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Button(
                    onClick = onStoreReferenceValues,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(start = 16.dp, end = 16.dp, bottom = 16.dp),
                ) {
                    Text(if (snapshot.sessionToken == null) "Save reference values" else "Save new reference values")
                }
            }
        }

        (uiState.storage.status as? StorageStatus.Failed)?.let { failure ->
            item(key = "error") {
                NoticeCard(
                    title = "Encrypted storage isn't available",
                    body = failure.message,
                    tone = Tone.CRITICAL,
                    icon = Icons.Outlined.ErrorOutline,
                )
            }
        }

        item(key = "values") {
            Section(title = "Stored values") {
                val token = snapshot.sessionToken
                InfoRow(
                    label = "Session token",
                    value = when {
                        token == null -> "Not saved"
                        revealToken -> token
                        else -> maskToken(token)
                    },
                    trailing = if (token != null) {
                        {
                            IconButton(onClick = { revealToken = !revealToken }) {
                                Icon(
                                    imageVector = if (revealToken) Icons.Outlined.VisibilityOff else Icons.Outlined.Visibility,
                                    contentDescription = if (revealToken) "Hide session token" else "Show session token",
                                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                        }
                    } else {
                        null
                    },
                )
                RowDivider()
                InfoRow(
                    label = "Last risk level",
                    value = snapshot.lastRiskLevel?.label() ?: "Not saved",
                )
            }
        }

        item(key = "display") {
            Section(title = "Display") {
                SwitchRow(
                    title = "Show detected signals on Overview",
                    supporting = "Saved in encrypted storage. Doesn't affect scoring.",
                    checked = snapshot.showSignalsOnHome,
                    onCheckedChange = onToggleShowSignalsOnHome,
                )
            }
        }

        item(key = "note") {
            SectionFooter(
                text = "TrustGate never writes card numbers, payment credentials, or production keys to the device. " +
                    "These values exist only to show encrypted persistence working.",
            )
        }
    }
}
