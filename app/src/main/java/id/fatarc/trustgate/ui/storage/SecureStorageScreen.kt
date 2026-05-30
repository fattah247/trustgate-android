package id.fatarc.trustgate.ui.storage

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import id.fatarc.trustgate.ui.KeyValueRow
import id.fatarc.trustgate.ui.SectionCard
import id.fatarc.trustgate.ui.TrustGateUiState
import id.fatarc.trustgate.ui.maskToken

@Composable
fun SecureStorageScreen(
    uiState: TrustGateUiState,
    onStoreDemoValues: () -> Unit,
    onRefreshStorage: () -> Unit,
    onToggleShowSignalsOnHome: (Boolean) -> Unit,
) {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        item {
            SectionCard(
                title = "Encrypted values",
                modifier = Modifier.padding(top = 16.dp),
            ) {
                Text(
                    text = "This demo stores a mock session token, the last risk decision, and one harmless UI preference in encrypted local storage.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                KeyValueRow(
                    label = "Session token",
                    value = maskToken(uiState.storageSnapshot.sessionToken),
                )
                KeyValueRow(
                    label = "Last risk level",
                    value = uiState.storageSnapshot.lastRiskLevel?.name ?: "Not stored",
                )
                KeyValueRow(
                    label = "Signals visible on home",
                    value = uiState.storageSnapshot.showSignalsOnHome.toString(),
                )
                Switch(
                    checked = uiState.storageSnapshot.showSignalsOnHome,
                    onCheckedChange = onToggleShowSignalsOnHome,
                )
                Button(
                    onClick = onStoreDemoValues,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text("Store demo values")
                }
                Button(
                    onClick = onRefreshStorage,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text("Reload stored values")
                }
                Text(uiState.storageMessage, style = MaterialTheme.typography.bodyMedium)
            }
        }

        item {
            SectionCard(
                title = "What is not stored",
                modifier = Modifier.padding(bottom = 24.dp),
            ) {
                Text(
                    text = "No real card data, payment credentials, or server secrets are stored in the app.",
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
        }
    }
}

