package id.fatarc.trustgate.ui.lab

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.KeyboardArrowRight
import androidx.compose.material.icons.outlined.ContentCut
import androidx.compose.material.icons.outlined.ErrorOutline
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.Receipt
import androidx.compose.material.icons.outlined.Repeat
import androidx.compose.material.icons.outlined.Schedule
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.dp
import id.fatarc.trustgate.core.keys.RegisteredKey
import id.fatarc.trustgate.domain.api.VerifiedBootState
import id.fatarc.trustgate.domain.signing.KeyRole
import id.fatarc.trustgate.domain.signing.ReferenceSigningScheme
import id.fatarc.trustgate.domain.signing.VerificationResult
import id.fatarc.trustgate.ui.LabTest
import id.fatarc.trustgate.ui.ListRow
import id.fatarc.trustgate.ui.Pill
import id.fatarc.trustgate.ui.RowDivider
import id.fatarc.trustgate.ui.ScreenScaffold
import id.fatarc.trustgate.ui.Section
import id.fatarc.trustgate.ui.SensitiveScreen
import id.fatarc.trustgate.ui.SwitchRow
import id.fatarc.trustgate.ui.Tone
import id.fatarc.trustgate.ui.TrustGateSpacing
import id.fatarc.trustgate.ui.TrustGateUiState
import id.fatarc.trustgate.ui.ValueRow
import id.fatarc.trustgate.ui.contentColor
import id.fatarc.trustgate.ui.label
import id.fatarc.trustgate.ui.maskToken
import id.fatarc.trustgate.ui.signing.icon
import id.fatarc.trustgate.ui.signing.label
import id.fatarc.trustgate.ui.signing.shortLabel
import id.fatarc.trustgate.ui.signing.title

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun LabScreen(
    uiState: TrustGateUiState,
    onRunTest: (LabTest) -> Unit,
    onSetSimulateLostResponse: (Boolean) -> Unit,
    onStoreTestValues: () -> Unit,
    onOpenRequest: () -> Unit,
    onOpenAbout: () -> Unit,
) {
    SensitiveScreen()
    var openKey by rememberSaveable { mutableStateOf<KeyRole?>(null) }
    val keys = uiState.keys.keys

    ScreenScaffold(title = "Lab") {
        item(key = "intro") {
            Text(
                text = "Attack the real server and watch it say no.",
                modifier = Modifier.padding(horizontal = 4.dp),
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        item(key = "attacks") {
            Section(title = "Try to break it") {
                LabTest.entries.forEachIndexed { index, test ->
                    LabTestRow(
                        test = test,
                        running = uiState.lab.running == test,
                        enabled = uiState.lab.running == null,
                        outcomes = uiState.lab.results[test],
                        onRun = { onRunTest(test) },
                    )
                    if (index != LabTest.entries.lastIndex) RowDivider(startIndent = TrustGateSpacing.listIconInset)
                }
            }
        }

        item(key = "network") {
            Section(title = "Network") {
                SwitchRow(
                    title = "Lose the first reply",
                    supporting = "On your next payment. The app retries and you're charged once.",
                    checked = uiState.simulateLostResponse,
                    onCheckedChange = onSetSimulateLostResponse,
                )
            }
        }

        item(key = "keys") {
            Section(title = "Keys on this phone") {
                when {
                    keys != null -> {
                        KeyRow(key = keys.device, onClick = { openKey = KeyRole.DEVICE })
                        RowDivider(startIndent = TrustGateSpacing.listIconInset)
                        val stepUp = keys.stepUp
                        if (stepUp != null) {
                            KeyRow(key = stepUp, onClick = { openKey = KeyRole.STEP_UP })
                        } else {
                            ListRow(
                                headline = KeyRole.STEP_UP.title(),
                                supporting = keys.stepUpUnavailableReason ?: "Not set up",
                                leadingIcon = KeyRole.STEP_UP.icon(),
                            )
                        }
                    }
                    uiState.keys.errorMessage != null -> ListRow(
                        headline = "Keys aren't ready",
                        supporting = uiState.keys.errorMessage,
                        leadingIcon = Icons.Outlined.ErrorOutline,
                        leadingTint = Tone.CRITICAL.contentColor(),
                    )
                    else -> ListRow(headline = "Setting up keys…", leadingIcon = KeyRole.DEVICE.icon())
                }
            }
        }

        item(key = "storage") {
            val snapshot = uiState.storage.snapshot
            Section(title = "Stored securely") {
                ListRow(
                    headline = "Session token",
                    supporting = snapshot.sessionToken?.let(::maskToken) ?: "Not saved",
                    leadingIcon = Icons.Outlined.Lock,
                )
                RowDivider(startIndent = TrustGateSpacing.listIconInset)
                ListRow(
                    headline = "Last risk level",
                    supporting = snapshot.lastRiskLevel?.label() ?: "Not saved",
                    leadingIcon = Icons.Outlined.Lock,
                )
                FilledTonalButton(onClick = onStoreTestValues, modifier = Modifier.padding(start = 16.dp, bottom = 16.dp, top = 4.dp)) {
                    Text("Save test values")
                }
            }
        }

        item(key = "more") {
            Section {
                ListRow(
                    headline = "What was sent last",
                    supporting = if (uiState.lastRequest == null) "Run a test or a payment first" else "The signed request, field by field",
                    leadingIcon = Icons.Outlined.Receipt,
                    trailing = { Icon(Icons.AutoMirrored.Outlined.KeyboardArrowRight, contentDescription = null) },
                    onClick = if (uiState.lastRequest != null) onOpenRequest else null,
                )
                RowDivider(startIndent = TrustGateSpacing.listIconInset)
                ListRow(
                    headline = "About TrustGate",
                    leadingIcon = Icons.Outlined.Info,
                    trailing = { Icon(Icons.AutoMirrored.Outlined.KeyboardArrowRight, contentDescription = null) },
                    onClick = onOpenAbout,
                )
            }
        }
    }

    val shown = when (openKey) {
        KeyRole.DEVICE -> keys?.device
        KeyRole.STEP_UP -> keys?.stepUp
        null -> null
    }
    if (shown != null) {
        ModalBottomSheet(onDismissRequest = { openKey = null }) { KeyDetails(shown) }
    }
}

@Composable
private fun LabTestRow(
    test: LabTest,
    running: Boolean,
    enabled: Boolean,
    outcomes: List<VerificationResult>?,
    onRun: () -> Unit,
) {
    val last = outcomes?.lastOrNull()
    ListRow(
        headline = test.title,
        supporting = when (last) {
            null -> test.description
            VerificationResult.Accepted -> "The server accepted it"
            is VerificationResult.Rejected -> "Refused: ${last.reason.shortLabel()}"
        },
        leadingIcon = test.icon,
        trailing = {
            when {
                running -> CircularProgressIndicator(modifier = Modifier.size(24.dp), strokeWidth = 2.5.dp)
                last is VerificationResult.Rejected -> Pill(text = "Stopped", tone = Tone.POSITIVE)
                last == VerificationResult.Accepted -> Pill(text = "Got through", tone = Tone.CRITICAL)
                else -> FilledTonalButton(onClick = onRun, enabled = enabled) { Text("Run") }
            }
        },
        onClickLabel = "Run the test",
        onClick = if (enabled && !running && last != null) onRun else null,
    )
}

private val LabTest.title: String
    get() = when (this) {
        LabTest.REPLAY -> "Replay a request"
        LabTest.CHANGED_AMOUNT -> "Change the amount"
        LabTest.SENT_LATE -> "Send it late"
    }

private val LabTest.description: String
    get() = when (this) {
        LabTest.REPLAY -> "Send one signed request twice"
        LabTest.CHANGED_AMOUNT -> "Edit a signed request on its way"
        LabTest.SENT_LATE -> "Deliver it after ${ReferenceSigningScheme.TIME_WINDOW.toMinutes()} minutes"
    }

private val LabTest.icon: ImageVector
    get() = when (this) {
        LabTest.REPLAY -> Icons.Outlined.Repeat
        LabTest.CHANGED_AMOUNT -> Icons.Outlined.ContentCut
        LabTest.SENT_LATE -> Icons.Outlined.Schedule
    }

@Composable
private fun KeyRow(
    key: RegisteredKey,
    onClick: () -> Unit,
) {
    ListRow(
        headline = key.role.title(),
        supporting = when (key.role) {
            KeyRole.DEVICE -> "Signs every payment · ${key.protection.label()}"
            KeyRole.STEP_UP -> "Signs only after your fingerprint or PIN"
        },
        leadingIcon = key.role.icon(),
        leadingTint = Tone.POSITIVE.contentColor(),
        trailing = { Icon(Icons.AutoMirrored.Outlined.KeyboardArrowRight, contentDescription = null) },
        onClickLabel = "Show details",
        onClick = onClick,
    )
}

@Composable
private fun KeyDetails(key: RegisteredKey) {
    val attestation = key.attestation
    Column(modifier = Modifier.navigationBarsPadding().padding(bottom = 16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(key.role.title(), modifier = Modifier.padding(horizontal = 24.dp), style = MaterialTheme.typography.titleLarge)
        Text(
            text = "The private half never leaves Android Keystore. The server checked these facts when it registered the key.",
            modifier = Modifier.padding(start = 24.dp, end = 24.dp, bottom = 8.dp),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        ValueRow(label = "Stored in", value = key.protection.label())
        ValueRow(label = "Proven by Keystore", value = if (attestation.attested) "Yes, ${attestation.chainLength} certificates" else "No")
        if (attestation.attested) {
            ValueRow(label = "Google's root", value = if (attestation.trustedRoot) "Yes" else "No (emulator or test device)")
        }
        attestation.verifiedBootState?.let {
            ValueRow(label = "Boot", value = if (it == VerifiedBootState.VERIFIED) "Verified" else "Not verified")
        }
        attestation.deviceLocked?.let { ValueRow(label = "Bootloader", value = if (it) "Locked" else "Unlocked") }
        ValueRow(label = "Key ID", value = key.keyId, monospace = true, copyable = true)
    }
}
