package id.fatarc.trustgate.ui.lab

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.KeyboardArrowRight
import androidx.compose.material.icons.outlined.ContentCut
import androidx.compose.material.icons.outlined.ErrorOutline
import androidx.compose.material.icons.outlined.ExpandMore
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.PhonelinkErase
import androidx.compose.material.icons.outlined.Receipt
import androidx.compose.material.icons.outlined.Repeat
import androidx.compose.material.icons.outlined.Schedule
import androidx.compose.material.icons.outlined.Shop
import androidx.compose.material.icons.outlined.Speed
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import id.fatarc.trustgate.core.integrity.PretendVerdict
import id.fatarc.trustgate.core.keys.RegisteredKey
import id.fatarc.trustgate.domain.api.VerifiedBootState
import id.fatarc.trustgate.domain.signing.KeyRole
import id.fatarc.trustgate.domain.signing.ReferenceSigningScheme
import id.fatarc.trustgate.ui.LabResult
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
import id.fatarc.trustgate.ui.signing.title

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun LabScreen(
    uiState: TrustGateUiState,
    onRunTest: (LabTest) -> Unit,
    onSetSimulateLostResponse: (Boolean) -> Unit,
    onSetPretendVerdict: (PretendVerdict) -> Unit,
    onRotateKey: () -> Unit,
    onRemovePhone: () -> Unit,
    account: AccountActions,
    onStoreTestValues: () -> Unit,
    onOpenRequest: () -> Unit,
    onOpenAbout: () -> Unit,
) {
    SensitiveScreen()
    var openKey by rememberSaveable { mutableStateOf<KeyRole?>(null) }
    var choosingVerdict by rememberSaveable { mutableStateOf(false) }
    var confirmRemove by rememberSaveable { mutableStateOf(false) }
    LaunchedEffect(Unit) { account.onRefresh() }
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
                        result = uiState.lab.results[test],
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

        uiState.pretendVerdict?.let { verdict ->
            item(key = "play") {
                Section(title = "Pretend Google Play found") {
                    ListRow(
                        headline = verdict.title,
                        supporting = "Test mode: this build makes up its Play Integrity answer",
                        leadingIcon = Icons.Outlined.Shop,
                        trailing = { Icon(Icons.Outlined.ExpandMore, contentDescription = null) },
                        onClickLabel = "Change",
                        onClick = { choosingVerdict = true },
                    )
                }
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
                        RowDivider(startIndent = TrustGateSpacing.listIconInset)
                        ListRow(
                            headline = "Remove this phone",
                            supporting = "The server forgets these keys; the app starts over",
                            leadingIcon = Icons.Outlined.PhonelinkErase,
                            leadingTint = Tone.CRITICAL.contentColor(),
                            onClickLabel = "Remove",
                            onClick = { confirmRemove = true },
                        )
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

        item(key = "account") {
            AccountSection(state = uiState.account, actions = account)
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
        ModalBottomSheet(onDismissRequest = { openKey = null }) {
            KeyDetails(
                key = shown,
                onReplace = if (shown.role == KeyRole.DEVICE) {
                    {
                        openKey = null
                        onRotateKey()
                    }
                } else {
                    null
                },
            )
        }
    }
    if (confirmRemove) {
        AlertDialog(
            onDismissRequest = { confirmRemove = false },
            icon = { Icon(Icons.Outlined.PhonelinkErase, contentDescription = null) },
            title = { Text("Remove this phone?") },
            text = { Text("The server stops accepting this phone's keys for good. The app then sets the phone up again as a new one.") },
            confirmButton = {
                TextButton(
                    onClick = {
                        confirmRemove = false
                        onRemovePhone()
                    },
                    colors = ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.error),
                ) { Text("Remove") }
            },
            dismissButton = { TextButton(onClick = { confirmRemove = false }) { Text("Cancel") } },
        )
    }
    if (choosingVerdict) {
        ModalBottomSheet(onDismissRequest = { choosingVerdict = false }) {
            VerdictChoices(
                selected = uiState.pretendVerdict,
                onSelect = { verdict ->
                    choosingVerdict = false
                    onSetPretendVerdict(verdict)
                },
            )
        }
    }
}

@Composable
private fun VerdictChoices(
    selected: PretendVerdict?,
    onSelect: (PretendVerdict) -> Unit,
) {
    Column(modifier = Modifier.navigationBarsPadding().padding(bottom = 16.dp).selectableGroup()) {
        Text(
            "Pretend Google Play found…",
            modifier = Modifier.padding(start = 24.dp, end = 24.dp, bottom = 4.dp),
            style = MaterialTheme.typography.titleLarge,
        )
        Text(
            "Your next payment carries this answer, and the server reacts as it would to Google's.",
            modifier = Modifier.padding(start = 24.dp, end = 24.dp, bottom = 8.dp),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        PretendVerdict.entries.forEach { verdict ->
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .selectable(selected = verdict == selected, role = Role.RadioButton, onClick = { onSelect(verdict) })
                    .padding(horizontal = 16.dp, vertical = 12.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                RadioButton(selected = verdict == selected, onClick = null)
                Text(verdict.title, style = MaterialTheme.typography.bodyLarge)
            }
        }
    }
}

private val PretendVerdict.title: String
    get() = when (this) {
        PretendVerdict.NOTHING -> "Nothing unusual"
        PretendVerdict.REMOTE_CONTROL -> "A remote-control app running"
        PretendVerdict.UNKNOWN_SCREEN_READER -> "An unknown app reading the screen"
        PretendVerdict.SCREEN_RECORDER -> "A screen recorder running"
        PretendVerdict.MALWARE -> "Dangerous apps on the phone"
        PretendVerdict.PLAY_PROTECT_OFF -> "Play Protect turned off"
        PretendVerdict.NOT_FROM_PLAY -> "App not installed from Google Play"
        PretendVerdict.TOKEN_FARMING -> "Too many checks from this phone"
    }

@Composable
private fun LabTestRow(
    test: LabTest,
    running: Boolean,
    enabled: Boolean,
    result: LabResult?,
    onRun: () -> Unit,
) {
    ListRow(
        headline = test.title,
        supporting = result?.summary ?: test.description,
        leadingIcon = test.icon,
        trailing = {
            when {
                running -> CircularProgressIndicator(modifier = Modifier.size(24.dp), strokeWidth = 2.5.dp)
                result?.stopped == true -> Pill(text = "Stopped", tone = Tone.POSITIVE)
                result != null -> Pill(text = "Got through", tone = Tone.CRITICAL)
                else -> FilledTonalButton(onClick = onRun, enabled = enabled) { Text("Run") }
            }
        },
        onClickLabel = "Run the test",
        onClick = if (enabled && !running && result != null) onRun else null,
    )
}

private val LabTest.title: String
    get() = when (this) {
        LabTest.REPLAY -> "Replay a request"
        LabTest.CHANGED_AMOUNT -> "Change the amount"
        LabTest.SENT_LATE -> "Send it late"
        LabTest.RAPID_PAYMENTS -> "Pay 6 times at once"
    }

private val LabTest.description: String
    get() = when (this) {
        LabTest.REPLAY -> "Send one signed request twice"
        LabTest.CHANGED_AMOUNT -> "Edit a signed request on its way"
        LabTest.SENT_LATE -> "Deliver it after ${ReferenceSigningScheme.TIME_WINDOW.toMinutes()} minutes"
        LabTest.RAPID_PAYMENTS -> "Drain the account faster than the limit allows"
    }

private val LabTest.icon: ImageVector
    get() = when (this) {
        LabTest.REPLAY -> Icons.Outlined.Repeat
        LabTest.CHANGED_AMOUNT -> Icons.Outlined.ContentCut
        LabTest.SENT_LATE -> Icons.Outlined.Schedule
        LabTest.RAPID_PAYMENTS -> Icons.Outlined.Speed
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
private fun KeyDetails(
    key: RegisteredKey,
    onReplace: (() -> Unit)?,
) {
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
        onReplace?.let {
            FilledTonalButton(onClick = it, modifier = Modifier.padding(start = 24.dp, top = 8.dp)) { Text("Replace this key") }
            Text(
                "The current key vouches for a new one, then stops working.",
                modifier = Modifier.padding(horizontal = 24.dp),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}
