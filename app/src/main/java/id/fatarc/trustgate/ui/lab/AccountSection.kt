package id.fatarc.trustgate.ui.lab

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.Login
import androidx.compose.material.icons.outlined.AddLink
import androidx.compose.material.icons.outlined.HourglassTop
import androidx.compose.material.icons.outlined.PhoneAndroid
import androidx.compose.material.icons.outlined.PhonelinkErase
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import id.fatarc.trustgate.domain.api.PhoneStatus
import id.fatarc.trustgate.domain.api.PhoneView
import id.fatarc.trustgate.domain.signing.ReferenceSigningScheme
import id.fatarc.trustgate.ui.AccountUiState
import id.fatarc.trustgate.ui.CodeTextStyle
import id.fatarc.trustgate.ui.ListRow
import id.fatarc.trustgate.ui.RowDivider
import id.fatarc.trustgate.ui.Section
import id.fatarc.trustgate.ui.Tone
import id.fatarc.trustgate.ui.TrustGateSpacing
import id.fatarc.trustgate.ui.contentColor

/** What the account section can ask for. */
class AccountActions(
    val onRefresh: () -> Unit,
    val onCreateLinkCode: () -> Unit,
    val onDismissLinkCode: () -> Unit,
    val onJoin: (code: String) -> Unit,
    val onDecide: (phoneId: String, action: String) -> Unit,
)

/**
 * The phones that can pay from this account. A new phone gets in only when a phone already on the
 * account approves it, with that phone's screen lock when it has one.
 */
@Composable
fun AccountSection(
    state: AccountUiState,
    actions: AccountActions,
) {
    var joining by rememberSaveable { mutableStateOf(false) }
    var removing by rememberSaveable { mutableStateOf<String?>(null) }
    val phones = state.view?.phones.orEmpty()

    Section(title = "Phones on this account") {
        when {
            state.view == null && state.loading -> ListRow(headline = "Loading…", leadingIcon = Icons.Outlined.PhoneAndroid)
            state.view == null -> ListRow(
                headline = "Couldn't load the phones",
                supporting = state.problem,
                leadingIcon = Icons.Outlined.PhoneAndroid,
                onClickLabel = "Try again",
                onClick = actions.onRefresh,
            )
            else -> phones.forEach { phone ->
                PhoneRow(
                    phone = phone,
                    onApprove = { actions.onDecide(phone.phoneId, ReferenceSigningScheme.DECISION_APPROVE) },
                    onDecline = { actions.onDecide(phone.phoneId, ReferenceSigningScheme.DECISION_DECLINE) },
                    onRemove = { removing = phone.phoneId },
                )
                RowDivider(startIndent = TrustGateSpacing.listIconInset)
            }
        }
        if (state.view?.waitingToJoin == true) {
            ListRow(
                headline = "Waiting to join another account",
                supporting = "Approve this phone on your other phone",
                leadingIcon = Icons.Outlined.HourglassTop,
                leadingTint = Tone.CAUTION.contentColor(),
            )
            RowDivider(startIndent = TrustGateSpacing.listIconInset)
        }
        ListRow(
            headline = "Add another phone",
            supporting = "Makes a code the other phone enters",
            leadingIcon = Icons.Outlined.AddLink,
            onClickLabel = "Make a code",
            onClick = actions.onCreateLinkCode,
        )
        RowDivider(startIndent = TrustGateSpacing.listIconInset)
        ListRow(
            headline = "Join another account",
            supporting = "Enter the code from your other phone",
            leadingIcon = Icons.AutoMirrored.Outlined.Login,
            onClickLabel = "Enter a code",
            onClick = { joining = true },
        )
    }

    state.linkCode?.let { code ->
        AlertDialog(
            onDismissRequest = actions.onDismissLinkCode,
            icon = { Icon(Icons.Outlined.AddLink, contentDescription = null) },
            title = { Text("Code for your other phone") },
            text = {
                Column {
                    Text(
                        code.code.chunked(4).joinToString(" "),
                        modifier = Modifier.fillMaxWidth().padding(vertical = 12.dp),
                        style = CodeTextStyle.copy(fontSize = MaterialTheme.typography.headlineMedium.fontSize),
                        textAlign = TextAlign.Center,
                    )
                    Text(
                        "On the other phone, open Lab, choose Join another account, and enter it. Then approve that phone here. " +
                            "The code works once, for 10 minutes. Never share it with someone who calls you.",
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
            },
            confirmButton = { TextButton(onClick = actions.onDismissLinkCode) { Text("Done") } },
        )
    }

    if (joining) {
        var code by rememberSaveable { mutableStateOf("") }
        AlertDialog(
            onDismissRequest = { joining = false },
            icon = { Icon(Icons.AutoMirrored.Outlined.Login, contentDescription = null) },
            title = { Text("Join another account") },
            text = {
                OutlinedTextField(
                    value = code,
                    onValueChange = { code = it.take(12) },
                    label = { Text("Code") },
                    singleLine = true,
                    textStyle = CodeTextStyle,
                    keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.Characters),
                )
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        joining = false
                        actions.onJoin(code)
                    },
                    enabled = ReferenceSigningScheme.normalizeLinkCode(code).length == 8,
                ) { Text("Join") }
            },
            dismissButton = { TextButton(onClick = { joining = false }) { Text("Cancel") } },
        )
    }

    removing?.let { phoneId ->
        val label = phones.firstOrNull { it.phoneId == phoneId }?.label ?: "this phone"
        AlertDialog(
            onDismissRequest = { removing = null },
            icon = { Icon(Icons.Outlined.PhonelinkErase, contentDescription = null) },
            title = { Text("Remove $label?") },
            text = { Text("It won't be able to pay from this account again. Use this if it's lost or stolen.") },
            confirmButton = {
                TextButton(
                    onClick = {
                        removing = null
                        actions.onDecide(phoneId, ReferenceSigningScheme.DECISION_REMOVE)
                    },
                    colors = ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.error),
                ) { Text("Remove") }
            },
            dismissButton = { TextButton(onClick = { removing = null }) { Text("Cancel") } },
        )
    }
}

@Composable
private fun PhoneRow(
    phone: PhoneView,
    onApprove: () -> Unit,
    onDecline: () -> Unit,
    onRemove: () -> Unit,
) {
    ListRow(
        headline = if (phone.thisPhone) "${phone.label} (this phone)" else phone.label,
        supporting = when (phone.status) {
            PhoneStatus.WAITING_FOR_APPROVAL -> "Wants to join this account"
            PhoneStatus.NEW -> "New on this account: confirms every payment for a day"
            PhoneStatus.ACTIVE -> "Can pay from this account"
        },
        leadingIcon = Icons.Outlined.PhoneAndroid,
        leadingTint = if (phone.status == PhoneStatus.WAITING_FOR_APPROVAL) Tone.CAUTION.contentColor() else Tone.POSITIVE.contentColor(),
        trailing = when {
            phone.status == PhoneStatus.WAITING_FOR_APPROVAL -> {
                {
                    Column {
                        FilledTonalButton(onClick = onApprove) { Text("Approve") }
                        TextButton(onClick = onDecline) { Text("Decline") }
                    }
                }
            }
            !phone.thisPhone -> {
                { TextButton(onClick = onRemove) { Text("Remove") } }
            }
            else -> null
        },
    )
}
