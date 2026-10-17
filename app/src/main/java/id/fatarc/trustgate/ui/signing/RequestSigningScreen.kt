package id.fatarc.trustgate.ui.signing

import androidx.compose.animation.animateContentSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.Send
import androidx.compose.material.icons.outlined.EditNote
import androidx.compose.material.icons.outlined.ErrorOutline
import androidx.compose.material.icons.outlined.GppBad
import androidx.compose.material.icons.outlined.Schedule
import androidx.compose.material.icons.outlined.VerifiedUser
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import id.fatarc.trustgate.core.backend.ReferenceBackend
import id.fatarc.trustgate.domain.signing.RejectionReason
import id.fatarc.trustgate.domain.signing.VerificationResult
import id.fatarc.trustgate.ui.CodeTextStyle
import id.fatarc.trustgate.ui.CopyButton
import id.fatarc.trustgate.ui.GroupedSurface
import id.fatarc.trustgate.ui.ListRow
import id.fatarc.trustgate.ui.NoticeCard
import id.fatarc.trustgate.ui.RowDivider
import id.fatarc.trustgate.ui.ScreenScaffold
import id.fatarc.trustgate.ui.Section
import id.fatarc.trustgate.ui.SensitiveScreen
import id.fatarc.trustgate.ui.SigningStatus
import id.fatarc.trustgate.ui.TimeFormats
import id.fatarc.trustgate.ui.Tone
import id.fatarc.trustgate.ui.TrustGateSpacing
import id.fatarc.trustgate.ui.TrustGateUiState
import id.fatarc.trustgate.ui.ValueRow
import id.fatarc.trustgate.ui.VerificationAttempt
import id.fatarc.trustgate.ui.VerificationRecord
import id.fatarc.trustgate.ui.contentColor
import id.fatarc.trustgate.ui.rememberTimeFormats

@Composable
fun RequestSigningScreen(
    uiState: TrustGateUiState,
    onNavigateUp: () -> Unit,
    onSignReferenceRequest: () -> Unit,
    onVerifyRequest: (VerificationAttempt) -> Unit,
) {
    val formats = rememberTimeFormats()
    val request = uiState.signing.signedRequest
    val verifications = uiState.signing.verifications

    SensitiveScreen()

    ScreenScaffold(
        title = "Request signing",
        onNavigateUp = onNavigateUp,
    ) {
        item(key = "intro") {
            GroupedSurface {
                Text(
                    text = "Signs a reference payment request with this device's P-256 key (ECDSA over SHA-256). " +
                        "The private key stays in Android Keystore; the backend checks the signature with the " +
                        "public key it registered.",
                    modifier = Modifier.padding(16.dp),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                val buttonModifier = Modifier
                    .fillMaxWidth()
                    .padding(start = 16.dp, end = 16.dp, bottom = 16.dp)
                if (request == null) {
                    Button(onClick = onSignReferenceRequest, modifier = buttonModifier) {
                        Text("Sign request")
                    }
                } else {
                    OutlinedButton(onClick = onSignReferenceRequest, modifier = buttonModifier) {
                        Text("Sign a new request")
                    }
                }
            }
        }

        item(key = "keys") {
            DeviceKeysSection(keys = uiState.keys)
        }

        (uiState.signing.status as? SigningStatus.Failed)?.let { failure ->
            item(key = "error") {
                NoticeCard(
                    title = "Signing failed",
                    body = failure.message,
                    tone = Tone.CRITICAL,
                    icon = Icons.Outlined.ErrorOutline,
                )
            }
        }

        if (request != null) {
            item(key = "verifier") {
                Section(
                    title = "Try it against the backend",
                    footer = "The reference backend verifies with the registered public key. The signature must " +
                        "cover what arrived, the timestamp must be within ${ReferenceBackend.ALLOWED_CLOCK_SKEW.toMinutes()} minutes, " +
                        "and the nonce must be a one-time challenge it issued to this device.",
                ) {
                    ListRow(
                        headline = "Send as signed",
                        supporting = "Sending it a second time replays the backend's one-time challenge.",
                        supportingColor = MaterialTheme.colorScheme.onSurfaceVariant,
                        leadingIcon = Icons.AutoMirrored.Outlined.Send,
                        onClickLabel = "Send to the verifier",
                        onClick = { onVerifyRequest(VerificationAttempt.AS_SIGNED) },
                    )
                    RowDivider(startIndent = TrustGateSpacing.listIconInset)
                    ListRow(
                        headline = "Send with a changed amount",
                        supporting = "Edits the body after signing, as someone in the middle would.",
                        supportingColor = MaterialTheme.colorScheme.onSurfaceVariant,
                        leadingIcon = Icons.Outlined.EditNote,
                        onClickLabel = "Send altered request",
                        onClick = { onVerifyRequest(VerificationAttempt.CHANGED_AMOUNT) },
                    )
                    RowDivider(startIndent = TrustGateSpacing.listIconInset)
                    ListRow(
                        headline = "Send after the time window",
                        supporting = "Delivers it as if it was held back and arrived too late.",
                        supportingColor = MaterialTheme.colorScheme.onSurfaceVariant,
                        leadingIcon = Icons.Outlined.Schedule,
                        onClickLabel = "Send late request",
                        onClick = { onVerifyRequest(VerificationAttempt.DELIVERED_LATE) },
                    )
                }
            }

            if (verifications.isNotEmpty()) {
                item(key = "responses") {
                    Section(title = "Backend responses", modifier = Modifier.animateContentSize()) {
                        verifications.forEachIndexed { index, record ->
                            VerificationRow(record = record, formats = formats)
                            if (index != verifications.lastIndex) RowDivider(startIndent = TrustGateSpacing.listIconInset)
                        }
                    }
                }
            }

            item(key = "request") {
                Section(title = "Request") {
                    ValueRow(label = "Endpoint", value = "${request.method} ${request.path}", monospace = true)
                    RowDivider()
                    ValueRow(label = "Signed by", value = request.keyId, monospace = true)
                    RowDivider()
                    ValueRow(label = "Body hash (SHA-256)", value = request.bodyHash, monospace = true, copyable = true)
                }
            }

            item(key = "body") {
                Section(
                    title = "Canonical body",
                    action = { CopyButton(label = "Body", value = request.canonicalBody) },
                    footer = "The exact bytes that were hashed. Any change to the body changes the hash and the signature.",
                ) {
                    SelectionContainer {
                        Text(
                            text = request.canonicalBody,
                            modifier = Modifier.padding(16.dp),
                            style = CodeTextStyle,
                        )
                    }
                }
            }

            item(key = "headers") {
                val headers = request.headers.toSortedMap().entries.toList()
                Section(
                    title = "Headers",
                    footer = "The signature covers the method, path, timestamp, nonce, and body hash.",
                ) {
                    headers.forEachIndexed { index, (name, value) ->
                        ValueRow(label = name, value = value, monospace = true, copyable = true)
                        if (index != headers.lastIndex) RowDivider()
                    }
                }
            }
        }
    }
}

@Composable
private fun VerificationRow(
    record: VerificationRecord,
    formats: TimeFormats,
) {
    val accepted = record.result is VerificationResult.Accepted
    val sentAs = when {
        record.sentByProtectedAction && record.lostResponses > 0 ->
            "Sent by the protected action; the first response was lost and the retry returned the same payment"
        record.sentByProtectedAction -> "Sent by the protected action"
        else -> when (record.attempt) {
            VerificationAttempt.AS_SIGNED -> "Sent as signed"
            VerificationAttempt.CHANGED_AMOUNT -> "Sent with a changed amount"
            VerificationAttempt.DELIVERED_LATE -> "Sent after the time window"
        }
    }
    ListRow(
        headline = when (val result = record.result) {
            VerificationResult.Accepted -> "Accepted"
            is VerificationResult.Rejected -> "Rejected: ${result.reason.shortLabel()}"
        },
        supporting = when (val result = record.result) {
            VerificationResult.Accepted -> "$sentAs · ${formats.preciseTime(record.at)}. Signature, time, and nonce all held."
            is VerificationResult.Rejected -> "$sentAs · ${formats.preciseTime(record.at)}. ${result.reason.sentence()}"
        },
        supportingColor = MaterialTheme.colorScheme.onSurfaceVariant,
        leadingIcon = if (accepted) Icons.Outlined.VerifiedUser else Icons.Outlined.GppBad,
        leadingTint = if (accepted) Tone.POSITIVE.contentColor() else Tone.CRITICAL.contentColor(),
        leadingIconDescription = if (accepted) "Accepted" else "Rejected",
    )
}

fun RejectionReason.shortLabel(): String = when (this) {
    RejectionReason.MISSING_HEADERS -> "headers missing"
    RejectionReason.MALFORMED_TIMESTAMP -> "bad timestamp"
    RejectionReason.OUTSIDE_TIME_WINDOW -> "too late"
    RejectionReason.UNKNOWN_KEY -> "unknown key"
    RejectionReason.SIGNATURE_MISMATCH -> "signature mismatch"
    RejectionReason.UNKNOWN_CHALLENGE -> "unknown challenge"
    RejectionReason.CHALLENGE_REUSED -> "replayed"
    RejectionReason.CONFIRMATION_REQUIRED -> "confirmation missing"
    RejectionReason.IDEMPOTENCY_CONFLICT -> "idempotency conflict"
    RejectionReason.MALFORMED_BODY -> "unreadable body"
}

/** What the rejection means for someone trying to abuse the request. */
fun RejectionReason.sentence(): String = when (this) {
    RejectionReason.MISSING_HEADERS -> "A signing header was missing or malformed."
    RejectionReason.MALFORMED_TIMESTAMP -> "The timestamp couldn't be read, so freshness can't be checked."
    RejectionReason.OUTSIDE_TIME_WINDOW -> "It was signed too long before it arrived, so a held-back request can't be used later."
    RejectionReason.UNKNOWN_KEY -> "The backend never registered the key that signed it."
    RejectionReason.SIGNATURE_MISMATCH -> "What arrived isn't what was signed, so an edited request can't get through."
    RejectionReason.UNKNOWN_CHALLENGE -> "The nonce isn't a challenge the backend issued to this device, or it expired."
    RejectionReason.CHALLENGE_REUSED -> "This one-time challenge was already used, so a captured request can't be sent twice."
    RejectionReason.CONFIRMATION_REQUIRED -> "The backend asked for confirmation and the request wasn't signed with it."
    RejectionReason.IDEMPOTENCY_CONFLICT -> "The idempotency key was already used for a different payment."
    RejectionReason.MALFORMED_BODY -> "The body isn't a payment the backend can process, so nothing was charged."
}
