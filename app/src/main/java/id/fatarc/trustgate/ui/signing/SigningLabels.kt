package id.fatarc.trustgate.ui.signing

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Fingerprint
import androidx.compose.material.icons.outlined.Key
import androidx.compose.ui.graphics.vector.ImageVector
import id.fatarc.trustgate.domain.api.SecurityLevel
import id.fatarc.trustgate.domain.signing.KeyRole
import id.fatarc.trustgate.domain.signing.RejectionReason

// How keys and backend rejections are named wherever they appear, from the signing screens to the activity log.

fun KeyRole.title(): String = when (this) {
    KeyRole.DEVICE -> "Device key"
    KeyRole.STEP_UP -> "Step-up key"
}

fun KeyRole.icon(): ImageVector = when (this) {
    KeyRole.DEVICE -> Icons.Outlined.Key
    KeyRole.STEP_UP -> Icons.Outlined.Fingerprint
}

fun SecurityLevel.label(): String = when (this) {
    SecurityLevel.STRONGBOX -> "StrongBox"
    SecurityLevel.TRUSTED_ENVIRONMENT -> "Secure hardware"
    SecurityLevel.SOFTWARE -> "Software"
    SecurityLevel.UNKNOWN -> "Unknown"
}

fun RejectionReason.shortLabel(): String = when (this) {
    RejectionReason.MISSING_HEADERS -> "headers missing"
    RejectionReason.MALFORMED_TIMESTAMP -> "bad timestamp"
    RejectionReason.OUTSIDE_TIME_WINDOW -> "outside the time window"
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
