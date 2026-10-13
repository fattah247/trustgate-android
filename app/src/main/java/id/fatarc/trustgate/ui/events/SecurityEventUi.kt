package id.fatarc.trustgate.ui.events

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Block
import androidx.compose.material.icons.outlined.Cancel
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material.icons.outlined.Fingerprint
import androidx.compose.material.icons.outlined.Flag
import androidx.compose.material.icons.outlined.GppBad
import androidx.compose.material.icons.outlined.Key
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.Payments
import androidx.compose.material.icons.outlined.PendingActions
import androidx.compose.material.icons.outlined.Radar
import androidx.compose.material.icons.outlined.Science
import androidx.compose.material.icons.outlined.VerifiedUser
import androidx.compose.ui.graphics.vector.ImageVector
import id.fatarc.trustgate.core.security.TrustGateSecurityService
import id.fatarc.trustgate.domain.events.SecurityEvent
import id.fatarc.trustgate.domain.events.SecurityEventType
import id.fatarc.trustgate.domain.risk.DeviceRiskLevel
import id.fatarc.trustgate.ui.Tone

enum class EventFilter(val label: String) {
    ALL("All"),
    CHECKS("Checks"),
    ACTIONS("Actions"),
    SIGNING("Signing"),
    STORAGE("Storage"),
}

fun SecurityEvent.matches(filter: EventFilter): Boolean = filter == EventFilter.ALL || group() == filter

val SecurityEvent.isScenario: Boolean
    get() = metadata["source"] == TrustGateSecurityService.SCENARIO_SOURCE

val SecurityEvent.isRejectedVerification: Boolean
    get() = type == SecurityEventType.REQUEST_VERIFIED && metadata["result"] == "rejected"

private val SecurityEvent.paymentResult: String?
    get() = metadata["result"].takeIf { type == SecurityEventType.PAYMENT_SUBMITTED }

/** Per-signal entries repeat what the check that produced them already says. */
val SecurityEvent.isSignalDetail: Boolean
    get() = type == SecurityEventType.ROOT_SIGNAL_FOUND ||
        type == SecurityEventType.EMULATOR_SIGNAL_FOUND ||
        type == SecurityEventType.DEBUGGER_ATTACHED

fun SecurityEvent.headline(): String = when (type) {
    SecurityEventType.DEVICE_RISK_ASSESSED -> when {
        isScenario -> "Simulated profile applied"
        metadata["trigger"] == "resume" ->
            if (metadata["previousLevel"] != null && metadata["previousLevel"] != riskLevel?.name) "Device risk changed" else "Detected signals changed"
        metadata["trigger"] == "before-action" -> "Device re-checked for an action"
        else -> "Device checked"
    }
    SecurityEventType.ROOT_SIGNAL_FOUND -> "Root signal found"
    SecurityEventType.EMULATOR_SIGNAL_FOUND -> "Emulator signal found"
    // Recorded for every debugging-category signal, including the debuggable build flag.
    SecurityEventType.DEBUGGER_ATTACHED -> "Debugging signal found"
    SecurityEventType.SENSITIVE_ACTION_ALLOWED -> "Protected action allowed"
    SecurityEventType.SENSITIVE_ACTION_REQUIRES_CONFIRMATION -> "Confirmation requested"
    SecurityEventType.SENSITIVE_ACTION_ALLOWED_AFTER_CONFIRMATION -> "Allowed after confirmation"
    SecurityEventType.SENSITIVE_ACTION_CANCELLED -> "Protected action cancelled"
    SecurityEventType.SENSITIVE_ACTION_BLOCKED -> "Protected action blocked"
    SecurityEventType.REQUEST_SIGNED -> "Request signed"
    SecurityEventType.REQUEST_VERIFIED -> if (isRejectedVerification) "Verifier rejected request" else "Verifier accepted request"
    SecurityEventType.SECURE_VALUE_STORED -> "Encrypted values saved"
    SecurityEventType.KEY_REGISTERED -> if (metadata["role"] == "step_up") "Step-up key registered" else "Device key registered"
    SecurityEventType.PAYMENT_SUBMITTED -> when (paymentResult) {
        "accepted" -> if (metadata["lostResponses"] != null) "Payment charged once after a retry" else "Payment charged"
        "unknown" -> "Payment outcome unknown"
        else -> "Payment refused"
    }
}

fun SecurityEvent.tone(): Tone = when (type) {
    SecurityEventType.DEVICE_RISK_ASSESSED -> when (riskLevel) {
        DeviceRiskLevel.MEDIUM -> Tone.CAUTION
        DeviceRiskLevel.HIGH -> Tone.CRITICAL
        DeviceRiskLevel.LOW, null -> Tone.NEUTRAL
    }

    SecurityEventType.ROOT_SIGNAL_FOUND,
    SecurityEventType.EMULATOR_SIGNAL_FOUND,
    SecurityEventType.DEBUGGER_ATTACHED,
    -> if (riskLevel == DeviceRiskLevel.HIGH) Tone.CRITICAL else Tone.CAUTION

    SecurityEventType.SENSITIVE_ACTION_ALLOWED,
    SecurityEventType.SENSITIVE_ACTION_ALLOWED_AFTER_CONFIRMATION,
    -> Tone.POSITIVE

    SecurityEventType.SENSITIVE_ACTION_REQUIRES_CONFIRMATION -> Tone.CAUTION
    SecurityEventType.SENSITIVE_ACTION_BLOCKED -> Tone.CRITICAL

    SecurityEventType.REQUEST_VERIFIED -> if (isRejectedVerification) Tone.CRITICAL else Tone.POSITIVE
    SecurityEventType.KEY_REGISTERED -> if (metadata["attestation"] == "verified") Tone.POSITIVE else Tone.CAUTION
    SecurityEventType.PAYMENT_SUBMITTED -> when (paymentResult) {
        "accepted" -> Tone.POSITIVE
        "unknown" -> Tone.CAUTION
        else -> Tone.CRITICAL
    }

    SecurityEventType.SENSITIVE_ACTION_CANCELLED,
    SecurityEventType.REQUEST_SIGNED,
    SecurityEventType.SECURE_VALUE_STORED,
    -> Tone.NEUTRAL
}

val SecurityEvent.icon: ImageVector
    get() = when (type) {
        SecurityEventType.DEVICE_RISK_ASSESSED -> if (isScenario) Icons.Outlined.Science else Icons.Outlined.Radar
        SecurityEventType.ROOT_SIGNAL_FOUND,
        SecurityEventType.EMULATOR_SIGNAL_FOUND,
        SecurityEventType.DEBUGGER_ATTACHED,
        -> Icons.Outlined.Flag

        SecurityEventType.SENSITIVE_ACTION_ALLOWED,
        SecurityEventType.SENSITIVE_ACTION_ALLOWED_AFTER_CONFIRMATION,
        -> Icons.Outlined.CheckCircle

        SecurityEventType.SENSITIVE_ACTION_REQUIRES_CONFIRMATION -> Icons.Outlined.PendingActions
        SecurityEventType.SENSITIVE_ACTION_CANCELLED -> Icons.Outlined.Cancel
        SecurityEventType.SENSITIVE_ACTION_BLOCKED -> Icons.Outlined.Block
        SecurityEventType.REQUEST_SIGNED -> Icons.Outlined.Key
        SecurityEventType.REQUEST_VERIFIED -> if (isRejectedVerification) Icons.Outlined.GppBad else Icons.Outlined.VerifiedUser
        SecurityEventType.SECURE_VALUE_STORED -> Icons.Outlined.Lock
        SecurityEventType.KEY_REGISTERED -> if (metadata["role"] == "step_up") Icons.Outlined.Fingerprint else Icons.Outlined.Key
        SecurityEventType.PAYMENT_SUBMITTED -> when (paymentResult) {
            "accepted" -> Icons.Outlined.Payments
            "unknown" -> Icons.Outlined.PendingActions
            else -> Icons.Outlined.GppBad
        }
    }

fun metadataLabel(key: String): String = when (key) {
    "score" -> "Score"
    "signalId" -> "Signal ID"
    "source" -> "Source"
    "nonce" -> "Nonce"
    "signaturePrefix" -> "Signature prefix"
    "keys" -> "Keys"
    "trigger" -> "Checked because"
    "previousLevel" -> "Previous level"
    "method" -> "Confirmed with"
    "attempt" -> "Sent"
    "result" -> "Result"
    "reason" -> "Reason"
    "decidedBy" -> "Decided by"
    "keyId" -> "Key ID"
    "role" -> "Key"
    "protection" -> "Held in"
    "attestation" -> "Attestation"
    "verifiedBoot" -> "Verified boot"
    "bootloaderLocked" -> "Bootloader locked"
    "idempotencyKey" -> "Idempotency key"
    "attempts" -> "Attempts"
    "lostResponses" -> "Lost responses"
    "paymentId" -> "Payment"
    else -> key
        .replace(Regex("([a-z])([A-Z])"), "$1 $2")
        .replace('_', ' ')
        .lowercase()
        .replaceFirstChar { it.titlecase() }
}

fun metadataValue(key: String, value: String): String = when {
    key == "source" && value == TrustGateSecurityService.SCENARIO_SOURCE -> "Simulated profile"
    key == "keys" -> value.split(',').joinToString(", ")
    key == "trigger" -> when (value) {
        "launch" -> "App opened"
        "manual" -> "Checked by hand"
        "before-action" -> "Protected action"
        "resume" -> "Returned to the app"
        else -> value
    }
    key == "previousLevel" -> value.lowercase().replaceFirstChar { it.titlecase() }
    key == "method" -> when (value) {
        "device-credential" -> "Screen lock or biometrics"
        "tap" -> "Tap (no screen lock set)"
        else -> value
    }
    key == "attempt" -> when (value) {
        "as-signed" -> "As signed"
        "changed-amount" -> "With a changed amount"
        "delivered-late" -> "After the time window"
        "protected-action" -> "By a protected action"
        else -> value
    }
    key == "reason" -> value.replace('_', ' ').replaceFirstChar { it.titlecase() }
    key == "decidedBy" -> if (value == "reference-backend") "Reference backend" else value
    key == "role" -> if (value == "step_up") "Step-up key" else "Device key"
    key == "protection" -> when (value) {
        "strongbox" -> "StrongBox"
        "trusted_environment" -> "Secure hardware"
        "software" -> "Software"
        else -> value.replaceFirstChar { it.titlecase() }
    }
    key == "attestation" || key == "verifiedBoot" -> value.replace('_', ' ').replaceFirstChar { it.titlecase() }
    key == "bootloaderLocked" -> if (value == "true") "Yes" else "No"
    key == "result" -> value.replaceFirstChar { it.titlecase() }
    else -> value
}

private fun SecurityEvent.group(): EventFilter = when (type) {
    SecurityEventType.DEVICE_RISK_ASSESSED,
    SecurityEventType.ROOT_SIGNAL_FOUND,
    SecurityEventType.EMULATOR_SIGNAL_FOUND,
    SecurityEventType.DEBUGGER_ATTACHED,
    -> EventFilter.CHECKS

    SecurityEventType.SENSITIVE_ACTION_ALLOWED,
    SecurityEventType.SENSITIVE_ACTION_REQUIRES_CONFIRMATION,
    SecurityEventType.SENSITIVE_ACTION_ALLOWED_AFTER_CONFIRMATION,
    SecurityEventType.SENSITIVE_ACTION_CANCELLED,
    SecurityEventType.SENSITIVE_ACTION_BLOCKED,
    -> EventFilter.ACTIONS

    SecurityEventType.REQUEST_SIGNED,
    SecurityEventType.REQUEST_VERIFIED,
    SecurityEventType.KEY_REGISTERED,
    -> EventFilter.SIGNING

    SecurityEventType.PAYMENT_SUBMITTED -> EventFilter.ACTIONS

    SecurityEventType.SECURE_VALUE_STORED -> EventFilter.STORAGE
}
