package id.fatarc.trustgate.core.security

import id.fatarc.trustgate.domain.actiongate.SensitiveActionDecision
import id.fatarc.trustgate.domain.actiongate.SensitiveActionGate
import id.fatarc.trustgate.domain.events.SecurityEvent
import id.fatarc.trustgate.domain.events.SecurityEventRepository
import id.fatarc.trustgate.domain.events.SecurityEventType
import id.fatarc.trustgate.domain.risk.DeviceRiskReport
import id.fatarc.trustgate.domain.risk.DeviceSignalCollector
import id.fatarc.trustgate.domain.risk.RiskScorer
import id.fatarc.trustgate.domain.risk.SignalCategory
import id.fatarc.trustgate.domain.risk.flaggedSignalIds
import id.fatarc.trustgate.domain.signing.RejectionReason
import id.fatarc.trustgate.domain.signing.SignedRequest
import id.fatarc.trustgate.domain.signing.VerificationResult

/** Why a device check ran. It decides how much of the result is worth writing to the capped log. */
enum class AssessmentTrigger(val metadataValue: String) {
    LAUNCH("launch"),
    MANUAL("manual"),

    /** Re-check right before a protected action; logs the check but not every signal again. */
    BEFORE_ACTION("before-action"),

    /** Quiet re-check when the app returns to the foreground; logs only if something changed. */
    RESUME("resume"),
}

enum class ConfirmationMethod(val metadataValue: String) {
    /** Biometric or screen lock through the system prompt. */
    DEVICE_CREDENTIAL("device-credential"),

    /** Explicit tap, used only when the device has no screen lock to step up to. */
    TAP("tap"),
}

class TrustGateSecurityService(
    private val signalCollector: DeviceSignalCollector,
    private val riskScorer: RiskScorer,
    private val actionGate: SensitiveActionGate,
    private val eventRepository: SecurityEventRepository,
) {
    suspend fun assessDeviceRisk(
        trigger: AssessmentTrigger = AssessmentTrigger.MANUAL,
        previous: DeviceRiskReport? = null,
    ): DeviceRiskReport {
        val report = riskScorer.score(signalCollector.collectSignals())
        val activeSignals = report.signals.count { it.detected }
        when (trigger) {
            AssessmentTrigger.LAUNCH,
            AssessmentTrigger.MANUAL,
            -> {
                recordAssessment(report, trigger, "Device risk assessed with $activeSignals active signals.")
                recordDetectedSignals(report)
            }

            AssessmentTrigger.BEFORE_ACTION -> recordAssessment(
                report = report,
                trigger = trigger,
                message = "Checked again before a protected action: $activeSignals active signals.",
            )

            AssessmentTrigger.RESUME -> if (previous == null || report.differsFrom(previous)) {
                val message = if (previous != null && previous.level != report.level) {
                    "Risk changed from ${previous.level.name.lowercase()} to ${report.level.name.lowercase()} since the last check."
                } else {
                    "Detected signals changed since the last check: $activeSignals active."
                }
                recordAssessment(
                    report = report,
                    trigger = trigger,
                    message = message,
                    extra = previous?.let { mapOf("previousLevel" to it.level.name) }.orEmpty(),
                )
                recordDetectedSignals(report)
            }
        }
        return report
    }

    suspend fun evaluateSensitiveAction(report: DeviceRiskReport): SensitiveActionDecision {
        return actionGate.decide(report.level).also { decision ->
            eventRepository.record(
                SecurityEvent(
                    type = decision.toSecurityEventType(),
                    riskLevel = report.level,
                    message = decision.toAuditMessage(),
                ),
            )
        }
    }

    suspend fun confirmSensitiveAction(report: DeviceRiskReport, method: ConfirmationMethod) {
        eventRepository.record(
            SecurityEvent(
                type = SecurityEventType.SENSITIVE_ACTION_ALLOWED_AFTER_CONFIRMATION,
                riskLevel = report.level,
                message = when (method) {
                    ConfirmationMethod.DEVICE_CREDENTIAL -> "Sensitive action allowed after the user confirmed with their screen lock or biometrics."
                    ConfirmationMethod.TAP -> "Sensitive action allowed after an explicit tap; the device has no screen lock to step up to."
                },
                metadata = mapOf("method" to method.metadataValue),
            ),
        )
    }

    suspend fun cancelSensitiveAction(report: DeviceRiskReport) {
        eventRepository.record(
            SecurityEvent(
                type = SecurityEventType.SENSITIVE_ACTION_CANCELLED,
                riskLevel = report.level,
                message = "Sensitive action cancelled at the confirmation step.",
            ),
        )
    }

    suspend fun recordScenarioApplied(report: DeviceRiskReport) {
        eventRepository.record(
            SecurityEvent(
                type = SecurityEventType.DEVICE_RISK_ASSESSED,
                riskLevel = report.level,
                message = "Simulated ${report.level.name.lowercase()}-risk profile applied.",
                metadata = mapOf(
                    "score" to report.score.toString(),
                    "source" to SCENARIO_SOURCE,
                ),
            ),
        )
    }

    suspend fun recordSignedRequest(request: SignedRequest, forProtectedAction: Boolean = false) {
        eventRepository.record(
            SecurityEvent(
                type = SecurityEventType.REQUEST_SIGNED,
                message = if (forProtectedAction) {
                    "Signed the payment request for ${request.payload.merchantReference} after the gate allowed it."
                } else {
                    "Signed payment-like request for ${request.payload.merchantReference}."
                },
                metadata = mapOf(
                    "nonce" to request.nonce,
                    "signaturePrefix" to request.signature.take(12),
                ),
            ),
        )
    }

    /** [attempt] names how the request was sent, for example as signed or deliberately altered. */
    suspend fun recordVerification(request: SignedRequest, result: VerificationResult, attempt: String) {
        eventRepository.record(
            SecurityEvent(
                type = SecurityEventType.REQUEST_VERIFIED,
                message = when (result) {
                    VerificationResult.Accepted ->
                        "Reference verifier accepted the request for ${request.payload.merchantReference}."

                    is VerificationResult.Rejected ->
                        "Reference verifier rejected the request: ${result.reason.auditPhrase()}."
                },
                metadata = buildMap {
                    put("nonce", request.nonce)
                    put("attempt", attempt)
                    put("result", if (result is VerificationResult.Accepted) "accepted" else "rejected")
                    if (result is VerificationResult.Rejected) put("reason", result.reason.name.lowercase())
                },
            ),
        )
    }

    suspend fun recordSecureValueStored(keys: List<String>) {
        eventRepository.record(
            SecurityEvent(
                type = SecurityEventType.SECURE_VALUE_STORED,
                message = "Stored reference values in encrypted local storage.",
                metadata = mapOf("keys" to keys.joinToString(",")),
            ),
        )
    }

    private suspend fun recordAssessment(
        report: DeviceRiskReport,
        trigger: AssessmentTrigger,
        message: String,
        extra: Map<String, String> = emptyMap(),
    ) {
        eventRepository.record(
            SecurityEvent(
                type = SecurityEventType.DEVICE_RISK_ASSESSED,
                riskLevel = report.level,
                message = message,
                metadata = mapOf(
                    "score" to report.score.toString(),
                    "trigger" to trigger.metadataValue,
                ) + extra,
            ),
        )
    }

    private suspend fun recordDetectedSignals(report: DeviceRiskReport) {
        report.signals.filter { it.detected }.forEach { signal ->
            signal.category.toSecurityEventType()?.let { eventType ->
                eventRepository.record(
                    SecurityEvent(
                        type = eventType,
                        riskLevel = report.level,
                        message = signal.name,
                        metadata = mapOf("signalId" to signal.id),
                    ),
                )
            }
        }
    }

    private fun DeviceRiskReport.differsFrom(other: DeviceRiskReport): Boolean =
        level != other.level || flaggedSignalIds() != other.flaggedSignalIds()

    companion object {
        const val SCENARIO_SOURCE = "scenario-selector"
    }

    private fun SignalCategory.toSecurityEventType(): SecurityEventType? = when (this) {
        SignalCategory.ROOT -> SecurityEventType.ROOT_SIGNAL_FOUND
        SignalCategory.EMULATOR -> SecurityEventType.EMULATOR_SIGNAL_FOUND
        SignalCategory.DEBUGGER -> SecurityEventType.DEBUGGER_ATTACHED
        SignalCategory.INSTALLER -> null
    }

    private fun SensitiveActionDecision.toSecurityEventType(): SecurityEventType = when (this) {
        SensitiveActionDecision.ALLOW -> SecurityEventType.SENSITIVE_ACTION_ALLOWED
        SensitiveActionDecision.REQUIRE_CONFIRMATION -> SecurityEventType.SENSITIVE_ACTION_REQUIRES_CONFIRMATION
        SensitiveActionDecision.BLOCK -> SecurityEventType.SENSITIVE_ACTION_BLOCKED
    }

    private fun SensitiveActionDecision.toAuditMessage(): String = when (this) {
        SensitiveActionDecision.ALLOW -> "Sensitive action allowed for low-risk device state."
        SensitiveActionDecision.REQUIRE_CONFIRMATION -> "Sensitive action requires confirmation because of medium-risk signals."
        SensitiveActionDecision.BLOCK -> "Sensitive action blocked because the device is high risk."
    }

    private fun RejectionReason.auditPhrase(): String = when (this) {
        RejectionReason.MISSING_HEADERS -> "signing headers missing"
        RejectionReason.MALFORMED_TIMESTAMP -> "timestamp malformed"
        RejectionReason.OUTSIDE_TIME_WINDOW -> "outside the time window"
        RejectionReason.SIGNATURE_MISMATCH -> "signature doesn't match the request"
        RejectionReason.NONCE_REUSED -> "nonce already used"
    }
}
