package id.fatarc.trustgate.backend

import id.fatarc.trustgate.backend.integrity.IntegrityVerifier
import id.fatarc.trustgate.domain.api.DeviceEvidence
import id.fatarc.trustgate.domain.risk.DeviceRiskLevel
import id.fatarc.trustgate.domain.risk.RiskScorer
import id.fatarc.trustgate.domain.risk.SignalCatalog
import id.fatarc.trustgate.domain.signing.ReferenceSigningScheme
import java.time.Duration
import java.time.Instant

/**
 * How the backend turns what a device reports into a risk level. Reported signals are only as
 * honest as the app that reports them; the Play Integrity verdict is what Google vouches for.
 */
class RiskPolicy(
    private val integrity: IntegrityVerifier?,
    private val packageName: String,
    /** SHA-256 of the app's signing certificates, lowercase hex. Empty skips the check. */
    private val signingCertificateDigests: Set<String>,
    val acceptSimulatedEvidence: Boolean,
    val requireIntegrityVerdict: Boolean,
    val acceptMockVerdicts: Boolean,
    private val scorer: RiskScorer = RiskScorer(),
) {
    class Assessment(val level: DeviceRiskLevel, val reasons: List<String>)

    /** [requestHash] is the SHA-256 of the evidence as it was signed, which the verdict must be bound to. */
    fun assess(evidence: DeviceEvidence, requestHash: String, integrityToken: String?, at: Instant): Assessment {
        var level = DeviceRiskLevel.LOW
        val reasons = mutableListOf<String>()
        fun note(reason: String, atLeast: DeviceRiskLevel = DeviceRiskLevel.LOW) {
            if (atLeast > level) level = atLeast
            reasons += reason
        }

        if (evidence.simulated) {
            if (acceptSimulatedEvidence) note("Demo phone") else note("Demo phones not accepted", DeviceRiskLevel.HIGH)
        }
        // Severities come from the catalog, never from the report, and unknown signals count for nothing.
        val signals = evidence.signals.mapNotNull { reported -> SignalCatalog.definition(reported.id)?.observed(reported.detected) }
        val flagged = signals.filter { it.detected }
        if (flagged.isEmpty()) {
            note("No problems found")
        } else {
            val scored = scorer.score(signals).level
            flagged.forEach { note(it.name, scored) }
        }

        if (integrityToken == null) {
            if (requireIntegrityVerdict) note("No Play Integrity check", DeviceRiskLevel.MEDIUM)
            return Assessment(level, reasons)
        }
        val verdict = integrity?.verify(integrityToken)
        when {
            verdict == null -> note("Play Integrity check invalid", DeviceRiskLevel.HIGH)
            verdict.requestHash != requestHash -> note("Play Integrity check was for a different request", DeviceRiskLevel.HIGH)
            verdict.requestPackageName != packageName -> note("Play Integrity check was for another app", DeviceRiskLevel.HIGH)
            // A mock has nothing Google issued to date or judge, so it's settled before those checks.
            verdict.mock ->
                if (acceptMockVerdicts) note("Play Integrity in test mode") else note("Test-mode Play Integrity not accepted", DeviceRiskLevel.HIGH)
            Duration.between(Instant.ofEpochMilli(verdict.timestampMillis), at).abs() > ReferenceSigningScheme.TIME_WINDOW ->
                note("Play Integrity check out of date", DeviceRiskLevel.HIGH)
            verdict.appRecognition != "PLAY_RECOGNIZED" -> note("App not recognised by Google Play", DeviceRiskLevel.HIGH)
            signingCertificateDigests.isNotEmpty() && verdict.certificateDigests.none { it in signingCertificateDigests } ->
                note("App signed by someone else", DeviceRiskLevel.HIGH)
            "MEETS_DEVICE_INTEGRITY" !in verdict.deviceRecognition -> note("Phone failed Play Integrity", DeviceRiskLevel.HIGH)
            "MEETS_STRONG_INTEGRITY" in verdict.deviceRecognition -> note("Play Integrity: strong")
            else -> note("Play Integrity: passed")
        }
        return Assessment(level, reasons)
    }
}
