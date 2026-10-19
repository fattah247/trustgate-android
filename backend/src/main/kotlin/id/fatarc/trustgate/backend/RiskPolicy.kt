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
            if (acceptSimulatedEvidence) note("The signals come from a simulated profile.") else note("This server doesn't accept simulated profiles.", DeviceRiskLevel.HIGH)
        }
        // Severities come from the catalog, never from the report, and unknown signals count for nothing.
        val signals = evidence.signals.mapNotNull { reported -> SignalCatalog.definition(reported.id)?.observed(reported.detected) }
        val flagged = signals.filter { it.detected }
        if (flagged.isEmpty()) {
            note("The device reported no risk signals.")
        } else {
            val report = scorer.score(signals)
            note("Reported signals score ${report.score}: ${flagged.joinToString { it.name.lowercase() }}.", report.level)
        }

        if (integrityToken == null) {
            if (requireIntegrityVerdict) note("No Play Integrity verdict came with the request.", DeviceRiskLevel.MEDIUM)
            return Assessment(level, reasons)
        }
        val verdict = integrity?.verify(integrityToken)
        when {
            verdict == null -> note("The Play Integrity token couldn't be verified.", DeviceRiskLevel.HIGH)
            verdict.requestHash != requestHash -> note("The integrity verdict was issued for a different request.", DeviceRiskLevel.HIGH)
            verdict.requestPackageName != packageName -> note("The integrity verdict is for another app.", DeviceRiskLevel.HIGH)
            // A mock has nothing Google issued to date or judge, so it's settled before those checks.
            verdict.mock ->
                if (acceptMockVerdicts) note("A mock integrity verdict, accepted in development.") else note("A mock integrity verdict isn't accepted here.", DeviceRiskLevel.HIGH)
            Duration.between(Instant.ofEpochMilli(verdict.timestampMillis), at).abs() > ReferenceSigningScheme.TIME_WINDOW ->
                note("The integrity verdict is out of date.", DeviceRiskLevel.HIGH)
            verdict.appRecognition != "PLAY_RECOGNIZED" -> note("Google Play doesn't recognise this copy of the app.", DeviceRiskLevel.HIGH)
            signingCertificateDigests.isNotEmpty() && verdict.certificateDigests.none { it in signingCertificateDigests } ->
                note("Google Play saw the app signed with a different certificate.", DeviceRiskLevel.HIGH)
            "MEETS_DEVICE_INTEGRITY" !in verdict.deviceRecognition -> note("Google Play doesn't vouch for this device's integrity.", DeviceRiskLevel.HIGH)
            "MEETS_STRONG_INTEGRITY" in verdict.deviceRecognition -> note("Google Play reports strong device integrity.")
            else -> note("Google Play reports device integrity.")
        }
        return Assessment(level, reasons)
    }
}
