package id.fatarc.trustgate.backend

import id.fatarc.trustgate.backend.integrity.IntegrityVerdict
import id.fatarc.trustgate.backend.integrity.IntegrityVerifier
import id.fatarc.trustgate.domain.api.DecisionReason
import id.fatarc.trustgate.domain.api.DeviceEvidence
import id.fatarc.trustgate.domain.api.PlayIntegrityLabels
import id.fatarc.trustgate.domain.api.Remedy
import id.fatarc.trustgate.domain.risk.DeviceRiskLevel
import id.fatarc.trustgate.domain.risk.RiskScorer
import id.fatarc.trustgate.domain.risk.SignalCatalog
import id.fatarc.trustgate.domain.risk.SignalCategory
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
    /** Without MEETS_STRONG_INTEGRITY, a payment needs the person to confirm it. */
    val requireStrongIntegrity: Boolean = false,
    /** The oldest app version the Play Integrity verdict may name. */
    val minimumAppVersionCode: Long? = null,
    private val scorer: RiskScorer = RiskScorer(),
) {
    class Assessment(
        val level: DeviceRiskLevel,
        val reasons: List<DecisionReason>,
        val remedy: Remedy? = null,
        val scamWarning: Boolean = false,
    )

    /** [requestHash] is the SHA-256 of the evidence as it was signed, which the verdict must be bound to. */
    fun assess(evidence: DeviceEvidence, requestHash: String, integrityToken: String?, at: Instant): Assessment {
        val findings = Findings()

        if (evidence.simulated) {
            if (acceptSimulatedEvidence) findings.note("Demo phone") else findings.note("Demo phones not accepted", DeviceRiskLevel.HIGH)
        }
        // Severities come from the catalog, never from the report, and unknown signals count for nothing.
        val signals = evidence.signals.mapNotNull { reported -> SignalCatalog.definition(reported.id)?.observed(reported.detected) }
        val flagged = signals.filter { it.detected }
        if (flagged.isEmpty()) {
            findings.note("No problems found")
        } else {
            val scored = scorer.score(signals).level
            flagged.forEach { findings.note(it.name, scored, scam = it.category == SignalCategory.SCAM) }
        }

        if (integrityToken == null) {
            if (requireIntegrityVerdict) findings.note("No Play Integrity check", DeviceRiskLevel.MEDIUM)
            return findings.assessment()
        }
        val verdict = integrity?.verify(integrityToken)
        if (verdict != null && verdictHolds(verdict, requestHash, at, findings)) {
            checkEnvironment(verdict, findings)
        } else if (verdict == null) {
            findings.note("Play Integrity check invalid", DeviceRiskLevel.HIGH)
        }
        return findings.assessment()
    }

    /** Whether the verdict is Google's answer about this app and this request; notes why not when it isn't. */
    private fun verdictHolds(verdict: IntegrityVerdict, requestHash: String, at: Instant, findings: Findings): Boolean {
        val problem = when {
            verdict.requestHash != requestHash -> "Play Integrity check was for a different request"
            verdict.requestPackageName != packageName -> "Play Integrity check was for another app"
            // A mock has nothing Google issued to date or judge, so it's settled before those checks.
            verdict.mock -> if (acceptMockVerdicts) null else "Test-mode Play Integrity not accepted"
            Duration.between(Instant.ofEpochMilli(verdict.timestampMillis), at).abs() > ReferenceSigningScheme.TIME_WINDOW ->
                "Play Integrity check out of date"
            verdict.appRecognition != PlayIntegrityLabels.PLAY_RECOGNIZED -> "App not recognised by Google Play"
            signingCertificateDigests.isNotEmpty() && verdict.certificateDigests.none { it in signingCertificateDigests } ->
                "App signed by someone else"
            PlayIntegrityLabels.MEETS_DEVICE_INTEGRITY !in verdict.deviceRecognition -> "Phone failed Play Integrity"
            else -> null
        }
        if (problem != null) {
            findings.note(problem, DeviceRiskLevel.HIGH)
            return false
        }
        when {
            verdict.mock -> findings.note("Play Integrity in test mode")
            PlayIntegrityLabels.MEETS_STRONG_INTEGRITY in verdict.deviceRecognition -> findings.note("Play Integrity: strong")
            requireStrongIntegrity -> findings.note("Play Integrity: not strong", DeviceRiskLevel.MEDIUM)
            else -> findings.note("Play Integrity: passed")
        }
        val minimumVersion = minimumAppVersionCode
        if (minimumVersion != null && !verdict.mock && (verdict.appVersionCode ?: 0) < minimumVersion) {
            findings.note("App out of date", DeviceRiskLevel.HIGH, Remedy.UPDATE_APP)
        }
        return true
    }

    /**
     * The optional verdicts: whether anything running could watch or drive the payment, whether
     * Play Protect is happy with the phone, and whether this copy came from Google Play.
     */
    private fun checkEnvironment(verdict: IntegrityVerdict, findings: Findings) {
        if (verdict.appLicensing == PlayIntegrityLabels.UNLICENSED) {
            findings.note("Not installed from Google Play", DeviceRiskLevel.MEDIUM, Remedy.GET_LICENSED)
        }

        val apps = verdict.appsDetected.orEmpty()
        // Someone watching or driving the screen is how most payment scams work, so these also warn.
        if (PlayIntegrityLabels.UNKNOWN_CONTROLLING in apps || PlayIntegrityLabels.UNKNOWN_CAPTURING in apps) {
            findings.note("Unknown app can see or control the screen", DeviceRiskLevel.HIGH, Remedy.CLOSE_UNKNOWN_ACCESS_RISK, scam = true)
        }
        // Remote help apps come from Google Play too, and scammers talk people into installing them.
        if (PlayIntegrityLabels.KNOWN_CONTROLLING in apps) {
            findings.note("Remote-control app running", DeviceRiskLevel.HIGH, Remedy.CLOSE_ALL_ACCESS_RISK, scam = true)
        }
        if (PlayIntegrityLabels.KNOWN_CAPTURING in apps) {
            findings.note("Screen-capturing app running", DeviceRiskLevel.MEDIUM, Remedy.CLOSE_ALL_ACCESS_RISK, scam = true)
        }
        if (PlayIntegrityLabels.UNKNOWN_OVERLAYS in apps) {
            findings.note("Unknown app drawing over the screen", DeviceRiskLevel.MEDIUM, Remedy.CLOSE_UNKNOWN_ACCESS_RISK, scam = true)
        }

        when (verdict.playProtect) {
            PlayIntegrityLabels.PLAY_PROTECT_HIGH_RISK ->
                findings.note("Play Protect found dangerous apps", DeviceRiskLevel.HIGH, Remedy.FIX_PLAY_PROTECT)
            PlayIntegrityLabels.PLAY_PROTECT_MEDIUM_RISK ->
                findings.note("Play Protect found harmful apps", DeviceRiskLevel.MEDIUM, Remedy.FIX_PLAY_PROTECT)
            PlayIntegrityLabels.PLAY_PROTECT_OFF ->
                findings.note("Play Protect is off", DeviceRiskLevel.MEDIUM, Remedy.FIX_PLAY_PROTECT)
            PlayIntegrityLabels.PLAY_PROTECT_NO_DATA -> findings.note("Play Protect hasn't scanned yet")
        }

        // Many requests from one phone is how tokens are farmed for use elsewhere.
        if (verdict.deviceActivity == PlayIntegrityLabels.ACTIVITY_LEVEL_4) {
            findings.note("Unusually many checks from this phone", DeviceRiskLevel.MEDIUM)
        }
    }

    /** Collects reasons in order and keeps the level of the worst. */
    private class Findings {
        private class Finding(val reason: String, val level: DeviceRiskLevel, val remedy: Remedy?, val scam: Boolean)

        private val found = mutableListOf<Finding>()

        fun note(reason: String, atLeast: DeviceRiskLevel = DeviceRiskLevel.LOW, remedy: Remedy? = null, scam: Boolean = false) {
            found += Finding(reason, atLeast, remedy, scam)
        }

        fun assessment(): Assessment {
            val level = found.maxOfOrNull { it.level } ?: DeviceRiskLevel.LOW
            // Only a fix for the worst problem changes the outcome; closing every risky app also
            // closes the unknown ones, so that fix wins when both are needed.
            val remedies = found.filter { it.level == level }.mapNotNull { it.remedy }
            val remedy = if (Remedy.CLOSE_ALL_ACCESS_RISK in remedies) Remedy.CLOSE_ALL_ACCESS_RISK else remedies.firstOrNull()
            return Assessment(level, found.map { DecisionReason(it.reason, it.level) }, remedy, scamWarning = found.any { it.scam })
        }
    }
}
