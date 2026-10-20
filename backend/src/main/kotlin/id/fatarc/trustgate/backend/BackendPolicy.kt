package id.fatarc.trustgate.backend

import id.fatarc.trustgate.backend.attestation.AttestationPolicy
import id.fatarc.trustgate.backend.integrity.IntegrityVerifier
import id.fatarc.trustgate.backend.integrity.MockIntegrityVerifier
import java.time.Duration

/** Everything the backend enforces, chosen together so a server can't be strict about keys and lax about devices. */
class BackendPolicy(
    val name: String,
    val attestation: AttestationPolicy,
    val risk: RiskPolicy,
    val limits: PaymentLimits = PaymentLimits.NONE,
    /** How long a device key serves before the backend asks the app to replace it; null never asks. */
    val keyMaxAge: Duration? = null,
) {
    companion object {
        /**
         * What production enforces. Without a Play Integrity verifier every verdict counts as
         * unverifiable. [minimumAppVersionCode] turns away older versions of the app, both when
         * they register a key and when they ask to pay.
         */
        fun strict(
            packageName: String,
            signingCertificateDigests: Set<String>,
            integrity: IntegrityVerifier?,
            minimumOsPatchLevel: Int? = null,
            minimumAppVersionCode: Long? = null,
            requireStrongIntegrity: Boolean = true,
            limits: PaymentLimits = PaymentLimits.strict(),
        ) = BackendPolicy(
            name = "strict",
            attestation = AttestationPolicy.strict(packageName, signingCertificateDigests, minimumOsPatchLevel, minimumAppVersionCode),
            risk = RiskPolicy(
                integrity = integrity,
                packageName = packageName,
                signingCertificateDigests = signingCertificateDigests,
                acceptSimulatedEvidence = false,
                requireIntegrityVerdict = true,
                acceptMockVerdicts = false,
                requireStrongIntegrity = requireStrongIntegrity,
                minimumAppVersionCode = minimumAppVersionCode,
            ),
            limits = limits,
            keyMaxAge = Duration.ofDays(90),
        )

        /** Relaxes what emulators can't provide: hardware attestation, Google Play, and real risk signals. */
        fun development(packageName: String, signingCertificateDigests: Set<String>) = BackendPolicy(
            name = "development",
            attestation = AttestationPolicy.development(packageName, signingCertificateDigests),
            risk = RiskPolicy(
                integrity = MockIntegrityVerifier(packageName),
                packageName = packageName,
                signingCertificateDigests = signingCertificateDigests,
                acceptSimulatedEvidence = true,
                requireIntegrityVerdict = false,
                acceptMockVerdicts = true,
            ),
            limits = PaymentLimits.development(),
        )
    }
}
