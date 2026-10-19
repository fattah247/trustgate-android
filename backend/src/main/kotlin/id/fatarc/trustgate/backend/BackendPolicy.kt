package id.fatarc.trustgate.backend

import id.fatarc.trustgate.backend.attestation.AttestationPolicy
import id.fatarc.trustgate.backend.integrity.IntegrityVerifier
import id.fatarc.trustgate.backend.integrity.MockIntegrityVerifier

/** Everything the backend enforces, chosen together so a server can't be strict about keys and lax about devices. */
class BackendPolicy(
    val name: String,
    val attestation: AttestationPolicy,
    val risk: RiskPolicy,
) {
    companion object {
        /** What production enforces. Without a Play Integrity verifier every verdict counts as unverifiable. */
        fun strict(
            packageName: String,
            signingCertificateDigests: Set<String>,
            integrity: IntegrityVerifier?,
            minimumOsPatchLevel: Int? = null,
        ) = BackendPolicy(
            name = "strict",
            attestation = AttestationPolicy.strict(packageName, signingCertificateDigests, minimumOsPatchLevel),
            risk = RiskPolicy(
                integrity = integrity,
                packageName = packageName,
                signingCertificateDigests = signingCertificateDigests,
                acceptSimulatedEvidence = false,
                requireIntegrityVerdict = true,
                acceptMockVerdicts = false,
            ),
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
        )
    }
}
