package id.fatarc.trustgate.testing

import id.fatarc.trustgate.backend.BackendPolicy
import id.fatarc.trustgate.backend.RiskPolicy
import id.fatarc.trustgate.backend.attestation.AttestationPolicy
import id.fatarc.trustgate.backend.integrity.IntegrityVerifier

val developmentPolicy: BackendPolicy = BackendPolicy.development(TEST_PACKAGE, setOf(TEST_SIGNER_DIGEST))

/** The production policy, with [attestation]'s root pinned in place of Google's. */
fun strictPolicyTrusting(
    attestation: TestAttestation,
    minimumOsPatchLevel: Int? = null,
    minimumAppVersionCode: Long? = null,
) = AttestationPolicy(
    packageName = TEST_PACKAGE,
    signingCertificateDigests = setOf(TEST_SIGNER_DIGEST),
    trustedRootKeys = setOf(attestation.rootKeyFingerprint),
    requireSecureHardware = true,
    requireVerifiedBoot = true,
    minimumOsPatchLevel = minimumOsPatchLevel,
    allowUnattested = false,
    minimumAppVersionCode = minimumAppVersionCode,
)

/** The production policy, trusting [attestation]'s root and verifying integrity tokens with [integrity]. */
fun strictBackendPolicy(
    attestation: TestAttestation,
    integrity: IntegrityVerifier?,
    minimumAppVersionCode: Long? = null,
) = BackendPolicy(
    name = "strict",
    attestation = strictPolicyTrusting(attestation, minimumAppVersionCode = minimumAppVersionCode),
    risk = RiskPolicy(
        integrity = integrity,
        packageName = TEST_PACKAGE,
        signingCertificateDigests = setOf(TEST_SIGNER_DIGEST),
        acceptSimulatedEvidence = false,
        requireIntegrityVerdict = true,
        acceptMockVerdicts = false,
        requireStrongIntegrity = true,
        minimumAppVersionCode = minimumAppVersionCode,
    ),
)
