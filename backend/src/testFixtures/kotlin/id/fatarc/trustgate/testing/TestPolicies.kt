package id.fatarc.trustgate.testing

import id.fatarc.trustgate.backend.attestation.AttestationPolicy

val developmentPolicy: AttestationPolicy = AttestationPolicy.development(TEST_PACKAGE, setOf(TEST_SIGNER_DIGEST))

/** The production policy, with [attestation]'s root pinned in place of Google's. */
fun strictPolicyTrusting(attestation: TestAttestation, minimumOsPatchLevel: Int? = null) = AttestationPolicy(
    packageName = TEST_PACKAGE,
    signingCertificateDigests = setOf(TEST_SIGNER_DIGEST),
    trustedRootKeys = setOf(attestation.rootKeyFingerprint),
    requireSecureHardware = true,
    requireVerifiedBoot = true,
    minimumOsPatchLevel = minimumOsPatchLevel,
    allowUnattested = false,
)
