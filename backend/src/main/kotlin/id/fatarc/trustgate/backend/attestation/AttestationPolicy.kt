package id.fatarc.trustgate.backend.attestation

import id.fatarc.trustgate.domain.api.SecurityLevel
import id.fatarc.trustgate.domain.api.VerifiedBootState

/**
 * What the backend requires of a key's certificate chain. [strict] is what a production backend
 * enforces. [development] relaxes only what emulators and test devices can't provide, and the
 * summary sent back with every key says when its root isn't one this backend trusts.
 */
class AttestationPolicy(
    val packageName: String,
    /** SHA-256 of the app's signing certificates, lowercase hex. Empty skips the check. */
    val signingCertificateDigests: Set<String>,
    /** SHA-256 of the root public keys a chain may end at. Empty accepts any self-signed root. */
    val trustedRootKeys: Set<String>,
    val requireSecureHardware: Boolean,
    val requireVerifiedBoot: Boolean,
    /** The oldest security patch level accepted, as YYYYMM. */
    val minimumOsPatchLevel: Int?,
    /** Accept a key with only its own self-signed certificate, from a device that can't attest. */
    val allowUnattested: Boolean,
) {
    fun trustsRoot(report: AttestationReport): Boolean = report.rootKeyFingerprint in trustedRootKeys

    /** Why [report] can't be accepted, or null when it can. */
    fun problemWith(report: AttestationReport, revocations: RevocationList): String? {
        if (report.chainLength == 0) return "The key came without a certificate chain."
        if (!report.wellFormed) return "The attestation chain couldn't be read."
        report.certificateSerials.firstOrNull { revocations.statusOf(it) != null }?.let { serial ->
            return "Google lists a certificate in this chain as ${revocations.statusOf(serial)?.status?.lowercase()} ($serial)."
        }

        val description = report.description
        if (description == null) {
            // Without attestation support, Keystore returns only the key's own self-signed certificate.
            val selfSigned = report.chainLength == 1 && report.leafMatchesKey && report.chainSignaturesValid
            return when {
                !selfSigned -> "The certificate chain carries no attestation for this key."
                !allowUnattested -> "This backend accepts only attested keys."
                else -> null
            }
        }

        val app = description.applicationId
        val boot = description.rootOfTrust
        return when {
            !report.chainSignaturesValid -> "The attestation chain doesn't verify."
            !report.leafMatchesKey -> "The attestation certifies a different key."
            !report.challengeMatches -> "The attestation was made for another challenge."
            trustedRootKeys.isNotEmpty() && !trustsRoot(report) -> "The chain doesn't end at a Google attestation root."
            app == null -> "The attestation doesn't say which app the key belongs to."
            packageName !in app.packageNames -> "The key was generated for another app."
            signingCertificateDigests.isNotEmpty() && app.signatureDigests.none { it in signingCertificateDigests } ->
                "The app that made the key isn't signed with this app's certificate, so it may be repackaged."
            description.origin != null && description.origin != KeyOrigin.GENERATED ->
                "The key was brought into Keystore instead of being generated there."
            requireSecureHardware && description.origin == null -> "The attestation doesn't say how the key was created."
            requireSecureHardware && SecurityLevel.SOFTWARE in setOf(description.keymasterSecurityLevel, description.attestationSecurityLevel) ->
                "The key isn't held in secure hardware."
            requireVerifiedBoot && (boot?.verifiedBootState != VerifiedBootState.VERIFIED || boot.deviceLocked != true) ->
                "The device doesn't boot a verified system with a locked bootloader."
            minimumOsPatchLevel != null && (description.osPatchLevel ?: 0) < minimumOsPatchLevel ->
                "The device's security patch level is older than this backend accepts."
            else -> null
        }
    }

    companion object {
        fun strict(packageName: String, signingCertificateDigests: Set<String>, minimumOsPatchLevel: Int? = null) = AttestationPolicy(
            packageName = packageName,
            signingCertificateDigests = signingCertificateDigests,
            trustedRootKeys = GoogleAttestationRoots.keyFingerprints,
            requireSecureHardware = true,
            requireVerifiedBoot = true,
            minimumOsPatchLevel = minimumOsPatchLevel,
            allowUnattested = false,
        )

        fun development(packageName: String, signingCertificateDigests: Set<String>) = AttestationPolicy(
            packageName = packageName,
            signingCertificateDigests = signingCertificateDigests,
            trustedRootKeys = emptySet(),
            requireSecureHardware = false,
            requireVerifiedBoot = false,
            minimumOsPatchLevel = null,
            allowUnattested = true,
        )
    }
}
