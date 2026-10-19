package id.fatarc.trustgate.domain.api

import kotlinx.serialization.Serializable

/** Where a key lives, as Android Keystore or its attestation reports it. */
@Serializable
enum class SecurityLevel {
    SOFTWARE,
    TRUSTED_ENVIRONMENT,
    STRONGBOX,
    UNKNOWN,
}

@Serializable
enum class VerifiedBootState {
    VERIFIED,
    SELF_SIGNED,
    UNVERIFIED,
    FAILED,
}

/** What the backend concluded from a key's certificate chain, as the app shows it. */
@Serializable
data class AttestationSummary(
    /** The chain carried Android's KeyDescription extension. */
    val attested: Boolean,
    /** The chain verified, certified this key, and carried the challenge the backend issued. */
    val verified: Boolean,
    val chainLength: Int,
    val securityLevel: SecurityLevel? = null,
    val verifiedBootState: VerifiedBootState? = null,
    val deviceLocked: Boolean? = null,
    val userAuthRequired: Boolean? = null,
)
