package id.fatarc.trustgate.core.keys

import id.fatarc.trustgate.domain.api.AttestationSummary
import id.fatarc.trustgate.domain.api.SecurityLevel
import id.fatarc.trustgate.domain.signing.KeyRole
import java.security.Signature
import kotlinx.serialization.Serializable

/** A freshly generated key pair's public half, with the certificate chain that attests it. */
class GeneratedKey(
    val role: KeyRole,
    val encodedPublicKey: ByteArray,
    val attestationChain: List<ByteArray>,
    /** Where Keystore says the private key lives. */
    val protection: SecurityLevel,
)

/** A key the backend accepted, as the app shows it. */
@Serializable
data class RegisteredKey(
    val role: KeyRole,
    val keyId: String,
    val protection: SecurityLevel,
    val attestation: AttestationSummary,
)

sealed interface StepUpSupport {
    data object Available : StepUpSupport

    /** [reason] says what the person would need, such as a screen lock. */
    data class Unavailable(val reason: String) : StepUpSupport
}

/** The step-up key stopped working, for example because the screen lock or fingerprints changed. */
class StepUpKeyInvalidatedException(cause: Throwable) : Exception("The step-up key is no longer valid.", cause)

/**
 * Holds the device's private keys. Implementations keep them where the app can use but never read
 * them; the Android one uses Keystore, preferring StrongBox hardware.
 */
interface DeviceKeyProvider {
    fun stepUpSupport(): StepUpSupport

    /** Replaces any existing key for [role], attesting it with the backend's [attestationChallenge]. */
    fun generate(role: KeyRole, attestationChallenge: ByteArray): GeneratedKey

    /**
     * Generates a new device key beside the current one, which keeps signing until
     * [promoteReplacement]; the current key has to vouch for its successor first.
     */
    fun generateReplacement(attestationChallenge: ByteArray): GeneratedKey

    /** Makes the replacement the device key and deletes the one it replaced. */
    fun promoteReplacement()

    /** Throws away a replacement the backend didn't accept. */
    fun discardReplacement()

    fun delete(role: KeyRole)

    /**
     * Whether the key for [role] still exists; the system deletes step-up keys when the lock is
     * removed. Throws when Keystore can't be read, which isn't the same as the key being gone.
     */
    fun hasKey(role: KeyRole): Boolean

    /** Signs with the device key, which needs no user authentication. */
    fun signWithDeviceKey(data: ByteArray): ByteArray

    /**
     * A signature on the step-up key, ready to be unlocked by the system prompt. It can't sign
     * until the person authenticates.
     *
     * @throws StepUpKeyInvalidatedException when the key must be generated again.
     */
    fun stepUpSignature(): Signature
}
