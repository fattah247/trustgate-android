package id.fatarc.trustgate.core.keys

import id.fatarc.trustgate.core.attestation.AttestationReport
import id.fatarc.trustgate.core.attestation.SecurityLevel
import id.fatarc.trustgate.domain.signing.KeyRole
import java.security.Signature

/** A freshly generated key pair's public half, with the certificate chain that attests it. */
class GeneratedKey(
    val role: KeyRole,
    encodedPublicKey: ByteArray,
    attestationChain: List<ByteArray>,
    /** Where Keystore says the private key lives. */
    val protection: SecurityLevel,
) {
    private val publicKey = encodedPublicKey.copyOf()
    private val chain = attestationChain.map { it.copyOf() }

    val encodedPublicKey: ByteArray get() = publicKey.copyOf()

    val attestationChain: List<ByteArray> get() = chain.map { it.copyOf() }
}

/** A key the backend accepted, as the app shows it. */
data class RegisteredKey(
    val role: KeyRole,
    val keyId: String,
    val protection: SecurityLevel,
    val attestation: AttestationReport,
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

    fun delete(role: KeyRole)

    /** Whether the key for [role] still exists; the system deletes step-up keys when the lock is removed. */
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
