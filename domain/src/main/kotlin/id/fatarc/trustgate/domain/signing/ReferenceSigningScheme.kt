package id.fatarc.trustgate.domain.signing

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Duration
import java.util.Base64

/**
 * The one definition of how reference requests are signed, shared by the app and the reference
 * backend so the two sides can't drift apart.
 */
object ReferenceSigningScheme {
    const val METHOD = "POST"
    const val PATH = "/payments/reference"

    /** ECDSA over P-256, the curve every Android Keystore implementation supports in hardware. */
    const val KEY_ALGORITHM = "EC"
    const val SIGNATURE_ALGORITHM = "SHA256withECDSA"

    const val HEADER_TIMESTAMP = "X-Request-Timestamp"
    const val HEADER_NONCE = "X-Request-Nonce"
    const val HEADER_KEY_ID = "X-Key-Id"
    const val HEADER_IDEMPOTENCY_KEY = "Idempotency-Key"
    const val HEADER_CONFIRMATION = "X-Confirmation"
    const val HEADER_SIGNATURE = "X-Request-Signature"

    /** How far a request's timestamp may be from the moment it arrives. */
    val TIME_WINDOW: Duration = Duration.ofMinutes(5)

    /** Value of [HEADER_CONFIRMATION] when the person confirmed with a tap because there was no lock to step up to. */
    const val CONFIRMATION_TAP = "tap"

    const val ACTION_ADD_STEP_UP = "register-step-up"
    const val ACTION_REMOVE_STEP_UP = "remove-step-up"

    /** The current device key hands over to a new one, named by its key ID. */
    const val ACTION_ROTATE_DEVICE = "rotate-device"

    /** The device key asks the backend to stop accepting this phone's keys. */
    const val ACTION_REMOVE_DEVICE = "remove-device"

    /**
     * Every value the signature covers, one per line. Changing any of them, including dropping or
     * adding the optional idempotency key or confirmation, breaks the signature.
     */
    fun signingInput(
        method: String,
        path: String,
        timestamp: String,
        nonce: String,
        keyId: String,
        idempotencyKey: String?,
        confirmation: String?,
        bodyHash: String,
    ): ByteArray = listOf(
        method,
        path,
        timestamp,
        nonce,
        keyId,
        idempotencyKey.orEmpty(),
        confirmation.orEmpty(),
        bodyHash,
    ).joinToString("\n").toByteArray(StandardCharsets.UTF_8)

    /**
     * What the device key signs to vouch for a change to its step-up key: the action, the one-time
     * registration challenge, and the key the change is about.
     */
    fun keyBindingInput(action: String, challenge: ByteArray, keyId: String): ByteArray =
        listOf(action, encode(challenge), keyId).joinToString("\n").toByteArray(StandardCharsets.UTF_8)

    /** A short, stable name for a public key, derived from its encoded form. */
    fun keyIdFor(encodedPublicKey: ByteArray): String = "k_" + sha256Hex(encodedPublicKey).take(16)

    fun sha256Hex(value: String): String = sha256Hex(value.toByteArray(StandardCharsets.UTF_8))

    fun sha256Hex(value: ByteArray): String = hex(MessageDigest.getInstance("SHA-256").digest(value))

    fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

    fun encode(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)

    fun decodeOrNull(value: String): ByteArray? = runCatching { Base64.getDecoder().decode(value) }.getOrNull()
}
