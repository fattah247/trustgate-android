package id.fatarc.trustgate.core.storage

import java.nio.charset.StandardCharsets
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Encrypts each stored value with AES-256-GCM and binds it to its name as associated data, so a
 * ciphertext copied into another slot fails to open instead of being read as that slot's value.
 */
class SealedValues(
    private val key: () -> SecretKey,
) {
    fun seal(name: String, value: String): String {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        // No IV is passed: Keystore insists on generating a fresh random one itself.
        cipher.init(Cipher.ENCRYPT_MODE, key())
        cipher.updateAAD(name.toByteArray(StandardCharsets.UTF_8))
        val ciphertext = cipher.doFinal(value.toByteArray(StandardCharsets.UTF_8))
        return Base64.getEncoder().encodeToString(cipher.iv + ciphertext)
    }

    /** @throws java.security.GeneralSecurityException when the value was altered, moved, or sealed under another key. */
    fun open(name: String, sealed: String): String {
        val bytes = Base64.getDecoder().decode(sealed)
        require(bytes.size > IV_BYTES) { "Sealed value is too short." }
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(TAG_BITS, bytes, 0, IV_BYTES))
        cipher.updateAAD(name.toByteArray(StandardCharsets.UTF_8))
        val plaintext = cipher.doFinal(bytes, IV_BYTES, bytes.size - IV_BYTES)
        return String(plaintext, StandardCharsets.UTF_8)
    }

    private companion object {
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val IV_BYTES = 12
        const val TAG_BITS = 128
    }
}
