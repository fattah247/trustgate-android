package id.fatarc.trustgate.core.storage

import com.google.common.truth.Truth.assertThat
import org.junit.Assert.assertThrows
import org.junit.Test
import java.security.GeneralSecurityException
import java.util.Base64
import javax.crypto.KeyGenerator

class SealedValuesTest {
    private val key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
    private val sealed = SealedValues { key }

    @Test
    fun `a sealed value opens to the original`() {
        val stored = sealed.seal("session_token", "tg-session-1234")

        assertThat(sealed.open("session_token", stored)).isEqualTo("tg-session-1234")
    }

    @Test
    fun `the same value seals differently each time`() {
        assertThat(sealed.seal("session_token", "same")).isNotEqualTo(sealed.seal("session_token", "same"))
    }

    @Test
    fun `a value moved into another slot does not open`() {
        val stored = sealed.seal("last_risk_level", "LOW")

        assertThrows(GeneralSecurityException::class.java) { sealed.open("session_token", stored) }
    }

    @Test
    fun `an altered value does not open`() {
        val bytes = Base64.getDecoder().decode(sealed.seal("session_token", "tg-session-1234"))
        bytes[bytes.size - 1] = (bytes.last().toInt() xor 0x01).toByte()

        assertThrows(GeneralSecurityException::class.java) {
            sealed.open("session_token", Base64.getEncoder().encodeToString(bytes))
        }
    }

    @Test
    fun `a value sealed under another key does not open`() {
        val other = SealedValues { KeyGenerator.getInstance("AES").apply { init(256) }.generateKey() }

        assertThrows(GeneralSecurityException::class.java) {
            sealed.open("session_token", other.seal("session_token", "tg-session-1234"))
        }
    }
}
