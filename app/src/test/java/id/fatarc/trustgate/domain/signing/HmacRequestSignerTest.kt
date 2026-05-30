package id.fatarc.trustgate.domain.signing

import com.google.common.truth.Truth.assertThat
import id.fatarc.trustgate.core.crypto.HmacRequestSigner
import org.junit.Test

class HmacRequestSignerTest {
    private val signer = HmacRequestSigner()
    private val payload = PaymentRequestPayload(
        amountMinor = 125_000,
        currency = "IDR",
        merchantReference = "REF-1001",
    )

    @Test
    fun `same payload with same timestamp and nonce produces same signature`() {
        val first = signer.sign(payload, timestamp = "2026-05-31T00:00:00Z", nonce = "abc123nonce")
        val second = signer.sign(payload, timestamp = "2026-05-31T00:00:00Z", nonce = "abc123nonce")

        assertThat(first.signature).isEqualTo(second.signature)
        assertThat(first.bodyHash).isEqualTo(second.bodyHash)
    }

    @Test
    fun `changed payload changes signature`() {
        val first = signer.sign(payload, timestamp = "2026-05-31T00:00:00Z", nonce = "abc123nonce")
        val second = signer.sign(
            payload.copy(amountMinor = 250_000),
            timestamp = "2026-05-31T00:00:00Z",
            nonce = "abc123nonce",
        )

        assertThat(first.signature).isNotEqualTo(second.signature)
    }

    @Test
    fun `changed nonce changes signature`() {
        val first = signer.sign(payload, timestamp = "2026-05-31T00:00:00Z", nonce = "abc123nonce")
        val second = signer.sign(payload, timestamp = "2026-05-31T00:00:00Z", nonce = "othernonce")

        assertThat(first.signature).isNotEqualTo(second.signature)
    }
}

