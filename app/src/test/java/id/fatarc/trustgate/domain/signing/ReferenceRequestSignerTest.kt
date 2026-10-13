package id.fatarc.trustgate.domain.signing

import com.google.common.truth.Truth.assertThat
import org.junit.Test

class ReferenceRequestSignerTest {
    private val signer = ReferenceRequestSigner()
    private val payload = PaymentRequestPayload(amountMinor = 125_000, currency = "IDR", merchantReference = "REF-1001")

    private fun prepare(
        body: PaymentRequestPayload = payload,
        nonce: String = "abc123nonce",
        idempotencyKey: String? = null,
        confirmation: String? = null,
    ) = signer.prepare(
        payload = body,
        nonce = nonce,
        keyId = "k_0123456789abcdef",
        timestamp = "2026-05-31T00:00:00Z",
        idempotencyKey = idempotencyKey,
        confirmation = confirmation,
    )

    @Test
    fun `the same fields always produce the same bytes to sign`() {
        assertThat(prepare().signingInput).isEqualTo(prepare().signingInput)
    }

    @Test
    fun `every signed field changes the bytes to sign`() {
        val base = prepare().signingInput

        assertThat(prepare(body = payload.copy(amountMinor = 250_000)).signingInput).isNotEqualTo(base)
        assertThat(prepare(nonce = "othernonce").signingInput).isNotEqualTo(base)
        assertThat(prepare(idempotencyKey = "idem-1").signingInput).isNotEqualTo(base)
        assertThat(prepare(confirmation = ReferenceSigningScheme.CONFIRMATION_TAP).signingInput).isNotEqualTo(base)
    }

    @Test
    fun `canonical body escapes embedded quotes`() {
        val request = prepare(body = payload.copy(merchantReference = "REF-\"1001\""))

        assertThat(request.canonicalBody)
            .isEqualTo("{\"amountMinor\":125000,\"currency\":\"IDR\",\"merchantReference\":\"REF-\\\"1001\\\"\"}")
    }

    @Test
    fun `signed request carries only the headers that apply`() {
        val plain = prepare().signedWith(byteArrayOf(1, 2, 3))
        val payment = prepare(idempotencyKey = "idem-1", confirmation = "tap").signedWith(byteArrayOf(1, 2, 3))

        assertThat(plain.headers).doesNotContainKey(ReferenceSigningScheme.HEADER_IDEMPOTENCY_KEY)
        assertThat(plain.headers).doesNotContainKey(ReferenceSigningScheme.HEADER_CONFIRMATION)
        assertThat(payment.headers).containsEntry(ReferenceSigningScheme.HEADER_IDEMPOTENCY_KEY, "idem-1")
        assertThat(payment.headers).containsEntry(ReferenceSigningScheme.HEADER_CONFIRMATION, "tap")
        assertThat(payment.headers).containsEntry(ReferenceSigningScheme.HEADER_SIGNATURE, "AQID")
    }
}
