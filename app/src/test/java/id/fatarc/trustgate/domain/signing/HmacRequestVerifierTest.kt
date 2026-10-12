package id.fatarc.trustgate.domain.signing

import com.google.common.truth.Truth.assertThat
import id.fatarc.trustgate.core.crypto.HmacRequestSigner
import id.fatarc.trustgate.core.crypto.HmacRequestVerifier
import org.junit.Test
import java.time.Duration
import java.time.Instant

class HmacRequestVerifierTest {
    private val signer = HmacRequestSigner()
    private val verifier = HmacRequestVerifier()
    private val signedAt = Instant.parse("2026-05-31T00:00:00Z")
    private val payload = PaymentRequestPayload(
        amountMinor = 125_000,
        currency = "IDR",
        merchantReference = "REF-1001",
    )

    private fun signed(nonce: String = "abc123nonce") =
        signer.sign(payload, timestamp = signedAt.toString(), nonce = nonce)

    @Test
    fun `freshly signed request is accepted`() {
        val result = verifier.verify(signed().asReceived(), receivedAt = signedAt.plusSeconds(2))

        assertThat(result).isEqualTo(VerificationResult.Accepted)
    }

    @Test
    fun `sending the same request twice is rejected as a replay`() {
        val request = signed().asReceived()
        verifier.verify(request, receivedAt = signedAt.plusSeconds(1))

        val replay = verifier.verify(request, receivedAt = signedAt.plusSeconds(30))

        assertThat(replay).isEqualTo(VerificationResult.Rejected(RejectionReason.NONCE_REUSED))
    }

    @Test
    fun `changing the body after signing breaks the signature`() {
        val tampered = signed().asReceived().copy(
            body = """{"amountMinor":9990000,"currency":"IDR","merchantReference":"REF-1001"}""",
        )

        val result = verifier.verify(tampered, receivedAt = signedAt.plusSeconds(1))

        assertThat(result).isEqualTo(VerificationResult.Rejected(RejectionReason.SIGNATURE_MISMATCH))
    }

    @Test
    fun `changing the path after signing breaks the signature`() {
        val redirected = signed().asReceived().copy(path = "/payments/other")

        val result = verifier.verify(redirected, receivedAt = signedAt.plusSeconds(1))

        assertThat(result).isEqualTo(VerificationResult.Rejected(RejectionReason.SIGNATURE_MISMATCH))
    }

    @Test
    fun `request signed with another key is rejected`() {
        val foreign = HmacRequestSigner(referenceSecret = "someone-elses-key")
            .sign(payload, timestamp = signedAt.toString(), nonce = "abc123nonce")

        val result = verifier.verify(foreign.asReceived(), receivedAt = signedAt.plusSeconds(1))

        assertThat(result).isEqualTo(VerificationResult.Rejected(RejectionReason.SIGNATURE_MISMATCH))
    }

    @Test
    fun `request arriving after the time window is rejected`() {
        val late = signedAt.plus(verifier.allowedClockSkew).plusSeconds(1)

        val result = verifier.verify(signed().asReceived(), receivedAt = late)

        assertThat(result).isEqualTo(VerificationResult.Rejected(RejectionReason.OUTSIDE_TIME_WINDOW))
    }

    @Test
    fun `request dated too far in the future is rejected`() {
        val early = signedAt.minus(verifier.allowedClockSkew).minusSeconds(1)

        val result = verifier.verify(signed().asReceived(), receivedAt = early)

        assertThat(result).isEqualTo(VerificationResult.Rejected(RejectionReason.OUTSIDE_TIME_WINDOW))
    }

    @Test
    fun `missing signature header is rejected`() {
        val request = signed().asReceived().let { it.copy(headers = it.headers - "X-Request-Signature") }

        val result = verifier.verify(request, receivedAt = signedAt)

        assertThat(result).isEqualTo(VerificationResult.Rejected(RejectionReason.MISSING_HEADERS))
    }

    @Test
    fun `malformed timestamp is rejected`() {
        val request = signed().asReceived().let { it.copy(headers = it.headers + ("X-Request-Timestamp" to "yesterday")) }

        val result = verifier.verify(request, receivedAt = signedAt)

        assertThat(result).isEqualTo(VerificationResult.Rejected(RejectionReason.MALFORMED_TIMESTAMP))
    }

    @Test
    fun `headers are matched case-insensitively like HTTP`() {
        val request = signed().asReceived().let { received ->
            received.copy(headers = received.headers.mapKeys { (name, _) -> name.lowercase() })
        }

        val result = verifier.verify(request, receivedAt = signedAt)

        assertThat(result).isEqualTo(VerificationResult.Accepted)
    }

    @Test
    fun `a rejected forgery does not use up the genuine request's nonce`() {
        val genuine = signed().asReceived()
        verifier.verify(genuine.copy(body = "{}"), receivedAt = signedAt)

        val result = verifier.verify(genuine, receivedAt = signedAt.plusSeconds(1))

        assertThat(result).isEqualTo(VerificationResult.Accepted)
    }

    @Test
    fun `nonces are forgotten only after they could no longer pass the time window`() {
        val first = signed(nonce = "n-1").asReceived()
        verifier.verify(first, receivedAt = signedAt)

        val replayAtEdge = verifier.verify(first, receivedAt = signedAt.plus(verifier.allowedClockSkew))
        val muchLater = verifier.verify(first, receivedAt = signedAt.plus(Duration.ofHours(1)))

        assertThat(replayAtEdge).isEqualTo(VerificationResult.Rejected(RejectionReason.NONCE_REUSED))
        assertThat(muchLater).isEqualTo(VerificationResult.Rejected(RejectionReason.OUTSIDE_TIME_WINDOW))
    }
}
