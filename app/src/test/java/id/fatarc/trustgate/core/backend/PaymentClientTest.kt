package id.fatarc.trustgate.core.backend

import com.google.common.truth.Truth.assertThat
import id.fatarc.trustgate.domain.risk.DeviceRiskLevel
import id.fatarc.trustgate.domain.signing.KeyRole
import id.fatarc.trustgate.domain.signing.PaymentRequestPayload
import id.fatarc.trustgate.domain.signing.ReceivedRequest
import id.fatarc.trustgate.domain.signing.ReferenceRequestSigner
import id.fatarc.trustgate.domain.signing.asReceived
import id.fatarc.trustgate.testing.MutableClock
import id.fatarc.trustgate.testing.TestKey
import kotlinx.coroutines.test.runTest
import org.junit.Test

class PaymentClientTest {
    private val clock = MutableClock()
    private val backend = ReferenceBackend(clock = clock)
    private val transport = ReferenceTransport(backend, clock)
    private val device = TestKey()

    private fun signedPayment(): ReceivedRequest {
        backend.registerKey(KeyRole.DEVICE, device.encodedPublicKey, emptyList(), backend.issueRegistrationChallenge())
        val authorization = backend.beginPayment(
            device.keyId,
            RiskEvidence(DeviceRiskLevel.LOW, emptySet(), simulated = true),
        ) as PaymentAuthorization.Proceed
        return device.sign(
            ReferenceRequestSigner().prepare(
                payload = PaymentRequestPayload(125_000, "IDR", "REF-1"),
                nonce = authorization.nonce,
                keyId = device.keyId,
                timestamp = clock.now.toString(),
                idempotencyKey = "idem-1",
            ),
        ).asReceived()
    }

    @Test
    fun `a lost response is retried and the payment is charged once`() = runTest {
        transport.loseFirstResponse = true
        val client = PaymentClient(transport)

        val outcome = client.submit(signedPayment())

        val processed = outcome.response as PaymentResponse.Processed
        assertThat(outcome.attempts).isEqualTo(2)
        assertThat(outcome.lostResponses).isEqualTo(1)
        assertThat(processed.replayed).isTrue()
        assertThat(backend.chargedPayments).isEqualTo(1)
    }

    @Test
    fun `without lost responses the first attempt answers`() = runTest {
        val outcome = PaymentClient(transport).submit(signedPayment())

        assertThat(outcome.attempts).isEqualTo(1)
        assertThat((outcome.response as PaymentResponse.Processed).replayed).isFalse()
    }

    @Test
    fun `when every response is lost the outcome is reported as unknown`() = runTest {
        val silent = PaymentTransport { throw ResponseLostException() }

        val outcome = PaymentClient(silent, maxAttempts = 3).submit(signedPayment())

        assertThat(outcome.response).isNull()
        assertThat(outcome.attempts).isEqualTo(3)
        assertThat(outcome.lostResponses).isEqualTo(3)
    }
}
