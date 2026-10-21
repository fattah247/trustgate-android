package id.fatarc.trustgate.core.backend

import id.fatarc.trustgate.testing.TEST_PAYMENT
import com.google.common.truth.Truth.assertThat
import id.fatarc.trustgate.backend.ReferenceBackend
import id.fatarc.trustgate.domain.api.PaymentAuthorization
import id.fatarc.trustgate.domain.api.PaymentResponse
import id.fatarc.trustgate.domain.risk.DeviceRiskLevel
import id.fatarc.trustgate.domain.signing.KeyRole
import id.fatarc.trustgate.domain.signing.PaymentRequestPayload
import id.fatarc.trustgate.domain.signing.ReceivedRequest
import id.fatarc.trustgate.domain.signing.ReferenceRequestSigner
import id.fatarc.trustgate.domain.signing.asReceived
import id.fatarc.trustgate.testing.MutableClock
import id.fatarc.trustgate.testing.TestKey
import id.fatarc.trustgate.testing.authorize
import id.fatarc.trustgate.testing.developmentPolicy
import id.fatarc.trustgate.testing.selfSignedChain
import kotlin.random.Random
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.currentTime
import kotlinx.coroutines.test.runTest
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class PaymentClientTest {
    private val clock = MutableClock()
    private val backend = ReferenceBackend(developmentPolicy, clock)
    private val transport = BackendTransport(InProcessTrustGateApi(backend))
    private val device = TestKey()

    private fun signedPayment(): ReceivedRequest {
        backend.registerKey(KeyRole.DEVICE, device.encodedPublicKey, selfSignedChain(device), backend.issueRegistrationChallenge())
        val authorization = backend.authorize(device, DeviceRiskLevel.LOW, clock.now) as PaymentAuthorization.Proceed
        return device.sign(
            ReferenceRequestSigner().prepare(
                payload = TEST_PAYMENT,
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

        val outcome = PaymentClient(silent).submit(signedPayment())

        assertThat(outcome.response).isNull()
        assertThat(outcome.attempts).isEqualTo(3)
        assertThat(outcome.lostResponses).isEqualTo(3)
    }

    @Test
    fun `retries back off exponentially and don't wait after the last attempt`() = runTest {
        val silent = PaymentTransport { throw ResponseLostException() }

        PaymentClient(silent, baseDelayMillis = 400, random = NoJitter).submit(signedPayment())

        assertThat(currentTime).isEqualTo(400L + 800L)
    }

    @Test
    fun `only a lost response is retried`() = runTest {
        var attempts = 0
        val failing = PaymentTransport {
            attempts++
            throw IllegalStateException("not a network failure")
        }

        runCatching { PaymentClient(failing).submit(signedPayment()) }

        assertThat(attempts).isEqualTo(1)
    }

    private object NoJitter : Random() {
        override fun nextBits(bitCount: Int): Int = 0
    }
}
