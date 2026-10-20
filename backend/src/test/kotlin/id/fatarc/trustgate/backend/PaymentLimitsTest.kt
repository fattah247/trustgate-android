package id.fatarc.trustgate.backend

import com.google.common.truth.Truth.assertThat
import id.fatarc.trustgate.domain.actiongate.SensitiveActionDecision
import id.fatarc.trustgate.domain.api.PaymentAuthorization
import id.fatarc.trustgate.domain.api.PaymentResponse
import id.fatarc.trustgate.domain.api.RegistrationResult
import id.fatarc.trustgate.domain.risk.DeviceRiskLevel
import id.fatarc.trustgate.domain.signing.KeyRole
import id.fatarc.trustgate.domain.signing.PaymentRequestPayload
import id.fatarc.trustgate.domain.signing.ReferenceRequestSigner
import id.fatarc.trustgate.domain.signing.ReferenceSigningScheme
import id.fatarc.trustgate.domain.signing.RejectionReason
import id.fatarc.trustgate.domain.signing.asReceived
import id.fatarc.trustgate.testing.MutableClock
import id.fatarc.trustgate.testing.TestKey
import id.fatarc.trustgate.testing.authorize
import id.fatarc.trustgate.testing.developmentPolicy
import id.fatarc.trustgate.testing.selfSignedChain
import java.time.Duration
import org.junit.Test

class PaymentLimitsTest {
    private val clock = MutableClock()
    private val device = TestKey()
    private val signer = ReferenceRequestSigner()
    private var paymentsSent = 0

    private fun backendWith(limits: PaymentLimits) = ReferenceBackend(
        BackendPolicy(developmentPolicy.name, developmentPolicy.attestation, developmentPolicy.risk, limits),
        clock,
    ).apply {
        val challenge = issueRegistrationChallenge()
        check(registerKey(KeyRole.DEVICE, device.encodedPublicKey, selfSignedChain(device), challenge) is RegistrationResult.Registered)
    }

    private fun ReferenceBackend.authorization(): PaymentAuthorization = authorize(device, DeviceRiskLevel.LOW, clock.now)

    private fun ReferenceBackend.pay(authorization: PaymentAuthorization, amountMinor: Long = 125_000): PaymentResponse {
        val proceed = authorization as PaymentAuthorization.Proceed
        val request = device.sign(
            signer.prepare(
                payload = PaymentRequestPayload(amountMinor = amountMinor, currency = "IDR", merchantReference = "REF-${++paymentsSent}"),
                nonce = proceed.nonce,
                keyId = device.keyId,
                timestamp = clock.now.toString(),
                idempotencyKey = "idem-$paymentsSent",
                confirmation = ReferenceSigningScheme.CONFIRMATION_TAP.takeIf { proceed.decision == SensitiveActionDecision.REQUIRE_CONFIRMATION },
            ),
        )
        return submitPayment(request.asReceived(), clock.now)
    }

    private fun limits(
        maxPayments: Int = Int.MAX_VALUE,
        dailyAmountMinor: Long? = null,
        newPhonePeriod: Duration? = null,
        newPhoneAmountMinor: Long? = null,
    ) = PaymentLimits(maxPayments, Duration.ofMinutes(1), dailyAmountMinor, newPhonePeriod, newPhoneAmountMinor)

    @Test
    fun `authorizations collected in advance can't add up past the payment count`() {
        val backend = backendWith(limits(maxPayments = 3))
        val authorizations = List(4) { backend.authorization() }

        val results = authorizations.map { backend.pay(it) }

        assertThat(results.take(3).all { it is PaymentResponse.Processed }).isTrue()
        assertThat(results.last()).isEqualTo(PaymentResponse.Rejected(RejectionReason.TOO_MANY_PAYMENTS))
        assertThat(backend.chargedPayments).isEqualTo(3)
    }

    @Test
    fun `a phone at its payment count is told to wait, and can pay again once the window passes`() {
        val backend = backendWith(limits(maxPayments = 2))
        repeat(2) { backend.pay(backend.authorization()) }

        val tooSoon = backend.authorization()
        clock.advanceSeconds(61)
        val later = backend.authorization()

        assertThat(tooSoon.decision).isEqualTo(SensitiveActionDecision.BLOCK)
        assertThat(tooSoon.reasons.map { it.text }).contains("Too many payments. Try again in a few minutes")
        assertThat(backend.pay(later)).isInstanceOf(PaymentResponse.Processed::class.java)
    }

    @Test
    fun `a payment that would pass the daily amount is refused`() {
        val backend = backendWith(limits(dailyAmountMinor = 200_000))

        assertThat(backend.pay(backend.authorization())).isInstanceOf(PaymentResponse.Processed::class.java)
        assertThat(backend.pay(backend.authorization())).isEqualTo(PaymentResponse.Rejected(RejectionReason.OVER_LIMIT))
    }

    @Test
    fun `a new phone has to confirm and may only pay small amounts until it has been registered a while`() {
        val backend = backendWith(limits(newPhonePeriod = Duration.ofDays(1), newPhoneAmountMinor = 100_000))

        val asNew = backend.authorization()
        val bigWhileNew = backend.pay(asNew, amountMinor = 125_000)
        clock.advanceSeconds(Duration.ofDays(1).seconds + 1)
        val settled = backend.authorization()

        assertThat(asNew.decision).isEqualTo(SensitiveActionDecision.REQUIRE_CONFIRMATION)
        assertThat(asNew.reasons.map { it.text }).contains("New phone")
        assertThat(bigWhileNew).isEqualTo(PaymentResponse.Rejected(RejectionReason.OVER_LIMIT))
        assertThat(settled.decision).isEqualTo(SensitiveActionDecision.ALLOW)
        assertThat(backend.pay(settled, amountMinor = 125_000)).isInstanceOf(PaymentResponse.Processed::class.java)
    }
}
