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
import id.fatarc.trustgate.domain.signing.asReceived
import id.fatarc.trustgate.testing.MutableClock
import id.fatarc.trustgate.testing.TestKey
import id.fatarc.trustgate.testing.authorize
import id.fatarc.trustgate.testing.developmentPolicy
import id.fatarc.trustgate.testing.selfSignedChain
import java.time.Instant
import org.junit.Test

class UnusualPaymentsTest {
    // Noon in Jakarta (UTC+7).
    private val clock = MutableClock(Instant.parse("2026-05-31T05:00:00Z"))
    private val jakarta = 7 * 60
    private val phone = TestKey()
    private val signer = ReferenceRequestSigner()
    private val backend = ReferenceBackend(
        BackendPolicy(developmentPolicy.name, developmentPolicy.attestation, developmentPolicy.risk, PaymentLimits.NONE),
        clock,
    ).apply {
        val challenge = issueRegistrationChallenge()
        check(registerKey(KeyRole.DEVICE, phone.encodedPublicKey, selfSignedChain(phone), challenge) is RegistrationResult.Registered)
    }
    private var sent = 0

    private fun payment(payee: String = "trustgate-store", amountMinor: Long = 125_000) =
        PaymentRequestPayload(amountMinor, "IDR", "REF-${++sent}", payee)

    private fun authorize(payment: PaymentRequestPayload): PaymentAuthorization =
        backend.authorize(phone, DeviceRiskLevel.LOW, clock.now, payment, utcOffsetMinutes = jakarta)

    /** Approves and pays [payment], confirming with a tap when the server asks for it. */
    private fun payNow(payment: PaymentRequestPayload = payment()) {
        val approval = authorize(payment) as PaymentAuthorization.Proceed
        val tap = ReferenceSigningScheme.CONFIRMATION_TAP.takeIf { approval.decision == SensitiveActionDecision.REQUIRE_CONFIRMATION }
        val request = signer.prepare(payment, approval.nonce, phone.keyId, clock.now.toString(), idempotencyKey = "idem-$sent", confirmation = tap)
        val response = backend.submitPayment(phone.sign(request).asReceived(), clock.now)
        check(response is PaymentResponse.Processed)
        clock.advanceSeconds(3600)
    }

    private fun PaymentAuthorization.reasonTexts() = reasons.map { it.text }

    @Test
    fun `an account with no history has nothing to compare with`() {
        assertThat(authorize(payment(payee = "someone-new")).decision).isEqualTo(SensitiveActionDecision.ALLOW)
    }

    @Test
    fun `the first payment to a payee asks for confirmation, and later ones don't`() {
        payNow()

        val first = authorize(payment(payee = "warung-sari"))
        payNow(payment(payee = "warung-sari"))
        val again = authorize(payment(payee = "warung-sari"))

        assertThat(first.decision).isEqualTo(SensitiveActionDecision.REQUIRE_CONFIRMATION)
        assertThat(first.reasonTexts()).contains("First payment to this payee")
        assertThat(again.decision).isEqualTo(SensitiveActionDecision.ALLOW)
    }

    @Test
    fun `far more than the account usually pays asks for confirmation`() {
        repeat(3) { payNow() }

        val usual = authorize(payment(amountMinor = 200_000))
        val large = authorize(payment(amountMinor = 7_500_000))

        assertThat(usual.decision).isEqualTo(SensitiveActionDecision.ALLOW)
        assertThat(large.decision).isEqualTo(SensitiveActionDecision.REQUIRE_CONFIRMATION)
        assertThat(large.reasonTexts()).contains("Much more than this account usually pays")
    }

    @Test
    fun `paying in the small hours, when the account never does, asks for confirmation`() {
        repeat(3) { payNow() }
        // 02:00 the next night in Jakarta.
        clock.now = Instant.parse("2026-05-31T19:00:00Z")

        val night = authorize(payment())

        assertThat(night.decision).isEqualTo(SensitiveActionDecision.REQUIRE_CONFIRMATION)
        assertThat(night.reasonTexts()).contains("Unusual time for this account")
    }
}
