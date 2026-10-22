package id.fatarc.trustgate.testing

import id.fatarc.trustgate.backend.ReferenceBackend
import id.fatarc.trustgate.domain.api.DeviceEvidence
import id.fatarc.trustgate.domain.api.PaymentAuthorization
import id.fatarc.trustgate.domain.api.ReportedSignal
import id.fatarc.trustgate.domain.api.TrustGateJson
import id.fatarc.trustgate.domain.risk.DeviceRiskLevel
import id.fatarc.trustgate.domain.risk.SignalCatalog
import id.fatarc.trustgate.domain.signing.PaymentRequestPayload
import java.time.Instant

/** The payment tests approve and make unless they say otherwise; fixed, so approval and payment always match. */
val TEST_PAYMENT = PaymentRequestPayload(amountMinor = 125_000, currency = "IDR", merchantReference = "REF-1001")

/** Signals that score to [level] on their own. */
fun signalsFor(level: DeviceRiskLevel): List<ReportedSignal> = when (level) {
    DeviceRiskLevel.LOW -> emptyList()
    DeviceRiskLevel.MEDIUM -> listOf(ReportedSignal(SignalCatalog.TEST_KEYS.id, detected = true))
    DeviceRiskLevel.HIGH -> listOf(ReportedSignal(SignalCatalog.DEBUGGER_CONNECTED.id, detected = true))
}

fun evidenceJson(
    deviceKeyId: String,
    level: DeviceRiskLevel,
    at: Instant,
    payment: PaymentRequestPayload = TEST_PAYMENT,
    utcOffsetMinutes: Int? = null,
): String = TrustGateJson.encodeToString(
    DeviceEvidence.serializer(),
    DeviceEvidence(deviceKeyId, at.toString(), signalsFor(level), payment = payment, utcOffsetMinutes = utcOffsetMinutes),
)

/** Asks [this] backend to authorize [payment], reporting signals that score [level], signed by [sign]. */
fun ReferenceBackend.authorize(
    deviceKeyId: String,
    sign: (ByteArray) -> ByteArray,
    level: DeviceRiskLevel,
    at: Instant = Instant.now(),
    payment: PaymentRequestPayload = TEST_PAYMENT,
    utcOffsetMinutes: Int? = null,
): PaymentAuthorization {
    val evidence = evidenceJson(deviceKeyId, level, at, payment, utcOffsetMinutes)
    return authorizePayment(deviceKeyId, evidence, sign(evidence.toByteArray()), integrityToken = null, receivedAt = at)
}

fun ReferenceBackend.authorize(
    device: TestKey,
    level: DeviceRiskLevel,
    at: Instant = Instant.now(),
    payment: PaymentRequestPayload = TEST_PAYMENT,
    utcOffsetMinutes: Int? = null,
): PaymentAuthorization = authorize(device.keyId, device::sign, level, at, payment, utcOffsetMinutes)
