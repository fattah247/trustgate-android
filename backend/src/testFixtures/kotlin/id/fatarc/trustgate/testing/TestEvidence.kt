package id.fatarc.trustgate.testing

import id.fatarc.trustgate.backend.ReferenceBackend
import id.fatarc.trustgate.domain.api.DeviceEvidence
import id.fatarc.trustgate.domain.api.PaymentAuthorization
import id.fatarc.trustgate.domain.api.ReportedSignal
import id.fatarc.trustgate.domain.api.TrustGateJson
import id.fatarc.trustgate.domain.risk.DeviceRiskLevel
import id.fatarc.trustgate.domain.risk.SignalCatalog
import java.time.Instant

/** Signals that score to [level] on their own. */
fun signalsFor(level: DeviceRiskLevel): List<ReportedSignal> = when (level) {
    DeviceRiskLevel.LOW -> emptyList()
    DeviceRiskLevel.MEDIUM -> listOf(ReportedSignal(SignalCatalog.TEST_KEYS.id, detected = true))
    DeviceRiskLevel.HIGH -> listOf(ReportedSignal(SignalCatalog.DEBUGGER_CONNECTED.id, detected = true))
}

fun evidenceJson(deviceKeyId: String, level: DeviceRiskLevel, at: Instant): String =
    TrustGateJson.encodeToString(DeviceEvidence.serializer(), DeviceEvidence(deviceKeyId, at.toString(), signalsFor(level)))

/** Asks [this] backend to authorize a payment, reporting signals that score [level], signed by [sign]. */
fun ReferenceBackend.authorize(
    deviceKeyId: String,
    sign: (ByteArray) -> ByteArray,
    level: DeviceRiskLevel,
    at: Instant = Instant.now(),
): PaymentAuthorization {
    val evidence = evidenceJson(deviceKeyId, level, at)
    return authorizePayment(deviceKeyId, evidence, sign(evidence.toByteArray()), integrityToken = null, receivedAt = at)
}

fun ReferenceBackend.authorize(device: TestKey, level: DeviceRiskLevel, at: Instant = Instant.now()): PaymentAuthorization =
    authorize(device.keyId, device::sign, level, at)
