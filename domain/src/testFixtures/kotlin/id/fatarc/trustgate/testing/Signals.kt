package id.fatarc.trustgate.testing

import id.fatarc.trustgate.domain.risk.RiskSignal
import id.fatarc.trustgate.domain.risk.SignalCategory
import id.fatarc.trustgate.domain.risk.SignalSeverity

fun riskSignal(
    id: String,
    severity: SignalSeverity,
    category: SignalCategory = SignalCategory.ROOT,
    detected: Boolean = true,
): RiskSignal = RiskSignal(
    id = id,
    name = id,
    category = category,
    severity = severity,
    detected = detected,
    explanation = "test signal",
)
