package id.fatarc.trustgate.domain.risk

fun scenarioRiskReport(level: DeviceRiskLevel): DeviceRiskReport {
    val signals = when (level) {
        DeviceRiskLevel.LOW -> listOf(
            scenarioSignal(
                id = "installer_known",
                name = "Known installer source",
                severity = SignalSeverity.LOW,
                detected = false,
                explanation = "This scenario profile keeps the gate open to show the allowed path.",
            ),
            scenarioSignal(
                id = "debugger_connected",
                name = "Debugger attached",
                severity = SignalSeverity.HIGH,
                detected = false,
                explanation = "No debugger signal is active in the low-risk scenario profile.",
            ),
        )

        DeviceRiskLevel.MEDIUM -> listOf(
            scenarioSignal(
                id = "test_keys",
                name = "Test-keys build tags",
                severity = SignalSeverity.MEDIUM,
                detected = true,
                explanation = "This scenario profile shows a moderate trust decision without a hard block.",
            ),
            scenarioSignal(
                id = "installer_unknown",
                name = "Installer source unknown",
                severity = SignalSeverity.LOW,
                detected = true,
                explanation = "Unknown installer source is a signal to review, not a guaranteed block.",
            ),
        )

        DeviceRiskLevel.HIGH -> listOf(
            scenarioSignal(
                id = "root_package",
                name = "Root management package",
                severity = SignalSeverity.HIGH,
                detected = true,
                explanation = "This scenario profile shows how the app blocks a sensitive action on high risk.",
            ),
            scenarioSignal(
                id = "debugger_connected",
                name = "Debugger attached",
                severity = SignalSeverity.HIGH,
                detected = true,
                explanation = "A connected debugger is treated as a strong signal in the blocked path scenario.",
            ),
        )
    }
    val score = signals.filter { it.detected }.sumOf { it.severity.weight }
    return DeviceRiskReport(
        signals = signals,
        score = score,
        level = level,
    )
}

private fun scenarioSignal(
    id: String,
    name: String,
    severity: SignalSeverity,
    detected: Boolean,
    explanation: String,
): RiskSignal {
    return RiskSignal(
        id = id,
        name = name,
        category = when (id) {
            "root_package" -> SignalCategory.ROOT
            "debugger_connected" -> SignalCategory.DEBUGGER
            "installer_unknown", "installer_known" -> SignalCategory.INSTALLER
            else -> SignalCategory.EMULATOR
        },
        severity = severity,
        detected = detected,
        explanation = explanation,
    )
}
