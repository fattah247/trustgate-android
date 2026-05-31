package id.fatarc.trustgate.domain.risk

fun demoRiskReport(level: DeviceRiskLevel): DeviceRiskReport {
    val signals = when (level) {
        DeviceRiskLevel.LOW -> listOf(
            demoSignal(
                id = "installer_known",
                name = "Known installer source",
                severity = SignalSeverity.LOW,
                detected = false,
                explanation = "This sample profile keeps the gate open to show the allowed path.",
            ),
            demoSignal(
                id = "debugger_connected",
                name = "Debugger attached",
                severity = SignalSeverity.HIGH,
                detected = false,
                explanation = "No debugger signal is active in the low-risk sample profile.",
            ),
        )

        DeviceRiskLevel.MEDIUM -> listOf(
            demoSignal(
                id = "test_keys",
                name = "Test-keys build tags",
                severity = SignalSeverity.MEDIUM,
                detected = true,
                explanation = "This sample profile shows a moderate trust decision without a hard block.",
            ),
            demoSignal(
                id = "installer_unknown",
                name = "Installer source unknown",
                severity = SignalSeverity.LOW,
                detected = true,
                explanation = "Unknown installer source is a signal to review, not a guaranteed block.",
            ),
        )

        DeviceRiskLevel.HIGH -> listOf(
            demoSignal(
                id = "root_package",
                name = "Root management package",
                severity = SignalSeverity.HIGH,
                detected = true,
                explanation = "This sample profile shows how the app blocks a sensitive action on high risk.",
            ),
            demoSignal(
                id = "debugger_connected",
                name = "Debugger attached",
                severity = SignalSeverity.HIGH,
                detected = true,
                explanation = "A connected debugger is treated as a strong signal in the blocked path sample.",
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

private fun demoSignal(
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

