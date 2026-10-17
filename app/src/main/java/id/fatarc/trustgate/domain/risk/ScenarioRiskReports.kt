package id.fatarc.trustgate.domain.risk

/**
 * A simulated device profile for exercising each gate path. The signals go through the real
 * [RiskScorer], so a profile can never claim a level its own signals don't produce.
 */
fun scenarioRiskReport(
    level: DeviceRiskLevel,
    scorer: RiskScorer = RiskScorer(),
): DeviceRiskReport {
    val signals = when (level) {
        DeviceRiskLevel.LOW -> listOf(
            scenarioSignal(
                id = "installer_source_unknown",
                name = "Installer source unknown",
                category = SignalCategory.INSTALLER,
                severity = SignalSeverity.LOW,
                detected = false,
                explanation = "This scenario profile keeps the gate open to show the allowed path.",
            ),
            scenarioSignal(
                id = "debugger_connected",
                name = "Debugger attached",
                category = SignalCategory.DEBUGGER,
                severity = SignalSeverity.HIGH,
                detected = false,
                explanation = "No debugger signal is active in the low-risk scenario profile.",
            ),
        )

        DeviceRiskLevel.MEDIUM -> listOf(
            scenarioSignal(
                id = "test_keys",
                name = "Test-keys build tags",
                category = SignalCategory.ROOT,
                severity = SignalSeverity.MEDIUM,
                detected = true,
                explanation = "This scenario profile shows a moderate trust decision without a hard block.",
            ),
            scenarioSignal(
                id = "installer_source_unknown",
                name = "Installer source unknown",
                category = SignalCategory.INSTALLER,
                severity = SignalSeverity.LOW,
                detected = true,
                explanation = "Unknown installer source is a signal to review, not a guaranteed block.",
            ),
        )

        DeviceRiskLevel.HIGH -> listOf(
            scenarioSignal(
                id = "root_package",
                name = "Root management package",
                category = SignalCategory.ROOT,
                severity = SignalSeverity.HIGH,
                detected = true,
                explanation = "This scenario profile shows how the app blocks a sensitive action on high risk.",
            ),
            scenarioSignal(
                id = "debugger_connected",
                name = "Debugger attached",
                category = SignalCategory.DEBUGGER,
                severity = SignalSeverity.HIGH,
                detected = true,
                explanation = "A connected debugger is treated as a strong signal in the blocked path scenario.",
            ),
        )
    }
    return scorer.score(signals).also { report ->
        check(report.level == level) { "Scenario signals for $level scored ${report.level}." }
    }
}

/** Uses the live collector's ids and categories, so a simulated signal reads like the real one. */
private fun scenarioSignal(
    id: String,
    name: String,
    category: SignalCategory,
    severity: SignalSeverity,
    detected: Boolean,
    explanation: String,
): RiskSignal = RiskSignal(
    id = id,
    name = name,
    category = category,
    severity = severity,
    detected = detected,
    explanation = explanation,
)
