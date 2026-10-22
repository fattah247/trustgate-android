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
            SignalCatalog.INSTALLER_SOURCE_UNKNOWN.observed(
                detected = false,
                explanation = "This scenario profile keeps the gate open to show the allowed path.",
            ),
            SignalCatalog.DEBUGGER_CONNECTED.observed(
                detected = false,
                explanation = "No debugger signal is active in the low-risk scenario profile.",
            ),
        )

        DeviceRiskLevel.MEDIUM -> listOf(
            SignalCatalog.TEST_KEYS.observed(
                detected = true,
                explanation = "This scenario profile shows a moderate trust decision without a hard block.",
            ),
            SignalCatalog.INSTALLER_SOURCE_UNKNOWN.observed(
                detected = true,
                explanation = "Unknown installer source is a signal to review, not a guaranteed block.",
            ),
        )

        DeviceRiskLevel.HIGH -> listOf(
            SignalCatalog.ROOT_PACKAGE.observed(
                detected = true,
                explanation = "This scenario profile shows how the app blocks a sensitive action on high risk.",
            ),
            SignalCatalog.DEBUGGER_CONNECTED.observed(
                detected = true,
                explanation = "A connected debugger is treated as a strong signal in the blocked path scenario.",
            ),
        )
    }
    return scorer.score(signals).also { report ->
        check(report.level == level) { "Scenario signals for $level scored ${report.level}." }
    }
}
