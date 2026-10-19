package id.fatarc.trustgate.domain.risk

/** A signal the app checks for, with the severity the server scores it at. */
class SignalDefinition(
    val id: String,
    val name: String,
    val category: SignalCategory,
    val severity: SignalSeverity,
    val explanation: String,
) {
    fun observed(detected: Boolean, explanation: String = this.explanation): RiskSignal = RiskSignal(
        id = id,
        name = name,
        category = category,
        severity = severity,
        detected = detected,
        explanation = explanation,
    )
}

/**
 * Every signal the app reports. The server scores reported signals from this catalog rather than
 * from what the app says about them, so a tampered app can't lower a signal's severity.
 */
object SignalCatalog {
    val ROOT_SU_PATH = SignalDefinition(
        "root_su_path", "Suspicious su path", SignalCategory.ROOT, SignalSeverity.HIGH,
        "Known su binaries usually indicate a rooted or modified device.",
    )
    val ROOT_PACKAGE = SignalDefinition(
        "root_package", "Root management package", SignalCategory.ROOT, SignalSeverity.HIGH,
        "Root management tools can weaken assumptions about the app runtime.",
    )
    val TEST_KEYS = SignalDefinition(
        "test_keys", "Test-keys build tags", SignalCategory.ROOT, SignalSeverity.MEDIUM,
        "Test builds can be easier to tamper with than normal production builds.",
    )
    val SYSTEM_PARTITION_WRITABLE = SignalDefinition(
        "system_partition_writable", "Writable system partition", SignalCategory.ROOT, SignalSeverity.MEDIUM,
        "A writable system partition can be a sign of device modification.",
    )
    val EMULATOR_FINGERPRINT = SignalDefinition(
        "emulator_fingerprint", "Known emulator build strings", SignalCategory.EMULATOR, SignalSeverity.MEDIUM,
        "Build properties line up with common emulator characteristics.",
    )
    val DEBUGGER_CONNECTED = SignalDefinition(
        "debugger_connected", "Debugger attached", SignalCategory.DEBUGGER, SignalSeverity.HIGH,
        "A connected debugger can change runtime behavior and inspection visibility.",
    )
    val APP_DEBUGGABLE = SignalDefinition(
        "app_debuggable", "App debuggable flag", SignalCategory.DEBUGGER, SignalSeverity.MEDIUM,
        "Debuggable builds are useful for development but reduce trust for sensitive actions.",
    )
    val INSTALLER_SOURCE_UNKNOWN = SignalDefinition(
        "installer_source_unknown", "Installer source unknown", SignalCategory.INSTALLER, SignalSeverity.LOW,
        "Unknown install source is a signal to review, not an automatic block.",
    )

    val all: List<SignalDefinition> = listOf(
        ROOT_SU_PATH,
        ROOT_PACKAGE,
        TEST_KEYS,
        SYSTEM_PARTITION_WRITABLE,
        EMULATOR_FINGERPRINT,
        DEBUGGER_CONNECTED,
        APP_DEBUGGABLE,
        INSTALLER_SOURCE_UNKNOWN,
    )

    private val byId = all.associateBy { it.id }

    fun definition(id: String): SignalDefinition? = byId[id]
}
