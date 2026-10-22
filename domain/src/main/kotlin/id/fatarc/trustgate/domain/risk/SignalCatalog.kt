package id.fatarc.trustgate.domain.risk

/** A signal the app checks for, with the severity the server scores it at. */
class SignalDefinition(
    val id: String,
    /** What was found, such as "Emulator". */
    val name: String,
    /** What a pass means, such as "Real phone, not an emulator". */
    val passedName: String,
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
        "root_su_path", "Rooted", "No root access", SignalCategory.ROOT, SignalSeverity.HIGH,
        "A root tool is on this phone, so other apps could take full control of it.",
    )
    val ROOT_PACKAGE = SignalDefinition(
        "root_package", "Root app installed", "No root apps", SignalCategory.ROOT, SignalSeverity.HIGH,
        "Apps like Magisk give anything that asks full control of the phone.",
    )
    val TEST_KEYS = SignalDefinition(
        "test_keys", "Test build of Android", "Official Android build", SignalCategory.ROOT, SignalSeverity.MEDIUM,
        "The phone runs a test version of Android, which is easier to tamper with.",
    )
    val SYSTEM_PARTITION_WRITABLE = SignalDefinition(
        "system_partition_writable", "System files changeable", "System files untouched", SignalCategory.ROOT, SignalSeverity.MEDIUM,
        "Android's own files can be changed, so the system may have been modified.",
    )
    val EMULATOR_FINGERPRINT = SignalDefinition(
        "emulator_fingerprint", "Emulator", "Real phone, not an emulator", SignalCategory.EMULATOR, SignalSeverity.MEDIUM,
        "This isn't a real phone, and an emulator can fake what it reports.",
    )
    val DEBUGGER_CONNECTED = SignalDefinition(
        "debugger_connected", "Debugger attached", "No debugger attached", SignalCategory.DEBUGGER, SignalSeverity.HIGH,
        "A debugger can read and change the app while it runs.",
    )
    val APP_DEBUGGABLE = SignalDefinition(
        "app_debuggable", "Debug version of the app", "Release version of the app", SignalCategory.DEBUGGER, SignalSeverity.MEDIUM,
        "This copy of the app was built for development, which lets tools look inside it.",
    )
    val INSTALLER_SOURCE_UNKNOWN = SignalDefinition(
        "installer_source_unknown", "Not from an app store", "Installed from an app store", SignalCategory.INSTALLER, SignalSeverity.LOW,
        "The app wasn't installed from a store, so it could be a modified copy.",
    )

    val CALL_ACTIVE = SignalDefinition(
        "call_active", "On a call", "Not on a call", SignalCategory.SCAM, SignalSeverity.MEDIUM,
        "Scammers often stay on the line and talk people through a payment.",
    )
    val SCREEN_READER_APP = SignalDefinition(
        "screen_reader_app", "App reading the screen", "No apps reading the screen", SignalCategory.SCAM, SignalSeverity.MEDIUM,
        "An app with accessibility access, other than a real accessibility tool, can read and tap anything on screen.",
    )
    val SCREEN_RECORDING = SignalDefinition(
        "screen_recording", "Screen being recorded", "Screen not recorded", SignalCategory.SCAM, SignalSeverity.MEDIUM,
        "Something is recording or sharing this screen, so someone else may be watching.",
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
        CALL_ACTIVE,
        SCREEN_READER_APP,
        SCREEN_RECORDING,
    )

    private val byId = all.associateBy { it.id }

    fun definition(id: String): SignalDefinition? = byId[id]

    /** How a check reads once it has passed; falls back to [RiskSignal.name] for signals outside the catalog. */
    fun passedName(signal: RiskSignal): String = byId[signal.id]?.passedName ?: signal.name
}
