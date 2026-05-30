package id.fatarc.trustgate.core.security

import android.content.Context
import android.content.pm.ApplicationInfo
import android.os.Build
import android.os.Debug
import id.fatarc.trustgate.domain.risk.DeviceSignalCollector
import id.fatarc.trustgate.domain.risk.RiskSignal
import id.fatarc.trustgate.domain.risk.SignalCategory
import id.fatarc.trustgate.domain.risk.SignalSeverity
import java.io.File

class AndroidDeviceSignalCollector(
    private val context: Context,
) : DeviceSignalCollector {

    override fun collectSignals(): List<RiskSignal> {
        val suspiciousSuPaths = listOf(
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/system/app/Superuser.apk",
            "/system/bin/.ext/su",
        )
        val rootPackages = listOf(
            "com.topjohnwu.magisk",
            "eu.chainfire.supersu",
            "com.koushikdutta.superuser",
        )
        val buildFingerprint = listOf(
            Build.FINGERPRINT,
            Build.MODEL,
            Build.MANUFACTURER,
            Build.BRAND,
            Build.DEVICE,
            Build.HARDWARE,
            Build.PRODUCT,
        ).joinToString(" ").lowercase()
        val installerPackage = resolveInstallerPackage()

        return listOf(
            RiskSignal(
                id = "root_su_path",
                name = "Suspicious su path",
                category = SignalCategory.ROOT,
                severity = SignalSeverity.HIGH,
                detected = suspiciousSuPaths.any { File(it).exists() },
                explanation = "Known su binaries usually indicate a rooted or modified device.",
            ),
            RiskSignal(
                id = "root_package",
                name = "Root management package",
                category = SignalCategory.ROOT,
                severity = SignalSeverity.HIGH,
                detected = rootPackages.any(::isPackageInstalled),
                explanation = "Root management tools can weaken assumptions about the app runtime.",
            ),
            RiskSignal(
                id = "test_keys",
                name = "Test-keys build tags",
                category = SignalCategory.ROOT,
                severity = SignalSeverity.MEDIUM,
                detected = Build.TAGS?.contains("test-keys", ignoreCase = true) == true,
                explanation = "Test builds can be easier to tamper with than normal production builds.",
            ),
            RiskSignal(
                id = "system_partition_writable",
                name = "Writable system partition",
                category = SignalCategory.ROOT,
                severity = SignalSeverity.MEDIUM,
                detected = File("/system").canWrite(),
                explanation = "A writable system partition can be a sign of device modification.",
            ),
            RiskSignal(
                id = "emulator_fingerprint",
                name = "Known emulator build strings",
                category = SignalCategory.EMULATOR,
                severity = SignalSeverity.MEDIUM,
                detected = listOf(
                    "generic",
                    "emulator",
                    "sdk_gphone",
                    "vbox",
                    "goldfish",
                    "ranchu",
                ).any(buildFingerprint::contains),
                explanation = "Build properties line up with common emulator characteristics.",
            ),
            RiskSignal(
                id = "debugger_connected",
                name = "Debugger attached",
                category = SignalCategory.DEBUGGER,
                severity = SignalSeverity.HIGH,
                detected = Debug.isDebuggerConnected(),
                explanation = "A connected debugger can change runtime behavior and inspection visibility.",
            ),
            RiskSignal(
                id = "app_debuggable",
                name = "App debuggable flag",
                category = SignalCategory.DEBUGGER,
                severity = SignalSeverity.MEDIUM,
                detected = (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0,
                explanation = "Debuggable builds are useful for development but reduce trust for sensitive actions.",
            ),
            RiskSignal(
                id = "installer_source_unknown",
                name = "Installer source unknown",
                category = SignalCategory.INSTALLER,
                severity = SignalSeverity.LOW,
                detected = installerPackage.isNullOrBlank(),
                explanation = "Unknown install source is a signal to review, not an automatic block.",
            ),
        )
    }

    private fun resolveInstallerPackage(): String? {
        return runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                context.packageManager.getInstallSourceInfo(context.packageName).installingPackageName
            } else {
                @Suppress("DEPRECATION")
                context.packageManager.getInstallerPackageName(context.packageName)
            }
        }.getOrNull()
    }

    private fun isPackageInstalled(packageName: String): Boolean {
        return runCatching {
            context.packageManager.getPackageInfo(packageName, 0)
        }.isSuccess
    }
}

