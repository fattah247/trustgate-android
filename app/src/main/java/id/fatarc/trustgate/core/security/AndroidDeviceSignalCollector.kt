package id.fatarc.trustgate.core.security

import android.content.Context
import android.content.pm.ApplicationInfo
import android.os.Build
import android.os.Debug
import id.fatarc.trustgate.domain.risk.DeviceSignalCollector
import id.fatarc.trustgate.domain.risk.RiskSignal
import id.fatarc.trustgate.domain.risk.SignalCatalog
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
        // Keep in step with the manifest's <queries>: Android 11+ can't see packages it doesn't declare.
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
            SignalCatalog.ROOT_SU_PATH.observed(suspiciousSuPaths.any { File(it).exists() }),
            SignalCatalog.ROOT_PACKAGE.observed(rootPackages.any(::isPackageInstalled)),
            SignalCatalog.TEST_KEYS.observed(Build.TAGS?.contains("test-keys", ignoreCase = true) == true),
            SignalCatalog.SYSTEM_PARTITION_WRITABLE.observed(File("/system").canWrite()),
            SignalCatalog.EMULATOR_FINGERPRINT.observed(
                listOf("generic", "emulator", "sdk_gphone", "vbox", "goldfish", "ranchu").any(buildFingerprint::contains),
            ),
            SignalCatalog.DEBUGGER_CONNECTED.observed(Debug.isDebuggerConnected()),
            SignalCatalog.APP_DEBUGGABLE.observed((context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0),
            SignalCatalog.INSTALLER_SOURCE_UNKNOWN.observed(installerPackage.isNullOrBlank()),
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

