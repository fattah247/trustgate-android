package id.fatarc.trustgate.core.storage

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import id.fatarc.trustgate.domain.risk.DeviceRiskLevel

class EncryptedSecurityStore(
    context: Context,
) : SecureValueStore {
    private val prefs = EncryptedSharedPreferences.create(
        context,
        FILE_NAME,
        MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build(),
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )

    override fun readSnapshot(): SecurityStorageSnapshot {
        return SecurityStorageSnapshot(
            sessionToken = prefs.getString(KEY_SESSION_TOKEN, null),
            lastRiskLevel = prefs.getString(KEY_LAST_RISK_LEVEL, null)?.let(DeviceRiskLevel::valueOf),
            showSignalsOnHome = prefs.getBoolean(KEY_SHOW_SIGNALS_ON_HOME, true),
        )
    }

    override fun storeSessionToken(token: String) {
        prefs.edit().putString(KEY_SESSION_TOKEN, token).apply()
    }

    override fun storeLastRiskLevel(level: DeviceRiskLevel) {
        prefs.edit().putString(KEY_LAST_RISK_LEVEL, level.name).apply()
    }

    override fun storeShowSignalsOnHome(enabled: Boolean) {
        prefs.edit().putBoolean(KEY_SHOW_SIGNALS_ON_HOME, enabled).apply()
    }

    private companion object {
        const val FILE_NAME = "trustgate_secure_values"
        const val KEY_SESSION_TOKEN = "session_token"
        const val KEY_LAST_RISK_LEVEL = "last_risk_level"
        const val KEY_SHOW_SIGNALS_ON_HOME = "show_signals_on_home"
    }
}
