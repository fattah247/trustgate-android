package id.fatarc.trustgate.core.storage

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import id.fatarc.trustgate.domain.risk.DeviceRiskLevel
import java.security.KeyStore
import javax.crypto.AEADBadTagException
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

/**
 * Stores reference values encrypted under an AES-256 key held in Android Keystore. It replaces
 * Jetpack Security's EncryptedSharedPreferences, which Google deprecated, and moves any values
 * that library wrote the first time it runs.
 */
class KeystoreSecureValueStore(
    context: Context,
) : SecureValueStore {
    private val appContext = context.applicationContext
    private val sealed = SealedValues(::storageKey)

    // Opened on first use so Keystore failures reach the caller instead of crashing app start.
    private val prefs: SharedPreferences by lazy {
        appContext.getSharedPreferences(FILE_NAME, Context.MODE_PRIVATE).also(::migrateLegacyValues)
    }

    @Synchronized
    override fun readSnapshot(): SecurityStorageSnapshot {
        var cleared = 0
        fun read(name: String): String? {
            val stored = prefs.getString(name, null) ?: return null
            fun discard(): String? {
                prefs.edit().remove(name).apply()
                cleared++
                return null
            }
            return try {
                sealed.open(name, stored)
            } catch (_: AEADBadTagException) {
                // Encrypted under a key this device doesn't have, typically after a restore or transfer.
                // Other Keystore errors may be temporary, so they reach the caller and the value is kept.
                discard()
            } catch (_: IllegalArgumentException) {
                discard()
            }
        }
        return SecurityStorageSnapshot(
            sessionToken = read(SecureValueNames.SESSION_TOKEN),
            lastRiskLevel = read(SecureValueNames.LAST_RISK_LEVEL)?.let { name -> DeviceRiskLevel.entries.firstOrNull { it.name == name } },
            showSignalsOnHome = read(SecureValueNames.SHOW_SIGNALS_ON_HOME)?.toBooleanStrictOrNull() ?: true,
            unreadableValuesCleared = cleared,
        )
    }

    @Synchronized
    override fun storeSessionToken(token: String) = put(SecureValueNames.SESSION_TOKEN, token)

    @Synchronized
    override fun storeLastRiskLevel(level: DeviceRiskLevel) = put(SecureValueNames.LAST_RISK_LEVEL, level.name)

    @Synchronized
    override fun storeShowSignalsOnHome(enabled: Boolean) = put(SecureValueNames.SHOW_SIGNALS_ON_HOME, enabled.toString())

    private fun put(name: String, value: String) {
        // commit, not apply: the caller reads back right away and must see the write or its failure.
        check(prefs.edit().putString(name, sealed.seal(name, value)).commit()) { "The value couldn't be saved." }
    }

    private fun storageKey(): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        (keyStore.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE).run {
            init(
                KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .build(),
            )
            generateKey()
        }
    }

    /** Copies values from the deprecated EncryptedSharedPreferences file, then deletes that file. */
    @Suppress("DEPRECATION")
    private fun migrateLegacyValues(target: SharedPreferences) {
        val legacyRaw = appContext.getSharedPreferences(LEGACY_FILE_NAME, Context.MODE_PRIVATE)
        if (legacyRaw.all.isEmpty()) return
        val values = runCatching {
            val legacy = EncryptedSharedPreferences.create(
                appContext,
                LEGACY_FILE_NAME,
                MasterKey.Builder(appContext).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build(),
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
            )
            buildMap {
                legacy.getString(SecureValueNames.SESSION_TOKEN, null)?.let { put(SecureValueNames.SESSION_TOKEN, it) }
                legacy.getString(SecureValueNames.LAST_RISK_LEVEL, null)?.let { put(SecureValueNames.LAST_RISK_LEVEL, it) }
                if (legacy.contains(SecureValueNames.SHOW_SIGNALS_ON_HOME)) {
                    put(SecureValueNames.SHOW_SIGNALS_ON_HOME, legacy.getBoolean(SecureValueNames.SHOW_SIGNALS_ON_HOME, true).toString())
                }
            }
        }.getOrElse {
            // A file the old library can't read now never will be.
            appContext.deleteSharedPreferences(LEGACY_FILE_NAME)
            return
        }
        val editor = target.edit()
        values.forEach { (name, value) -> editor.putString(name, sealed.seal(name, value)) }
        // Keep the old file when the new values weren't written, so the next run tries again.
        if (editor.commit()) appContext.deleteSharedPreferences(LEGACY_FILE_NAME)
    }

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val KEY_ALIAS = "trustgate_storage_key"
        const val FILE_NAME = "trustgate_secure_values_v2"
        const val LEGACY_FILE_NAME = "trustgate_secure_values"
    }
}
