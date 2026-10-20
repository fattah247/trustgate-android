package id.fatarc.trustgate.core.keys

import android.content.Context
import id.fatarc.trustgate.domain.api.TrustGateJson

/**
 * Remembers which keys the backend registered, so the phone keeps one identity across launches
 * instead of enrolling as a new phone each time. It holds key IDs and what the backend said about
 * them, never key material; the keys themselves stay in Keystore.
 */
interface RegisteredKeyStore {
    fun load(): KeySet?

    fun save(keys: KeySet?)
}

class InMemoryRegisteredKeyStore : RegisteredKeyStore {
    private var keys: KeySet? = null

    override fun load(): KeySet? = keys

    override fun save(keys: KeySet?) {
        this.keys = keys
    }
}

class PreferencesRegisteredKeyStore(context: Context) : RegisteredKeyStore {
    private val prefs = context.applicationContext.getSharedPreferences("trustgate_registered_keys", Context.MODE_PRIVATE)

    // A record from an older format is simply forgotten; the keys are registered again.
    override fun load(): KeySet? = prefs.getString(KEYS, null)?.let { json ->
        runCatching { TrustGateJson.decodeFromString(KeySet.serializer(), json) }.getOrNull()
    }

    override fun save(keys: KeySet?) {
        prefs.edit().apply {
            if (keys == null) remove(KEYS) else putString(KEYS, TrustGateJson.encodeToString(KeySet.serializer(), keys))
        }.apply()
    }

    private companion object {
        const val KEYS = "keys"
    }
}
