package id.fatarc.trustgate.data.securityevent

import android.content.Context
import id.fatarc.trustgate.domain.events.SecurityEvent
import id.fatarc.trustgate.domain.events.SecurityEventRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.withContext
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json

class PersistedSecurityEventRepository(
    context: Context,
) : SecurityEventRepository {
    private val prefs = context.getSharedPreferences(FILE_NAME, Context.MODE_PRIVATE)
    private val json = Json { ignoreUnknownKeys = true }
    private val serializer = ListSerializer(SecurityEvent.serializer())
    private val state = MutableStateFlow(loadEvents())

    override val events: StateFlow<List<SecurityEvent>> = state

    override suspend fun record(event: SecurityEvent) {
        withContext(Dispatchers.IO) {
            val updated = (state.value + event).takeLast(MAX_EVENTS)
            prefs.edit().putString(KEY_EVENTS, json.encodeToString(serializer, updated)).apply()
            state.value = updated
        }
    }

    private fun loadEvents(): List<SecurityEvent> {
        val stored = prefs.getString(KEY_EVENTS, null) ?: return emptyList()
        return runCatching { json.decodeFromString(serializer, stored) }.getOrElse { emptyList() }
    }

    private companion object {
        const val FILE_NAME = "trustgate_security_events"
        const val KEY_EVENTS = "events"
        const val MAX_EVENTS = 150
    }
}

