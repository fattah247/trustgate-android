package id.fatarc.trustgate.data.securityevent

import id.fatarc.trustgate.domain.events.SecurityEvent
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

/** A self-describing snapshot of the local audit log, for sharing outside the app. */
@Serializable
data class AuditLogExport(
    val app: String,
    val exportedAt: String,
    val eventCount: Int,
    val events: List<SecurityEvent>,
) {
    fun toJson(): String = ExportJson.encodeToString(this)

    companion object {
        private val ExportJson = Json {
            prettyPrint = true
            encodeDefaults = true
        }
    }
}
