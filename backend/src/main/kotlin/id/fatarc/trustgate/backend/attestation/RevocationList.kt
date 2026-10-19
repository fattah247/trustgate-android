package id.fatarc.trustgate.backend.attestation

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/**
 * Google's attestation certificate status list, published at [URL]. It names certificates whose
 * key leaked or misbehaved; a revoked or suspended one anywhere in a chain makes the chain worthless.
 */
class RevocationList(private val entries: Map<String, Entry>) {
    @Serializable
    data class Entry(
        val status: String,
        val reason: String? = null,
        val expires: String? = null,
        val comment: String? = null,
    )

    val size: Int get() = entries.size

    /** [serial] is a certificate serial number in lowercase hex, the way the list keys them. */
    fun statusOf(serial: String): Entry? = entries[serial]

    @Serializable
    private class Document(val entries: Map<String, Entry>)

    companion object {
        const val URL = "https://android.googleapis.com/attestation/status"

        val EMPTY = RevocationList(emptyMap())

        private val json = Json { ignoreUnknownKeys = true }

        fun parse(document: String): RevocationList = RevocationList(json.decodeFromString(Document.serializer(), document).entries)
    }
}
