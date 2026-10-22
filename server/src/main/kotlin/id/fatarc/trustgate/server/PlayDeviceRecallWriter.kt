package id.fatarc.trustgate.server

import com.google.auth.oauth2.GoogleCredentials
import id.fatarc.trustgate.backend.integrity.DeviceRecallWriter
import id.fatarc.trustgate.domain.api.RecallBit
import java.io.File
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration
import java.util.concurrent.Executors
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonObject
import org.slf4j.LoggerFactory

/**
 * Sets device recall bits with Google's deviceRecall:write, one at a time on a background thread
 * so a payment never waits for it. Device recall is in beta and has to be turned on for the
 * developer account; until it is, Google refuses the writes and they're only logged.
 */
class PlayDeviceRecallWriter(
    private val packageName: String,
    credentialsFile: File,
) : DeviceRecallWriter {
    private val log = LoggerFactory.getLogger(PlayDeviceRecallWriter::class.java)
    private val credentials = credentialsFile.inputStream().use { GoogleCredentials.fromStream(it) }
        .createScoped(listOf("https://www.googleapis.com/auth/playintegrity"))
    private val http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build()
    private val worker = Executors.newSingleThreadExecutor { runnable -> Thread(runnable, "device-recall").apply { isDaemon = true } }

    override fun write(token: String, bits: Map<RecallBit, Boolean>) {
        worker.execute {
            runCatching {
                credentials.refreshIfExpired()
                val request = HttpRequest.newBuilder(URI("https://playintegrity.googleapis.com/v1/$packageName/deviceRecall:write"))
                    .header("Authorization", "Bearer ${credentials.accessToken.tokenValue}")
                    .header("Content-Type", "application/json")
                    .timeout(Duration.ofSeconds(15))
                    .POST(HttpRequest.BodyPublishers.ofString(body(token, bits)))
                    .build()
                val response = http.send(request, HttpResponse.BodyHandlers.ofString())
                check(response.statusCode() == 200) { "Play Integrity answered ${response.statusCode()}" }
            }.onFailure { log.warn("Couldn't write device recall bits {}: {}", bits.keys, it.message) }
        }
    }

    internal companion object {
        /** Only the bits given are sent; Google leaves the others as they were. */
        fun body(token: String, bits: Map<RecallBit, Boolean>): String = buildJsonObject {
            put("integrityToken", token)
            putJsonObject("newValues") {
                bits.forEach { (bit, value) -> put("bit" + bit.name.lowercase().replaceFirstChar { it.uppercase() }, value) }
            }
        }.toString()
    }
}
