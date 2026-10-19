package id.fatarc.trustgate.server

import com.google.auth.oauth2.GoogleCredentials
import id.fatarc.trustgate.backend.integrity.IntegrityVerdict
import id.fatarc.trustgate.backend.integrity.IntegrityVerifier
import java.io.File
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration
import java.util.Base64
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.slf4j.LoggerFactory

/**
 * Decodes Play Integrity tokens with Google's API, authenticated as the service account in
 * [credentialsFile]. The token is opaque to the server until Google decrypts and checks it.
 */
class PlayIntegrityVerifier(
    private val packageName: String,
    credentialsFile: File,
) : IntegrityVerifier {
    private val log = LoggerFactory.getLogger(PlayIntegrityVerifier::class.java)
    private val credentials = credentialsFile.inputStream().use { GoogleCredentials.fromStream(it) }
        .createScoped(listOf("https://www.googleapis.com/auth/playintegrity"))
    private val http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build()

    override fun verify(token: String): IntegrityVerdict? = runCatching {
        credentials.refreshIfExpired()
        val request = HttpRequest.newBuilder(URI("https://playintegrity.googleapis.com/v1/$packageName:decodeIntegrityToken"))
            .header("Authorization", "Bearer ${credentials.accessToken.tokenValue}")
            .header("Content-Type", "application/json")
            .timeout(Duration.ofSeconds(15))
            .POST(HttpRequest.BodyPublishers.ofString(json.encodeToString(DecodeRequest.serializer(), DecodeRequest(token))))
            .build()
        val response = http.send(request, HttpResponse.BodyHandlers.ofString())
        check(response.statusCode() == 200) { "Play Integrity answered ${response.statusCode()}" }
        verdictFrom(response.body())
    }.onFailure { log.warn("Couldn't decode a Play Integrity token: {}", it.message) }.getOrNull()

    @Serializable
    private class DecodeRequest(val integrityToken: String)

    @Serializable
    internal class DecodeResponse(val tokenPayloadExternal: Payload)

    @Serializable
    internal class Payload(
        val requestDetails: RequestDetails,
        val appIntegrity: AppIntegrity = AppIntegrity(),
        val deviceIntegrity: DeviceIntegrity = DeviceIntegrity(),
    )

    @Serializable
    internal class RequestDetails(val requestPackageName: String, val requestHash: String = "", val timestampMillis: String)

    @Serializable
    internal class AppIntegrity(val appRecognitionVerdict: String? = null, val certificateSha256Digest: List<String> = emptyList())

    @Serializable
    internal class DeviceIntegrity(val deviceRecognitionVerdict: List<String> = emptyList())

    internal companion object {
        private val json = Json { ignoreUnknownKeys = true }

        /** Play reports certificate digests in URL-safe Base64; the backend compares them as hex. */
        fun verdictFrom(body: String): IntegrityVerdict {
            val payload = json.decodeFromString(DecodeResponse.serializer(), body).tokenPayloadExternal
            return IntegrityVerdict(
                requestPackageName = payload.requestDetails.requestPackageName,
                requestHash = payload.requestDetails.requestHash,
                timestampMillis = payload.requestDetails.timestampMillis.toLong(),
                appRecognition = payload.appIntegrity.appRecognitionVerdict,
                certificateDigests = payload.appIntegrity.certificateSha256Digest.mapTo(mutableSetOf()) { digest ->
                    Base64.getUrlDecoder().decode(digest.replace('+', '-').replace('/', '_').trimEnd('='))
                        .joinToString("") { "%02x".format(it) }
                },
                deviceRecognition = payload.deviceIntegrity.deviceRecognitionVerdict.toSet(),
            )
        }
    }
}
