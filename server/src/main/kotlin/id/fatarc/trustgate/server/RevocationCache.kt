package id.fatarc.trustgate.server

import id.fatarc.trustgate.backend.attestation.RevocationList
import java.io.File
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Clock
import java.time.Duration
import java.time.Instant
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.slf4j.LoggerFactory

/**
 * Keeps a recent copy of Google's attestation status list, on disk so a restart works offline.
 * A copy older than [maxAge] counts as none, and the strict policy then refuses attested keys
 * rather than accept a chain it can't check.
 */
class RevocationCache(
    private val url: String?,
    private val cacheFile: File,
    private val clock: Clock = Clock.systemUTC(),
    private val maxAge: Duration = Duration.ofHours(24),
) {
    private class Snapshot(val list: RevocationList, val fetchedAt: Instant)

    private val log = LoggerFactory.getLogger(RevocationCache::class.java)
    private val http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build()

    @Volatile
    private var snapshot: Snapshot? = loadCached()

    /** The list to check chains against; empty when fetching is off, null when the copy is too old. */
    fun current(): RevocationList? {
        if (url == null) return RevocationList.EMPTY
        return snapshot?.takeIf { Duration.between(it.fetchedAt, clock.instant()) <= maxAge }?.list
    }

    fun refresh() {
        val source = url ?: return
        runCatching {
            val request = HttpRequest.newBuilder(URI(source)).timeout(Duration.ofSeconds(20)).GET().build()
            val response = http.send(request, HttpResponse.BodyHandlers.ofString())
            check(response.statusCode() == 200) { "status list answered ${response.statusCode()}" }
            val list = RevocationList.parse(response.body())
            cacheFile.parentFile?.mkdirs()
            cacheFile.writeText(response.body())
            snapshot = Snapshot(list, clock.instant())
            list.size
        }.onSuccess { log.info("Loaded Google's attestation status list: {} entries.", it) }
            .onFailure { log.warn("Couldn't refresh Google's attestation status list: {}", it.message) }
    }

    fun startRefreshing(scope: CoroutineScope, every: Duration = Duration.ofHours(6)) {
        if (url == null) return
        scope.launch(Dispatchers.IO) {
            while (isActive) {
                refresh()
                delay(every.toMillis())
            }
        }
    }

    private fun loadCached(): Snapshot? = runCatching {
        Snapshot(RevocationList.parse(cacheFile.readText()), Instant.ofEpochMilli(cacheFile.lastModified()))
    }.getOrNull()
}
