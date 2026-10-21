package id.fatarc.trustgate.attacklab

import java.io.File
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.time.Duration
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import kotlin.system.exitProcess

/**
 * Runs the attack lab against a running server: ./gradlew :server:attackLab, with the server
 * started by ./gradlew :server:run. Exits non-zero when any attack gets through.
 */
fun main(args: Array<String>) {
    val baseUrl = args.getOrNull(0) ?: "https://127.0.0.1:8443"
    val certificate = File(args.getOrNull(1) ?: "build/dev-tls/server.pem")
    val transport = HttpsTransport(baseUrl, certificate)

    println("Attacking $baseUrl\n")
    val results = AttackLab(transport).run()
    val width = results.maxOf { it.attack.length }
    results.forEach { result ->
        val mark = when {
            result.skipped -> "SKIPPED     "
            result.stopped -> "STOPPED     "
            else -> "GOT THROUGH "
        }
        println("$mark ${result.attack.padEnd(width)}  ${result.serverSaid}")
    }
    val tried = results.filterNot { it.skipped }
    val through = tried.count { !it.stopped }
    println("\n${tried.size - through} of ${tried.size} attacks stopped.")
    if (through > 0) exitProcess(1)
}

/** HTTPS that trusts only the given certificate, the way the app's debug build trusts the development server. */
internal class HttpsTransport(private val baseUrl: String, certificate: File) : Transport {
    private val client: HttpClient = HttpClient.newBuilder()
        .sslContext(sslTrusting(certificate))
        .connectTimeout(Duration.ofSeconds(5))
        .build()

    override fun post(path: String, body: String, headers: Map<String, String>): Reply {
        val request = HttpRequest.newBuilder(URI(baseUrl.trimEnd('/') + path))
            .header("Content-Type", "application/json")
            .apply { headers.forEach { (name, value) -> header(name, value) } }
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .build()
        return send(request)
    }

    override fun get(path: String): Reply = send(HttpRequest.newBuilder(URI(baseUrl.trimEnd('/') + path)).GET().build())

    private fun send(request: HttpRequest): Reply =
        client.send(request, HttpResponse.BodyHandlers.ofString()).let { Reply(it.statusCode(), it.body()) }

    private fun sslTrusting(certificate: File): SSLContext {
        val trusted = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null)
            setCertificateEntry("trustgate", certificate.inputStream().use { CertificateFactory.getInstance("X.509").generateCertificate(it) })
        }
        val trustManagers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(trusted) }.trustManagers
        return SSLContext.getInstance("TLS").apply { init(null, trustManagers, null) }
    }
}
