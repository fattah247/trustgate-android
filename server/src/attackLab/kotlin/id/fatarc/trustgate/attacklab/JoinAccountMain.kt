package id.fatarc.trustgate.attacklab

import java.io.File

/**
 * Plays a second phone for a demo with one emulator: ./gradlew :server:joinAccount -Pcode=CODE,
 * with the code the app shows under Add another phone. The app then shows this phone waiting for
 * approval.
 */
fun main(args: Array<String>) {
    val code = args.getOrNull(0)?.takeIf { it.isNotBlank() } ?: error("Pass the code the app shows: -Pcode=CODE")
    val baseUrl = args.getOrNull(1) ?: "https://127.0.0.1:8443"
    val certificate = File(args.getOrNull(2) ?: "build/dev-tls/server.pem")
    val result = AttackLab(HttpsTransport(baseUrl, certificate)).joinAsNewPhone(code)
    println(if (result.waitingForApproval) "Asked to join. Now approve \"Second phone (lab)\" in the app's Lab tab." else result.message)
}
