import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import java.util.Base64
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

// The TrustGate backend served over HTTPS, with its state in SQLite.
plugins {
    id("org.jetbrains.kotlin.jvm")
    id("org.jetbrains.kotlin.plugin.serialization")
    application
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

tasks.withType<KotlinCompile>().configureEach {
    kotlinOptions.jvmTarget = "17"
}

application {
    mainClass.set("id.fatarc.trustgate.server.ServerKt")
}

val ktorVersion = "2.3.12"

dependencies {
    implementation(project(":backend"))
    implementation("io.ktor:ktor-server-core-jvm:$ktorVersion")
    implementation("io.ktor:ktor-server-netty-jvm:$ktorVersion")
    implementation("io.ktor:ktor-server-content-negotiation-jvm:$ktorVersion")
    implementation("io.ktor:ktor-serialization-kotlinx-json-jvm:$ktorVersion")
    implementation("io.ktor:ktor-server-status-pages-jvm:$ktorVersion")
    implementation("io.ktor:ktor-server-call-logging-jvm:$ktorVersion")
    implementation("org.xerial:sqlite-jdbc:3.46.1.0")
    implementation("ch.qos.logback:logback-classic:1.5.6")

    testImplementation(testFixtures(project(":backend")))
    testImplementation("io.ktor:ktor-server-test-host-jvm:$ktorVersion")
    testImplementation("junit:junit:4.13.2")
    testImplementation("com.google.truth:truth:1.4.4")
}

/*
 * A self-signed key and certificate for the server on this machine. The app's debug build trusts
 * only this certificate for the development host and pins its key; nothing here is committed.
 */
val devTlsDir = layout.buildDirectory.dir("dev-tls")
val generateDevCertificate by tasks.registering {
    description = "Creates the local server's TLS key, certificate, and key pin."
    outputs.dir(devTlsDir)
    doLast {
        val dir = devTlsDir.get().asFile
        if (File(dir, "server.p12").exists()) return@doLast
        dir.mkdirs()
        val password = Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(24).also(SecureRandom()::nextBytes))
        File(dir, "password").writeText(password)
        val keytool = File(System.getProperty("java.home"), "bin/keytool").path
        fun run(vararg command: String) {
            val process = ProcessBuilder(*command).directory(dir).redirectErrorStream(true).start()
            val output = process.inputStream.bufferedReader().readText()
            check(process.waitFor() == 0) { "keytool failed: $output" }
        }
        run(
            keytool, "-genkeypair", "-alias", "trustgate", "-keyalg", "EC", "-groupname", "secp256r1",
            "-sigalg", "SHA256withECDSA", "-dname", "CN=TrustGate development server",
            "-ext", "SAN=ip:10.0.2.2,ip:127.0.0.1,dns:localhost", "-validity", "825",
            "-keystore", "server.p12", "-storetype", "PKCS12", "-storepass", password, "-keypass", password,
        )
        run(keytool, "-exportcert", "-rfc", "-alias", "trustgate", "-keystore", "server.p12", "-storepass", password, "-file", "server.pem")
        val certificate = File(dir, "server.pem").inputStream().use { CertificateFactory.getInstance("X.509").generateCertificate(it) }
        val pin = Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(certificate.publicKey.encoded))
        File(dir, "pin").writeText(pin)
    }
}

/** SHA-256 of the local debug signing certificate, which a debug build's key attestation names. */
fun debugSignerDigest(): String? {
    val keystore = File(System.getProperty("user.home"), ".android/debug.keystore").takeIf { it.exists() } ?: return null
    val certificate = KeyStore.getInstance(keystore, "android".toCharArray()).getCertificate("androiddebugkey") ?: return null
    return MessageDigest.getInstance("SHA-256").digest(certificate.encoded).joinToString("") { "%02x".format(it) }
}

tasks.named<JavaExec>("run") {
    dependsOn(generateDevCertificate)
    val dir = devTlsDir.get().asFile
    environment("TRUSTGATE_TLS_KEYSTORE", File(dir, "server.p12").path)
    environment("TRUSTGATE_TLS_PASSWORD_FILE", File(dir, "password").path)
    environment("TRUSTGATE_DATABASE", layout.buildDirectory.file("trustgate.db").get().asFile.path)
    environment("TRUSTGATE_POLICY", providers.gradleProperty("trustgate.policy").getOrElse("development"))
    environment("TRUSTGATE_PACKAGE", "id.fatarc.trustgate")
    debugSignerDigest()?.let { environment("TRUSTGATE_SIGNING_DIGESTS", it) }
}
