import org.gradle.api.DefaultTask
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.Optional
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.serialization")
}

android {
    namespace = "id.fatarc.trustgate"
    compileSdk = 35

    defaultConfig {
        applicationId = "id.fatarc.trustgate"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "1.0.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        // Google Cloud project linked to Play Integrity; without one, debug builds send a mock token.
        buildConfigField("long", "PLAY_INTEGRITY_PROJECT_NUMBER", "${providers.gradleProperty("trustgate.cloudProjectNumber").getOrElse("0")}L")
    }

    buildTypes {
        debug {
            // The server from ./gradlew :server:run, as the emulator sees the host.
            buildConfigField("String", "SERVER_URL", "\"https://10.0.2.2:8443\"")
            buildConfigField("boolean", "SERVER_PINNED", "true")
        }
        release {
            buildConfigField("String", "SERVER_URL", "\"${providers.gradleProperty("trustgate.serverUrl").getOrElse("")}\"")
            buildConfigField("boolean", "SERVER_PINNED", "${providers.gradleProperty("trustgate.serverPins").isPresent}")
            // Shrinks and obfuscates release builds; it raises the cost of reverse engineering, it doesn't prevent it.
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    composeOptions {
        kotlinCompilerExtensionVersion = "1.5.14"
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.19.1")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation(platform("androidx.compose:compose-bom:2026.09.00"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-core")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.navigation:navigation-compose:2.10.2")
    implementation("androidx.security:security-crypto:1.1.0")
    // Step-up confirmation with the device's biometrics or screen lock for medium-risk actions.
    implementation("androidx.biometric:biometric:1.1.0")
    implementation("androidx.fragment:fragment-ktx:1.9.1")
    implementation("com.google.android.play:integrity:1.4.0")
    implementation(project(":domain"))
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.6.3")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")

    testImplementation(project(":backend"))
    testImplementation(testFixtures(project(":domain")))
    testImplementation(testFixtures(project(":backend")))
    testImplementation("junit:junit:4.13.2")
    testImplementation("com.google.truth:truth:1.4.4")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.9.0")

    // Layout Inspector support in debug builds.
    debugImplementation("androidx.compose.ui:ui-tooling")
}

/**
 * Writes the network security config for a build. Debug builds trust the local development server
 * only through its own certificate and pin its key; release builds use the system's authorities,
 * pinned to the keys in trustgate.serverPins when trustgate.serverHost names the server.
 */
abstract class NetworkSecurityConfigTask : DefaultTask() {
    @get:InputFile
    @get:Optional
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val developmentCertificate: RegularFileProperty

    @get:InputFile
    @get:Optional
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val developmentPin: RegularFileProperty

    @get:Input
    abstract val releaseHost: Property<String>

    @get:Input
    abstract val releasePins: Property<String>

    @get:OutputDirectory
    abstract val outputDir: DirectoryProperty

    @TaskAction
    fun generate() {
        val res = outputDir.get().asFile.apply { deleteRecursively() }
        val domainConfig = when {
            developmentCertificate.isPresent -> {
                developmentCertificate.get().asFile.copyTo(File(res, "raw/trustgate_dev_server.pem"), overwrite = true)
                domainConfig(
                    host = "10.0.2.2",
                    trustAnchors = "@raw/trustgate_dev_server",
                    pins = listOf(developmentPin.get().asFile.readText().trim()),
                )
            }
            releaseHost.get().isNotBlank() && releasePins.get().isNotBlank() ->
                domainConfig(host = releaseHost.get(), trustAnchors = "system", pins = releasePins.get().split(',').map(String::trim))
            else -> ""
        }
        File(res, "xml").mkdirs()
        File(res, "xml/network_security_config.xml").writeText(
            """
            |<?xml version="1.0" encoding="utf-8"?>
            |<!-- Generated by the build; see NetworkSecurityConfigTask in app/build.gradle.kts. -->
            |<network-security-config>
            |    <base-config cleartextTrafficPermitted="false">
            |        <trust-anchors>
            |            <certificates src="system" />
            |        </trust-anchors>
            |    </base-config>
            |$domainConfig
            |</network-security-config>
            |
            """.trimMargin(),
        )
    }

    private fun domainConfig(host: String, trustAnchors: String, pins: List<String>): String = buildString {
        appendLine("    <domain-config cleartextTrafficPermitted=\"false\">")
        appendLine("        <domain includeSubdomains=\"false\">$host</domain>")
        appendLine("        <trust-anchors>")
        appendLine("            <certificates src=\"$trustAnchors\" />")
        appendLine("        </trust-anchors>")
        appendLine("        <pin-set>")
        pins.forEach { appendLine("            <pin digest=\"SHA-256\">$it</pin>") }
        appendLine("        </pin-set>")
        append("    </domain-config>")
    }
}

androidComponents {
    onVariants { variant ->
        val generate = tasks.register<NetworkSecurityConfigTask>("generate${variant.name.replaceFirstChar(Char::uppercase)}NetworkSecurityConfig") {
            if (variant.buildType == "debug") {
                dependsOn(":server:generateDevCertificate")
                val devTls = rootProject.layout.projectDirectory.dir("server/build/dev-tls")
                developmentCertificate.set(devTls.file("server.pem"))
                developmentPin.set(devTls.file("pin"))
            }
            releaseHost.set(providers.gradleProperty("trustgate.serverHost").orElse(""))
            releasePins.set(providers.gradleProperty("trustgate.serverPins").orElse(""))
        }
        variant.sources.res?.addGeneratedSourceDirectory(generate, NetworkSecurityConfigTask::outputDir)
    }
}
