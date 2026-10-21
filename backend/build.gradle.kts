import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

// What the server enforces: key registration from attestation, challenges, the gate decision, payments.
plugins {
    id("org.jetbrains.kotlin.jvm")
    id("org.jetbrains.kotlin.plugin.serialization")
    `java-test-fixtures`
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

tasks.withType<KotlinCompile>().configureEach {
    kotlinOptions.jvmTarget = "17"
}

dependencies {
    api(project(":domain"))

    testFixturesApi(testFixtures(project(":domain")))

    testImplementation("junit:junit:4.13.2")
    testImplementation("com.google.truth:truth:1.4.4")

    // Coverage-guided fuzzing of the parsers that read what clients send. In a normal test run each
    // fuzz test replays its saved inputs; JAZZER_FUZZ=1 makes it generate new ones.
    testImplementation(platform("org.junit:junit-bom:5.14.4"))
    testImplementation("org.junit.jupiter:junit-jupiter-api")
    testImplementation("com.code-intelligence:jazzer-junit:0.30.0")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine")
    testRuntimeOnly("org.junit.vintage:junit-vintage-engine")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.test {
    // JUnit 4 tests run on the vintage engine beside the fuzz tests.
    useJUnitPlatform()
}
