// Resolves the aapt2 builds for other platforms, so their checksums land in the verification metadata too.
rootProject {
    val aapt2Platforms = configurations.create("aapt2Platforms")
    dependencies {
        listOf("linux", "windows", "osx").forEach { platform ->
            add(aapt2Platforms.name, "com.android.tools.build:aapt2:8.5.2-11315950:$platform")
        }
    }
    tasks.register("resolveAapt2Platforms") {
        doLast { aapt2Platforms.resolve() }
    }
}
