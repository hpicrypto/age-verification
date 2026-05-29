plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.google.devtools.ksp)
    alias(libs.plugins.jetbrains.kotlin.plugin.serialization)
}

android {
    namespace = "com.example.wallet"
    compileSdk = 37

    defaultConfig {
        applicationId = "com.example.wallet"
        minSdk = 31
        targetSdk = 37
        versionCode = 1
        versionName = "1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    buildFeatures {
        compose = true
    }
    
    // Specify the NDK version to use, AGP will resolve the path automatically.
    // Based on your system, version 30.0.14904198 is installed.
    ndkVersion = "30.0.14904198"
}

val ageverDir = file("../../crypto/agever")

val rustWorkspaceDir = file("../..")

val cargoExecutable = File(System.getProperty("user.home"), ".cargo/bin/cargo").let {
    if (it.exists()) it.absolutePath else "cargo"
}

// --- NDK Toolchain Discovery via AGP ---
val androidComponents = project.extensions.getByType<com.android.build.api.variant.ApplicationAndroidComponentsExtension>()
val ndkDirProvider = androidComponents.sdkComponents.ndkDirectory

val hostTag = when {
    System.getProperty("os.name").contains("Mac", ignoreCase = true) -> "darwin-x86_64"
    System.getProperty("os.name").contains("Windows", ignoreCase = true) -> "windows-x86_64"
    else -> "linux-x86_64"
}

fun Exec.setupRustEnv(rustTarget: String) {
    val targetUnderscored = rustTarget.replace("-", "_").uppercase()
    // For armv7, the clang wrapper has a slightly different name prefix than the rust target triple
    val clangSuffix = if (rustTarget.contains("armv7")) "armv7a-linux-androideabi" else rustTarget
    
    doFirst {
        val ndkDir = ndkDirProvider.get().asFile
        val minSdk = android.defaultConfig.minSdk
        val toolchainBin = ndkDir.resolve("toolchains/llvm/prebuilt/$hostTag/bin")
        val clang = toolchainBin.resolve("$clangSuffix$minSdk-clang")
        val ar = toolchainBin.resolve("llvm-ar")

        environment("CARGO_TARGET_${targetUnderscored}_LINKER", clang.absolutePath)
        environment("CC_$rustTarget", clang.absolutePath)
        environment("AR_$rustTarget", ar.absolutePath)
        
        // Also set generic CC and AR just in case
        environment("CC", clang.absolutePath)
        environment("AR", ar.absolutePath)

        // Ensure cargo is in PATH, especially on macOS where Android Studio might not inherit it
        val currentPath = environment["PATH"]?.toString() ?: System.getenv("PATH")
        val cargoBin = "${System.getProperty("user.home")}/.cargo/bin"
        environment("PATH", "$cargoBin${File.pathSeparator}$currentPath")
        
        println("Using NDK toolchain: $clang")
    }
}

val buildRustAarch64 = tasks.register<Exec>("buildRustAarch64") {
    group = "build"
    workingDir(ageverDir)
    setupRustEnv("aarch64-linux-android")
    commandLine(cargoExecutable, "build", "--release", "--lib", "--target", "aarch64-linux-android")
    inputs.dir(ageverDir.resolve("src"))
    inputs.file(ageverDir.resolve("Cargo.toml"))
    outputs.file(ageverDir.resolve("target/aarch64-linux-android/release/libagever.so"))
}

val buildRustX86_64 = tasks.register<Exec>("buildRustX86_64") {
    group = "build"
    workingDir(ageverDir)
    setupRustEnv("x86_64-linux-android")
    commandLine(cargoExecutable, "build", "--release", "--lib", "--target", "x86_64-linux-android")
    inputs.dir(ageverDir.resolve("src"))
    inputs.file(ageverDir.resolve("Cargo.toml"))
    outputs.file(ageverDir.resolve("target/x86_64-linux-android/release/libagever.so"))
}

val copyAarch64So = tasks.register<Copy>("copyAarch64So") {
    dependsOn(buildRustAarch64)
    from(rustWorkspaceDir.resolve("target/aarch64-linux-android/release/libagever.so"))
    into(file("src/main/jniLibs/arm64-v8a"))
    rename("libagever.so", "libuniffi_agever.so")
}

val copyX86_64So = tasks.register<Copy>("copyX86_64So") {
    dependsOn(buildRustX86_64)
    from(rustWorkspaceDir.resolve("target/x86_64-linux-android/release/libagever.so"))
    into(file("src/main/jniLibs/x86_64"))
    rename("libagever.so", "libuniffi_agever.so")
}

val generateUniFFIBindings = tasks.register<Exec>("generateUniFFIBindings") {
    dependsOn(copyAarch64So)
    workingDir(ageverDir)
    val sampleSo = file("src/main/jniLibs/arm64-v8a/libuniffi_agever.so")
    val javaDir = file("src/main/java")

    doFirst {
        val currentPath = environment["PATH"]?.toString() ?: System.getenv("PATH")
        val cargoBin = "${System.getProperty("user.home")}/.cargo/bin"
        environment("PATH", "$cargoBin${File.pathSeparator}$currentPath")
    }

    commandLine(
        cargoExecutable, "run", "--features=uniffi/cli", "--bin", "uniffi-bindgen",
        "generate", "--language", "kotlin",
        "--out-dir", javaDir.absolutePath,
        sampleSo.absolutePath
    )
    outputs.dir(javaDir.resolve("uniffi"))
}

val buildRust = tasks.register("buildRust") {
    group = "build"
    description = "Builds the Rust library and generates UniFFI bindings"
    dependsOn(copyAarch64So, copyX86_64So, generateUniFFIBindings)
}

tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>().configureEach {
    dependsOn(buildRust)
}

tasks.matching { it.name.startsWith("ksp") }.configureEach {
    dependsOn(buildRust)
}

tasks.named("preBuild") {
    dependsOn(buildRust)
}

dependencies {
    implementation("net.java.dev.jna:jna:5.18.1@aar")
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.accompanist.permissions)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.camera.camera2)
    implementation(libs.androidx.camera.core)
    implementation(libs.androidx.camera.lifecycle)
    implementation(libs.androidx.camera.view)
    implementation(libs.barcode.scanning)
    implementation(libs.androidx.camera.mlkit.vision)
    implementation(libs.androidx.compose.adaptive)
    implementation(libs.androidx.compose.adaptive.layout)
    implementation(libs.androidx.compose.adaptive.navigation3)
    implementation(libs.androidx.compose.material.icons.core)
    implementation(libs.androidx.compose.material.icons.extended)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.core.splashscreen)
    implementation(libs.androidx.datastore.preferences)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.lifecycle.viewmodel.navigation3)
    implementation(libs.androidx.navigation3.runtime)
    implementation(libs.androidx.navigation3.ui)
    implementation(libs.androidx.room.ktx)
    implementation(libs.androidx.room.runtime)
    implementation(libs.coil.compose)
    implementation(libs.converter.moshi)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.kotlinx.coroutines.core)
    implementation(libs.kotlinx.serialization.core)
    implementation(libs.logging.interceptor)
    implementation(libs.material)
    implementation(libs.moshi.kotlin)
    implementation(libs.okhttp)
    implementation(libs.play.services.location)
    implementation(libs.retrofit)
    testImplementation(libs.androidx.core)
    testImplementation(libs.androidx.junit)
    testImplementation(libs.junit)
    testImplementation(libs.kotlinx.coroutines.test)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.compose.ui.test.junit4)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.runner)
    debugImplementation(libs.androidx.compose.ui.test.manifest)
    debugImplementation(libs.androidx.compose.ui.tooling)
    "ksp"(libs.androidx.room.compiler)
    "ksp"(libs.moshi.kotlin.codegen)
}

