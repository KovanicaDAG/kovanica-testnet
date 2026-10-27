plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "io.kovanica.light"
    compileSdk = 34

    defaultConfig {
        applicationId = "io.kovanica.light"
        minSdk = 24
        targetSdk = 34
        versionCode = 13
        versionName = "0.8.3"
        ndk {
            abiFilters += listOf("arm64-v8a")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    buildFeatures {
        // Settings reads BuildConfig.VERSION_NAME / VERSION_CODE for the About card.
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    sourceSets {
        getByName("main") {
            java.srcDir(projectDir.resolve("../../android-chain/src/main/kotlin"))
        }
        getByName("test") {
            java.srcDir(projectDir.resolve("../../android-chain/src/test/kotlin"))
        }
    }
}

dependencies {
    implementation("net.java.dev.jna:jna:5.14.0@aar")
    // Vendored zxing core only (encode + decode, plain Java, no androidx). See libs/.
    implementation(files("libs/core-3.5.4.jar"))
    testImplementation("junit:junit:4.13.2")
}

// JNA registers every UniFFI symbol on the first call (`faucetAllowed` in
// MainActivity.onCreate). A library built before those exports existed crashes
// the process with UnsatisfiedLinkError. Refuse to package that library.
tasks.register("checkNativeSymbols") {
    doLast {
        val so = file("src/main/jniLibs/arm64-v8a/libkovanica_light_ffi.so")
        val bindings = file("src/main/java/uniffi/kovanica_light/kovanica_light.kt")
        if (!so.isFile) {
            throw GradleException(
                "missing ${so.path}. Rebuild with: cargo ndk -t arm64-v8a " +
                    "-o app/src/main/jniLibs build -p kovanica-light-ffi --release",
            )
        }
        val process = ProcessBuilder("nm", "-D", "--defined-only", so.absolutePath)
            .redirectErrorStream(true)
            .start()
        val text = process.inputStream.bufferedReader().readText()
        val code = process.waitFor()
        if (code != 0) {
            throw GradleException("nm failed ($code): $text")
        }
        val have = HashSet<String>()
        for (raw in text.lineSequence()) {
            val line = raw.trim()
            if (line.isEmpty()) continue
            have.add(line.split(Regex("\\s+")).last())
        }
        val need = HashSet<String>()
        val symbol = Regex("uniffi_kovanica_light_ffi_[A-Za-z0-9_]+")
        for (match in symbol.findAll(bindings.readText())) {
            need.add(match.value)
        }
        val missing = need.filter { name -> name !in have }.sorted()
        if (missing.isNotEmpty()) {
            throw GradleException(
                "libkovanica_light_ffi.so is missing symbols the bindings register at launch:\n" +
                    missing.joinToString("\n") +
                    "\nRebuild with: cargo ndk -t arm64-v8a -o app/src/main/jniLibs " +
                    "build -p kovanica-light-ffi --release",
            )
        }
    }
}
tasks.named("preBuild").configure { dependsOn("checkNativeSymbols") }
