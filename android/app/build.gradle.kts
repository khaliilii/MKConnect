plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

// Versions come from CI (-PversionName=2.0.0 -PversionCode=42).
val appVersionName = (project.findProperty("versionName") as String?) ?: "0.0.0"
val appVersionCode = ((project.findProperty("versionCode") as String?) ?: "1").toInt()

android {
    namespace = "com.khaliilii.mkconnect"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.khaliilii.mkconnect"
        minSdk = 21
        targetSdk = 35
        versionCode = appVersionCode
        versionName = appVersionName
    }

    // A release keystore can be supplied by CI (MKCONNECT_KEYSTORE etc.);
    // otherwise release builds are signed with the debug key so they install.
    val keystore = System.getenv("MKCONNECT_KEYSTORE")
    signingConfigs {
        if (keystore != null) {
            create("release") {
                storeFile = file(keystore)
                storePassword = System.getenv("MKCONNECT_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("MKCONNECT_KEY_ALIAS")
                keyPassword = System.getenv("MKCONNECT_KEY_PASSWORD")
            }
        }
    }
    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.findByName("release") ?: signingConfigs.getByName("debug")
        }
    }

    // One APK per ABI plus a universal one.
    splits {
        abi {
            isEnable = true
            reset()
            include("arm64-v8a", "armeabi-v7a", "x86", "x86_64")
            isUniversalApk = true
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
    }
    packaging {
        jniLibs.useLegacyPackaging = true
    }
}

dependencies {
    // The Go core, built by `gomobile bind` into app/libs/mkmobile.aar.
    implementation(fileTree(mapOf("dir" to "libs", "include" to listOf("*.aar"))))

    implementation(platform("androidx.compose:compose-bom:2024.12.01"))
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
}
