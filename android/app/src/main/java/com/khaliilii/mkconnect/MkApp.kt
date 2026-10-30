package com.khaliilii.mkconnect

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.os.Build
import mkmobile.Mkmobile
import java.io.File
import java.util.Date

class MkApp : Application() {
    override fun onCreate() {
        super.onCreate()
        // Accounts, settings and the core log live in the app's private storage.
        recordCrashes()
        Mkmobile.init(filesDir.absolutePath)
        Mkmobile.setDataDir(filesDir.absolutePath)

        if (Build.VERSION.SDK_INT >= 26) {
            val channel = NotificationChannel(CHANNEL_ID, "VPN status", NotificationManager.IMPORTANCE_LOW)
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
    }

    /**
     * Writes the report of a crash where the core keeps its own (crash.log),
     * so the log screen shows what went wrong the next time the app opens.
     */
    private fun recordCrashes() {
        val previous = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, e ->
            runCatching {
                File(filesDir, "crash.log").appendText("${Date()} FATAL EXCEPTION in ${thread.name}\n${e.stackTraceToString()}\n")
            }
            previous?.uncaughtException(thread, e)
        }
    }

    companion object {
        const val CHANNEL_ID = "vpn"
    }
}
