package com.khaliilii.mkconnect

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.os.Build
import mkmobile.Mkmobile

class MkApp : Application() {
    override fun onCreate() {
        super.onCreate()
        // Accounts, settings and the core log live in the app's private storage.
        Mkmobile.init(filesDir.absolutePath)
        Mkmobile.setDataDir(filesDir.absolutePath)

        if (Build.VERSION.SDK_INT >= 26) {
            val channel = NotificationChannel(CHANNEL_ID, "VPN status", NotificationManager.IMPORTANCE_LOW)
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
    }

    companion object {
        const val CHANNEL_ID = "vpn"
    }
}
