package com.khaliilii.mkconnect

import android.app.Notification
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import mkmobile.Mkmobile
import mkmobile.Platform
import mkmobile.TunConfig
import org.json.JSONArray
import org.json.JSONObject
import java.net.NetworkInterface
import kotlin.concurrent.thread

/**
 * Runs the Go core as the system VPN (or, in proxy mode, just keeps it running
 * in the background). Implements [Platform] for the core: it builds the TUN,
 * protects the core's own sockets (VpnService.protect has the same signature)
 * and reports the network interfaces Android won't let the core read itself.
 */
class MkVpnService : VpnService(), Platform {

    private var tun: ParcelFileDescriptor? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stop()
                return START_NOT_STICKY
            }
            else -> start(intent?.getBooleanExtra(EXTRA_VPN, true) ?: true)
        }
        return START_STICKY
    }

    private fun start(vpn: Boolean) {
        val notification = notification("Connecting…")
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
        watchDefaultNetwork()
        thread(name = "mkconnect-start") {
            try {
                Mkmobile.start(if (vpn) this else null)
                val status = JSONObject(Mkmobile.status())
                updateNotification("Connected to ${status.optString("profile")}")
            } catch (e: Exception) {
                Log.e(TAG, "start failed", e)
                lastError = e.message
                stop()
            }
        }
    }

    private fun stop() {
        thread(name = "mkconnect-stop") {
            try {
                Mkmobile.stop()
            } catch (e: Exception) {
                Log.e(TAG, "stop failed", e)
            }
            tun?.close()
            tun = null
            networkCallback?.let { getSystemService(ConnectivityManager::class.java).unregisterNetworkCallback(it) }
            networkCallback = null
            if (Build.VERSION.SDK_INT >= 24) stopForeground(STOP_FOREGROUND_REMOVE) else @Suppress("DEPRECATION") stopForeground(true)
            stopSelf()
        }
    }

    override fun onRevoke() {
        // Another VPN took over or the user revoked the permission.
        stop()
    }

    override fun onDestroy() {
        try {
            Mkmobile.stop()
        } catch (_: Exception) {
        }
        tun?.close()
        super.onDestroy()
    }

    // --- Platform (called by the Go core) ---

    override fun openTun(cfg: TunConfig): Int {
        val builder = Builder().setSession("MKConnect").setMtu(cfg.mtu())
        cfg.addresses().split(",").filter { it.isNotBlank() }.forEach {
            val (ip, prefix) = it.split("/")
            builder.addAddress(ip, prefix.toInt())
        }
        cfg.routes().split(",").filter { it.isNotBlank() }.forEach {
            val (ip, prefix) = it.split("/")
            builder.addRoute(ip, prefix.toInt())
        }
        if (cfg.dnsServer().isNotBlank()) builder.addDnsServer(cfg.dnsServer())
        // The core's own connections must not loop back into the VPN.
        builder.addDisallowedApplication(packageName)
        if (Build.VERSION.SDK_INT >= 29) builder.setMetered(false)
        val pfd = builder.establish() ?: throw IllegalStateException("VPN permission was revoked")
        tun?.close()
        tun = pfd
        return pfd.fd
    }

    override fun interfaces(): String {
        val cm = getSystemService(ConnectivityManager::class.java)
        val byName = HashMap<String, Pair<NetworkCapabilities?, LinkProperties?>>()
        for (network in cm.allNetworks) {
            val lp = cm.getLinkProperties(network) ?: continue
            val name = lp.interfaceName ?: continue
            byName[name] = cm.getNetworkCapabilities(network) to lp
        }
        val out = JSONArray()
        for (ni in NetworkInterface.getNetworkInterfaces() ?: return "[]") {
            val (caps, lp) = byName[ni.name] ?: (null to null)
            var flags = 0
            if (ni.isUp) flags = flags or 1 or 32
            if (ni.isLoopback) flags = flags or 4
            if (ni.isPointToPoint) flags = flags or 8
            if (ni.supportsMulticast()) flags = flags or 16
            val type = when {
                caps == null -> 3
                caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> 0
                caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> 1
                caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> 2
                else -> 3
            }
            val addresses = JSONArray()
            ni.interfaceAddresses.forEach {
                val host = it.address.hostAddress?.substringBefore('%') ?: return@forEach
                addresses.put("$host/${it.networkPrefixLength}")
            }
            val dns = JSONArray()
            lp?.dnsServers?.forEach { dns.put(it.hostAddress) }
            out.put(JSONObject().apply {
                put("name", ni.name)
                put("index", ni.index)
                put("mtu", runCatching { ni.mtu }.getOrDefault(1500))
                put("addresses", addresses)
                put("flags", flags)
                put("type", type)
                put("dns", dns)
                put("metered", caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED) == false)
            })
        }
        return out.toString()
    }

    /** Keeps the core informed about Android's default (non-VPN) network. */
    private fun watchDefaultNetwork() {
        if (networkCallback != null || Build.VERSION.SDK_INT < 24) return
        val cm = getSystemService(ConnectivityManager::class.java)
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onLinkPropertiesChanged(network: Network, lp: LinkProperties) = report(lp)
            override fun onAvailable(network: Network) {
                cm.getLinkProperties(network)?.let { report(it) }
            }
            override fun onLost(network: Network) = Mkmobile.updateDefaultInterface("", -1)

            private fun report(lp: LinkProperties) {
                val name = lp.interfaceName ?: return
                val index = runCatching { NetworkInterface.getByName(name)?.index ?: -1 }.getOrDefault(-1)
                Mkmobile.updateDefaultInterface(name, index)
            }
        }
        cm.registerDefaultNetworkCallback(callback)
        networkCallback = callback
    }

    private fun notification(text: String): Notification {
        val open = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val stop = PendingIntent.getService(
            this, 1, Intent(this, MkVpnService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val builder = if (Build.VERSION.SDK_INT >= 26) Notification.Builder(this, MkApp.CHANNEL_ID)
        else @Suppress("DEPRECATION") Notification.Builder(this)
        return builder
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle("MKConnect")
            .setContentText(text)
            .setContentIntent(open)
            .setOngoing(true)
            .addAction(Notification.Action.Builder(null, "Disconnect", stop).build())
            .build()
    }

    private fun updateNotification(text: String) {
        getSystemService(android.app.NotificationManager::class.java).notify(NOTIFICATION_ID, notification(text))
    }

    companion object {
        private const val TAG = "MKConnect"
        private const val NOTIFICATION_ID = 1
        const val ACTION_STOP = "com.khaliilii.mkconnect.STOP"
        const val EXTRA_VPN = "vpn"

        /** Error of the last failed start, shown by the UI. */
        @Volatile
        var lastError: String? = null

        fun start(context: Context, vpn: Boolean) {
            lastError = null
            val intent = Intent(context, MkVpnService::class.java).putExtra(EXTRA_VPN, vpn)
            if (Build.VERSION.SDK_INT >= 26) context.startForegroundService(intent) else context.startService(intent)
        }

        fun stop(context: Context) {
            context.startService(Intent(context, MkVpnService::class.java).setAction(ACTION_STOP))
        }
    }
}
