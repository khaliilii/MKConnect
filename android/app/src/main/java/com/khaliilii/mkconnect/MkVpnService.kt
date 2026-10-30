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
import java.util.concurrent.Executors
import kotlin.concurrent.thread

/**
 * Runs the Go core as the system VPN (or, in proxy mode, just keeps it running
 * in the background). Implements [Platform] for the core: it builds the TUN,
 * protects the core's own sockets (VpnService.protect has the same signature)
 * and reports the network interfaces Android won't let the core read itself.
 *
 * Connect, disconnect and switch commands run one at a time on [worker], in
 * the order they arrive, so a disconnect followed at once by a connect (picking
 * another account) can't end the new connection.
 */
class MkVpnService : VpnService(), Platform {

    private val worker = Executors.newSingleThreadExecutor { Thread(it, "mkconnect-service") }
    private var tun: ParcelFileDescriptor? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    /** Counts connections; a status watcher of an older one stops. */
    @Volatile
    private var generation = 0

    /** A connection is up (or starting); only then does the service have anything to stop. */
    @Volatile
    private var active = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Restarted by the system (no intent) or by always-on VPN: connect as a VPN.
        val vpn = intent?.getBooleanExtra(EXTRA_VPN, true) ?: true
        when (intent?.action) {
            ACTION_STOP -> worker.execute {
                disconnect()
                stopSelfResult(startId) // only if no newer command came in
            }
            ACTION_SWITCH -> {
                goForeground("Switching account…")
                worker.execute {
                    disconnect()
                    connect(vpn, startId)
                }
            }
            else -> {
                goForeground("Connecting…")
                worker.execute { connect(vpn, startId) }
            }
        }
        return START_STICKY
    }

    private fun goForeground(text: String) {
        val notification = notification(text)
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    /** Runs on [worker]. */
    private fun connect(vpn: Boolean, startId: Int) {
        goForeground("Connecting…") // a disconnect just before may have left the foreground
        watchDefaultNetwork()
        try {
            active = true
            Mkmobile.start(if (vpn) this else null)
            watchStatus(++generation, startId)
        } catch (e: Exception) {
            Log.e(TAG, "start failed", e)
            lastError = e.message
            disconnect()
            stopSelfResult(startId)
        }
    }

    /** Runs on [worker]. Stops the core and gives the network back. */
    private fun disconnect() {
        generation++
        active = false
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
    }

    // The notification follows the connection, so the shade shows what the
    // app does: the latency, "no internet" or a reconnect. When the core ends
    // the connection by itself (an error), the VPN is taken down too, so the
    // phone isn't left with a tunnel that carries nothing.
    private fun watchStatus(gen: Int, startId: Int) {
        thread(name = "mkconnect-status") {
            var shown = ""
            while (gen == generation) {
                val status = runCatching { loadStatus() }.getOrNull()
                if (status != null && !status.busy) {
                    if (status.state == "error") lastError = status.error
                    // The service may be gone already (a disconnect raced this).
                    runCatching {
                        worker.execute {
                            if (gen == generation) {
                                disconnect()
                                stopSelfResult(startId) // not if a newer command came in
                            }
                        }
                    }
                    break
                }
                val text = status?.text().orEmpty()
                if (text.isNotEmpty() && text != shown) {
                    shown = text
                    updateNotification(text)
                }
                Thread.sleep(3000)
            }
        }
    }

    override fun onRevoke() {
        // Another VPN took over or the user revoked the permission: whatever
        // is queued, the tunnel is gone.
        runCatching {
            worker.execute {
                disconnect()
                stopSelf()
            }
        }
    }

    override fun onDestroy() {
        // Normally the connection was stopped before the service ends; if the
        // system ends it while connected, stop the core too. Never otherwise:
        // a new service's connection may already be starting.
        if (active) runCatching { worker.execute { disconnect() } }
        worker.shutdown()
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
            .setOnlyAlertOnce(true)
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
        const val ACTION_SWITCH = "com.khaliilii.mkconnect.SWITCH"
        const val EXTRA_VPN = "vpn"

        /** Error of the last failed start, shown by the UI. */
        @Volatile
        var lastError: String? = null

        fun start(context: Context, vpn: Boolean) = send(context, null, vpn)

        /** Reconnects with the account now selected. */
        fun switch(context: Context, vpn: Boolean) = send(context, ACTION_SWITCH, vpn)

        fun stop(context: Context) {
            context.startService(Intent(context, MkVpnService::class.java).setAction(ACTION_STOP))
        }

        private fun send(context: Context, action: String?, vpn: Boolean) {
            lastError = null
            val intent = Intent(context, MkVpnService::class.java).setAction(action).putExtra(EXTRA_VPN, vpn)
            if (Build.VERSION.SDK_INT >= 26) context.startForegroundService(intent) else context.startService(intent)
        }
    }
}
