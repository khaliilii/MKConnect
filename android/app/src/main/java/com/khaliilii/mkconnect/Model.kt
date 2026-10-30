package com.khaliilii.mkconnect

import mkmobile.Mkmobile
import org.json.JSONArray
import org.json.JSONObject

// The Go core is the single source of truth: accounts, settings and
// measurements all live in profiles.json and cross as JSON, so this file is
// the only place that knows the shape of it.

data class Account(
    val id: String,
    val name: String,
    val type: String,
    val summary: String,
    val group: String,
    val test: String,
    val testOk: Boolean,
    val latency: Int,
)

data class Group(
    val id: String,
    val name: String,
    val url: String,
    val count: Int,
    val usedText: String,
    val used: Long,
    val total: Long,
) {
    val isSubscription: Boolean get() = url.isNotEmpty()
}

data class Accounts(val active: String, val list: List<Account>, val groups: List<Group>) {
    fun groupName(id: String): String = groups.firstOrNull { it.id == id }?.name ?: ""
}

fun JSONArray.objects(): List<JSONObject> = (0 until length()).map { getJSONObject(it) }

fun loadAccounts(): Accounts {
    val o = JSONObject(Mkmobile.profiles())
    return Accounts(
        active = o.optString("active"),
        list = o.getJSONArray("profiles").objects().map {
            Account(
                id = it.getString("id"),
                name = it.getString("name"),
                type = it.getString("type"),
                summary = it.getString("summary"),
                group = it.optString("group"),
                test = it.optString("test"),
                testOk = it.optBoolean("test_ok"),
                latency = it.optInt("latency_ms"),
            )
        },
        groups = o.getJSONArray("groups").objects().map {
            val usage = it.optJSONObject("usage")
            Group(
                id = it.getString("id"),
                name = it.getString("name"),
                url = it.optString("url"),
                count = it.optInt("count"),
                usedText = it.optString("used_text"),
                used = (usage?.optLong("upload") ?: 0L) + (usage?.optLong("download") ?: 0L),
                total = usage?.optLong("total") ?: 0L,
            )
        },
    )
}

// ---------- settings ----------

data class Settings(
    val vpnMode: Boolean,
    val port: Int,
    val allowLan: Boolean,
    val proxyUser: String,
    val proxyPass: String,
    val remoteDns: String,
    val ipv6: Boolean,
    val logLevel: String,
    val autoReconnect: Boolean,
    val sortBy: String,
    val tunStack: String,
    val tunMtu: Int,
    val clipboardImport: Boolean,
    val directIran: Boolean,
    val fakeDns: Boolean,
    val failover: Boolean,
    val blockQuic: Boolean,
    val testSites: List<String>,
    val defaultTestSites: List<String>,
) {
    fun toJson(): String = JSONObject().apply {
        put("mode", if (vpnMode) "vpn" else "proxy")
        put("port", port)
        put("allow_lan", allowLan)
        put("proxy_user", proxyUser)
        put("proxy_pass", proxyPass)
        put("remote_dns", remoteDns)
        put("ipv6", ipv6)
        put("log_level", logLevel)
        put("auto_reconnect", autoReconnect)
        put("sort_by", sortBy)
        put("tun_stack", tunStack)
        put("tun_mtu", tunMtu)
        put("clipboard_import", clipboardImport)
        put("direct_iran", directIran)
        put("fake_dns", fakeDns)
        put("failover", failover)
        put("block_quic", blockQuic)
        put("test_sites", JSONArray(testSites))
    }.toString()
}

private fun JSONObject.strings(key: String): List<String> =
    optJSONArray(key)?.let { a -> (0 until a.length()).map { a.getString(it) } } ?: emptyList()

fun loadSettings(): Settings {
    val o = JSONObject(Mkmobile.settings())
    return Settings(
        vpnMode = o.optString("mode") != "proxy",
        port = o.optInt("port", 1080),
        allowLan = o.optBoolean("allow_lan"),
        proxyUser = o.optString("proxy_user"),
        proxyPass = o.optString("proxy_pass"),
        remoteDns = o.optString("remote_dns", "1.1.1.1"),
        ipv6 = o.optBoolean("ipv6"),
        logLevel = o.optString("log_level", "info"),
        autoReconnect = o.optBoolean("auto_reconnect", true),
        sortBy = o.optString("sort_by"),
        tunStack = o.optString("tun_stack"),
        tunMtu = o.optInt("tun_mtu"),
        clipboardImport = o.optBoolean("clipboard_import"),
        directIran = o.optBoolean("direct_iran", true),
        fakeDns = o.optBoolean("fake_dns", true),
        failover = o.optBoolean("failover", true),
        blockQuic = o.optBoolean("block_quic", true),
        testSites = o.strings("test_sites"),
        defaultTestSites = o.strings("default_test_sites"),
    )
}

// ---------- form choices, from the core so both apps offer the same ----------

class Options(private val o: JSONObject) {
    fun list(key: String): List<String> = o.optJSONArray(key)?.let { a -> (0 until a.length()).map { a.getString(it) } } ?: emptyList()
    val types get() = list("types")
    val vmessCiphers get() = list("vmess_ciphers")
    val ssMethods get() = list("ss_methods")
    val networks get() = list("networks")
    val headerTypes get() = list("header_types")
    val tlsModes get() = list("tls_modes")
    val fingerprints get() = list("fingerprints")
    val flows get() = list("flows")
    val congestionControls get() = list("congestion_controls")
    val udpRelayModes get() = list("udp_relay_modes")
    val logLevels get() = list("log_levels")
    val payloadTags get() = list("payload_tags")

    companion object {
        fun load(): Options = Options(JSONObject(Mkmobile.options()))
    }
}

// ---------- status ----------

data class Status(val state: String, val profile: String, val error: String, val health: String, val healthMs: Long, val upText: String, val downText: String, val core: String, val outbound: String, val inbounds: List<String>) {
    val busy: Boolean get() = state == "connected" || state == "connecting" || state == "reconnecting"

    /** What to show as the connection's state, including whether traffic really flows. */
    fun text(): String = when {
        state == "connected" && health.isNotEmpty() -> "Connected to $profile, but no internet: $health"
        state == "connected" -> {
            val ms = if (healthMs > 0) " · $healthMs ms" else ""
            "Connected to $profile$ms · ↑ $upText ↓ $downText"
        }
        state == "connecting" -> "Connecting…"
        state == "reconnecting" -> "Connection lost; reconnecting…"
        state == "error" -> "Error: $error"
        else -> "Disconnected"
    }

    val warning: Boolean get() = state == "error" || (state == "connected" && health.isNotEmpty()) || state == "reconnecting"
}

fun loadStatus(): Status {
    val o = JSONObject(Mkmobile.status())
    val ins = o.optJSONArray("inbounds")
    return Status(
        state = o.optString("state"),
        profile = o.optString("profile"),
        error = o.optString("error"),
        health = o.optString("health"),
        healthMs = o.optLong("health_ms"),
        upText = o.optString("up_text"),
        downText = o.optString("down_text"),
        core = o.optString("core"),
        outbound = o.optString("outbound"),
        inbounds = (0 until (ins?.length() ?: 0)).map { ins!!.getString(it) },
    )
}

// ---------- server test ----------

data class TestRun(val running: Boolean, val done: Int, val total: Int, val results: Map<String, String>)

fun loadTestRun(): TestRun {
    val o = JSONObject(Mkmobile.testProgress())
    val res = o.optJSONObject("results")
    val map = mutableMapOf<String, String>()
    res?.keys()?.forEach { key -> map[key] = res.getJSONObject(key).optString("summary") }
    return TestRun(o.optBoolean("running"), o.optInt("done"), o.optInt("total"), map)
}
