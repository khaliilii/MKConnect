package com.khaliilii.mkconnect

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import mkmobile.Mkmobile
import org.json.JSONObject

// The account editor: the fields the desktop app's form has, one section per
// protocol plus the shared transport and TLS sections.
//
// The form is a flat map of "dotted key" to text ("name", "transport.host"),
// which keeps Compose's state tracking simple; on save it is written back
// into the profile JSON the core stores, so fields this form doesn't show
// (a pinned host key, the last measurement) survive an edit.

private val intFields = setOf("port", "alter_id", "udpgw_port", "up_mbps", "down_mbps")
private val boolFields = setOf("udpgw_dns", "tls.insecure")

// Only the sections the form shows are flattened; anything else (the last
// measurement, an ALPN list) stays in the profile JSON untouched.
private val sections = setOf("transport", "tls")

private fun formOf(json: JSONObject): Map<String, String> {
    val out = mutableMapOf<String, String>()
    for (key in json.keys()) {
        val value = json.get(key)
        when {
            key in sections && value is JSONObject ->
                for (inner in value.keys()) {
                    val v = value.get(inner)
                    if (v !is JSONObject && v !is org.json.JSONArray) out["$key.$inner"] = v.toString()
                }
            value is JSONObject || value is org.json.JSONArray -> Unit // left as it is
            else -> out[key] = value.toString()
        }
    }
    return out
}

private fun applyForm(json: JSONObject, form: Map<String, String>): JSONObject {
    for ((key, raw) in form) {
        val value: Any? = when {
            key in intFields -> raw.toIntOrNull() ?: 0
            key in boolFields -> raw.toBoolean()
            raw.isEmpty() -> null
            else -> raw
        }
        val dot = key.indexOf('.')
        if (dot < 0) {
            if (value == null) json.remove(key) else json.put(key, value)
            continue
        }
        val section = key.substring(0, dot)
        val field = key.substring(dot + 1)
        val obj = json.optJSONObject(section) ?: JSONObject()
        if (value == null) obj.remove(field) else obj.put(field, value)
        if (obj.length() == 0) json.remove(section) else json.put(section, obj)
    }
    return json
}

/**
 * EditorDialog edits an account, or adds one when [id] is empty.
 * [onSaved] gets a message once the core has accepted it.
 */
@Composable
fun EditorDialog(id: String, options: Options, onClose: () -> Unit, onSaved: (String) -> Unit) {
    val json = remember { if (id.isEmpty()) JSONObject() else JSONObject(Mkmobile.profileJSON(id)) }
    val form = remember {
        mutableStateMapOf<String, String>().apply {
            putAll(formOf(json))
            if (id.isEmpty()) {
                put("type", "vmess")
                put("port", "443")
            }
        }
    }
    var error by remember { mutableStateOf("") }

    fun get(key: String): String = form[key] ?: ""
    fun set(key: String, value: String) { form[key] = value }
    fun flag(key: String): Boolean = get(key).toBoolean()
    val type = get("type").ifEmpty { "vmess" }
    val network = get("transport.network").ifEmpty { "tcp" }
    val tlsMode = get("tls.mode")

    fun save() {
        val payload = applyForm(JSONObject(json.toString()), form.toMap()).toString()
        runCatching { Mkmobile.saveProfile(payload) }
            .onSuccess {
                onSaved(if (id.isEmpty()) "Account added." else "Account saved.")
                onClose()
            }
            .onFailure { error = it.message ?: "invalid account" }
    }

    FullScreenDialog(if (id.isEmpty()) "New account" else "Edit account", "Save", ::save, onClose) {
        if (error.isNotEmpty()) {
            Text(error, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium)
        }
        Picker("Protocol", options.types, type) { set("type", it) }
        Field("Name", get("name"), { set("name", it) }, hint = "shown in the list")
        Field("Server", get("server"), { set("server", it) }, hint = "host name or IP")
        Field("Port", get("port"), { set("port", it) }, number = true)

        when (type) {
            "ssh" -> {
                SectionTitle("SSH")
                Field("Username", get("user"), { set("user", it) }, hint = "root")
                Field("Password", get("password"), { set("password", it) }, password = true)
                Field("Private key file", get("private_key_path"), { set("private_key_path", it) }, hint = "optional path on the phone")
                if (get("host_key").isNotEmpty()) {
                    Hint("A host key is pinned for this server; changing the server clears it.")
                }
                Field("UDPGW port", get("udpgw_port"), { set("udpgw_port", it) }, hint = "e.g. 7300, empty = no UDP", number = true)
                SwitchRow("UDPGW transparent DNS (uses the server's resolver)", flag("udpgw_dns")) { set("udpgw_dns", it.toString()) }
                SectionTitle("Payload (HTTP Injector style)")
                Field(
                    "Payload", get("payload"), { set("payload", it) },
                    hint = "GET / HTTP/1.1[crlf]Host: bug.example[crlf][crlf]", lines = 3,
                )
                Hint("Sent before the SSH handshake. Tags: " + options.payloadTags.joinToString(" "))
                Field("Payload proxy", get("payload_proxy"), { set("payload_proxy", it) }, hint = "host:port, optional")
            }
            "vmess", "vless" -> {
                SectionTitle(type.uppercase())
                Field("UUID", get("uuid"), { set("uuid", it) }, hint = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")
                if (type == "vmess") {
                    Picker("Cipher", options.vmessCiphers, get("security").ifEmpty { "auto" }) { set("security", it) }
                    Field("alterId", get("alter_id"), { set("alter_id", it) }, number = true)
                } else {
                    Picker("Flow", options.flows, get("flow")) { set("flow", it) }
                }
            }
            "trojan" -> {
                SectionTitle("Trojan")
                Field("Password", get("password"), { set("password", it) }, password = true)
            }
            "shadowsocks" -> {
                SectionTitle("Shadowsocks")
                Picker("Method", options.ssMethods, get("method").ifEmpty { options.ssMethods.firstOrNull() ?: "" }) { set("method", it) }
                Field("Password", get("password"), { set("password", it) }, password = true)
            }
            "hysteria2" -> {
                SectionTitle("Hysteria2")
                Field("Password", get("password"), { set("password", it) }, password = true)
                Field("Obfuscation password", get("obfs_password"), { set("obfs_password", it) }, hint = "salamander, optional")
                Field("Up Mbps", get("up_mbps"), { set("up_mbps", it) }, number = true)
                Field("Down Mbps", get("down_mbps"), { set("down_mbps", it) }, number = true)
            }
            "tuic" -> {
                SectionTitle("TUIC")
                Field("UUID", get("uuid"), { set("uuid", it) })
                Field("Password", get("password"), { set("password", it) }, password = true)
                Picker("Congestion control", options.congestionControls, get("congestion_control").ifEmpty { "bbr" }) { set("congestion_control", it) }
                Picker("UDP relay mode", options.udpRelayModes, get("udp_relay_mode").ifEmpty { "native" }) { set("udp_relay_mode", it) }
            }
        }

        if (type == "vmess" || type == "vless" || type == "trojan" || type == "shadowsocks") {
            HorizontalDivider()
            SectionTitle("Transport")
            Picker("Network", options.networks, network) { set("transport.network", it) }
            when (network) {
                "tcp" -> Picker("TCP header", options.headerTypes, get("transport.header_type")) { set("transport.header_type", it) }
                "grpc" -> Field("gRPC service name", get("transport.service_name"), { set("transport.service_name", it) })
                else -> {
                    Field("Path", get("transport.path"), { set("transport.path", it) }, hint = "/")
                    Field("Host header", get("transport.host"), { set("transport.host", it) })
                }
            }
        }

        if (type != "ssh") {
            HorizontalDivider()
            SectionTitle("TLS")
            Picker("Security", options.tlsModes, tlsMode) { set("tls.mode", it) }
            if (tlsMode.isNotEmpty()) {
                Field("SNI", get("tls.sni"), { set("tls.sni", it) })
                Picker("Fingerprint (uTLS)", options.fingerprints, get("tls.fingerprint")) { set("tls.fingerprint", it) }
                if (tlsMode == "reality") {
                    Field("REALITY public key", get("tls.reality_public_key"), { set("tls.reality_public_key", it) })
                    Field("REALITY short id", get("tls.reality_short_id"), { set("tls.reality_short_id", it) })
                } else {
                    SwitchRow("Skip certificate verification (insecure)", flag("tls.insecure")) { set("tls.insecure", it.toString()) }
                }
            }
        }
    }
}

/** ImportDialog takes links or a subscription URL, optionally into a group. */
@Composable
fun ImportDialog(onClose: () -> Unit, onNewAccount: () -> Unit, onImport: (String, String) -> Unit) {
    var text by remember { mutableStateOf("") }
    var group by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onClose,
        title = { Text("Add accounts") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Field(
                    "Links or subscription URL", text, { text = it },
                    hint = "vmess://, vless://, trojan://, ss://, hy2://, tuic://, ssh:// or an https:// subscription",
                    lines = 4,
                )
                Field("Group (optional)", group, { group = it }, hint = "new or existing group name")
                Hint("Several links at once are fine, in any surrounding text or base64; duplicates are skipped.")
                TextButton(onNewAccount) { Text("Add an account by hand instead") }
            }
        },
        confirmButton = { TextButton({ onImport(text, group); onClose() }, enabled = text.isNotBlank()) { Text("Import") } },
        dismissButton = { TextButton(onClose) { Text("Cancel") } },
    )
}

/** A dialog that asks for one line of text (a group name, …). */
@Composable
fun PromptDialog(title: String, label: String, initial: String, onClose: () -> Unit, onDone: (String) -> Unit) {
    var text by remember { mutableStateOf(initial) }
    AlertDialog(
        onDismissRequest = onClose,
        title = { Text(title) },
        text = { Field(label, text, { text = it }) },
        confirmButton = { TextButton({ onDone(text.trim()); onClose() }, enabled = text.isNotBlank()) { Text("OK") } },
        dismissButton = { TextButton(onClose) { Text("Cancel") } },
    )
}

/** Lets the user move an account into one of the groups, or out of them. */
@Composable
fun GroupPickerDialog(groups: List<Group>, onClose: () -> Unit, onPick: (String) -> Unit) {
    AlertDialog(
        onDismissRequest = onClose,
        title = { Text("Move to group") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                TextButton({ onPick(""); onClose() }) { Text("No group") }
                groups.filter { !it.isSubscription }.forEach { g ->
                    TextButton({ onPick(g.id); onClose() }) { Text(g.name) }
                }
                if (groups.none { !it.isSubscription }) {
                    Row(Modifier.padding(top = 8.dp)) { Hint("No groups yet: create one from the menu.") }
                }
            }
        },
        confirmButton = { TextButton(onClose) { Text("Close") } },
    )
}
