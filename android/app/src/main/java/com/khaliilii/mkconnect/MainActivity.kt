package com.khaliilii.mkconnect

import android.Manifest
import android.content.ClipboardManager
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import mkmobile.Mkmobile
import org.json.JSONObject

class MainActivity : ComponentActivity() {

    private var pendingVpnStart = false

    private val vpnPermission = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        if (it.resultCode == RESULT_OK && pendingVpnStart) MkVpnService.start(this, vpn = true)
        else if (pendingVpnStart) Toast.makeText(this, "VPN permission is needed to connect", Toast.LENGTH_LONG).show()
        pendingVpnStart = false
    }

    private val notificationPermission = registerForActivityResult(ActivityResultContracts.RequestPermission()) {}

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
        setContent {
            MaterialTheme(colorScheme = if (isSystemInDarkThemeCompat()) darkColorScheme() else lightColorScheme()) {
                App(
                    onConnect = ::connect,
                    onDisconnect = { MkVpnService.stop(this) },
                    clipboardText = ::clipboardText,
                    openUrl = { startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(it))) },
                )
            }
        }
    }

    private fun connect(vpn: Boolean) {
        if (!vpn) {
            MkVpnService.start(this, vpn = false)
            return
        }
        val prepare = VpnService.prepare(this)
        if (prepare == null) {
            MkVpnService.start(this, vpn = true)
        } else {
            pendingVpnStart = true
            vpnPermission.launch(prepare)
        }
    }

    private fun clipboardText(): String {
        val cm = getSystemService(ClipboardManager::class.java)
        val clip = cm.primaryClip ?: return ""
        return (0 until clip.itemCount).joinToString("\n") { clip.getItemAt(it).coerceToText(this).toString() }
    }

    private fun isSystemInDarkThemeCompat(): Boolean =
        (resources.configuration.uiMode and android.content.res.Configuration.UI_MODE_NIGHT_MASK) ==
            android.content.res.Configuration.UI_MODE_NIGHT_YES
}

// ---------- data ----------

data class Account(val id: String, val name: String, val type: String, val summary: String, val group: String)
data class Group(val id: String, val name: String, val url: String, val count: Int, val usedText: String, val used: Long, val total: Long, val expire: Long)
data class Accounts(val active: String, val list: List<Account>, val groups: List<Group>)

fun loadAccounts(): Accounts {
    val o = JSONObject(Mkmobile.profiles())
    val ps = o.getJSONArray("profiles")
    val gs = o.getJSONArray("groups")
    return Accounts(
        active = o.optString("active"),
        list = (0 until ps.length()).map { ps.getJSONObject(it) }.map {
            Account(it.getString("id"), it.getString("name"), it.getString("type"), it.getString("summary"), it.optString("group"))
        },
        groups = (0 until gs.length()).map { gs.getJSONObject(it) }.map {
            val usage = it.optJSONObject("usage")
            Group(
                it.getString("id"), it.getString("name"), it.optString("url"), it.optInt("count"), it.optString("used_text"),
                (usage?.optLong("upload") ?: 0) + (usage?.optLong("download") ?: 0), usage?.optLong("total") ?: 0,
                0,
            )
        },
    )
}

// ---------- UI ----------

@Composable
fun App(onConnect: (Boolean) -> Unit, onDisconnect: () -> Unit, clipboardText: () -> String, openUrl: (String) -> Unit) {
    var tab by remember { mutableIntStateOf(0) }
    var accounts by remember { mutableStateOf(loadAccounts()) }
    var status by remember { mutableStateOf(JSONObject(Mkmobile.status())) }
    var message by remember { mutableStateOf<String?>(null) }
    var showAbout by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    LaunchedEffect(Unit) {
        while (true) {
            status = JSONObject(Mkmobile.status())
            MkVpnService.lastError?.let { message = it; MkVpnService.lastError = null }
            delay(1000)
        }
    }
    fun refresh() { accounts = loadAccounts() }
    fun import(text: String) = scope.launch {
        val result = withContext(Dispatchers.IO) { runCatching { JSONObject(Mkmobile.import_(text)) } }
        result.onSuccess {
            val skipped = it.getJSONArray("skipped")
            message = buildString {
                append("Added ${it.getInt("added")} account(s).")
                if (it.getInt("existing") > 0) append(" ${it.getInt("existing")} already in the list.")
                if (skipped.length() > 0) append("\nSkipped ${skipped.length()}: ${skipped.optString(0)}")
            }
            refresh()
        }.onFailure { message = it.message }
    }

    Scaffold(
        topBar = {
            Row(
                Modifier.fillMaxWidth().statusBarsPadding().padding(horizontal = 16.dp, vertical = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text("MKConnect", style = MaterialTheme.typography.titleLarge, modifier = Modifier.weight(1f))
                IconButton(onClick = { showAbout = true }) { Icon(Icons.Filled.Info, "About") }
            }
        },
        bottomBar = {
            NavigationBar {
                NavigationBarItem(tab == 0, { tab = 0 }, { Icon(Icons.Filled.List, null) }, label = { Text("Accounts") })
                NavigationBarItem(tab == 1, { tab = 1 }, { Icon(Icons.Filled.Settings, null) }, label = { Text("Settings") })
                NavigationBarItem(tab == 2, { tab = 2 }, { Icon(Icons.Filled.Description, null) }, label = { Text("Logs") })
            }
        },
    ) { padding ->
        Box(Modifier.padding(padding).fillMaxSize()) {
            when (tab) {
                0 -> AccountsScreen(accounts, status, ::refresh, { import(clipboardText()) }, ::import, onConnect, onDisconnect,
                    onUpdateSubs = {
                        scope.launch {
                            val n = withContext(Dispatchers.IO) { runCatching { Mkmobile.updateSubscriptions() } }
                            message = n.fold({ "Updated $it subscription(s)." }, { it.message })
                            refresh()
                        }
                    })
                1 -> SettingsScreen { message = it }
                2 -> LogsScreen()
            }
        }
    }

    message?.let { AlertDialog(onDismissRequest = { message = null }, confirmButton = { TextButton({ message = null }) { Text("OK") } }, text = { Text(it) }) }
    if (showAbout) AboutDialog(onClose = { showAbout = false }, openUrl = openUrl)
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
fun AccountsScreen(
    accounts: Accounts,
    status: JSONObject,
    refresh: () -> Unit,
    importClipboard: () -> Unit,
    importText: (String) -> Unit,
    onConnect: (Boolean) -> Unit,
    onDisconnect: () -> Unit,
    onUpdateSubs: () -> Unit,
) {
    var menuFor by remember { mutableStateOf<Account?>(null) }
    var showPaste by remember { mutableStateOf(false) }
    val state = status.optString("state")
    val connected = state == "connected" || state == "connecting"

    Column(Modifier.fillMaxSize()) {
        Row(Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 4.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = importClipboard, modifier = Modifier.weight(1f)) {
                Icon(Icons.Filled.ContentPaste, null); Spacer(Modifier.width(6.dp)); Text("Clipboard")
            }
            OutlinedButton(onClick = { showPaste = true }, modifier = Modifier.weight(1f)) {
                Icon(Icons.Filled.Add, null); Spacer(Modifier.width(6.dp)); Text("Add")
            }
            if (accounts.groups.any { it.url.isNotEmpty() }) {
                IconButton(onClick = onUpdateSubs) { Icon(Icons.Filled.Refresh, "Update subscriptions") }
            }
        }
        accounts.groups.filter { it.url.isNotEmpty() && it.usedText.isNotEmpty() }.forEach { g ->
            Card(Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 4.dp)) {
                Column(Modifier.padding(12.dp)) {
                    Text(g.name, fontWeight = FontWeight.Bold)
                    if (g.total > 0) LinearProgressIndicator(
                        progress = { (g.used.toFloat() / g.total).coerceIn(0f, 1f) },
                        modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
                    )
                    Text("${g.usedText} · ${g.count} accounts", style = MaterialTheme.typography.bodySmall)
                }
            }
        }
        if (accounts.list.isEmpty()) {
            Box(Modifier.weight(1f).fillMaxWidth(), contentAlignment = Alignment.Center) {
                Text("No accounts yet.\nCopy a share link or subscription URL\nand tap Clipboard.", style = MaterialTheme.typography.bodyMedium)
            }
        } else {
            LazyColumn(Modifier.weight(1f)) {
                items(accounts.list, key = { it.id }) { a ->
                    val selected = a.id == accounts.active
                    Column(
                        Modifier.fillMaxWidth()
                            .background(if (selected) MaterialTheme.colorScheme.primaryContainer else Color.Transparent)
                            .combinedClickable(onClick = { Mkmobile.setActive(a.id); refresh() }, onLongClick = { menuFor = a })
                            .padding(horizontal = 16.dp, vertical = 10.dp),
                    ) {
                        Text(a.name, fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis)
                        Text(a.summary, style = MaterialTheme.typography.bodySmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    }
                    HorizontalDivider()
                }
            }
        }

        // Status and the Connect button, always at hand.
        Surface(tonalElevation = 3.dp) {
            Column(Modifier.fillMaxWidth().padding(12.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                val text = when (state) {
                    "connected" -> "Connected to ${status.optString("profile")} · ↑ ${status.optString("up_text")} ↓ ${status.optString("down_text")}"
                    "connecting" -> "Connecting…"
                    "error" -> "Error: ${status.optString("error")}"
                    else -> "Disconnected"
                }
                Text(text, style = MaterialTheme.typography.bodyMedium, maxLines = 2, overflow = TextOverflow.Ellipsis)
                Spacer(Modifier.height(8.dp))
                Button(
                    onClick = {
                        if (connected) onDisconnect()
                        else onConnect(JSONObject(Mkmobile.settings()).optString("mode") != "proxy")
                    },
                    enabled = connected || accounts.active.isNotEmpty(),
                    colors = if (connected) ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error) else ButtonDefaults.buttonColors(),
                    modifier = Modifier.fillMaxWidth().height(52.dp),
                ) {
                    Icon(if (connected) Icons.Filled.Stop else Icons.Filled.PlayArrow, null)
                    Spacer(Modifier.width(8.dp))
                    Text(if (connected) "Disconnect" else "Connect", fontSize = 18.sp)
                }
            }
        }
    }

    menuFor?.let { a ->
        AlertDialog(
            onDismissRequest = { menuFor = null },
            title = { Text(a.name) },
            text = { Text(a.summary) },
            confirmButton = {
                TextButton({
                    Mkmobile.delete(a.id); refresh(); menuFor = null
                }) { Text("Delete") }
            },
            dismissButton = { TextButton({ menuFor = null }) { Text("Close") } },
        )
    }
    if (showPaste) {
        var text by remember { mutableStateOf("") }
        AlertDialog(
            onDismissRequest = { showPaste = false },
            title = { Text("Add accounts") },
            text = {
                OutlinedTextField(
                    value = text, onValueChange = { text = it },
                    placeholder = { Text("vmess://, vless://, trojan://, ss://, hy2://, tuic://, ssh:// links or a subscription URL") },
                    modifier = Modifier.fillMaxWidth().heightIn(min = 140.dp),
                )
            },
            confirmButton = { TextButton({ importText(text); showPaste = false }) { Text("Import") } },
            dismissButton = { TextButton({ showPaste = false }) { Text("Cancel") } },
        )
    }
}

@Composable
fun SettingsScreen(onMessage: (String) -> Unit) {
    val initial = remember { JSONObject(Mkmobile.settings()) }
    var vpn by remember { mutableStateOf(initial.optString("mode") != "proxy") }
    var port by remember { mutableStateOf(initial.optInt("port", 1080).toString()) }
    var lan by remember { mutableStateOf(initial.optBoolean("allow_lan")) }
    var user by remember { mutableStateOf(initial.optString("proxy_user")) }
    var pass by remember { mutableStateOf(initial.optString("proxy_pass")) }
    var dns by remember { mutableStateOf(initial.optString("remote_dns", "1.1.1.1")) }

    fun save() {
        val json = JSONObject().apply {
            put("mode", if (vpn) "vpn" else "proxy")
            put("port", port.toIntOrNull() ?: 1080)
            put("allow_lan", lan)
            put("proxy_user", user)
            put("proxy_pass", pass)
            put("remote_dns", dns)
        }
        runCatching { Mkmobile.setSettings(json.toString()) }.onFailure { onMessage(it.message ?: "invalid settings") }
    }

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("Mode", fontWeight = FontWeight.Bold)
        Row(verticalAlignment = Alignment.CenterVertically) {
            RadioButton(vpn, { vpn = true; save() }); Text("VPN (all apps)")
            Spacer(Modifier.width(16.dp))
            RadioButton(!vpn, { vpn = false; save() }); Text("Proxy only")
        }
        Text(
            if (vpn) "All apps go through the tunnel (Android asks for VPN permission the first time)."
            else "Only apps set to use the local proxy go through the tunnel.",
            style = MaterialTheme.typography.bodySmall,
        )
        HorizontalDivider()
        OutlinedTextField(port, { port = it; save() }, label = { Text("Local proxy port") },
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number), modifier = Modifier.fillMaxWidth())
        Row(verticalAlignment = Alignment.CenterVertically) {
            Switch(lan, { lan = it; save() }); Spacer(Modifier.width(8.dp))
            Text("Share the proxy with other devices (e.g. over this phone's hotspot)")
        }
        OutlinedTextField(user, { user = it; save() }, label = { Text("Proxy user (optional)") }, modifier = Modifier.fillMaxWidth())
        OutlinedTextField(pass, { pass = it; save() }, label = { Text("Proxy password (optional)") },
            visualTransformation = PasswordVisualTransformation(), modifier = Modifier.fillMaxWidth())
        OutlinedTextField(dns, { dns = it; save() }, label = { Text("DNS through the tunnel") }, modifier = Modifier.fillMaxWidth())
        Text("Changes apply on the next connect.", style = MaterialTheme.typography.bodySmall)
    }
}

@Composable
fun LogsScreen() {
    var logs by remember { mutableStateOf("") }
    LaunchedEffect(Unit) {
        while (true) {
            logs = withContext(Dispatchers.IO) { Mkmobile.logs(300) }
            delay(2000)
        }
    }
    Text(
        logs.ifEmpty { "No logs yet. Connect to see the core's log." },
        fontFamily = FontFamily.Monospace, fontSize = 11.sp,
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(12.dp),
    )
}

@Composable
fun AboutDialog(onClose: () -> Unit, openUrl: (String) -> Unit) {
    AlertDialog(
        onDismissRequest = onClose,
        title = { Text("MKConnect") },
        text = {
            Column {
                Text("Version ${Mkmobile.version()}")
                Spacer(Modifier.height(8.dp))
                Text("SSH, VMess, VLESS, Trojan, Shadowsocks, Hysteria2 and TUIC client.")
                Spacer(Modifier.height(12.dp))
                Text("Developed by")
                TextButton({ openUrl("https://github.com/khaliilii") }) { Text("github.com/khaliilii") }
                TextButton({ openUrl("https://github.com/khaliilii/MKConnect") }) { Text("Source code & releases") }
            }
        },
        confirmButton = { TextButton(onClose) { Text("Close") } },
    )
}
