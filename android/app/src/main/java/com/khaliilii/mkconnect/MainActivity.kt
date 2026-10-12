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
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.List
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationRail
import androidx.compose.material3.NavigationRailItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.VerticalDivider
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
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

// ---------- the app shell ----------
//
// One pane with a bottom bar on a phone; from a tablet's width (or a phone in
// landscape) a navigation rail and two panes, with the account list and the
// connect button always visible next to the settings or the log.

private const val TAB_ACCOUNTS = 0
private const val TAB_SETTINGS = 1
private const val TAB_LOGS = 2

@Composable
fun App(onConnect: (Boolean) -> Unit, onDisconnect: () -> Unit, clipboardText: () -> String, openUrl: (String) -> Unit) {
    var tab by remember { mutableIntStateOf(TAB_ACCOUNTS) }
    var accounts by remember { mutableStateOf(loadAccounts()) }
    var settings by remember { mutableStateOf(loadSettings()) }
    var status by remember { mutableStateOf(loadStatus()) }
    var test by remember { mutableStateOf(loadTestRun()) }
    var message by remember { mutableStateOf<String?>(null) }
    var showAbout by remember { mutableStateOf(false) }
    var editing by remember { mutableStateOf<String?>(null) } // account id; "" = a new account
    var showImport by remember { mutableStateOf(false) }
    var newGroup by remember { mutableStateOf(false) }
    var renaming by remember { mutableStateOf<Group?>(null) }
    var moving by remember { mutableStateOf<Account?>(null) }
    val options = remember { Options.load() }
    val clipboard = LocalClipboardManager.current
    val scope = rememberCoroutineScope()

    fun refresh() {
        accounts = loadAccounts()
        settings = loadSettings()
    }

    LaunchedEffect(Unit) {
        var wasTesting = false
        while (true) {
            status = loadStatus()
            test = loadTestRun()
            if (wasTesting && !test.running) refresh() // the measurements were saved
            wasTesting = test.running
            MkVpnService.lastError?.let { message = it; MkVpnService.lastError = null }
            delay(1000)
        }
    }

    fun import(text: String, group: String) = scope.launch {
        val result = withContext(Dispatchers.IO) {
            runCatching {
                JSONObject(if (group.isEmpty()) Mkmobile.import_(text) else Mkmobile.importInto(text, group))
            }
        }
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

    // Like the desktop app: add links copied while the app was in the background.
    LaunchedEffect(settings.clipboardImport) {
        if (settings.clipboardImport) {
            val text = clipboardText()
            if (text.contains("://")) import(text, "")
        }
    }

    val actions = AccountActions(
        select = { a -> Mkmobile.setActive(a.id); refresh() },
        edit = { a -> editing = a.id },
        share = { a ->
            runCatching { Mkmobile.shareLink(a.id) }
                .onSuccess { clipboard.setText(AnnotatedString(it)); message = "Share link copied." }
                .onFailure { message = it.message }
        },
        delete = { a ->
            runCatching { Mkmobile.delete(a.id) }.onFailure { message = it.message }
            refresh()
        },
        test = { a ->
            runCatching { Mkmobile.startTest(a.id, false) }.onFailure { message = it.message }
            test = loadTestRun()
        },
        move = { a -> moving = a },
    )

    BoxWithConstraints(Modifier.fillMaxSize()) {
        val wide = maxWidth >= 720.dp
        val tabs = listOf(
            Triple(TAB_ACCOUNTS, "Accounts", Icons.Filled.List),
            Triple(TAB_SETTINGS, "Connection", Icons.Filled.Settings),
            Triple(TAB_LOGS, "Logs", Icons.Filled.Description),
        )

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
                if (!wide) {
                    NavigationBar {
                        tabs.forEach { (index, label, icon) ->
                            NavigationBarItem(tab == index, { tab = index }, { Icon(icon, null) }, label = { Text(label) })
                        }
                    }
                }
            },
        ) { padding ->
            val accountsPane: @Composable () -> Unit = {
                AccountsScreen(
                    accounts = accounts,
                    test = test,
                    sortBy = settings.sortBy,
                    actions = actions,
                    onImportClipboard = { import(clipboardText(), "") },
                    onShowImport = { showImport = true },
                    onNewAccount = { editing = "" },
                    onUpdateSubs = {
                        scope.launch {
                            val n = withContext(Dispatchers.IO) { runCatching { Mkmobile.updateSubscriptions() } }
                            message = n.fold({ "Updated $it subscription(s)." }, { it.message })
                            refresh()
                        }
                    },
                    onStartTest = { speed ->
                        runCatching { Mkmobile.startTest("", speed) }.onFailure { message = it.message }
                        test = loadTestRun()
                    },
                    onCancelTest = { Mkmobile.cancelTest() },
                    onSortBy = { value ->
                        runCatching { Mkmobile.setSettings(settings.copy(sortBy = value).toJson()) }
                            .onFailure { message = it.message }
                        refresh()
                    },
                    onNewGroup = { newGroup = true },
                    onRenameGroup = { g -> renaming = g },
                    onDeleteGroup = { g ->
                        runCatching { Mkmobile.deleteGroup(g.id) }.onFailure { message = it.message }
                        refresh()
                    },
                )
            }
            val settingsPane: @Composable () -> Unit = {
                SettingsScreen(options, status, { message = it }, { refresh() })
            }
            val connectBar: @Composable () -> Unit = {
                Surface(tonalElevation = 3.dp) {
                    Column(Modifier.fillMaxWidth().padding(12.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                        Text(
                            status.text(),
                            style = MaterialTheme.typography.bodyMedium,
                            color = if (status.warning) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface,
                            maxLines = 2,
                            overflow = TextOverflow.Ellipsis,
                        )
                        Spacer(Modifier.height(8.dp))
                        Button(
                            onClick = { if (status.busy) onDisconnect() else onConnect(settings.vpnMode) },
                            enabled = status.busy || accounts.active.isNotEmpty(),
                            colors = if (status.busy) {
                                ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error)
                            } else {
                                ButtonDefaults.buttonColors()
                            },
                            modifier = Modifier.fillMaxWidth().height(52.dp),
                        ) {
                            Icon(if (status.busy) Icons.Filled.Stop else Icons.Filled.PlayArrow, null)
                            Spacer(Modifier.width(8.dp))
                            Text(if (status.busy) "Disconnect" else "Connect", fontSize = 18.sp)
                        }
                    }
                }
            }

            Row(Modifier.padding(padding).fillMaxSize()) {
                if (wide) {
                    NavigationRail {
                        tabs.forEach { (index, label, icon) ->
                            NavigationRailItem(tab == index, { tab = index }, { Icon(icon, null) }, label = { Text(label) })
                        }
                    }
                    Column(Modifier.weight(0.42f).fillMaxHeight()) {
                        Box(Modifier.weight(1f)) { accountsPane() }
                        connectBar()
                    }
                    VerticalDivider()
                    Box(Modifier.weight(0.58f).fillMaxHeight()) {
                        if (tab == TAB_LOGS) LogsScreen() else settingsPane()
                    }
                } else {
                    Column(Modifier.fillMaxSize()) {
                        Box(Modifier.weight(1f)) {
                            when (tab) {
                                TAB_ACCOUNTS -> accountsPane()
                                TAB_SETTINGS -> settingsPane()
                                else -> LogsScreen()
                            }
                        }
                        if (tab != TAB_LOGS) connectBar()
                    }
                }
            }
        }
    }

    message?.let {
        AlertDialog(
            onDismissRequest = { message = null },
            confirmButton = { TextButton({ message = null }) { Text("OK") } },
            text = { Text(it) },
        )
    }
    editing?.let { id ->
        EditorDialog(id, options, onClose = { editing = null }) { msg ->
            message = msg
            refresh()
        }
    }
    if (showImport) {
        ImportDialog(onClose = { showImport = false }) { text, group -> import(text, group) }
    }
    if (newGroup) {
        PromptDialog("New group", "Name", "", onClose = { newGroup = false }) { name ->
            runCatching { Mkmobile.addGroup(name) }.onFailure { message = it.message }
            refresh()
        }
    }
    renaming?.let { g ->
        PromptDialog("Rename group", "Name", g.name, onClose = { renaming = null }) { name ->
            runCatching { Mkmobile.renameGroup(g.id, name) }.onFailure { message = it.message }
            refresh()
        }
    }
    moving?.let { a ->
        GroupPickerDialog(accounts.groups, onClose = { moving = null }) { groupId ->
            runCatching { Mkmobile.setGroup(a.id, groupId) }.onFailure { message = it.message }
            refresh()
        }
    }
    if (showAbout) AboutDialog(onClose = { showAbout = false }, openUrl = openUrl)
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
                Text("SSH (with HTTP payload), VMess, VLESS, Trojan, Shadowsocks, Hysteria2 and TUIC client.")
                Spacer(Modifier.height(4.dp))
                Text(
                    "Accounts, groups and subscriptions, server tests, a system-wide VPN or a local proxy to share.",
                    style = MaterialTheme.typography.bodySmall,
                )
                Spacer(Modifier.height(12.dp))
                Text("Developed by")
                TextButton({ openUrl("https://github.com/khaliilii") }) { Text("github.com/khaliilii") }
                TextButton({ openUrl("https://github.com/khaliilii/MKConnect") }) { Text("Source code & releases") }
            }
        },
        confirmButton = { TextButton(onClose) { Text("Close") } },
    )
}
