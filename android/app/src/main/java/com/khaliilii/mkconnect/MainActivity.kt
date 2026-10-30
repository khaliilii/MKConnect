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
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.consumeWindowInsets
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.List
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.Info
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
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.VerticalDivider
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
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
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
        setContent {
            MkTheme {
                App(
                    connection = Connection(
                        connect = ::connect,
                        disconnect = { MkVpnService.stop(this) },
                        switch = { vpn -> MkVpnService.switch(this, vpn) },
                    ),
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
}

/** The system's light or dark theme, in the wallpaper's colors where Android has them (12+). */
@Composable
fun MkTheme(content: @Composable () -> Unit) {
    val dark = isSystemInDarkTheme()
    val context = LocalContext.current
    val colors = when {
        Build.VERSION.SDK_INT >= 31 -> if (dark) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
        dark -> darkColorScheme()
        else -> lightColorScheme()
    }
    MaterialTheme(colorScheme = colors, content = content)
}

/** Starting and stopping the VPN service; switch reconnects with the account now selected. */
class Connection(val connect: (vpn: Boolean) -> Unit, val disconnect: () -> Unit, val switch: (vpn: Boolean) -> Unit)

// ---------- the app shell ----------
//
// One pane with a bottom bar on a phone; from a tablet's width (or a phone in
// landscape) a navigation rail and two panes, with the account list and the
// connect bar always visible next to the settings or the log.

private enum class Tab(val label: String, val icon: ImageVector) {
    ACCOUNTS("Accounts", Icons.AutoMirrored.Filled.List),
    SETTINGS("Settings", Icons.Filled.Settings),
    LOGS("Logs", Icons.Filled.Description),
}

@OptIn(ExperimentalLayoutApi::class) // consumeWindowInsets, on older Compose versions
@Composable
fun App(connection: Connection, clipboardText: () -> String, openUrl: (String) -> Unit) {
    var tab by rememberSaveable { mutableIntStateOf(Tab.ACCOUNTS.ordinal) }
    var accounts by remember { mutableStateOf(loadAccounts()) }
    var settings by remember { mutableStateOf(loadSettings()) }
    var status by remember { mutableStateOf(loadStatus()) }
    var test by remember { mutableStateOf(loadTestRun()) }
    var error by remember { mutableStateOf<String?>(null) }
    var showAbout by remember { mutableStateOf(false) }
    var editing by remember { mutableStateOf<String?>(null) } // account id; "" = a new account
    var showImport by remember { mutableStateOf(false) }
    var newGroup by remember { mutableStateOf(false) }
    var renaming by remember { mutableStateOf<Group?>(null) }
    var moving by remember { mutableStateOf<Account?>(null) }
    var rankStage by remember { mutableStateOf("") } // "" unless Update & test is updating
    val options = remember { Options.load() }
    val clipboard = LocalClipboardManager.current
    val scope = rememberCoroutineScope()
    val snackbar = remember { SnackbarHostState() }

    fun refresh() {
        accounts = loadAccounts()
        settings = loadSettings()
    }

    fun notify(text: String) {
        scope.launch { snackbar.showSnackbar(text) }
    }

    /** Runs a call into the core; a failure is shown, and the list reloaded either way. */
    fun core(call: () -> Unit) {
        runCatching(call).onFailure { error = it.message }
        refresh()
    }

    // The core is polled off the UI thread: a connection starting or a test
    // running must never freeze the screen.
    LaunchedEffect(Unit) {
        var wasTesting = false
        var connectedTo = ""
        while (true) {
            val (s, t) = withContext(Dispatchers.IO) { loadStatus() to loadTestRun() }
            status = s
            test = t
            // A finished test saved its measurements; failover may have moved
            // the connection to another account.
            if (wasTesting && !t.running || s.profile != connectedTo) refresh()
            wasTesting = t.running
            connectedTo = s.profile
            MkVpnService.lastError?.let { error = it; MkVpnService.lastError = null }
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
            val added = it.getInt("added")
            val existing = it.getInt("existing")
            val summary = buildString {
                append("Added $added account(s).")
                if (existing > 0) append(" $existing already in the list.")
            }
            if (skipped.length() > 0) error = "$summary\nSkipped ${skipped.length()}: ${skipped.optString(0)}" else notify(summary)
            refresh()
        }.onFailure { error = it.message }
    }

    // Like the desktop app: add links copied while the app was closed.
    LaunchedEffect(settings.clipboardImport) {
        if (settings.clipboardImport) {
            val text = clipboardText()
            if (text.contains("://")) import(text, "")
        }
    }

    fun updateSubscriptions() = scope.launch {
        val n = withContext(Dispatchers.IO) { runCatching { Mkmobile.updateSubscriptions() } }
        n.onSuccess { notify("Updated $it subscription(s).") }.onFailure { error = it.message }
        refresh()
    }

    val actions = AccountActions(
        select = { a ->
            if (a.id != accounts.active) {
                core { Mkmobile.setActive(a.id) }
                // Picking another account while connected switches to it, as the
                // desktop app does.
                if (status.busy) connection.switch(settings.vpnMode)
            }
        },
        edit = { a -> editing = a.id },
        share = { a ->
            runCatching { Mkmobile.shareLink(a.id) }
                .onSuccess { clipboard.setText(AnnotatedString(it)); notify("Share link copied.") }
                .onFailure { error = it.message }
        },
        delete = { a -> core { Mkmobile.delete(a.id) } },
        test = { a ->
            runCatching { Mkmobile.startTest(a.id, true) }.onFailure { error = it.message }
        },
        move = { a -> moving = a },
    )

    val callbacks = AccountsCallbacks(
        pasteClipboard = {
            val text = clipboardText()
            if (text.isBlank()) error = "The clipboard is empty. Copy share links or a subscription address first." else import(text, "")
        },
        showImport = { showImport = true },
        newAccount = { editing = "" },
        updateSubscriptions = { updateSubscriptions() },
        startTest = { speed -> runCatching { Mkmobile.startTest("", speed) }.onFailure { error = it.message } },
        cancelTest = { Mkmobile.cancelTest() },
        sortBy = { value -> core { Mkmobile.setSettings(settings.copy(sortBy = value).toJson()) } },
        updateAndRank = { filter ->
            if (rankStage.isEmpty() && !test.running) {
                rankStage = "Updating subscriptions…"
                scope.launch {
                    withContext(Dispatchers.IO) { runCatching { Mkmobile.updateSubscriptions() } }
                    refresh()
                    // The accounts shown under the chosen group, as they are now.
                    val ids = accounts.list.filter { a ->
                        when (filter) {
                            "" -> true
                            "-" -> a.group.isEmpty()
                            else -> a.group == filter
                        }
                    }.map { it.id }
                    rankStage = ""
                    runCatching { Mkmobile.setSettings(loadSettings().copy(sortBy = "speed").toJson()) }
                    runCatching { Mkmobile.startTest(ids.joinToString(","), true) }.onFailure { error = it.message }
                    refresh()
                }
            }
        },
        newGroup = { newGroup = true },
        renameGroup = { g -> renaming = g },
        deleteGroup = { g -> core { Mkmobile.deleteGroup(g.id) } },
    )

    val selectedName = accounts.list.firstOrNull { it.id == accounts.active }?.name.orEmpty()

    BoxWithConstraints(Modifier.fillMaxSize()) {
        val wide = maxWidth >= 720.dp

        Scaffold(
            topBar = {
                Row(
                    Modifier.fillMaxWidth().statusBarsPadding().padding(start = 16.dp, end = 4.dp, top = 4.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text("MKConnect", style = MaterialTheme.typography.titleLarge, modifier = Modifier.weight(1f))
                    IconButton(onClick = { showAbout = true }) { Icon(Icons.Filled.Info, "About") }
                }
            },
            bottomBar = {
                if (!wide) {
                    NavigationBar {
                        Tab.entries.forEach { t ->
                            NavigationBarItem(tab == t.ordinal, { tab = t.ordinal }, { Icon(t.icon, null) }, label = { Text(t.label) })
                        }
                    }
                }
            },
            snackbarHost = { SnackbarHost(snackbar) },
        ) { padding ->
            val accountsPane: @Composable () -> Unit = {
                AccountsScreen(accounts, test, settings.sortBy, rankStage, actions, callbacks)
            }
            val settingsPane: @Composable () -> Unit = {
                SettingsScreen(options, status, { error = it }, { refresh() })
            }
            val connectBar: @Composable () -> Unit = {
                ConnectBar(status, selectedName, accounts.active.isNotEmpty()) {
                    if (status.busy) connection.disconnect() else connection.connect(settings.vpnMode)
                }
            }

            Row(Modifier.padding(padding).consumeWindowInsets(padding).imePadding().fillMaxSize()) {
                if (wide) {
                    NavigationRail {
                        Tab.entries.forEach { t ->
                            NavigationRailItem(tab == t.ordinal, { tab = t.ordinal }, { Icon(t.icon, null) }, label = { Text(t.label) })
                        }
                    }
                    Column(Modifier.weight(0.45f).fillMaxHeight()) {
                        Box(Modifier.weight(1f)) { accountsPane() }
                        connectBar()
                    }
                    VerticalDivider()
                    Box(Modifier.weight(0.55f).fillMaxHeight()) {
                        if (tab == Tab.LOGS.ordinal) LogsScreen() else settingsPane()
                    }
                } else {
                    Column(Modifier.fillMaxSize()) {
                        Box(Modifier.weight(1f)) {
                            when (tab) {
                                Tab.ACCOUNTS.ordinal -> accountsPane()
                                Tab.SETTINGS.ordinal -> settingsPane()
                                else -> LogsScreen()
                            }
                        }
                        if (tab != Tab.LOGS.ordinal) connectBar()
                    }
                }
            }
        }
    }

    error?.let {
        AlertDialog(
            onDismissRequest = { error = null },
            confirmButton = { TextButton({ error = null }) { Text("OK") } },
            text = { Text(it) },
        )
    }
    editing?.let { id ->
        EditorDialog(id, options, onClose = { editing = null }) { msg ->
            notify(msg)
            refresh()
        }
    }
    if (showImport) {
        ImportDialog(onClose = { showImport = false }, onNewAccount = { showImport = false; editing = "" }) { text, group ->
            import(text, group)
        }
    }
    if (newGroup) {
        PromptDialog("New group", "Name", "", onClose = { newGroup = false }) { name -> core { Mkmobile.addGroup(name) } }
    }
    renaming?.let { g ->
        PromptDialog("Rename group", "Name", g.name, onClose = { renaming = null }) { name -> core { Mkmobile.renameGroup(g.id, name) } }
    }
    moving?.let { a ->
        GroupPickerDialog(accounts.groups, onClose = { moving = null }) { groupId -> core { Mkmobile.setGroup(a.id, groupId) } }
    }
    if (showAbout) AboutDialog(onClose = { showAbout = false }, openUrl = openUrl)
}

/**
 * The connection's state and the one button that changes it: what is going
 * on in a word or two, which account and how much went through, Connect or
 * Disconnect beside it.
 */
@Composable
private fun ConnectBar(status: Status, selectedName: String, hasAccount: Boolean, onToggle: () -> Unit) {
    val colors = MaterialTheme.colorScheme
    Surface(tonalElevation = 3.dp) {
        Row(
            Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(Modifier.weight(1f)) {
                Text(
                    status.headline(),
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                    color = if (status.warning) colors.error else colors.onSurface,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    status.detail(selectedName),
                    style = MaterialTheme.typography.bodySmall,
                    color = colors.onSurfaceVariant,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            Spacer(Modifier.width(12.dp))
            Button(
                onClick = onToggle,
                enabled = status.busy || hasAccount,
                colors = if (status.busy) ButtonDefaults.buttonColors(containerColor = colors.error) else ButtonDefaults.buttonColors(),
                modifier = Modifier.height(48.dp),
            ) {
                Icon(if (status.busy) Icons.Filled.Stop else Icons.Filled.PlayArrow, null)
                Spacer(Modifier.width(6.dp))
                Text(if (status.busy) "Disconnect" else "Connect")
            }
        }
    }
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
