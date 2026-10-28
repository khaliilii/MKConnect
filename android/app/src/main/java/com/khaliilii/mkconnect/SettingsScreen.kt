package com.khaliilii.mkconnect

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Card
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp

// Every setting the desktop app has that means anything on a phone. Changes
// are saved as they are made (like the desktop panel) and apply to the next
// connection.

@Composable
fun SettingsScreen(options: Options, status: Status, onMessage: (String) -> Unit, onChanged: () -> Unit) {
    var s by remember { mutableStateOf(loadSettings()) }
    fun save(next: Settings) {
        s = next
        runCatching { mkmobile.Mkmobile.setSettings(next.toJson()) }
            .onSuccess { onChanged() }
            .onFailure { onMessage(it.message ?: "invalid settings") }
    }

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        if (status.busy) {
            ConnectionCard(status)
        }

        Text("Mode", fontWeight = FontWeight.Bold)
        Row(verticalAlignment = Alignment.CenterVertically) {
            RadioButton(s.vpnMode, { save(s.copy(vpnMode = true)) }); Text("VPN (all apps)")
            Spacer(Modifier.width(16.dp))
            RadioButton(!s.vpnMode, { save(s.copy(vpnMode = false)) }); Text("Proxy only")
        }
        Hint(
            if (s.vpnMode) "All apps go through the tunnel (Android asks for VPN permission the first time)."
            else "Only apps set to use the local proxy go through the tunnel."
        )

        HorizontalDivider()
        Text("Connection", fontWeight = FontWeight.Bold)
        Field("Local proxy port", s.port.toString(), { save(s.copy(port = it.toIntOrNull() ?: s.port)) }, number = true)
        SwitchRow(
            "Share the proxy with other devices (e.g. over this phone's hotspot)",
            s.allowLan,
        ) { save(s.copy(allowLan = it)) }
        if (s.allowLan && s.proxyUser.isEmpty()) {
            Hint("⚠ No proxy password set: anyone on the network can use it.")
        }
        Field("Proxy user (optional)", s.proxyUser, { save(s.copy(proxyUser = it)) })
        Field("Proxy password (optional)", s.proxyPass, { save(s.copy(proxyPass = it)) }, password = true)
        Field("DNS through the tunnel", s.remoteDns, { save(s.copy(remoteDns = it)) }, hint = "1.1.1.1")
        SwitchRow("IPv6 through the tunnel (only if the server has IPv6)", s.ipv6) { save(s.copy(ipv6 = it)) }
        SwitchRow(
            "Reconnect automatically when the connection drops or stops working",
            s.autoReconnect,
            hint = "The connection is checked every 45 seconds; after two failed checks it is started again.",
        ) { save(s.copy(autoReconnect = it)) }
        if (s.autoReconnect) {
            SwitchRow(
                "If the account keeps failing, switch to the fastest working one of its subscription",
                s.failover,
                hint = "Uses the last server test; accounts that bill extra usage (×2, ضریب مصرف) are never picked.",
            ) { save(s.copy(failover = it)) }
        }
        SwitchRow(
            "Open Iranian sites (.ir, Aparat, Digikala…) directly, not through the server",
            s.directIran,
            hint = "Faster for those sites, and it saves the server's traffic.",
        ) { save(s.copy(directIran = it)) }
        if (s.vpnMode) {
            SwitchRow(
                "Fast DNS (FakeIP): new sites don't wait for a DNS lookup through the tunnel",
                s.fakeDns,
            ) { save(s.copy(fakeDns = it)) }
        }
        SwitchRow(
            "Add share links found on the clipboard when the app opens",
            s.clipboardImport,
        ) { save(s.copy(clipboardImport = it)) }

        HorizontalDivider()
        Text("Advanced", fontWeight = FontWeight.Bold)
        Picker("Log level", options.logLevels, s.logLevel) { save(s.copy(logLevel = it)) }
        Picker("VPN network stack", listOf("", "system", "gvisor", "mixed"), s.tunStack) { save(s.copy(tunStack = it)) }
        Field(
            "VPN MTU (0 = default)", s.tunMtu.toString(),
            { save(s.copy(tunMtu = it.toIntOrNull() ?: 0)) }, number = true,
        )
        Hint("Changes apply on the next connect.")
    }
}

/** What the running connection is made of, as the desktop session box shows it. */
@Composable
fun ConnectionCard(status: Status) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(status.text(), fontWeight = FontWeight.SemiBold, style = MaterialTheme.typography.bodyMedium)
            if (status.outbound.isNotEmpty()) {
                Text("Outbound: ${status.outbound}", style = MaterialTheme.typography.bodySmall)
            }
            status.inbounds.forEach { Text("Inbound: $it", style = MaterialTheme.typography.bodySmall) }
            if (status.core.isNotEmpty()) {
                Text("Core: ${status.core}", style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}
