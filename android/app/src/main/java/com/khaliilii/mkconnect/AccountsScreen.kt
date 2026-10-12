package com.khaliilii.mkconnect

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.ContentPaste
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Speed
import androidx.compose.material.icons.filled.Sort
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp

// The accounts screen: the desktop list, with what a phone needs — a search
// box, group chips, the measurements of the last server test and a long press
// for the per-account actions.

data class AccountActions(
    val select: (Account) -> Unit,
    val edit: (Account) -> Unit,
    val share: (Account) -> Unit,
    val delete: (Account) -> Unit,
    val test: (Account) -> Unit,
    val move: (Account) -> Unit,
)

@OptIn(ExperimentalFoundationApi::class)
@Composable
fun AccountsScreen(
    accounts: Accounts,
    test: TestRun,
    sortBy: String,
    actions: AccountActions,
    onImportClipboard: () -> Unit,
    onShowImport: () -> Unit,
    onNewAccount: () -> Unit,
    onUpdateSubs: () -> Unit,
    onStartTest: (Boolean) -> Unit,
    onCancelTest: () -> Unit,
    onSortBy: (String) -> Unit,
    onNewGroup: () -> Unit,
    onRenameGroup: (Group) -> Unit,
    onDeleteGroup: (Group) -> Unit,
) {
    var search by remember { mutableStateOf("") }
    var groupFilter by remember { mutableStateOf("") } // "" = all, "-" = ungrouped
    var menuFor by remember { mutableStateOf<Account?>(null) }
    var groupMenuFor by remember { mutableStateOf<Group?>(null) }
    var sortMenu by remember { mutableStateOf(false) }
    var testMenu by remember { mutableStateOf(false) }

    val shown = accounts.list.filter { a ->
        (search.isEmpty() || a.name.contains(search, true) || a.summary.contains(search, true)) &&
            when (groupFilter) {
                "" -> true
                "-" -> a.group.isEmpty()
                else -> a.group == groupFilter
            }
    }

    Column(Modifier.fillMaxSize()) {
        Row(
            Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 6.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Button(onClick = onImportClipboard, modifier = Modifier.weight(1f)) {
                Icon(Icons.Filled.ContentPaste, null); Spacer(Modifier.width(6.dp)); Text("Clipboard")
            }
            OutlinedButton(onClick = onShowImport, modifier = Modifier.weight(1f)) {
                Icon(Icons.Filled.Add, null); Spacer(Modifier.width(6.dp)); Text("Import")
            }
            IconButton(onClick = onNewAccount) { Icon(Icons.Filled.Add, "New account by hand") }
            Box {
                IconButton(onClick = { testMenu = true }) { Icon(Icons.Filled.Speed, "Test servers") }
                DropdownMenu(expanded = testMenu, onDismissRequest = { testMenu = false }) {
                    DropdownMenuItem(text = { Text("Test all (latency)") }, onClick = { testMenu = false; onStartTest(false) })
                    DropdownMenuItem(text = { Text("Test all (latency + speed)") }, onClick = { testMenu = false; onStartTest(true) })
                    if (test.running) {
                        DropdownMenuItem(text = { Text("Cancel the running test") }, onClick = { testMenu = false; onCancelTest() })
                    }
                }
            }
            Box {
                IconButton(onClick = { sortMenu = true }) { Icon(Icons.Filled.Sort, "Sort") }
                DropdownMenu(expanded = sortMenu, onDismissRequest = { sortMenu = false }) {
                    listOf("" to "As added", "latency" to "By latency", "speed" to "By speed").forEach { (value, label) ->
                        DropdownMenuItem(
                            text = { Text(if (value == sortBy) "✓ $label" else label) },
                            onClick = { sortMenu = false; onSortBy(value) },
                        )
                    }
                    HorizontalDivider()
                    DropdownMenuItem(text = { Text("New group…") }, onClick = { sortMenu = false; onNewGroup() })
                    if (accounts.groups.any { it.isSubscription }) {
                        DropdownMenuItem(text = { Text("Update subscriptions") }, onClick = { sortMenu = false; onUpdateSubs() })
                    }
                }
            }
        }

        Row(Modifier.fillMaxWidth().padding(horizontal = 12.dp)) {
            Field("", search, { search = it }, hint = "Search accounts")
        }

        if (accounts.groups.isNotEmpty()) {
            LazyRow(
                Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 6.dp),
                horizontalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                item {
                    FilterChip(groupFilter == "", { groupFilter = "" }, { Text("All (${accounts.list.size})") })
                }
                item {
                    FilterChip(groupFilter == "-", { groupFilter = "-" }, { Text("Ungrouped") })
                }
                items(accounts.groups) { g ->
                    FilterChip(
                        selected = groupFilter == g.id,
                        onClick = { groupFilter = g.id },
                        label = { Text("${g.name} (${g.count})") },
                    )
                }
            }
        }

        // Subscription usage, like the desktop usage card.
        accounts.groups.filter { it.isSubscription && it.usedText.isNotEmpty() }.forEach { g ->
            Card(Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 4.dp)) {
                Column(Modifier.padding(12.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(g.name, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
                        IconButton(onClick = onUpdateSubs) { Icon(Icons.Filled.Refresh, "Update") }
                        TextButton({ groupMenuFor = g }) { Text("…") }
                    }
                    if (g.total > 0) {
                        LinearProgressIndicator(
                            progress = { (g.used.toFloat() / g.total).coerceIn(0f, 1f) },
                            modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
                        )
                    }
                    Text("${g.usedText} · ${g.count} accounts", style = MaterialTheme.typography.bodySmall)
                }
            }
        }

        if (test.running || test.done > 0 && test.done < test.total) {
            Column(Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 4.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("Testing ${test.done} of ${test.total}…", style = MaterialTheme.typography.bodySmall, modifier = Modifier.weight(1f))
                    TextButton(onCancelTest) { Text("Cancel") }
                }
                LinearProgressIndicator(
                    progress = { if (test.total == 0) 0f else test.done.toFloat() / test.total },
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        }

        if (shown.isEmpty()) {
            Box(Modifier.weight(1f).fillMaxWidth(), contentAlignment = Alignment.Center) {
                Text(
                    if (accounts.list.isEmpty()) "No accounts yet.\nCopy a share link or subscription URL\nand tap Clipboard."
                    else "No account matches.",
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
        } else {
            LazyColumn(Modifier.weight(1f)) {
                items(shown, key = { it.id }) { a ->
                    val selected = a.id == accounts.active
                    Column(
                        Modifier.fillMaxWidth()
                            .background(if (selected) MaterialTheme.colorScheme.primaryContainer else Color.Transparent)
                            .combinedClickable(onClick = { actions.select(a) }, onLongClick = { menuFor = a })
                            .padding(horizontal = 16.dp, vertical = 10.dp),
                    ) {
                        Text(a.name, fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis)
                        Text(a.summary, style = MaterialTheme.typography.bodySmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
                        val measured = test.results[a.id] ?: a.test
                        if (measured.isNotEmpty()) {
                            Text(
                                measured,
                                style = MaterialTheme.typography.bodySmall,
                                color = if (a.testOk || measured.contains("ms")) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error,
                            )
                        }
                        if (a.group.isNotEmpty() && groupFilter == "") {
                            Text(accounts.groupName(a.group), style = MaterialTheme.typography.labelSmall)
                        }
                    }
                    HorizontalDivider()
                }
            }
        }
    }

    menuFor?.let { a ->
        AlertDialog(
            onDismissRequest = { menuFor = null },
            title = { Text(a.name) },
            text = {
                Column {
                    Text(a.summary, style = MaterialTheme.typography.bodySmall)
                    Spacer(Modifier.height(8.dp))
                    TextButton({ actions.edit(a); menuFor = null }) { Text("Edit") }
                    TextButton({ actions.test(a); menuFor = null }) { Text("Test this account") }
                    TextButton({ actions.share(a); menuFor = null }) { Text("Copy share link") }
                    TextButton({ actions.move(a); menuFor = null }) { Text("Move to group") }
                    TextButton({ actions.delete(a); menuFor = null }) { Text("Delete") }
                }
            },
            confirmButton = { TextButton({ menuFor = null }) { Text("Close") } },
        )
    }

    groupMenuFor?.let { g ->
        AlertDialog(
            onDismissRequest = { groupMenuFor = null },
            title = { Text(g.name) },
            text = {
                Column {
                    Text("${g.count} accounts", style = MaterialTheme.typography.bodySmall)
                    Spacer(Modifier.height(8.dp))
                    TextButton({ onRenameGroup(g); groupMenuFor = null }) { Text("Rename") }
                    TextButton({ onDeleteGroup(g); groupMenuFor = null }) { Text("Delete with its accounts") }
                }
            },
            confirmButton = { TextButton({ groupMenuFor = null }) { Text("Close") } },
        )
    }
}
