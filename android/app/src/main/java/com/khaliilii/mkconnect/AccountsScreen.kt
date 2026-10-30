package com.khaliilii.mkconnect

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.ContentPaste
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Speed
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
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp

// The accounts screen: a search bar with the Add and More menus, then one
// scrolling list — Update & test, the group chips, subscription usage and the
// accounts — so nothing above the accounts can squeeze them off a small or
// landscape screen. Every account has its actions behind a visible ⋮ button
// (a long press opens them too).

data class AccountActions(
    val select: (Account) -> Unit,
    val edit: (Account) -> Unit,
    val share: (Account) -> Unit,
    val delete: (Account) -> Unit,
    val test: (Account) -> Unit,
    val move: (Account) -> Unit,
)

/** What the screen asks of the app, apart from the per-account actions. */
data class AccountsCallbacks(
    val pasteClipboard: () -> Unit,
    val showImport: () -> Unit,
    val newAccount: () -> Unit,
    val updateSubscriptions: () -> Unit,
    val startTest: (speed: Boolean) -> Unit,
    val cancelTest: () -> Unit,
    val sortBy: (String) -> Unit,
    val updateAndRank: (groupFilter: String) -> Unit,
    val newGroup: () -> Unit,
    val renameGroup: (Group) -> Unit,
    val deleteGroup: (Group) -> Unit,
)

// Group filter values besides a group id.
private const val ALL = ""
private const val UNGROUPED = "-"

private val sortOrders = listOf("" to "As added", "latency" to "By latency", "speed" to "By speed")

@Composable
fun AccountsScreen(
    accounts: Accounts,
    test: TestRun,
    sortBy: String,
    rankStage: String,
    actions: AccountActions,
    on: AccountsCallbacks,
) {
    var search by rememberSaveable { mutableStateOf("") }
    var groupFilter by rememberSaveable { mutableStateOf(ALL) }
    var deleting by remember { mutableStateOf<Account?>(null) }
    var deletingGroup by remember { mutableStateOf<Group?>(null) }

    val shown = accounts.list.filter { a ->
        (search.isEmpty() || a.name.contains(search, true) || a.summary.contains(search, true)) &&
            when (groupFilter) {
                ALL -> true
                UNGROUPED -> a.group.isEmpty()
                else -> a.group == groupFilter
            }
    }
    val usage = accounts.groups.filter {
        it.isSubscription && it.usedText.isNotEmpty() && (groupFilter == ALL || groupFilter == it.id)
    }
    val busy = rankStage.isNotEmpty() || test.running

    Column(Modifier.fillMaxSize()) {
        Row(
            Modifier.fillMaxWidth().padding(start = 12.dp, end = 4.dp, top = 4.dp, bottom = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            SearchField(search, { search = it }, "Search accounts", Modifier.weight(1f))
            AddMenu(on)
            MoreMenu(accounts, test, sortBy, on)
        }

        LazyColumn(Modifier.weight(1f).fillMaxWidth(), contentPadding = PaddingValues(bottom = 8.dp)) {
            if (accounts.list.isNotEmpty()) {
                item(key = "rank") {
                    // One tap to pick a server: refresh the subscriptions, measure
                    // every account shown (latency, speed, sites), sort by speed.
                    Button(
                        onClick = { on.updateAndRank(groupFilter) },
                        enabled = !busy,
                        modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 4.dp),
                    ) {
                        Icon(Icons.Filled.Speed, null)
                        Spacer(Modifier.width(8.dp))
                        Text("Update & test")
                    }
                }
            }
            if (rankStage.isNotEmpty() || test.running) {
                item(key = "progress") { TestProgress(rankStage, test, on.cancelTest) }
            }
            if (accounts.groups.isNotEmpty()) {
                item(key = "groups") {
                    GroupChips(accounts, groupFilter) { groupFilter = it }
                }
            }
            items(usage, key = { "usage-" + it.id }) { g ->
                UsageCard(g, on.updateSubscriptions, on.renameGroup) { deletingGroup = g }
            }
            if (shown.isEmpty()) {
                item(key = "empty") { EmptyAccounts(accounts.list.isEmpty(), on) }
            }
            items(shown, key = { it.id }) { a ->
                AccountRow(
                    account = a,
                    selected = a.id == accounts.active,
                    measured = test.results[a.id] ?: a.test,
                    groupName = if (groupFilter == ALL) accounts.groupName(a.group) else "",
                    actions = actions,
                    onDelete = { deleting = a },
                )
                HorizontalDivider()
            }
        }
    }

    deleting?.let { a ->
        ConfirmDialog("Delete account?", "\"${a.name}\" will be removed from this phone.", "Delete",
            onConfirm = { actions.delete(a) }, onClose = { deleting = null })
    }
    deletingGroup?.let { g ->
        ConfirmDialog(
            "Delete ${g.name}?",
            "The group and its ${g.count} account(s) will be removed from this phone.",
            "Delete",
            onConfirm = { on.deleteGroup(g) }, onClose = { deletingGroup = null },
        )
    }
}

@Composable
private fun AddMenu(on: AccountsCallbacks) {
    var open by remember { mutableStateOf(false) }
    Box {
        IconButton({ open = true }) { Icon(Icons.Filled.Add, "Add accounts") }
        DropdownMenu(open, { open = false }) {
            DropdownMenuItem(
                text = { Text("Paste links from the clipboard") },
                leadingIcon = { Icon(Icons.Filled.ContentPaste, null) },
                onClick = { open = false; on.pasteClipboard() },
            )
            DropdownMenuItem(text = { Text("Import links or a subscription…") }, onClick = { open = false; on.showImport() })
            DropdownMenuItem(text = { Text("Add an account by hand…") }, onClick = { open = false; on.newAccount() })
        }
    }
}

@Composable
private fun MoreMenu(accounts: Accounts, test: TestRun, sortBy: String, on: AccountsCallbacks) {
    var open by remember { mutableStateOf(false) }
    val checked: @Composable (Boolean) -> Unit = { if (it) Icon(Icons.Filled.Check, "Selected") }
    Box {
        IconButton({ open = true }) { Icon(Icons.Filled.MoreVert, "More") }
        DropdownMenu(open, { open = false }) {
            if (test.running) {
                DropdownMenuItem(text = { Text("Cancel the running test") }, onClick = { open = false; on.cancelTest() })
            } else {
                DropdownMenuItem(text = { Text("Test all: latency") }, onClick = { open = false; on.startTest(false) })
                DropdownMenuItem(text = { Text("Test all: latency, speed and sites") }, onClick = { open = false; on.startTest(true) })
            }
            HorizontalDivider()
            sortOrders.forEach { (value, label) ->
                DropdownMenuItem(
                    text = { Text("Sort: $label") },
                    trailingIcon = { checked(value == sortBy) },
                    onClick = { open = false; on.sortBy(value) },
                )
            }
            HorizontalDivider()
            DropdownMenuItem(text = { Text("New group…") }, onClick = { open = false; on.newGroup() })
            if (accounts.groups.any { it.isSubscription }) {
                DropdownMenuItem(text = { Text("Update subscriptions") }, onClick = { open = false; on.updateSubscriptions() })
            }
        }
    }
}

@Composable
private fun TestProgress(rankStage: String, test: TestRun, onCancel: () -> Unit) {
    Column(Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 4.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                rankStage.ifEmpty { "Testing ${test.done} of ${test.total}…" },
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.weight(1f),
            )
            if (test.running) TextButton(onCancel) { Text("Cancel") }
        }
        if (rankStage.isNotEmpty() || test.total == 0) {
            LinearProgressIndicator(Modifier.fillMaxWidth())
        } else {
            LinearProgressIndicator(
                progress = { test.done.toFloat() / test.total },
                modifier = Modifier.fillMaxWidth(),
            )
        }
    }
}

@Composable
private fun GroupChips(accounts: Accounts, filter: String, onFilter: (String) -> Unit) {
    val ungrouped = accounts.list.count { it.group.isEmpty() }
    LazyRow(
        Modifier.fillMaxWidth().padding(vertical = 4.dp),
        contentPadding = PaddingValues(horizontal = 12.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        item { FilterChip(filter == ALL, { onFilter(ALL) }, { Text("All (${accounts.list.size})") }) }
        if (ungrouped > 0) {
            item { FilterChip(filter == UNGROUPED, { onFilter(UNGROUPED) }, { Text("No group ($ungrouped)") }) }
        }
        items(accounts.groups, key = { it.id }) { g ->
            FilterChip(filter == g.id, { onFilter(g.id) }, { Text("${g.name} (${g.count})", maxLines = 1) })
        }
    }
}

@Composable
private fun UsageCard(g: Group, onUpdate: () -> Unit, onRename: (Group) -> Unit, onDelete: () -> Unit) {
    var menu by remember { mutableStateOf(false) }
    Card(Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 4.dp)) {
        Column(Modifier.padding(start = 16.dp, end = 4.dp, top = 4.dp, bottom = 12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(g.name, fontWeight = FontWeight.Bold, maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f))
                IconButton(onUpdate) { Icon(Icons.Filled.Refresh, "Update subscription") }
                Box {
                    IconButton({ menu = true }) { Icon(Icons.Filled.MoreVert, "Subscription actions") }
                    DropdownMenu(menu, { menu = false }) {
                        DropdownMenuItem(text = { Text("Rename") }, onClick = { menu = false; onRename(g) })
                        DropdownMenuItem(text = { Text("Delete with its accounts") }, onClick = { menu = false; onDelete() })
                    }
                }
            }
            if (g.total > 0) {
                LinearProgressIndicator(
                    progress = { (g.used.toFloat() / g.total).coerceIn(0f, 1f) },
                    modifier = Modifier.fillMaxWidth().padding(end = 12.dp, bottom = 6.dp),
                )
            }
            Text("${g.usedText} · ${g.count} accounts", style = MaterialTheme.typography.bodySmall)
        }
    }
}

@Composable
private fun EmptyAccounts(noAccounts: Boolean, on: AccountsCallbacks) {
    Column(
        Modifier.fillMaxWidth().padding(horizontal = 24.dp, vertical = 48.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        if (!noAccounts) {
            Text("No account matches.", style = MaterialTheme.typography.bodyLarge)
            return@Column
        }
        Text("No accounts yet", style = MaterialTheme.typography.titleMedium)
        Text(
            "Copy share links (vmess://, vless://, …) or a subscription address, then paste them here.",
            style = MaterialTheme.typography.bodyMedium,
            textAlign = TextAlign.Center,
        )
        Button(on.pasteClipboard) {
            Icon(Icons.Filled.ContentPaste, null)
            Spacer(Modifier.width(8.dp))
            Text("Paste from clipboard")
        }
        OutlinedButton(on.showImport) { Text("Import or add by hand…") }
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun AccountRow(
    account: Account,
    selected: Boolean,
    measured: String,
    groupName: String,
    actions: AccountActions,
    onDelete: () -> Unit,
) {
    var menu by remember { mutableStateOf(false) }
    val colors = MaterialTheme.colorScheme
    Row(
        Modifier.fillMaxWidth()
            .background(if (selected) colors.secondaryContainer else Color.Transparent)
            .combinedClickable(onClick = { actions.select(account) }, onLongClick = { menu = true })
            .padding(start = 4.dp, end = 4.dp, top = 6.dp, bottom = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        RadioButton(selected, { actions.select(account) })
        Column(Modifier.weight(1f).padding(vertical = 4.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(account.name, fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Text(
                account.summary,
                style = MaterialTheme.typography.bodySmall,
                color = colors.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            if (measured.isNotEmpty()) {
                Text(
                    measured,
                    style = MaterialTheme.typography.bodySmall,
                    color = when (measuredOf(measured)) {
                        Measured.FAILED -> colors.error
                        Measured.PARTLY -> colors.tertiary
                        Measured.OK -> colors.primary
                    },
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            if (groupName.isNotEmpty()) {
                Text(groupName, style = MaterialTheme.typography.labelSmall, color = colors.onSurfaceVariant, maxLines = 1)
            }
        }
        Box {
            IconButton({ menu = true }) { Icon(Icons.Filled.MoreVert, "Actions for ${account.name}") }
            DropdownMenu(menu, { menu = false }) {
                DropdownMenuItem(text = { Text("Edit") }, onClick = { menu = false; actions.edit(account) })
                DropdownMenuItem(text = { Text("Test this account") }, onClick = { menu = false; actions.test(account) })
                DropdownMenuItem(text = { Text("Copy share link") }, onClick = { menu = false; actions.share(account) })
                DropdownMenuItem(text = { Text("Move to group…") }, onClick = { menu = false; actions.move(account) })
                HorizontalDivider()
                DropdownMenuItem(
                    text = { Text("Delete…", color = colors.error) },
                    onClick = { menu = false; onDelete() },
                )
            }
        }
    }
}
