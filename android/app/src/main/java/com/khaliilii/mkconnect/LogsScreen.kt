package com.khaliilii.mkconnect

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import mkmobile.Mkmobile

// The log screen the desktop app has: wrapped lines that can be read, a
// filter, a follow switch so reading isn't interrupted, copy and clear. The
// log level itself is in Settings, because the core needs it at startup.

@Composable
fun LogsScreen() {
    var lines by remember { mutableStateOf(listOf<String>()) }
    var filter by remember { mutableStateOf("") }
    var follow by remember { mutableStateOf(true) }
    var detail by remember { mutableStateOf<String?>(null) }
    val listState = rememberLazyListState()
    val clipboard = LocalClipboardManager.current

    LaunchedEffect(Unit) {
        while (true) {
            val text = withContext(Dispatchers.IO) { Mkmobile.logs(1000) }
            lines = if (text.isEmpty()) emptyList() else text.split("\n")
            delay(1500)
        }
    }
    val shown = if (filter.isEmpty()) lines else lines.filter { it.contains(filter, true) }
    LaunchedEffect(shown.size, follow) {
        if (follow && shown.isNotEmpty()) listState.scrollToItem(shown.size - 1)
    }

    Column(Modifier.fillMaxSize()) {
        Row(
            Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 4.dp),
            horizontalArrangement = Arrangement.spacedBy(4.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(Modifier.weight(1f)) { Field("", filter, { filter = it }, hint = "Filter") }
            Text("Follow", style = MaterialTheme.typography.labelMedium)
            Switch(follow, { follow = it })
            IconButton(onClick = { clipboard.setText(AnnotatedString(lines.joinToString("\n"))) }) {
                Icon(Icons.Filled.ContentCopy, "Copy all")
            }
            IconButton(onClick = { Mkmobile.clearLogs(); lines = emptyList() }) {
                Icon(Icons.Filled.Delete, "Clear")
            }
        }
        if (shown.isEmpty()) {
            Box(Modifier.weight(1f).fillMaxWidth(), contentAlignment = Alignment.Center) {
                Text(
                    if (lines.isEmpty()) "No logs yet. Connect to see the core's log." else "No line matches the filter.",
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
        } else {
            LazyColumn(state = listState, modifier = Modifier.weight(1f).fillMaxWidth()) {
                items(shown) { line ->
                    Text(
                        line,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 11.sp,
                        modifier = Modifier.fillMaxWidth()
                            .clickable { detail = line } // a tap shows the whole line, for copying
                            .padding(horizontal = 12.dp, vertical = 2.dp),
                    )
                }
            }
            Text(
                "${shown.size} lines" + if (filter.isEmpty()) "" else " of ${lines.size}",
                style = MaterialTheme.typography.labelSmall,
                modifier = Modifier.padding(horizontal = 12.dp, vertical = 2.dp),
            )
        }
    }

    detail?.let { line ->
        AlertDialog(
            onDismissRequest = { detail = null },
            text = { Text(line, fontFamily = FontFamily.Monospace, fontSize = 12.sp) },
            confirmButton = {
                TextButton({ clipboard.setText(AnnotatedString(line)); detail = null }) { Text("Copy") }
            },
            dismissButton = { TextButton({ detail = null }) { Text("Close") } },
        )
    }
}
