package com.khaliilii.mkconnect

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.systemBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.MenuAnchorType
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import kotlinx.coroutines.delay

// Small building blocks the forms are made of, so every screen looks the same
// and the account editor stays readable.

@Composable
fun Field(
    label: String,
    value: String,
    onChange: (String) -> Unit,
    hint: String = "",
    number: Boolean = false,
    password: Boolean = false,
    lines: Int = 1,
) {
    OutlinedTextField(
        value = value,
        onValueChange = onChange,
        label = { Text(label) },
        placeholder = if (hint.isEmpty()) null else ({ Text(hint) }),
        singleLine = lines == 1,
        minLines = lines,
        visualTransformation = if (password) PasswordVisualTransformation() else androidx.compose.ui.text.input.VisualTransformation.None,
        keyboardOptions = KeyboardOptions(keyboardType = if (number) KeyboardType.Number else KeyboardType.Text),
        modifier = Modifier.fillMaxWidth(),
    )
}

/**
 * A number setting: the text is the field's own while it is typed (it may be
 * empty or out of range for a moment), and a valid number is passed on once
 * typing pauses, not every digit on the way (port 1, 10, 108 for 1080);
 * until it is valid the field says what it takes.
 */
@Composable
fun NumberField(label: String, value: Int, valid: (Int) -> Boolean, rule: String, onChange: (Int) -> Unit) {
    var text by remember(value) { mutableStateOf(value.toString()) }
    val n = text.toIntOrNull()
    val ok = n != null && valid(n)
    LaunchedEffect(text) {
        delay(800)
        if (n != null && ok && n != value) onChange(n)
    }
    OutlinedTextField(
        value = text,
        onValueChange = { text = it.filter(Char::isDigit).take(5) },
        label = { Text(label) },
        isError = !ok,
        supportingText = if (ok) null else ({ Text(rule) }),
        singleLine = true,
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
        modifier = Modifier.fillMaxWidth(),
    )
}

/** A dropdown; an empty option is shown as "none". */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun Picker(label: String, options: List<String>, value: String, onChange: (String) -> Unit) {
    var open by remember { mutableStateOf(false) }
    val shown = { v: String -> if (v.isEmpty()) "none" else v }
    ExposedDropdownMenuBox(expanded = open, onExpandedChange = { open = it }) {
        OutlinedTextField(
            value = shown(value),
            onValueChange = {},
            readOnly = true,
            label = { Text(label) },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = open) },
            modifier = Modifier.fillMaxWidth().menuAnchor(MenuAnchorType.PrimaryNotEditable),
        )
        ExposedDropdownMenu(expanded = open, onDismissRequest = { open = false }) {
            options.forEach { option ->
                DropdownMenuItem(
                    text = { Text(shown(option)) },
                    onClick = { onChange(option); open = false },
                )
            }
        }
    }
}

@Composable
fun SwitchRow(label: String, checked: Boolean, hint: String = "", onChange: (Boolean) -> Unit) {
    Column(Modifier.fillMaxWidth()) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Switch(checked = checked, onCheckedChange = onChange)
            Spacer(Modifier.width(12.dp))
            Text(label, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
        }
        if (hint.isNotEmpty()) {
            Text(hint, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(start = 52.dp))
        }
    }
}

@Composable
fun SectionTitle(text: String) {
    Text(text, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold, modifier = Modifier.padding(top = 8.dp))
}

@Composable
fun Hint(text: String) {
    Text(text, style = MaterialTheme.typography.bodySmall, modifier = Modifier.fillMaxWidth())
}

/** A search or filter box: an icon instead of a label, and a button to clear it. */
@Composable
fun SearchField(value: String, onChange: (String) -> Unit, placeholder: String, modifier: Modifier = Modifier) {
    OutlinedTextField(
        value = value,
        onValueChange = onChange,
        placeholder = { Text(placeholder) },
        leadingIcon = { Icon(Icons.Filled.Search, null) },
        trailingIcon = {
            if (value.isNotEmpty()) {
                IconButton({ onChange("") }) { Icon(Icons.Filled.Close, "Clear") }
            }
        },
        singleLine = true,
        modifier = modifier,
    )
}

/**
 * A dialog that fills the screen, for forms too long for an alert: a bar with
 * close, the title and the action, and the content scrolling above the keyboard.
 */
@Composable
fun FullScreenDialog(
    title: String,
    actionLabel: String,
    onAction: () -> Unit,
    onClose: () -> Unit,
    content: @Composable ColumnScope.() -> Unit,
) {
    Dialog(onDismissRequest = onClose, properties = DialogProperties(usePlatformDefaultWidth = false)) {
        Surface(Modifier.fillMaxSize()) {
            Column(Modifier.fillMaxSize().systemBarsPadding().imePadding()) {
                Row(
                    Modifier.fillMaxWidth().padding(horizontal = 4.dp, vertical = 4.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    IconButton(onClose) { Icon(Icons.Filled.Close, "Close") }
                    Text(title, style = MaterialTheme.typography.titleLarge, modifier = Modifier.weight(1f))
                    Button(onAction, modifier = Modifier.padding(end = 8.dp)) { Text(actionLabel) }
                }
                HorizontalDivider()
                Column(
                    Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                    content = content,
                )
            }
        }
    }
}

/** Asks before something that can't be undone, naming what goes. */
@Composable
fun ConfirmDialog(title: String, text: String, confirmLabel: String, onConfirm: () -> Unit, onClose: () -> Unit) {
    AlertDialog(
        onDismissRequest = onClose,
        title = { Text(title) },
        text = { Text(text) },
        confirmButton = {
            TextButton({ onConfirm(); onClose() }) { Text(confirmLabel, color = MaterialTheme.colorScheme.error) }
        },
        dismissButton = { TextButton(onClose) { Text("Cancel") } },
    )
}
