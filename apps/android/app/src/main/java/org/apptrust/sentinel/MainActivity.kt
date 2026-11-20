package org.apptrust.sentinel

import android.net.Uri
import android.os.Bundle
import android.provider.OpenableColumns
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.darkColorScheme
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            MaterialTheme(colorScheme = darkColorScheme(
                primary = Color(0xFF70E3F1), background = Color(0xFF0B111D),
                surface = Color(0xFF121C2C)
            )) { Sentinel() }
        }
    }
}

private fun JSONArray?.objects(): List<JSONObject> = this?.let { values ->
    (0 until values.length()).mapNotNull { values.optJSONObject(it) }
} ?: emptyList()

private fun JSONArray?.lines(): String = this?.let { values ->
    (0 until values.length()).joinToString("\n") { values.optString(it) }
}.orEmpty()

private fun display(value: String) = value.replace("_", " ").replaceFirstChar { it.uppercaseChar() }

@Composable
private fun Sentinel() {
    val resolver = LocalContext.current.contentResolver
    val scope = rememberCoroutineScope()
    var endpoint by remember { mutableStateOf(if (BuildConfig.DEBUG) "http://10.0.2.2:8080" else "") }
    var email by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var client by remember { mutableStateOf<SentinelApi?>(null) }
    var picked by remember { mutableStateOf<ApkFile?>(null) }
    var consent by remember { mutableStateOf(false) }
    var selected by remember { mutableStateOf<String?>(null) }
    var report by remember { mutableStateOf<JSONObject?>(null) }
    var history by remember { mutableStateOf<List<JSONObject>>(emptyList()) }
    var hasMore by remember { mutableStateOf(false) }
    var offset by remember { mutableIntStateOf(0) }
    var reload by remember { mutableIntStateOf(0) }
    var busy by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf("") }

    fun clearSession() {
        client = null
        picked = null
        consent = false
        selected = null
        report = null
        history = emptyList()
        offset = 0
        hasMore = false
    }

    fun failure(error: Exception) {
        if (error is CancellationException) throw error
        if (error is SessionExpired && client != null) clearSession()
        message = error.localizedMessage ?: "The request failed."
    }

    fun work(block: suspend () -> Unit) {
        if (busy) return
        busy = true
        message = ""
        scope.launch {
            try { block() }
            catch (error: Exception) { failure(error) }
            finally { busy = false }
        }
    }

    fun pickDetails(uri: Uri): ApkFile {
        val columns = arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE)
        return resolver.query(uri, columns, null, null, null)?.use { cursor ->
            if (!cursor.moveToFirst()) return@use null
            val nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            val sizeIndex = cursor.getColumnIndex(OpenableColumns.SIZE)
            val name = if (nameIndex >= 0) cursor.getString(nameIndex) else null
            val size = if (sizeIndex >= 0 && !cursor.isNull(sizeIndex)) cursor.getLong(sizeIndex) else null
            ApkFile(uri, name ?: "selected.apk", size)
        } ?: ApkFile(uri, "selected.apk", null)
    }

    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) work {
            picked = withContext(Dispatchers.IO) { pickDetails(uri) }
            consent = false
        }
    }

    LaunchedEffect(client, selected, offset, reload) {
        val api = client ?: return@LaunchedEffect
        try {
            val id = selected
            if (id == null) {
                val data = api.scans(offset)
                history = data.optJSONArray("items").objects()
                hasMore = offset + history.size < data.optInt("total")
                return@LaunchedEffect
            }
            do {
                val scan = api.scan(id)
                report = scan
                val active = scan.optString("status") in listOf("queued", "running")
                if (!active) break
                delay(1500)
            } while (true)
        } catch (error: Exception) { failure(error) }
    }

    Scaffold { padding ->
        LazyColumn(
            modifier = Modifier.padding(padding).padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            item { Text("AppTrust Sentinel", style = MaterialTheme.typography.headlineMedium) }
            if (message.isNotEmpty()) item { Text(message, color = MaterialTheme.colorScheme.error) }
            if (busy) item { LinearProgressIndicator(Modifier.fillMaxWidth()) }
            val api = client
            if (api == null) {
                item {
                    Text("Sign in to your Sentinel workspace. Create an account in the web dashboard first.")
                    OutlinedTextField(endpoint, { endpoint = it }, label = { Text("Server URL") },
                        singleLine = true, modifier = Modifier.fillMaxWidth())
                    OutlinedTextField(email, { email = it }, label = { Text("Email") },
                        singleLine = true, modifier = Modifier.fillMaxWidth())
                    OutlinedTextField(password, { password = it }, label = { Text("Password") },
                        singleLine = true, visualTransformation = PasswordVisualTransformation(),
                        modifier = Modifier.fillMaxWidth())
                    Button(enabled = !busy && email.isNotBlank() && password.isNotEmpty(), onClick = {
                        work {
                            val next = SentinelApi(endpoint)
                            try { next.signIn(email.trim(), password); client = next }
                            finally { password = "" }
                        }
                    }) { Text("Sign in") }
                }
            } else if (selected != null) {
                item {
                    TextButton(onClick = { selected = null; report = null; message = "" }) { Text("Back to scans") }
                    val current = report
                    Text(current?.optString("filename") ?: "Loading scan", style = MaterialTheme.typography.titleLarge)
                    if (current != null) {
                        Text(display(current.optString("status")))
                        current.optString("error").takeUnless { it.isBlank() || it == "null" }?.let { Text(it) }
                        current.optJSONObject("report")?.let { SecurityReport(it) }
                    }
                    if (!busy && message.isNotEmpty()) TextButton(onClick = { message = ""; reload++ }) { Text("Retry") }
                }
            } else {
                item {
                    TextButton(enabled = !busy, onClick = { work { try { api.signOut() } finally { clearSession() } } }) { Text("Sign out") }
                    Text("Scan an APK", style = MaterialTheme.typography.titleLarge)
                    Button(enabled = !busy, onClick = { picker.launch(arrayOf("application/vnd.android.package-archive", "application/octet-stream")) }) {
                        Text("Choose APK")
                    }
                    picked?.let { file ->
                        Text(file.name + (file.size?.let { " · $it bytes" } ?: ""))
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Checkbox(checked = consent, onCheckedChange = { consent = it })
                            Text("I consent to upload this APK to the configured server for static analysis.")
                        }
                        Button(enabled = consent && !busy, onClick = {
                            work {
                                val result = api.upload(resolver, file)
                                report = result
                                selected = result.getString("id")
                                picked = null
                                consent = false
                            }
                        }) { Text("Upload and scan") }
                    }
                }
                item {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text("Scan history", style = MaterialTheme.typography.titleLarge)
                        TextButton(onClick = { message = ""; reload++ }) { Text("Refresh") }
                    }
                    if (history.isEmpty()) Text("No scans on this page.")
                }
                items(history, key = { it.getString("id") }) { job ->
                    Card(onClick = { selected = job.getString("id"); report = job; message = "" },
                        modifier = Modifier.fillMaxWidth()) {
                        Column(Modifier.padding(14.dp)) {
                            Text(job.optString("filename"))
                            Text(display(job.optString("status")) + (if (job.isNull("risk")) "" else " · " + display(job.optString("risk"))))
                        }
                    }
                }
                item {
                    Row {
                        TextButton(enabled = offset > 0, onClick = { offset -= 25 }) { Text("Previous") }
                        TextButton(enabled = hasMore, onClick = { offset += 25 }) { Text("Next") }
                    }
                }
            }
        }
    }
}

@Composable
private fun SecurityReport(report: JSONObject) {
    var details by remember { mutableStateOf(false) }
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        val identity = report.optJSONObject("identity")
        val meta = report.optJSONObject("metadata")
        val signing = report.optJSONObject("signing")
        val assessment = report.optJSONObject("assessment")
        Text("Risk assessment", style = MaterialTheme.typography.titleLarge)
        Text(display(assessment?.optString("level").orEmpty()))
        Text(assessment?.optJSONArray("reasons").lines())
        Text("Publisher authenticity", style = MaterialTheme.typography.titleMedium)
        Text(display(identity?.optString("verdict").orEmpty()))
        Text(identity?.optString("reason").orEmpty())
        Text("APK information", style = MaterialTheme.typography.titleMedium)
        Text(meta?.optString("package").orEmpty() + "\nSHA-256 " + report.optString("sha256"))
        Text("Signing verification · " + display(signing?.optString("status").orEmpty()))
        Text(signing?.optJSONArray("sha256").lines().ifBlank { signing?.optString("reason").orEmpty() })
        Text("Model", style = MaterialTheme.typography.titleMedium)
        Text(report.optJSONObject("model")?.optString("reason").orEmpty())
        Text("Findings", style = MaterialTheme.typography.titleMedium)
        val findings = report.optJSONArray("findings").objects()
        if (findings.isEmpty()) Text("No rule findings for the available checks.")
        findings.forEach { finding ->
            Text(finding.optString("title") + " · " + display(finding.optString("severity")))
            Text(finding.optString("description"))
            Text(finding.optString("action"))
        }
        Text("Coverage and limitations", style = MaterialTheme.typography.titleMedium)
        Text(report.optJSONArray("limitations").lines())
        report.optJSONArray("missing").objects().forEach {
            Text(it.optString("field") + " · " + it.optString("reason"))
        }
        TextButton(onClick = { details = !details }) { Text(if (details) "Hide structured report" else "Show structured report") }
        if (details) Text(report.toString(2))
    }
}
