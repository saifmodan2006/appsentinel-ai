package org.apptrust.sentinel

import android.content.ContentResolver
import android.net.Uri
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URI
import java.net.URLEncoder

internal data class ApkFile(val uri: Uri, val name: String, val size: Long?)

internal class SentinelApi(endpoint: String) {
    private val base = URI(endpoint.trim())
    private var token: String? = null
    private val maximum = 512L * 1024 * 1024

    init {
        val local = BuildConfig.DEBUG && base.scheme == "http" && base.host == "10.0.2.2"
        require((base.scheme == "https" || local) && base.host != null &&
            base.userInfo == null && base.query == null && base.fragment == null &&
            base.path in listOf("", "/")) { "Enter a valid HTTPS server URL." }
    }

    suspend fun signIn(email: String, password: String) {
        val body = JSONObject().put("email", email).put("password", password).toString()
        val result = send("/auth/login?client=android", "POST", "application/json") { connection ->
            connection.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
        }
        token = result.getString("token")
    }

    suspend fun signOut() {
        try { send("/auth/logout", "POST") }
        finally { token = null }
    }

    suspend fun scans(offset: Int = 0) = send("/scans?limit=25&offset=$offset")
    suspend fun scan(id: String): JSONObject {
        require(runCatching { java.util.UUID.fromString(id).toString() == id }.getOrDefault(false))
        return send("/scans/$id")
    }

    suspend fun upload(resolver: ContentResolver, item: ApkFile): JSONObject {
        require(item.name.endsWith(".apk", true)) { "Choose a file ending in .apk." }
        require(item.size == null || item.size in 1..maximum) { "APK size is outside the supported range." }
        return send("/scans", "POST", "application/vnd.android.package-archive") { connection ->
            val name = URLEncoder.encode(item.name, "UTF-8").replace("+", "%20")
            connection.setRequestProperty("X-APK-Filename", name)
            connection.setChunkedStreamingMode(64 * 1024)
            val source = resolver.openInputStream(item.uri) ?: error("The file provider did not open this APK.")
            source.use { input ->
                connection.outputStream.use { output ->
                    val buffer = ByteArray(64 * 1024)
                    var total = 0L
                    while (true) {
                        val count = input.read(buffer)
                        if (count < 0) break
                        total += count
                        require(total <= maximum) { "APK exceeds the client size limit." }
                        output.write(buffer, 0, count)
                    }
                }
            }
        }
    }

    private fun read(stream: InputStream?): String = stream?.use { input ->
        val output = java.io.ByteArrayOutputStream()
        val buffer = ByteArray(8192)
        while (true) {
            val count = input.read(buffer)
            if (count < 0) break
            require(output.size() + count <= 9 * 1024 * 1024) { "Response exceeds the client size limit." }
            output.write(buffer, 0, count)
        }
        output.toString("UTF-8")
    } ?: ""

    private suspend fun send(path: String, method: String = "GET", contentType: String? = null,
                             body: ((HttpURLConnection) -> Unit)? = null): JSONObject = withContext(Dispatchers.IO) {
        val url = base.resolve("/api/v1$path").toURL()
        val connection = url.openConnection() as HttpURLConnection
        try {
            connection.requestMethod = method
            connection.instanceFollowRedirects = false
            connection.connectTimeout = 12000
            connection.readTimeout = 35000
            connection.setRequestProperty("Accept", "application/json")
            connection.setRequestProperty("X-Sentinel-Request", "1")
            token?.let { connection.setRequestProperty("Authorization", "Bearer $it") }
            if (body != null) {
                connection.doOutput = true
                connection.setRequestProperty("Content-Type", contentType)
                body(connection)
            }
            val code = connection.responseCode
            val ok = code in 200..299
            val payload = read(if (ok) connection.inputStream else connection.errorStream)
            val json = runCatching { JSONObject(payload) }.getOrElse { JSONObject() }
            if (code == 401) throw SessionExpired(json.optString("detail", "Sign in again."))
            if (!ok) {
                val detail = json.opt("detail")
                throw IllegalStateException(if (detail is String) detail else "Server returned HTTP $code.")
            }
            json
        } finally {
            connection.disconnect()
        }
    }
}

internal class SessionExpired(message: String) : IllegalStateException(message)
