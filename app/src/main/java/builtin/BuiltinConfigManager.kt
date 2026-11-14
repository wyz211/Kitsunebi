package builtin

import android.content.Context
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.util.Base64
import kotlin.concurrent.thread

sealed class BuiltinError : Exception() {
    class MissingTemplate : BuiltinError()
    class BadEndpoint : BuiltinError()
    class BadPublicKey : BuiltinError()
    class Network : BuiltinError()
    class BadSignature : BuiltinError()
    class BadJson : BuiltinError()
}

class BuiltinConfigManager private constructor(private val ctx: Context) {

    companion object {
        @Volatile private var instance: BuiltinConfigManager? = null
        fun get(context: Context): BuiltinConfigManager =
            instance ?: synchronized(this) {
                instance ?: BuiltinConfigManager(context.applicationContext).also { instance = it }
            }
    }

    fun loadBuiltinRules(): List<String> {
        val text = ctx.assets.open("builtin/rule.txt").bufferedReader().use { it.readText() }
        return text.lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() && !it.startsWith("#") }
            .toList()
    }

    fun loadBuiltinConfig(): JSONObject? = try {
        val text = ctx.assets.open("builtin/config.json").bufferedReader().use { it.readText() }
        JSONObject(text)
    } catch (e: Exception) { null }

    fun downloadBuiltinConfig(callback: (Result<JSONObject>) -> Unit) {
        val template = loadBuiltinConfig()
            ?: return callback(Result.failure(BuiltinError.MissingTemplate()))

        val endpoint = template.optString("downloadEndpoint", "")
        if (endpoint.isEmpty() || !endpoint.startsWith("https://"))
            return callback(Result.failure(BuiltinError.BadEndpoint()))

        val pkB64 = template.optString("publicKey", "")
        val pkBytes = try { Base64.getDecoder().decode(pkB64) } catch (e: Exception) { null }
        if (pkBytes == null || pkBytes.size != 32)
            return callback(Result.failure(BuiltinError.BadPublicKey()))

        thread {
            try {
                val configBytes = httpGet(endpoint)
                val sigText = String(httpGet("$endpoint.sig"), Charsets.UTF_8).trim()
                val sigBytes = Base64.getDecoder().decode(sigText)

                if (!Ed25519Verifier.verify(pkBytes, configBytes, sigBytes))
                    return@thread callback(Result.failure(BuiltinError.BadSignature()))

                val json = JSONObject(String(configBytes, Charsets.UTF_8))
                File(ctx.filesDir, "builtin_config.json").writeBytes(configBytes)
                callback(Result.success(json))
            } catch (e: Exception) {
                callback(Result.failure(BuiltinError.Network()))
            }
        }
    }

    private fun httpGet(urlStr: String): ByteArray {
        val conn = URL(urlStr).openConnection() as HttpURLConnection
        conn.connectTimeout = 15000
        conn.readTimeout = 15000
        conn.requestMethod = "GET"
        conn.setRequestProperty("Cache-Control", "no-cache")
        return try {
            if (conn.responseCode !in 200..299) throw BuiltinError.Network()
            conn.inputStream.use { it.readBytes() }
        } finally {
            conn.disconnect()
        }
    }
}
