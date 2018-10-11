package burp

import org.json.JSONArray
import org.json.JSONObject
import org.json.JSONTokener
import java.awt.event.ActionEvent
import java.awt.event.ActionListener
import java.net.URL
import java.net.URLDecoder
import java.util.regex.Pattern
import javax.swing.Timer

class BurpExtender: IBurpExtender, IExtensionStateListener {
    companion object {
        lateinit var callbacks: IBurpExtenderCallbacks
    }

    lateinit var timer: Timer

    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks) {
        Companion.callbacks = callbacks
        callbacks.setExtensionName("Macro Payload Generator")
        timer = Timer(10000, SyncFactories())
        timer.initialDelay = 0
        callbacks.registerExtensionStateListener(this)
        timer.start()
    }

    override fun extensionUnloaded() {
        timer.stop()
    }
}


class SyncFactories(): ActionListener {

    override fun actionPerformed(e: ActionEvent?) {
        val registeredFactories = mutableMapOf<String, IIntruderPayloadGeneratorFactory>()
        for(factory in BurpExtender.callbacks.intruderPayloadGeneratorFactories) {
            registeredFactories[(factory as IntruderPayloadGeneratorFactory).macroName] = factory
        }
        for(macro in listMacros()) {
            if(registeredFactories.remove(macro) == null) {
                BurpExtender.callbacks.registerIntruderPayloadGeneratorFactory(IntruderPayloadGeneratorFactory(macro))
            }
        }
        for(factory in registeredFactories.values) {
            BurpExtender.callbacks.removeIntruderPayloadGeneratorFactory(factory)
        }
    }

    fun listMacros(): List<String> {
        val macros = getMacrosJSON()
        val rc = mutableListOf<String>()
        for(i in 0 until macros.length()) {
            val macro = macros.getJSONObject(i)
            val items = macro.getJSONArray("items")
            if(items.length() != 1) {
                continue
            }
            val customParameters = items.getJSONObject(0).getJSONArray("custom_parameters")
            if(customParameters.length() != 1) {
                continue
            }
            rc.add(macros.getJSONObject(i).getString("description"))
        }
        return rc
    }
}


fun getMacrosJSON(): JSONArray {
    val configString = BurpExtender.callbacks.saveConfigAsJson("project_options.sessions.macros.macros")
    val root = JSONObject(JSONTokener(configString))
    return root.getJSONObject("project_options")
            .getJSONObject("sessions")
            .getJSONObject("macros")
            .getJSONArray("macros")
}


class IntruderPayloadGeneratorFactory(val macroName: String) : IIntruderPayloadGeneratorFactory {
    override val generatorName = "Run macro: " + macroName
    override fun createNewInstance(attack: IIntruderAttack) = IntruderPayloadGenerator(macroName)
}


class IntruderPayloadGenerator(val macroName: String): IIntruderPayloadGenerator {
    val macro = getMacro(macroName)
    val item = macro.getJSONArray("items").getJSONObject(0)
    val request = item.getString("request").toByteArray(Charsets.ISO_8859_1)
    val url = URL(item.getString("url"))
    val httpService = BurpExtender.callbacks.helpers.buildHttpService(url.host, url.port, url.protocol)
    val customParameter = item.getJSONArray("custom_parameters").getJSONObject(0)

    override fun getNextPayload(baseValue: ByteArray): ByteArray {
        val response = BurpExtender.callbacks.makeHttpRequest(httpService, request)
        return extractCustomParameter(String(response.response, Charsets.ISO_8859_1)).toByteArray(Charsets.ISO_8859_1)
    }

    fun extractCustomParameter(response: String): String {
        val caseSensitive = customParameter.getBoolean("case_sensitive")
        var value = ""
        if(customParameter.getString("extract_mode") == "define_start_and_end") {
            var startOffset: Int
            if(customParameter.getString("start_at_mode") == "after_expression") {
                val expression = customParameter.getString("start_after_expression")
                startOffset = response.indexOf(expression, 0, caseSensitive) + expression.length
            }
            else {
                startOffset = customParameter.getInt("start_af_offset")
            }

            var length: Int
            if(customParameter.getString("end_mode") == "at_delimiter") {
                val expression = customParameter.getString("end_at_delimiter")
                length = response.indexOf(expression, startOffset, caseSensitive) - startOffset
            }
            else {
                length = customParameter.getInt("end_at_fixed_length")
            }

            value = response.substring(startOffset, startOffset + length)
        }
        else {
            val pattern = Pattern.compile(customParameter.getString("regular_expression"), if (!caseSensitive) { Pattern.CASE_INSENSITIVE } else { 0 } )
            with(pattern.matcher(response)) {
                find()
                value = group(1)
            }
        }

        if(customParameter.getBoolean("url_encoded")) {
            value = URLDecoder.decode(value, "ISO_8859_1")
        }
        return value
    }

    override fun hasMorePayloads() = true
    override fun reset() {}

    fun getMacro(macroName: String): JSONObject {
        val macros = getMacrosJSON()
        for(i in 0 until macros.length()) {
            val jsonObject = macros.getJSONObject(i)
            if(jsonObject.getString("description") == macroName) {
                return jsonObject
            }
        }
        throw IllegalArgumentException(macroName)
    }
}
