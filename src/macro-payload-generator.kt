package burp

import com.google.gson.Gson
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
        val registeredFactories = BurpExtender.callbacks.intruderPayloadGeneratorFactories.map { (it as IntruderPayloadGeneratorFactory).macroName to it }.toMap().toMutableMap()
        val macros = getMacros().filter{ it.items.size == 1 && it.items[0].custom_parameters.size == 1 }.map{ it.description }
        macros.filter{ registeredFactories.remove(it) == null }.forEach{
            BurpExtender.callbacks.registerIntruderPayloadGeneratorFactory(IntruderPayloadGeneratorFactory(it))
        }
        registeredFactories.values.forEach { BurpExtender.callbacks.removeIntruderPayloadGeneratorFactory(it) }
    }
}


fun getMacros(): List<Macro> {
    val configString = BurpExtender.callbacks.saveConfigAsJson("project_options.sessions.macros.macros")
    try {
        val root = Gson().fromJson(configString, Root::class.java)
        return root.project_options.sessions.macros.macros
    }
    catch(ex: Exception) {
        BurpExtender.callbacks.printError(ex.toString())
        throw ex
    }
}


class IntruderPayloadGeneratorFactory(val macroName: String) : IIntruderPayloadGeneratorFactory {
    override val generatorName = "Run macro: $macroName"
    override fun createNewInstance(attack: IIntruderAttack) = IntruderPayloadGenerator(macroName)
}


class IntruderPayloadGenerator(val macroName: String): IIntruderPayloadGenerator {
    val item = getMacros().filter{ it.description == macroName }[0].items[0]
    val request = item.request.toByteArray(Charsets.ISO_8859_1)
    val httpService = with(URL(item.url)) { BurpExtender.callbacks.helpers.buildHttpService(host, port, protocol) }

    override fun hasMorePayloads() = true
    override fun reset() {}
    override fun getNextPayload(baseValue: ByteArray): ByteArray {
        val response = BurpExtender.callbacks.makeHttpRequest(httpService, request)
        return extractCustomParameter(String(response.response, Charsets.ISO_8859_1), item.custom_parameters[0]).toByteArray(Charsets.ISO_8859_1)
    }

    fun extractCustomParameter(response: String, parameter: CustomParameter): String {
        val caseSensitive = parameter.case_sensitive
        var value = ""
        if(parameter.extract_mode == "define_start_and_end") {
            var startOffset: Int
            if(parameter.start_at_mode == "after_expression") {
                val expression = parameter.start_after_expression
                startOffset = response.indexOf(expression, 0, caseSensitive) + expression.length
            }
            else {
                startOffset = parameter.start_af_offset
            }

            var length: Int
            if(parameter.end_mode == "at_delimiter") {
                val expression = parameter.end_at_delimiter
                length = response.indexOf(expression, startOffset, caseSensitive) - startOffset
            }
            else {
                length = parameter.end_at_fixed_length
            }

            value = response.substring(startOffset, startOffset + length)
        }
        else {
            val pattern = Pattern.compile(parameter.regular_expression, if (!caseSensitive) { Pattern.CASE_INSENSITIVE } else { 0 } )
            with(pattern.matcher(response)) {
                find()
                value = group(1)
            }
        }

        if(parameter.url_encoded) {
            value = URLDecoder.decode(value, "ISO_8859_1")
        }
        return value
    }
}
