# Macro Payload Generator

This Burp extension lets you use a value returned from a macro as an Intruder payload.

It is primarily useful with the Pitchfork attack type, as it returns an unending sequence.

To use it you need to define a macro with a single item, and configure that item to have a single custome
parameter location. When suitable macros are detected, a corresponding *IntruderPayloadGenerator* will be registered.
The extension polls every 10 seconds for new macros.

Within Intruder you can then select an extension-generated payload and choose the generator that corresponds to your macro.