package io.kovanica.light

/**
 * The first native call happens while the home screen is being created.
 *
 * JNA registers every UniFFI symbol at that moment. A stale
 * `libkovanica_light_ffi.so` (or a device that cannot load it) throws
 * [UnsatisfiedLinkError], which is an [Error], not an [Exception]. Callers
 * that only catch [Exception] therefore kill the process before the first
 * frame. This probe turns that into a failed faucet check so the screen
 * still comes up.
 */
internal object StartupNative {
    data class Probe(val allowed: Boolean, val failure: String?)

    fun faucetAllowed(configured: Boolean, probe: () -> Boolean): Probe {
        if (!configured) return Probe(allowed = false, failure = null)
        return try {
            Probe(allowed = probe(), failure = null)
        } catch (error: Throwable) {
            Probe(allowed = false, failure = loadFailure(error))
        }
    }

    private fun loadFailure(error: Throwable): String {
        val detail = error.message?.lineSequence()?.firstOrNull()?.trim().orEmpty()
        val why = if (detail.isEmpty()) {
            error.javaClass.simpleName
        } else {
            "${error.javaClass.simpleName}: ${detail.take(180)}"
        }
        return "Light client library failed to load ($why)."
    }
}
