package io.kovanica.light

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class StartupNativeTest {
    @Test
    fun unsatisfiedLinkErrorDoesNotEscape() {
        val result = StartupNative.faucetAllowed(true) {
            throw UnsatisfiedLinkError(
                "Error looking up function 'uniffi_kovanica_light_ffi_fn_func_change_passphrase_raw':",
            )
        }
        assertFalse(result.allowed)
        assertTrue(
            result.failure!!.contains("UnsatisfiedLinkError") &&
                result.failure!!.contains("change_passphrase_raw"),
        )
    }

    @Test
    fun checkedExceptionDoesNotEscape() {
        val result = StartupNative.faucetAllowed(true) {
            throw IllegalStateException("UniFFI API checksum mismatch")
        }
        assertFalse(result.allowed)
        assertTrue(result.failure!!.contains("IllegalStateException"))
    }

    @Test
    fun successIsPassedThrough() {
        val result = StartupNative.faucetAllowed(true) { true }
        assertTrue(result.allowed)
        assertNull(result.failure)
    }

    @Test
    fun falseIsPassedThrough() {
        val result = StartupNative.faucetAllowed(true) { false }
        assertEquals(false, result.allowed)
        assertNull(result.failure)
    }

    @Test
    fun missingFaucetDoesNotCallTheLibrary() {
        val result = StartupNative.faucetAllowed(false) { error("must not run") }
        assertFalse(result.allowed)
        assertNull(result.failure)
    }
}
