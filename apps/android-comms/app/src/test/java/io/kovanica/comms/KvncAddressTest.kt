package io.kovanica.comms

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Same known answers as `kovanica-types` address tests and
 * `packages/signer` (`fixtures/wire.json`).
 */
class KvncAddressTest {
    private val zero = "00".repeat(32)
    private val sample = (0 until 32).joinToString("") { "%02x".format(it) }
    private val sender = "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c"
    private val recipient = "22".repeat(32)

    /** Rust `KAT_ZERO` / `KAT_SAMPLE` and the signer wire fixture. */
    private val katZero = "kvncqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqz4k5rcdag"
    private val katSample = "kvncqqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc07228f2dag"
    private val senderCanonical = "kvncaf9xcclzn3fq40h42pa3xtk9lx25wa4wh6l8hyjzrm4xj9zx6gkqsu0n4dag"
    private val senderLegacy =
        "kvncea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c0871f3aadag"
    private val recipientCanonical = "kvncyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg38e2j3fdag"
    private val recipientLegacy =
        "kvnc22222222222222222222222222222222222222222222222222222222222222227caa514adag"
    private val zeroLegacy =
        "kvnc00000000000000000000000000000000000000000000000000000000000000002ada83c1dag"
    private val sampleLegacy =
        "kvnc000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fe528e957dag"

    @Test
    fun canonicalKnownAnswersMatchRustAndTypescript() {
        assertEquals(64, KvncAddress.CANONICAL_LENGTH)
        assertEquals(katZero, KvncAddress.display(zero))
        assertEquals(katSample, KvncAddress.display(sample))
        assertEquals(senderCanonical, KvncAddress.display(sender))
        assertEquals(recipientCanonical, KvncAddress.display(recipient))
        assertEquals(katZero, KvncAddress.canonical(zero))
        assertEquals(sender, KvncAddress.normalizeHex(senderCanonical, 1))
        assertEquals(sender, KvncAddress.normalizeHex("  $senderCanonical  ", 2))
        assertEquals(sample, KvncAddress.normalizeHex(katSample, 99))
        assertEquals(zero, KvncAddress.storedKey(katZero))
        assertEquals(recipient, KvncAddress.storedKey(recipientCanonical))
    }

    @Test
    fun legacyHexFollowsTheChainPolicy() {
        val allowed = longArrayOf(3, 4, 1337)
        val refused = longArrayOf(1, 2, 0, 42, Long.MAX_VALUE)
        val forms = listOf(senderLegacy, sender, "0x$sender", recipientLegacy, sampleLegacy, zeroLegacy)
        for (chain in allowed) {
            assertTrue(KvncAddress.legacyAllowed(chain))
            for (form in forms) {
                val key = when {
                    form.contains("ea4a") || form == sender || form == "0x$sender" -> sender
                    form.contains("222222") -> recipient
                    form.startsWith("kvnc000102") || form == sample -> sample
                    else -> zero
                }
                assertEquals("$form on $chain", key, KvncAddress.normalizeHex(form, chain))
            }
        }
        for (chain in refused) {
            assertFalse("chain $chain", KvncAddress.legacyAllowed(chain))
            for (form in forms) {
                if (form == senderCanonical || form.length == 64 && form.startsWith("kvnc")) continue
                assertNull("$form on $chain", KvncAddress.normalizeHex(form, chain))
            }
            assertEquals(sender, KvncAddress.normalizeHex(senderCanonical, chain))
            assertEquals(katSample, KvncAddress.display(sample))
            assertTrue(KvncAddress.isValid(katSample, chain))
        }
    }

    @Test
    fun legacyHexDigitsAreCaseInsensitiveAndBase32IsLowercase() {
        val upperHex = sender.uppercase()
        assertEquals(sender, KvncAddress.normalizeHex(upperHex, 4))
        assertEquals(sender, KvncAddress.normalizeHex("0x$upperHex", 1337))
        val body = senderLegacy.substring(4, senderLegacy.length - 3)
        val upperLegacy = "kvnc${body.uppercase()}dag"
        assertEquals(sender, KvncAddress.normalizeHex(upperLegacy, 3))
        assertNull(KvncAddress.normalizeHex(upperLegacy, 1))
        assertNull(KvncAddress.normalizeHex(upperLegacy, 2))
        assertNull(KvncAddress.normalizeHex("0X$upperHex", 4))
        assertNull(KvncAddress.normalizeHex(senderLegacy.uppercase(), 4))
        val upperBody = senderCanonical.replaceRange(10, 11, senderCanonical[10].uppercase())
        assertNull(KvncAddress.normalizeHex(upperBody, 4))
        assertFalse(KvncAddress.isValid(upperBody, 1))
    }

    @Test
    fun checksumLengthAndAlphabetErrorsAreRejected() {
        val flipped = katSample.replaceRange(10, 11, "q")
        assertNull(KvncAddress.normalizeHex(flipped, 4))
        for (bad in listOf('b', 'i', 'o', '1', 'Q')) {
            val tampered = katSample.replaceRange(10, 11, bad.toString())
            assertNull("$bad", KvncAddress.normalizeHex(tampered, 4))
        }
        assertNull(KvncAddress.normalizeHex(katSample.dropLast(1), 4))
        assertNull(KvncAddress.normalizeHex(katSample + "q", 4))
        assertNull(KvncAddress.normalizeHex("kvnx${katSample.substring(4)}", 4))
        assertNull(KvncAddress.normalizeHex("0x1234", 4))
        assertNull(KvncAddress.normalizeHex("kvnc00dag", 4))
        // The pre-PRO-21 app label, `kvnc<64hex>dag`, is not a Rust address.
        val oldLabel = "kvnc${sender}dag"
        assertEquals(71, oldLabel.length)
        assertNull(KvncAddress.normalizeHex(oldLabel, 4))
        assertNull(KvncAddress.normalizeHex(oldLabel, 1))
        assertFalse(KvncAddress.isValid(oldLabel, 1337))
        val brokenLegacy = sampleLegacy.replaceRange(sampleLegacy.length - 4, sampleLegacy.length - 3, "0")
        assertNull(KvncAddress.normalizeHex(brokenLegacy, 4))
    }

    @Test
    fun storedKeysRoundTripWithoutAChainAndShortIsBase32() {
        assertEquals(sender, KvncAddress.storedKey(sender))
        assertEquals(sender, KvncAddress.storedKey("0x$sender"))
        assertEquals(senderCanonical, KvncAddress.canonical(sender))
        assertNull(KvncAddress.storedKey(senderLegacy))
        assertNull(KvncAddress.canonical(senderLegacy))
        assertEquals("kvncqqqqqq…z4k5rcdag", KvncAddress.short(zero))
        assertEquals("kvncaf9xcc…qsu0n4dag", KvncAddress.short(senderCanonical))
        assertTrue(KvncAddress.short(sender).startsWith("kvnc"))
        assertTrue(KvncAddress.short(sender).endsWith("dag"))
        assertFalse(KvncAddress.short(sender).contains(sender.take(8)))
    }
}
