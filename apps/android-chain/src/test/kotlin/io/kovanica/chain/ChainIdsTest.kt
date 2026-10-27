package io.kovanica.chain

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ChainIdsTest {
    @Test
    fun legacySetMatchesRust() {
        assertTrue(ChainIds.legacyAllowed(ChainIds.DEVNET))
        assertTrue(ChainIds.legacyAllowed(ChainIds.CHAIN_4))
        assertTrue(ChainIds.legacyAllowed(ChainIds.TESTNET_V2))
        assertTrue(ChainIds.legacyAllowed(ChainIds.TESTNET))
        assertTrue(ChainIds.legacyAllowed(ChainIds.LOCAL))
        assertFalse(ChainIds.legacyAllowed(ChainIds.MAINNET))
        assertFalse(ChainIds.legacyAllowed(ChainIds.TESTNET_V1))
        assertFalse(ChainIds.legacyAllowed(ChainIds.UNSPECIFIED))
        assertFalse(ChainIds.legacyAllowed(0))
    }

    @Test
    fun blankOrGarbageFieldUsesTheProfileNotZero() {
        assertEquals(ChainIds.CHAIN_4.toULong(), ChainIds.resolve("", ChainIds.CHAIN_4))
        assertEquals(ChainIds.CHAIN_4.toULong(), ChainIds.resolve("   ", ChainIds.CHAIN_4))
        assertEquals(ChainIds.CHAIN_4.toULong(), ChainIds.resolve("nope", ChainIds.CHAIN_4))
        assertEquals(ChainIds.LOCAL.toULong(), ChainIds.resolve("", ChainIds.LOCAL))
        assertEquals(1UL, ChainIds.resolve("1", ChainIds.TESTNET))
        assertEquals(0UL, ChainIds.resolve("0", ChainIds.CHAIN_4))
    }
}
