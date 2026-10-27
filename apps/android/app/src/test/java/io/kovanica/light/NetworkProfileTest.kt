package io.kovanica.light

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class NetworkProfileTest {
    @Test
    fun testnetProfileUsesChain4() {
        assertEquals(4L, Networks.TESTNET.chainId)
        assertEquals("testnet", Networks.TESTNET.id)
        assertTrue(Networks.TESTNET.enabled)
    }

    @Test
    fun otherProfilesKeepTheirChainIds() {
        assertEquals(1L, Networks.MAINNET.chainId)
        assertEquals(1337L, Networks.LOCAL.chainId)
    }
}
