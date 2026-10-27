package io.kovanica.wallet

import io.kovanica.chain.ChainIds
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Profiles and the address policy must read [ChainIds], not a second copy of the numbers. */
class ChainIdSourceTest {
    @Test
    fun profilesAndAddressPolicyShareChainIds() {
        assertEquals(ChainIds.MAINNET, Networks.MAINNET.chainId)
        assertEquals(ChainIds.TESTNET, Networks.TESTNET.chainId)
        assertEquals(ChainIds.LOCAL, Networks.LOCAL.chainId)
        assertEquals(
            ChainIds.legacyAllowed(ChainIds.CHAIN_4),
            KvncAddress.legacyAllowed(ChainIds.CHAIN_4),
        )
        assertFalse(KvncAddress.legacyAllowed(ChainIds.MAINNET))
        assertFalse(KvncAddress.legacyAllowed(ChainIds.TESTNET_V1))
        assertTrue(KvncAddress.legacyAllowed(ChainIds.TESTNET))
        assertFalse(KvncAddress.legacyAllowed(ChainIds.UNSPECIFIED))
    }
}
