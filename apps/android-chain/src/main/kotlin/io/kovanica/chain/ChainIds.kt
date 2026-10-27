package io.kovanica.chain

/**
 * The only chain-id constants for the Android apps.
 *
 * Network profiles, the legacy-address policy, and the chain text field all
 * read this object.
 */
object ChainIds {
    const val MAINNET: Long = 1
    const val TESTNET_V1: Long = 2
    const val DEVNET: Long = 3
    const val CHAIN_4: Long = 4
    const val TESTNET_V2: Long = 4
    const val TESTNET: Long = 4
    const val LOCAL: Long = 1337

    /** No chain was configured. Legacy hex stays refused. */
    const val UNSPECIFIED: Long = -1

    /** Devnet 3, chain 4 (public testnet), local 1337. Same set as Rust `legacy_address_allowed`. */
    fun legacyAllowed(chainId: Long): Boolean =
        chainId == DEVNET || chainId == CHAIN_4 || chainId == LOCAL

    /**
     * Chain id for signing and address checks.
     *
     * A typed integer wins, including `0`. A blank or unparseable field uses
     * [profileChainId] from the network profile. It does not become 0.
     */
    fun resolve(fieldText: String, profileChainId: Long): ULong {
        val typed = fieldText.trim()
        val parsed = if (typed.isEmpty()) null else typed.toULongOrNull()
        return parsed ?: profileChainId.toULong()
    }
}
