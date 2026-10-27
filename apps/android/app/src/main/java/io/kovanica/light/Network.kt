package io.kovanica.light

import android.content.Context
import android.content.SharedPreferences
import io.kovanica.chain.ChainIds

/**
 * One selectable network profile.
 *
 * @property id stable key persisted as `network_id` (`"mainnet"` | `"testnet"` | `"local"`).
 * @property label human-readable name shown in the selector.
 * @property chainId chain id used for signing (`1` mainnet, `4` testnet, `3` devnet, `1337` local).
 * @property rpcUrl full JSON-RPC base, including the `/rpc` path ([NodeClient] tolerates either form).
 * @property faucetUrl full faucet `POST` target, or `null` when the network has no faucet.
 * @property enabled when `false` the entry is shown but not selectable.
 * @property soon text shown instead of allowing selection while [enabled] is `false`.
 */
data class Network(
    val id: String,
    val label: String,
    val chainId: Long,
    val rpcUrl: String,
    val faucetUrl: String?,
    val enabled: Boolean,
    val soon: String? = null,
)

/**
 * Built-in network profiles (mirrors `packages/console/src/network.ts`).
 *
 * Chain ids are mainnet 1, testnet 4, devnet 3, and local 1337. Devnet has no
 * preset here. Mainnet stays listed but disabled until it is open. Every
 * endpoint stays editable once selected.
 */
object Networks {
    val MAINNET: Network = Network(
        "mainnet", "Mainnet", ChainIds.MAINNET,
        "https://rpc.kovanica.online/rpc", null, enabled = false,
        soon = "Mainnet is not open yet.",
    )
    val TESTNET: Network = Network(
        "testnet", "Testnet", ChainIds.TESTNET,
        "https://rpc-testnet.kovanica.online/rpc",
        "https://faucet-testnet.kovanica.online/faucet", enabled = true,
    )
    val LOCAL: Network = Network(
        "local", "Local", ChainIds.LOCAL,
        "http://10.0.2.2:8545/rpc", "http://10.0.2.2:8080/faucet", enabled = true,
    )

    val ALL: List<Network> = listOf(MAINNET, TESTNET, LOCAL)
    val DEFAULT: Network = LOCAL

    /** Look up a profile by id; `null` when unknown (including `null`). */
    fun byId(id: String?): Network? = ALL.firstOrNull { it.id == id }
}

/**
 * Reads and writes the network selection plus its editable overrides in the
 * app's existing `"kvnc"` SharedPreferences file.
 *
 * The selected profile is pinned by `network_id`; the `rpc`, `chainId`,
 * `faucet` and `epoch` keys are editable overrides. A blank (`""`) or absent
 * override falls back to the selected profile's value. Numeric values are
 * stored as strings.
 *
 * Note: [effective] applies the `rpc`/`chainId`/`faucet` overrides — [Network]
 * has no `epoch` field, so the epoch override is exposed only through
 * [epoch]/[setEpoch].
 */
object NetworkPrefs {
    const val PREFS: String = "kvnc"
    const val KEY_NETWORK_ID: String = "network_id"
    const val KEY_RPC: String = "rpc"
    const val KEY_CHAIN_ID: String = "chainId"
    const val KEY_EPOCH: String = "epoch"
    const val KEY_FAUCET: String = "faucet"

    private fun prefs(ctx: Context): SharedPreferences =
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    /** Stored `network_id` when it maps to a known profile, else [Networks.DEFAULT]'s id. */
    fun selectedId(ctx: Context): String {
        val stored = prefs(ctx).getString(KEY_NETWORK_ID, null)
        return (Networks.byId(stored) ?: Networks.DEFAULT).id
    }

    /** The selected profile, falling back to [Networks.DEFAULT]. */
    fun selected(ctx: Context): Network =
        Networks.byId(selectedId(ctx)) ?: Networks.DEFAULT

    /** Persist [n] as the selected network and prefill the `rpc`/`chainId`/`faucet` overrides. */
    fun select(ctx: Context, n: Network) {
        prefs(ctx).edit()
            .putString(KEY_NETWORK_ID, n.id)
            .putString(KEY_RPC, n.rpcUrl)
            .putString(KEY_CHAIN_ID, n.chainId.toString())
            .putString(KEY_FAUCET, n.faucetUrl ?: "")
            .apply()
    }

    /** Effective RPC URL: the override when set, else the selected profile's. */
    fun rpc(ctx: Context): String = overrideOrNull(ctx, KEY_RPC) ?: selected(ctx).rpcUrl

    fun setRpc(ctx: Context, value: String) = put(ctx, KEY_RPC, value)

    /** Effective chain id: the override when set, else the selected profile's. */
    fun chainId(ctx: Context): Long =
        overrideOrNull(ctx, KEY_CHAIN_ID)?.toLongOrNull() ?: selected(ctx).chainId

    fun setChainId(ctx: Context, value: Long) = put(ctx, KEY_CHAIN_ID, value.toString())

    /** Committee epoch override (no profile value); `0` when unset or unparseable. */
    fun epoch(ctx: Context): Long =
        prefs(ctx).getString(KEY_EPOCH, null)?.toLongOrNull() ?: 0L

    fun setEpoch(ctx: Context, value: Long) = put(ctx, KEY_EPOCH, value.toString())

    /** Effective faucet URL: the override when set, else the selected profile's (`null` = no faucet). */
    fun faucet(ctx: Context): String? = overrideOrNull(ctx, KEY_FAUCET) ?: selected(ctx).faucetUrl

    /** Set the faucet override; `null` or blank clears it so the profile value applies again. */
    fun setFaucet(ctx: Context, value: String?) = put(ctx, KEY_FAUCET, value ?: "")

    /** The selected profile with the `rpc`/`chainId`/`faucet` overrides applied where non-empty. */
    fun effective(ctx: Context): Network {
        val base = selected(ctx)
        return base.copy(
            rpcUrl = rpc(ctx),
            chainId = chainId(ctx),
            faucetUrl = faucet(ctx),
        )
    }

    private fun overrideOrNull(ctx: Context, key: String): String? =
        prefs(ctx).getString(key, null)?.trim()?.takeIf { it.isNotEmpty() }

    private fun put(ctx: Context, key: String, value: String) {
        prefs(ctx).edit().putString(key, value).apply()
    }
}
