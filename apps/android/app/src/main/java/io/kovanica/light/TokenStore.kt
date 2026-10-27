package io.kovanica.light

import android.content.Context
import android.content.SharedPreferences
import org.json.JSONArray
import org.json.JSONObject

/**
 * The watched-token list, persisted in the app's existing `"kvnc"`
 * SharedPreferences file (same store as `keystore`, `rpc`, `network_id`).
 *
 * The list is keyed by **network id** because a contract address is only
 * meaningful on the chain it was deployed to: a token watched on Testnet must
 * not appear, or be read, while the Mainnet profile is selected.
 *
 * Storage shape: `watchlist` -> JSON object `{ "<networkId>": ["<64hex>", …] }`.
 * Addresses are stored normalised (lowercase 64-hex, no `kvnc…dag` wrapper).
 */
class TokenStore(context: Context) {
    private val prefs: SharedPreferences =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    /** Watched token contract addresses for [networkId], in insertion order. */
    fun watched(networkId: String): List<String> {
        val all = load()
        val list = all.optJSONArray(networkId) ?: return emptyList()
        val out = ArrayList<String>(list.length())
        for (i in 0 until list.length()) {
            val raw = list.optString(i)
            KvncAddress.storedKey(raw)?.let { if (it !in out) out.add(it) }
        }
        return out
    }

    /** Add [addressHex] to [networkId]; a no-op when already present. */
    fun add(networkId: String, addressHex: String) {
        val hex = KvncAddress.storedKey(addressHex) ?: return
        val current = watched(networkId).toMutableList()
        if (current.contains(hex)) return
        current.add(hex)
        save(networkId, current)
    }

    /** Remove [addressHex] from [networkId]; a no-op when absent. */
    fun remove(networkId: String, addressHex: String) {
        val hex = KvncAddress.storedKey(addressHex) ?: return
        val current = watched(networkId).toMutableList()
        if (!current.remove(hex)) return
        save(networkId, current)
    }

    private fun save(networkId: String, addresses: List<String>) {
        val all = load()
        all.put(networkId, JSONArray(addresses))
        prefs.edit().putString(KEY_WATCHLIST, all.toString()).apply()
    }

    private fun load(): JSONObject {
        val stored = prefs.getString(KEY_WATCHLIST, null) ?: return JSONObject()
        return try {
            JSONObject(stored)
        } catch (_: Exception) {
            JSONObject()
        }
    }

    companion object {
        const val PREFS: String = "kvnc"
        const val KEY_WATCHLIST: String = "watchlist"
    }
}
