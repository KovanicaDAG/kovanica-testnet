package io.kovanica.light

import android.content.Context
import android.content.SharedPreferences
import org.json.JSONArray
import org.json.JSONObject

/**
 * A local, per-network record of what this phone submitted.
 *
 * The node exposes no history RPC, so this is a client-side log written at the
 * moment a transaction is sent. It records what the *phone* sent — not what the
 * chain confirmed — so an entry can describe a transaction that was never mined
 * or was rejected by the network. Treat it as a convenience, not a ledger.
 *
 * Stored as a JSON array under `history_<networkId>` in the app's existing
 * `"kvnc"` SharedPreferences file, newest first, capped at [MAX_ENTRIES]. Keeping
 * it per network means a Testnet transfer never shows up under Local.
 */
class HistoryStore(context: Context) {
    private val prefs: SharedPreferences =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    /** Newest-first entries recorded on [networkId]; empty when there are none. */
    fun entries(networkId: String): List<HistoryEntry> {
        val raw = prefs.getString(key(networkId), null) ?: return emptyList()
        val array = try {
            JSONArray(raw)
        } catch (_: Exception) {
            return emptyList()
        }
        val out = ArrayList<HistoryEntry>(array.length())
        for (i in 0 until array.length()) {
            val obj = array.optJSONObject(i) ?: continue
            HistoryEntry.fromJson(obj)?.let(out::add)
        }
        return out
    }

    /** Record [entry] on [networkId], newest first, keeping only the newest [MAX_ENTRIES]. */
    fun add(networkId: String, entry: HistoryEntry) {
        val next = ArrayList<HistoryEntry>(MAX_ENTRIES)
        next.add(entry)
        for (existing in entries(networkId)) {
            if (next.size >= MAX_ENTRIES) break
            next.add(existing)
        }
        save(networkId, next)
    }

    /** Drop every entry recorded on [networkId]. Local only — the chain is untouched. */
    fun clear(networkId: String) {
        prefs.edit().remove(key(networkId)).apply()
    }

    private fun save(networkId: String, list: List<HistoryEntry>) {
        val array = JSONArray()
        list.forEach { array.put(it.toJson()) }
        prefs.edit().putString(key(networkId), array.toString()).apply()
    }

    private fun key(networkId: String): String = KEY_PREFIX + networkId

    companion object {
        const val PREFS: String = "kvnc"
        const val KEY_PREFIX: String = "history_"
        const val MAX_ENTRIES: Int = 100

        /** A 32-byte (64-hex) hash, with or without the `0x` prefix. */
        private val HASH_RE = Regex("0x[0-9a-fA-F]{64}|[0-9a-fA-F]{64}")

        /**
         * The first transaction hash carried by [text], or `null` when there is
         * none. Used to decide whether a faucet response is worth recording —
         * some faucets answer with a hash, some with a plain message.
         */
        fun extractTxHash(text: String): String? = HASH_RE.find(text)?.value
    }
}

/**
 * One row of local history.
 *
 * @property kind what was sent — one of the [KIND_*] constants.
 * @property hash transaction hash the node returned at submission time.
 * @property networkId network the entry belongs to (mirrors the storage key).
 * @property timestampMs wall-clock time the phone submitted it.
 * @property to recipient address, in whatever form was typed (native send, token transfer).
 * @property contract token contract, for the token kinds.
 * @property amount human-readable amount, already scaled by the asset's decimals.
 * @property symbol asset ticker shown next to the amount (`KUNA`, or a token's symbol).
 * @property status always [STATUS_SUBMITTED]: the app has no confirmation feed.
 */
data class HistoryEntry(
    val kind: String,
    val hash: String,
    val networkId: String,
    val timestampMs: Long,
    val to: String? = null,
    val contract: String? = null,
    val amount: String? = null,
    val symbol: String? = null,
    val status: String = STATUS_SUBMITTED,
) {
    fun toJson(): JSONObject = JSONObject()
        .put("kind", kind)
        .put("hash", hash)
        .putOrNull("to", to)
        .putOrNull("contract", contract)
        .putOrNull("amount", amount)
        .putOrNull("symbol", symbol)
        .put("networkId", networkId)
        .put("timestampMs", timestampMs)
        .put("status", status)

    companion object {
        const val STATUS_SUBMITTED: String = "submitted"

        const val KIND_SEND: String = "send"
        const val KIND_TOKEN_SEND: String = "token_send"
        const val KIND_BOND: String = "bond"
        const val KIND_WITNESS: String = "witness"
        const val KIND_EXIT: String = "exit"
        const val KIND_FAUCET: String = "faucet"
        const val KIND_TOKEN_CREATE: String = "token_create"

        /** Parse one stored object; `null` when the required fields are missing. */
        fun fromJson(obj: JSONObject): HistoryEntry? {
            val kind = obj.stringOrNull("kind") ?: return null
            val hash = obj.stringOrNull("hash") ?: return null
            val networkId = obj.stringOrNull("networkId") ?: return null
            return HistoryEntry(
                kind = kind,
                hash = hash,
                networkId = networkId,
                timestampMs = obj.optLong("timestampMs", 0L),
                to = obj.stringOrNull("to"),
                contract = obj.stringOrNull("contract"),
                amount = obj.stringOrNull("amount"),
                symbol = obj.stringOrNull("symbol"),
                status = obj.stringOrNull("status") ?: STATUS_SUBMITTED,
            )
        }
    }
}

private fun JSONObject.putOrNull(key: String, value: String?): JSONObject =
    if (value == null) put(key, JSONObject.NULL) else put(key, value)

private fun JSONObject.stringOrNull(key: String): String? =
    if (isNull(key)) null else optString(key).takeIf { it.isNotEmpty() }
