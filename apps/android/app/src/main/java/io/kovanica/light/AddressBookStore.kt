package io.kovanica.light

import android.content.Context
import android.content.SharedPreferences
import org.json.JSONArray
import org.json.JSONObject

/**
 * The saved-recipient list, persisted in the app's existing `"kvnc"`
 * SharedPreferences file (same store as `keystore`, `rpc`, `network_id`).
 *
 * The book is **global**, not keyed by network: a Kovanica address comes from a
 * public key, so the same entry is payable on every chain the app can reach.
 * (Contracts are the exception — a token address only means something on the
 * chain it was deployed to — so those live per network in [TokenStore].)
 *
 * Storage shape: `address_book` -> JSON array of
 * `{"label":String,"address":"<64hex>"}`. Addresses are stored normalised
 * (lowercase 64-hex, no `kvnc…dag` wrapper) so duplicates cannot slip in via a
 * different spelling of the same address.
 */
class AddressBookStore(context: Context) {
    private val prefs: SharedPreferences =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    /** Saved entries in the order they were added. */
    fun list(): List<AddressBookEntry> = load()

    /**
     * Entries whose label contains [query], case-insensitively. A blank query
     * returns the whole book. Only the label is searched — a label is the part a
     * person remembers, and it is the part they type.
     */
    fun search(query: String): List<AddressBookEntry> {
        val needle = query.trim()
        if (needle.isEmpty()) return list()
        return list().filter { it.label.contains(needle, ignoreCase = true) }
    }

    /** The saved label for [address], or `null` when it is not in the book. */
    fun label(address: String?): String? {
        val hex = KvncAddress.storedKey(address) ?: return null
        return list().firstOrNull { it.address == hex }?.label
    }

    /**
     * Save [label] against [address]. Returns false when the address is not a
     * usable Kovanica address or the label is blank. Saving an address that is
     * already present replaces its label, so a typo can be fixed without first
     * deleting the row.
     */
    fun add(label: String, address: String): Boolean {
        val hex = KvncAddress.storedKey(address) ?: return false
        val name = label.trim()
        if (name.isEmpty()) return false

        val current = list().toMutableList()
        val existing = current.indexOfFirst { it.address == hex }
        if (existing >= 0) {
            current[existing] = AddressBookEntry(name, hex)
            save(current)
            return true
        }
        while (current.size >= MAX_ENTRIES) current.removeAt(0)
        current.add(AddressBookEntry(name, hex))
        save(current)
        return true
    }

    /** Drop [address] from the book. Returns true when a row was removed. */
    fun remove(address: String): Boolean {
        val hex = KvncAddress.storedKey(address) ?: return false
        val current = list().toMutableList()
        if (!current.removeAll { it.address == hex }) return false
        save(current)
        return true
    }

    private fun load(): List<AddressBookEntry> {
        val stored = prefs.getString(KEY_BOOK, null) ?: return emptyList()
        val array = try {
            JSONArray(stored)
        } catch (_: Exception) {
            return emptyList()
        }
        val out = ArrayList<AddressBookEntry>(array.length())
        for (i in 0 until array.length()) {
            val obj = array.optJSONObject(i) ?: continue
            val hex = KvncAddress.storedKey(obj.optString("address")) ?: continue
            val name = obj.optString("label").trim()
            if (name.isEmpty()) continue
            if (out.any { it.address == hex }) continue
            out.add(AddressBookEntry(name, hex))
        }
        return out
    }

    private fun save(entries: List<AddressBookEntry>) {
        val array = JSONArray()
        entries.forEach { entry ->
            array.put(JSONObject().put("label", entry.label).put("address", entry.address))
        }
        prefs.edit().putString(KEY_BOOK, array.toString()).apply()
    }

    companion object {
        const val PREFS: String = "kvnc"
        const val KEY_BOOK: String = "address_book"

        /** Once the book is this long, the oldest row is dropped to make room. */
        const val MAX_ENTRIES: Int = 100
    }
}

/** One saved recipient: a label and its normalised (lowercase 64-hex) address. */
data class AddressBookEntry(
    val label: String,
    val address: String,
)
