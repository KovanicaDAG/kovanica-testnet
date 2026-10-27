package io.kovanica.light

import android.content.Context
import android.content.SharedPreferences
import org.json.JSONArray
import org.json.JSONObject

/**
 * Comms settings, the local contact book, and the on-chain name-registry
 * contract address, persisted in the app's existing `"kvnc"` SharedPreferences
 * file (same store as `keystore`, `rpc`, ...).
 *
 * Keys: `relay_url`, `display_name`, `registry_contract`, `contacts`.
 *
 * Schema v2: `contacts` is a compact JSON object of
 * `pubkeyHex -> {"label":String,"name":String?,"relay_endpoints":[String]?}`.
 * Values written by schema v1 (a plain `String`) are still read as the `label`
 * with no name/endpoints, so an upgrade loses nothing.
 */
class CommsStore(context: Context) {
    private val prefs: SharedPreferences =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    /** Relay origin, e.g. `http://10.0.2.2:8787`. Defaults to the emulator host. */
    var relayUrl: String
        get() = prefs.getString(KEY_RELAY_URL, DEFAULT_RELAY_URL) ?: DEFAULT_RELAY_URL
        set(value) = prefs.edit().putString(KEY_RELAY_URL, value).apply()

    /** Friendly name shown for this identity. Empty until the user sets one. */
    var displayName: String
        get() = prefs.getString(KEY_DISPLAY_NAME, "") ?: ""
        set(value) = prefs.edit().putString(KEY_DISPLAY_NAME, value).apply()

    /**
     * Address (`kvnc…dag` or raw 32-byte hex) of the deployed
     * `kovanica-name-registry` contract. Empty means "not configured" and name
     * lookup degrades gracefully.
     */
    val registryContract: String
        get() = prefs.getString(KEY_REGISTRY_CONTRACT, "") ?: ""

    /** Persist the name-registry contract address (empty clears it). */
    fun setRegistryContract(value: String) {
        prefs.edit().putString(KEY_REGISTRY_CONTRACT, value).apply()
    }

    /** Snapshot of the contact book (keys normalized to lowercase hex, no `0x`). */
    fun contacts(): List<Contact> {
        val raw = loadRaw()
        val out = ArrayList<Contact>(raw.length())
        for (key in raw.keys()) {
            val contact = readContact(normalize(key), raw.opt(key)) ?: continue
            out.add(contact)
        }
        return out
    }

    /** Label for [pubkeyHex], or null when unknown. */
    fun label(pubkeyHex: String): String? {
        val key = normalize(pubkeyHex)
        return readContact(key, loadRaw().opt(key))?.label
    }

    /** Insert or overwrite a contact. */
    fun upsertContact(contact: Contact) {
        val raw = loadRaw()
        raw.put(normalize(contact.pubkeyHex), toJson(contact))
        save(raw)
    }

    /** Drop a contact. No-op when absent. */
    fun removeContact(pubkeyHex: String) {
        val raw = loadRaw()
        if (raw.remove(normalize(pubkeyHex)) != null) {
            save(raw)
        }
    }

    /** Remove every contact. */
    fun clearContacts() {
        prefs.edit().remove(KEY_CONTACTS).apply()
    }

    private fun loadRaw(): JSONObject {
        val stored = prefs.getString(KEY_CONTACTS, null) ?: return JSONObject()
        return try {
            JSONObject(stored)
        } catch (_: Exception) {
            JSONObject()
        }
    }

    private fun save(raw: JSONObject) {
        prefs.edit().putString(KEY_CONTACTS, raw.toString()).apply()
    }

    /** Read one contact value: schema v2 object, or legacy plain-string label. */
    private fun readContact(pubkeyHex: String, value: Any?): Contact? = when (value) {
        is String -> Contact(pubkeyHex, value, null, null)
        is JSONObject -> Contact(
            pubkeyHex = pubkeyHex,
            label = value.optString("label"),
            name = if (value.has("name") && !value.isNull("name")) {
                value.optString("name").ifBlank { null }
            } else {
                null
            },
            relayEndpoints = value.optJSONArray("relay_endpoints")?.let { array ->
                List(array.length()) { i -> array.optString(i) }.filter { it.isNotEmpty() }
            },
        )
        else -> null
    }

    private fun toJson(contact: Contact): JSONObject {
        val json = JSONObject().put("label", contact.label)
        if (contact.name != null) {
            json.put("name", contact.name)
        }
        if (contact.relayEndpoints != null) {
            json.put("relay_endpoints", JSONArray(contact.relayEndpoints))
        }
        return json
    }

    private fun normalize(pubkeyHex: String): String =
        pubkeyHex.trim().removePrefix("0x").removePrefix("0X").lowercase()

    companion object {
        const val PREFS: String = "kvnc"
        const val KEY_RELAY_URL: String = "relay_url"
        const val KEY_DISPLAY_NAME: String = "display_name"
        const val KEY_CONTACTS: String = "contacts"
        const val KEY_REGISTRY_CONTRACT: String = "registry_contract"

        /** Emulator loopback to the host machine (matches the spec default). */
        const val DEFAULT_RELAY_URL: String = "http://10.0.2.2:8787"
    }
}

/** One address-book entry. Hex fields are lowercase, no `0x`. */
data class Contact(
    val pubkeyHex: String,
    val label: String,
    val name: String?,
    val relayEndpoints: List<String>?,
)
