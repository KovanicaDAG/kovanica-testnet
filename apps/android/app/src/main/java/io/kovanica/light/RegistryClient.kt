package io.kovanica.light

import org.json.JSONArray
import org.json.JSONObject
import uniffi.kovanica_light.registryDecodeEntry
import uniffi.kovanica_light.registrySlotHex

/** A resolved on-chain name-registry entry. Hex fields are lowercase, no `0x`. */
data class RegistryEntry(
    val ownerHex: String,
    val pubkeyHex: String,
    val relayEndpoints: List<String>,
)

/**
 * Read-only name lookups against a deployed `kovanica-name-registry` contract.
 *
 * There is no view RPC for name resolution, so [resolve] mirrors the raw
 * contract-storage path in `docs/COMMS-ANDROID-INTERFACES.md` §7.1: compute the
 * storage slot via the generated `registrySlotHex`, then read it with
 * `kovanica_getStorageAt`. Nothing is ever signed or submitted, and the app never
 * deploys a contract. Call it off the UI thread.
 *
 * @param contractAddress canonical 64-character `kvnc…dag` address. Blank means
 *   the registry is not configured and every lookup returns null. The caller
 *   applies the chain policy before this string is sent.
 */
class RegistryClient(
    private val node: NodeClient,
    private val contractAddress: String,
) {
    /**
     * Resolve [name] to its registry entry, or null when the registry is not
     * configured or the name is not registered. An absent key and a not-found
     * name both come back as `"0x"` and are indistinguishable (§7.1).
     *
     * @throws IllegalArgumentException when [name] is not a valid registry name.
     */
    fun resolve(name: String): RegistryEntry? {
        val address = contractAddress.trim()
        if (address.isEmpty()) {
            return null
        }
        val normalized = normalizeName(name)
        val slot = registrySlotHex(normalized)
        val result = node.call(
            "kovanica_getStorageAt",
            JSONArray().put(address).put("0x" + slot),
        )
        val valueHex = result?.toString()?.trim() ?: return null
        if (valueHex.isEmpty() || valueHex.equals("0x", ignoreCase = true)) {
            return null
        }
        return decode(registryDecodeEntry(valueHex))
    }

    /** Lowercase a name and enforce §7.2's rules (throws on invalid input). */
    private fun normalizeName(name: String): String {
        val normalized = name.trim().lowercase()
        val bytes = normalized.toByteArray(Charsets.UTF_8)
        require(bytes.size in 3..32) {
            "registry name must be 3..32 UTF-8 bytes: \"$name\""
        }
        require(normalized.all { it in 'a'..'z' || it in '0'..'9' || it == '-' }) {
            "registry name may only contain [a-z0-9-]: \"$name\""
        }
        require(!normalized.startsWith('-') && !normalized.endsWith('-')) {
            "registry name must not start or end with '-': \"$name\""
        }
        require(!normalized.contains("--")) {
            "registry name must not contain '--': \"$name\""
        }
        return normalized
    }

    /** Parse `registryDecodeEntry`'s compact JSON into a [RegistryEntry]. */
    private fun decode(json: String): RegistryEntry {
        val obj = JSONObject(json)
        val endpoints = obj.optJSONArray("relay_endpoints")?.let { array ->
            List(array.length()) { i -> array.optString(i) }.filter { it.isNotEmpty() }
        } ?: emptyList()
        return RegistryEntry(
            ownerHex = normalizeHex(obj.optString("owner")),
            pubkeyHex = normalizeHex(obj.optString("pubkey")),
            relayEndpoints = endpoints,
        )
    }

    private fun normalizeHex(value: String): String =
        value.trim().removePrefix("0x").removePrefix("0X").lowercase()
}
