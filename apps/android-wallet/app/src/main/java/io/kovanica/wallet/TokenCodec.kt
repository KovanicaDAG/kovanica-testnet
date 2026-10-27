package io.kovanica.wallet

import java.math.BigInteger

/**
 * A KVP-102 fungible token, decoded from its contract's singleton storage slot.
 *
 * All amounts are kept as [BigInteger] because the contract encodes them as
 * `u128` (`kovanica_common::Amount`), which does not fit a Kotlin `ULong`. Balances
 * are keyed by lowercase 64-hex address so they line up with [KvncAddress].
 */
data class TokenInfo(
    val name: String,
    val symbol: String,
    val decimals: Int,
    val totalSupply: BigInteger,
    val ownerHex: String,
    val minterHex: String,
    /** Holder address (64-hex, lowercase) -> amount, exactly as stored on chain. */
    val balances: Map<String, BigInteger>,
    val paused: Boolean,
) {
    /** Balance of [addressHex] (64-hex, lowercase, no `0x`); zero when absent. */
    fun balanceOf(addressHex: String): BigInteger =
        balances[addressHex.lowercase()] ?: BigInteger.ZERO

    /** Number of addresses holding a non-zero balance. */
    val holders: Int get() = balances.count { it.value.signum() > 0 }
}

/**
 * Decoder for the `kovanica-token` `Token` singleton (KVP-102).
 *
 * ## Why this is hand-rolled
 *
 * Token balances are **not** native KUNA and have no view RPC — `token_balance`
 * is explicitly unimplemented (`kovanica-rpc`). The only read path is the raw
 * contract slot, read with `kovanica_getStorageAt`, decoded with bincode. The light
 * FFI exposes no generic `Token` decoder, so the layout is reproduced here.
 *
 * ## Exact on-chain layout
 *
 * Source of truth: `crates/kovanica-token/src/lib.rs` (`pub struct Token`) and
 * `crates/kovanica-common/src/lib.rs` (`type Address = [u8; 32]`,
 * `type Amount = u128`). Fields, in order, exactly as bincode 1.3 writes them
 * with the crate's default fixint / little-endian / u64-length config:
 *
 * ```
 * name          String                     u64le len + utf8 bytes
 * symbol        String                     u64le len + utf8 bytes
 * decimals      u8                         1 byte
 * total_supply  u128                       16 bytes LE
 * owner         [u8; 32]                   32 bytes
 * minter        [u8; 32]                   32 bytes
 * balances      BTreeMap<[u8;32], u128>    u64le count + count×(32 + 16)
 * allowances    BTreeMap<([u8;32],[u8;32]), u128>
 *                                          u64le count + count×(32 + 32 + 16)
 * paused        bool                       1 byte
 * ```
 *
 * `[u8; 32]` serialises as a bare 32-byte array (serde treats arrays as fixed
 * tuples), so map keys carry no length prefix. `owner`/`minter`/`paused` and
 * the `u128` amount width are easy to miss — a decoder that stops after
 * `total_supply` (or assumes `u64`) silently misreads the whole tail.
 *
 * ## Failure mode
 *
 * Every read is bounds-checked and every length is clamped against the bytes
 * that actually remain, so a foreign contract that happens to hold data at
 * this slot is rejected rather than mis-parsed. [decode] returns `null` on any
 * structural problem; the UI shows that as "unreadable", never as a number.
 */
object TokenCodec {
    /**
     * The namespaced slot the token singleton lives at, as raw bytes.
     *
     * `kovanica-token` writes its state under the raw key `b"kvnc/v1/state"`; the
     * host namespaces contract storage as `blake3(raw_key)`
     * (`kovanica-execution`'s `ContractHost::namespace`). The light FFI exposes
     * only registry-slot hashing, not a generic `blake3`, so the digest is
     * pinned here as bytes. [stateSlotHex] renders it for the RPC.
     */
    private val SLOT_BYTES: ByteArray = intArrayOf(
        0xD4, 0x90, 0x05, 0x9B, 0x20, 0xA5, 0x1C, 0xD3,
        0x1A, 0xD8, 0x72, 0x40, 0x21, 0x23, 0x1C, 0x58,
        0x1D, 0x67, 0xA6, 0x2D, 0x29, 0x46, 0xF7, 0xF2,
        0xA4, 0x40, 0x5D, 0xD8, 0xAE, 0x73, 0x8D, 0xF1,
    ).map { it.toByte() }.toByteArray()

    /** The 64-hex slot string (no `0x`) to pass to `kovanica_getStorageAt`. */
    fun stateSlotHex(): String = hex(SLOT_BYTES)

    /** Longest name/symbol we will accept, as a guard against absurd lengths. */
    private const val MAX_TEXT_BYTES = 512

    /** Bincode entry sizes, used to clamp map counts to what can physically fit. */
    private const val BALANCE_ENTRY_BYTES = 32 + 16
    private const val ALLOWANCE_ENTRY_BYTES = 32 + 32 + 16

    /** Decode a raw storage value into a [TokenInfo], or `null` when it is not one. */
    fun decode(raw: ByteArray): TokenInfo? {
        val r = Reader(raw)

        val name = r.text(MAX_TEXT_BYTES) ?: return null
        val symbol = r.text(MAX_TEXT_BYTES) ?: return null
        val decimals = r.u8() ?: return null
        val totalSupply = r.u128() ?: return null
        val owner = r.bytes(32) ?: return null
        val minter = r.bytes(32) ?: return null

        val balanceCount = r.count(BALANCE_ENTRY_BYTES) ?: return null
        val balances = LinkedHashMap<String, BigInteger>(balanceCount)
        repeat(balanceCount) {
            val addr = r.bytes(32) ?: return null
            val amount = r.u128() ?: return null
            // BTreeMap is keyed and deduplicated on chain, so a duplicate here
            // means the bytes are not a real token state.
            if (balances.put(hex(addr), amount) != null) return null
        }

        // Allowances are decoded only to prove the tail is well-formed; the
        // wallet does not surface them (no approval UI yet).
        val allowanceCount = r.count(ALLOWANCE_ENTRY_BYTES) ?: return null
        repeat(allowanceCount) {
            r.bytes(32) ?: return null
            r.bytes(32) ?: return null
            r.u128() ?: return null
        }

        val paused = r.bool() ?: return null

        // A token always has a symbol; a missing one means this is not Token.
        if (symbol.isBlank()) return null

        return TokenInfo(
            name = name,
            symbol = symbol,
            decimals = decimals,
            totalSupply = totalSupply,
            ownerHex = hex(owner),
            minterHex = hex(minter),
            balances = balances,
            paused = paused,
        )
    }

    // --- byte helpers --------------------------------------------------------------------

    private class Reader(private val bytes: ByteArray) {
        private var pos = 0

        private fun want(n: Int): Boolean = n >= 0 && pos + n <= bytes.size

        fun u8(): Int? {
            if (!want(1)) return null
            return bytes[pos++].toInt() and 0xFF
        }

        fun bool(): Boolean? {
            val v = u8() ?: return null
            return v != 0
        }

        /** Read a 64-bit little-endian count; negative (i.e. >= 2^63) is rejected. */
        fun count(entryBytes: Int): Int? {
            val raw = u64() ?: return null
            if (raw < 0 || raw > (bytes.size - pos) / entryBytes) return null
            return raw.toInt()
        }

        private fun u64(): Long? {
            if (!want(8)) return null
            var value = 0L
            for (i in 7 downTo 0) {
                value = (value shl 8) or (bytes[pos + i].toLong() and 0xFF)
            }
            pos += 8
            return value
        }

        fun u128(): BigInteger? {
            if (!want(16)) return null
            val le = bytes.copyOfRange(pos, pos + 16)
            pos += 16
            le.reverse()
            return BigInteger(1, le)
        }

        fun bytes(n: Int): ByteArray? {
            if (!want(n)) return null
            val out = bytes.copyOfRange(pos, pos + n)
            pos += n
            return out
        }

        /** A bincode `String`: u64 length, then that many UTF-8 bytes. */
        fun text(maxBytes: Int): String? {
            val len = u64() ?: return null
            if (len < 0 || len > maxBytes) return null
            val raw = bytes(len.toInt()) ?: return null
            val decoded = String(raw, Charsets.UTF_8)
            // Round-trip to reject bytes that are not valid UTF-8.
            if (!decoded.toByteArray(Charsets.UTF_8).contentEquals(raw)) return null
            return decoded
        }
    }

    /** Lowercase hex, no `0x`. */
    fun hex(bytes: ByteArray): String {
        val out = StringBuilder(bytes.size * 2)
        for (b in bytes) {
            val v = b.toInt() and 0xFF
            out.append(HEX[v ushr 4]).append(HEX[v and 0x0F])
        }
        return out.toString()
    }

    /** Parse hex (with or without `0x`, even length) into bytes; `null` when malformed. */
    fun unhex(value: String): ByteArray? {
        val s = value.trim().removePrefix("0x").removePrefix("0X")
        if (s.isEmpty() || s.length % 2 != 0) return null
        val out = ByteArray(s.length / 2)
        for (i in out.indices) {
            val hi = Character.digit(s[i * 2], 16)
            val lo = Character.digit(s[i * 2 + 1], 16)
            if (hi < 0 || lo < 0) return null
            out[i] = ((hi shl 4) or lo).toByte()
        }
        return out
    }

    private const val HEX = "0123456789abcdef"
}
