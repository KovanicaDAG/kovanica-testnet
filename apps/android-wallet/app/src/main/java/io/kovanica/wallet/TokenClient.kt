package io.kovanica.wallet

import org.json.JSONArray
import uniffi.kovanica_light.signCallRaw
import uniffi.kovanica_light.walletAddress
import java.math.BigInteger

/**
 * Outcome of reading one watched token. Kept as an explicit state so the UI can
 * tell "that address isn't a token" apart from "the node didn't answer" instead
 * of collapsing everything into an empty balance.
 */
sealed interface TokenRead {
    /** The address holds a decodable KVP-102 token. */
    data class Ok(val info: TokenInfo) : TokenRead

    /** Storage at the token slot is empty: nothing is deployed there. */
    data object NotAToken : TokenRead

    /** Storage exists but is not a `Token` (a different contract, or corrupt). */
    data object Unreadable : TokenRead

    /** The RPC call itself failed — network down, bad endpoint, node error. */
    data class Failed(val message: String) : TokenRead
}

/**
 * Read **and send** for KVP-102 tokens.
 *
 * There is no view RPC for token balances (`token_balance` is unimplemented on
 * the node), so [read] mirrors the raw contract-storage path the registry uses:
 * read the token singleton slot with `kovanica_getStorageAt`, then decode the
 * bincode `Token` with [TokenCodec].
 *
 * [sendTransfer] is the signing counterpart: it bincode-encodes the
 * `token_transfer` calldata, signs a `Call` through the light FFI's
 * `sign_call_raw` (bound here as `uniffi.kovanica_light.signCallRaw`), and submits
 * the raw transaction with `kovanica_sendRawTransaction`. A token transfer moves
 * the contract's **own** balances and never touches native KUNA.
 *
 * Call these off the UI thread — [NodeClient] is blocking and `signCallRaw`
 * decrypts the keystore (Argon2id).
 */
class TokenClient(private val node: NodeClient) {

    /**
     * Read the token deployed at [contractHex].
     *
     * @param contractHex canonical lowercase 64-hex contract address.
     */
    fun read(contractHex: String): TokenRead {
        val valueHex = try {
            val contract = KvncAddress.canonical(contractHex) ?: contractHex
            node.call(
                "kovanica_getStorageAt",
                JSONArray().put(contract).put("0x" + TokenCodec.stateSlotHex()),
            )
        } catch (error: Exception) {
            return TokenRead.Failed(error.message ?: "the node didn't answer")
        }
        val text = valueHex?.toString()?.trim().orEmpty()
        if (text.isEmpty() || text.equals("0x", ignoreCase = true)) {
            return TokenRead.NotAToken
        }
        val bytes = TokenCodec.unhex(text) ?: return TokenRead.Unreadable
        val info = TokenCodec.decode(bytes) ?: return TokenRead.Unreadable
        return TokenRead.Ok(info)
    }

    /**
     * Move [amount] of the token at [contractHex] to [toHex], end to end.
     *
     * This is a `token_transfer` call into the token contract, **not** a KUNA
     * transfer: it updates the contract's own balance map and never moves
     * native KUNA. The signed `Call.value` is therefore `0`.
     *
     * The calldata is the bincode `(to: [u8;32], amount: u128)` tuple the
     * `token_transfer` entry point decodes — the exact bytes
     * `kovanica_execution::call_args::encode_token_transfer` produces: a bare
     * 32-byte address followed by a 16-byte little-endian `u128`, no length
     * prefixes (bincode 1.x fixint). Nonce and fee rate come from the node
     * (`kovanica_getNonce` / `kovanica_estimateFee`), the same path the native send
     * uses.
     *
     * @param keystoreJson the encrypted keystore from this phone's prefs.
     * @param passphrase passphrase that unlocks [keystoreJson].
     * @param chainId the active network's chain id.
     * @param contractHex token contract address (lowercase 64-hex, `kvnc…dag`
     *   or `0x`-prefixed hex).
     * @param toHex recipient address (any accepted [KvncAddress] form).
     * @param amount transfer amount in the token's base units.
     * @param decimals the token's decimals (used only in the error wording).
     * @return the submitted transaction hash as the node reports it.
     * @throws IllegalArgumentException on a malformed address or an amount that
     *   is zero, negative or does not fit a `u128`.
     * @throws uniffi.kovanica_light.LightFfiException when the FFI refuses to sign
     *   (bad keystore, passphrase, calldata, address).
     * @throws IllegalStateException when the node rejects or drops the submit.
     */
    fun sendTransfer(
        keystoreJson: String,
        passphrase: String,
        chainId: ULong,
        contractHex: String,
        toHex: String,
        amount: BigInteger,
        decimals: Int,
    ): String {
        val contract = addressBytes(contractHex, "contract address")
        val recipient = addressBytes(toHex, "recipient address")
        if (amount.signum() <= 0) {
            throw IllegalArgumentException(
                "Amount must be a positive whole number of base units" +
                    decimalsNote(decimals) + ".",
            )
        }
        if (amount.bitLength() > 128) {
            throw IllegalArgumentException(
                "That amount is larger than the largest token amount (a 128-bit integer)" +
                    decimalsNote(decimals) + ".",
            )
        }

        // bincode `(to: [u8;32], amount: u128)` — 32 raw address bytes then a
        // 16-byte little-endian u128, exactly as `encode_token_transfer` writes.
        val argsHex = TokenCodec.hex(recipient + u128le(amount))

        val sender = walletAddress(keystoreJson)
        val nonce = parseQuantity(node.call("kovanica_getNonce", JSONArray().put(sender)))
        val rate = parseQuantity(node.call("kovanica_estimateFee", JSONArray()))

        val raw = signCallRaw(
            keystoreJson,
            passphrase,
            chainId,
            KvncAddress.canonical(TokenCodec.hex(contract))
                ?: throw IllegalArgumentException("That isn't a valid contract address."),
            NO_NATIVE_VALUE, // a token transfer sends no KUNA
            TRANSFER_METHOD, // "token_transfer"
            argsHex,
            TRANSFER_GAS_LIMIT,
            nonce,
            rate,
        )
        val hash = node.call("kovanica_sendRawTransaction", JSONArray().put(raw))
        return hash?.toString()
            ?: throw IllegalStateException("The node accepted the transaction but returned no hash.")
    }

    /** A validated 32-byte address as raw bytes; throws on any malformed input. */
    private fun addressBytes(hex: String, what: String): ByteArray {
        val normalized = KvncAddress.storedKey(hex)
            ?: throw IllegalArgumentException("That isn't a valid $what.")
        return TokenCodec.unhex(normalized)
            ?: throw IllegalArgumentException("That isn't a valid $what.")
    }

    /**
     * A `u128` as bincode writes it: 16 bytes, little-endian. The caller has
     * already checked `0 < value < 2^128`, so the leading sign byte
     * `BigInteger.toByteArray` may add for a high bit is a zero and is dropped.
     */
    private fun u128le(value: BigInteger): ByteArray {
        val out = ByteArray(16)
        val be = value.toByteArray()
        val n = minOf(be.size, 16)
        for (i in 0 until n) {
            out[i] = be[be.size - 1 - i]
        }
        return out
    }

    private fun decimalsNote(decimals: Int): String =
        if (decimals > 0) " (this token has $decimals decimals)" else ""

    private companion object {
        /** `token_transfer` — the kovanica-token entry point that moves internal balances. */
        const val TRANSFER_METHOD = "token_transfer"

        /** A token transfer moves no native KUNA; the signed `value` stays 0. */
        const val NO_NATIVE_VALUE = 0uL

        /**
         * Gas limit for one token call, in gas units (1 fuel = 1 gas). Matches
         * the node's `ExecutionConfig` default of 10_000_000 (`docs/GAS_SCHEDULE.md`
         * §1) and stays within the mempool's default `max_gas_limit` (§8). A
         * token transfer serialises the contract's whole holder map, so a small
         * limit risks an out-of-gas trap on a busy token; unused gas is not
         * refunded but is also not charged beyond the transaction fee.
         */
        const val TRANSFER_GAS_LIMIT = 10_000_000uL
    }
}
