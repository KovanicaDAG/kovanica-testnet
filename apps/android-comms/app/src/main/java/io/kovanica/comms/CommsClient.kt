package io.kovanica.comms

import org.json.JSONObject
import uniffi.kovanica_light.commsOpenEnvelope
import uniffi.kovanica_light.commsSealEnvelope
import uniffi.kovanica_light.commsVerifyEnvelope
import uniffi.kovanica_light.deriveCommsId
import uniffi.kovanica_light.walletPubkeyHex

/** One decrypted inbox entry. */
data class ReceivedMessage(
    val envelopeId: String,
    val senderCommsId: String,
    val payloadJson: String,
    val sentAtMs: Long,
)

/**
 * Client-only comms logic: seals/sends envelopes through the relay and opens
 * the recipient's inbox. Crypto runs through the generated UniFFI bindings
 * (`uniffi.kovanica_light`); this class never touches keys directly. Every method
 * decrypts the keystore, so call it off the UI thread (Argon2id).
 */
class CommsClient(
    private val keystoreJson: String,
    private val passphrase: String,
    private val relay: RelayClient,
) {
    /** Wallet Ed25519 public key hex (64 hex, no `0x`). Does not decrypt the seed. */
    fun myPubkeyHex(): String = walletPubkeyHex(keystoreJson)

    /** Comms identity hex derived from [myPubkeyHex]. */
    fun myCommsId(): String = deriveCommsId(myPubkeyHex())

    /**
     * Seal a text payload for [recipientPubkeyHex] and submit it to the relay.
     * Returns the envelope id assigned by the relay.
     *
     * The plaintext payload is compact JSON with key order `kind, body, ts`
     * (mirrors `payloadJson` in `packages/comms/src/messaging.ts`).
     */
    fun sendEnvelope(
        recipientPubkeyHex: String,
        body: String,
        kind: String = DEFAULT_KIND,
        ttlMs: Long = DEFAULT_TTL_MS,
    ): String {
        val now = System.currentTimeMillis()
        val payload = JSONObject()
            .put("kind", kind)
            .put("body", body)
            .put("ts", now)
            .toString()
        val envelope = commsSealEnvelope(
            keystoreJson,
            passphrase,
            recipientPubkeyHex,
            payload,
            now.toULong(),
            (now + ttlMs).toULong(),
        )
        return relay.postEnvelope(envelope)
    }

    /**
     * Fetch and open the recipient's inbox. Envelopes that cannot be parsed or
     * decrypted (wrong recipient, corrupt, expired-trimmed) are skipped, not
     * fatal. Returns entries oldest-first, matching relay arrival order.
     */
    fun fetchInbox(limit: Int = 50, sinceMs: Long? = null): List<ReceivedMessage> {
        val raw = relay.getInbox(myCommsId(), limit, sinceMs)
        val out = ArrayList<ReceivedMessage>(raw.size)
        for (envelopeJson in raw) {
            val envelope = try {
                JSONObject(envelopeJson)
            } catch (_: Exception) {
                continue
            }
            val payloadJson = try {
                commsOpenEnvelope(keystoreJson, passphrase, envelopeJson)
            } catch (_: Exception) {
                continue
            }
            out.add(
                ReceivedMessage(
                    envelopeId = envelope.optString("id"),
                    senderCommsId = envelope.optString("from"),
                    payloadJson = payloadJson,
                    sentAtMs = envelope.optLong("sentAt", 0L),
                ),
            )
        }
        return out
    }

    /** Acknowledge (delete) delivered envelopes on the relay. Returns the count. */
    fun ackMessages(ids: List<String>): Int = relay.ack(myCommsId(), ids)

    /**
     * Verify the sender's Ed25519 signature over [envelopeJson] against
     * [senderPubkeyHex]. Returns false on a bad signature or mismatched
     * `from`; only malformed JSON/hex is an error. The sender public key is
     * not carried in the envelope, so callers resolve it from [CommsStore].
     */
    fun verifyEnvelope(envelopeJson: String, senderPubkeyHex: String): Boolean =
        commsVerifyEnvelope(envelopeJson, senderPubkeyHex)

    companion object {
        const val DEFAULT_KIND: String = "text"
        const val DEFAULT_TTL_MS: Long = 7L * 24 * 3600 * 1000
    }
}
