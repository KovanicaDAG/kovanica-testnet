import { useState } from "react";
import { feeForRate, formatKuna, parseAddress, parseKuna } from "@kovanica/signer";

import { ReviewSheet, type ReviewDetails } from "../components";
import { useSession } from "../session";
import { submitTransaction } from "../submit";

/** Recipient bytes for a transfer on `chainId`. Legacy hex follows that chain. */
export function transferRecipient(to: string, chainId: number): Uint8Array {
  return parseAddress(to, chainId);
}

export function Transfer() {
  const { key, client, network } = useSession();
  const [to, setTo] = useState("");
  const [amount, setAmount] = useState("");
  const [review, setReview] = useState<ReviewDetails | null>(null);
  const [kindTo, setKindTo] = useState<Uint8Array | null>(null);
  const [atoms, setAtoms] = useState<bigint | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [hash, setHash] = useState<string | null>(null);

  async function openReview() {
    if (!key) {
      setError("Create or import a key on the Account page first.");
      return;
    }
    setError(null);
    setHash(null);
    try {
      const recipient = transferRecipient(to, network.chainId);
      const value = parseKuna(amount);
      if (value === 0n) throw new Error("amount must be greater than 0");
      const [nonce, rate] = await Promise.all([client.getNonce(key.address), client.estimateFee()]);
      const fee = feeForRate(
        {
          sender: key.publicKey,
          nonce,
          kind: { type: "transfer", to: recipient, amount: value },
        },
        rate < 1n ? 1n : rate,
      );
      setKindTo(recipient);
      setAtoms(value);
      setReview({
        network,
        action: "Transfer",
        amount: formatKuna(value),
        feeAtoms: fee,
        nonce,
        detail: to.trim(),
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not prepare the transfer");
    }
  }

  async function confirm() {
    if (!key || !review || !kindTo || atoms === null) return;
    setBusy(true);
    setError(null);
    try {
      const sent = await submitTransaction({
        client,
        network,
        key,
        nonce: review.nonce,
        summary: `Transfer ${review.amount} KUNA`,
        kind: { type: "transfer", to: kindTo, amount: atoms },
      });
      setHash(sent.hash);
      setReview(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "The transfer was rejected");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section>
      <h1>Transfer</h1>
      <p className="lede">Send KUNA on {network.label}. The key signs in this browser.</p>
      {!key ? <p className="muted">Unlock a key on the Account page to send.</p> : null}
      <div className="card">
        <label>
          Recipient
          <input value={to} onChange={(event) => setTo(event.target.value)} placeholder="kvnc…dag" />
        </label>
        <label>
          Amount (KUNA)
          <input value={amount} onChange={(event) => setAmount(event.target.value)} placeholder="1.5" />
        </label>
        <button type="button" className="btn primary" onClick={() => void openReview()} disabled={!key}>
          Review
        </button>
      </div>
      {error && !review ? <p className="error">{error}</p> : null}
      {hash ? <p className="mono">Submitted {hash}</p> : null}
      {review ? (
        <ReviewSheet
          details={review}
          busy={busy}
          error={error}
          onConfirm={() => void confirm()}
          onCancel={() => {
            setReview(null);
            setError(null);
          }}
        />
      ) : null}
    </section>
  );
}
