import { useEffect, useState } from "react";
import type { ValidatorInfo } from "@kovanica/api-client";
import { feeForRate, formatKuna, parseAddress, parseKuna, type TxKind } from "@kovanica/signer";

import { ReviewSheet, type ReviewDetails } from "../components";
import { useSession } from "../session";
import { submitTransaction } from "../submit";
import { useAccountFigures } from "./figures";

export type Action = "stake" | "unstake" | "delegate" | "claim";

export function Stake() {
  const { key, client, network } = useSession();
  const figures = useAccountFigures();
  const [action, setAction] = useState<Action>("stake");
  const [amount, setAmount] = useState("");
  const [validator, setValidator] = useState("");
  const [validators, setValidators] = useState<ValidatorInfo[]>([]);
  const [review, setReview] = useState<ReviewDetails | null>(null);
  const [kind, setKind] = useState<TxKind | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [hash, setHash] = useState<string | null>(null);

  useEffect(() => {
    let cancel = false;
    void client
      .getValidators()
      .then((rows) => {
        if (!cancel) setValidators(rows);
      })
      .catch(() => {
        if (!cancel) setValidators([]);
      });
    return () => {
      cancel = true;
    };
  }, [client]);

  async function openReview() {
    if (!key) {
      setError("Create or import a key on the Account page first.");
      return;
    }
    setError(null);
    setHash(null);
    try {
      const next = buildKind(action, amount, validator, network.chainId);
      const [nonce, rate] = await Promise.all([client.getNonce(key.address), client.estimateFee()]);
      const fee = feeForRate(
        { sender: key.publicKey, nonce, kind: next },
        rate < 1n ? 1n : rate,
      );
      const shown = action === "claim" ? null : formatKuna(parseKuna(amount));
      setKind(next);
      setReview({
        network,
        action: label(action),
        amount: shown,
        feeAtoms: fee,
        nonce,
        detail: action === "delegate" || action === "claim" ? validator.trim() || "all validators" : null,
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not prepare the transaction");
    }
  }

  async function confirm() {
    if (!key || !review || !kind) return;
    setBusy(true);
    setError(null);
    try {
      const sent = await submitTransaction({
        client,
        network,
        key,
        kind,
        nonce: review.nonce,
        summary: review.amount ? `${review.action} ${review.amount} KUNA` : review.action,
      });
      setHash(sent.hash);
      setReview(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "The transaction was rejected");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section>
      <h1>Stake</h1>
      <p className="lede">
        A validator needs at least 50 000 KUNA staked. The node enforces that minimum.
      </p>
      <p className="muted">
        Reward balances are not accounted per address yet. The node reports{" "}
        {figures.rewards === null ? "—" : formatKuna(figures.rewards)} KUNA. Claim still submits a
        ClaimRewards transaction.
      </p>
      {!key ? <p className="muted">Unlock a key on the Account page to stake.</p> : null}
      <div className="card">
        <label>
          Action
          <select value={action} onChange={(event) => setAction(event.target.value as Action)}>
            <option value="stake">Stake</option>
            <option value="unstake">Unstake</option>
            <option value="delegate">Delegate</option>
            <option value="claim">Claim rewards</option>
          </select>
        </label>
        {action !== "claim" ? (
          <label>
            Amount (KUNA)
            <input value={amount} onChange={(event) => setAmount(event.target.value)} placeholder="50000" />
          </label>
        ) : null}
        {action === "delegate" || action === "claim" ? (
          <label>
            Validator
            <select value={validator} onChange={(event) => setValidator(event.target.value)}>
              <option value="">{action === "claim" ? "All validators" : "Choose a validator"}</option>
              {validators.map((row) => (
                <option key={row.address} value={row.address}>
                  {row.address} · {formatKuna(row.stake)} KUNA
                  {row.active ? "" : " · inactive"}
                </option>
              ))}
            </select>
          </label>
        ) : null}
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

export function buildKind(
  action: Action,
  amount: string,
  validator: string,
  chainId: number,
): TxKind {
  if (action === "claim") {
    const target = validator.trim();
    return {
      type: "claimRewards",
      validator: target ? parseAddress(target, chainId) : null,
    };
  }
  const atoms = parseKuna(amount);
  if (atoms === 0n) throw new Error("amount must be greater than 0");
  if (action === "stake") return { type: "stake", amount: atoms };
  if (action === "unstake") return { type: "unstake", amount: atoms };
  if (!validator.trim()) throw new Error("choose a validator");
  return { type: "delegate", validator: parseAddress(validator, chainId), amount: atoms };
}

function label(action: Action): string {
  switch (action) {
    case "stake":
      return "Stake";
    case "unstake":
      return "Unstake";
    case "delegate":
      return "Delegate";
    case "claim":
      return "Claim rewards";
  }
}
