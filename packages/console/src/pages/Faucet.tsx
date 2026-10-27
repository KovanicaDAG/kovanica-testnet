import { useState } from "react";

import { useSession } from "../session";

interface FaucetBody {
  success?: boolean;
  message?: string;
  tx_hash?: string | null;
}

export function Faucet() {
  const { network, key } = useSession();
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  if (!network.faucetUrl) {
    return (
      <section>
        <h1>Faucet</h1>
        <p>The faucet is not available on {network.label}.</p>
      </section>
    );
  }

  async function dispense() {
    if (!key || !network.faucetUrl) return;
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      const response = await fetch(network.faucetUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ address: key.address }),
      });
      const body = (await response.json()) as FaucetBody;
      if (!response.ok || body.success === false) {
        throw new Error(body.message || `HTTP ${response.status}`);
      }
      setMessage(body.tx_hash ? `${body.message ?? "Sent"} (${body.tx_hash})` : body.message ?? "Sent");
    } catch (err) {
      setError(err instanceof Error ? err.message : "The faucet did not respond");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section>
      <h1>Faucet</h1>
      <p className="lede">Testnet KUNA for the unlocked address. Mainnet has no faucet.</p>
      {!key ? <p className="muted">Unlock a key on the Account page first.</p> : null}
      {key ? <p className="mono address">{key.address}</p> : null}
      <button type="button" className="btn primary" disabled={!key || busy} onClick={() => void dispense()}>
        {busy ? "Requesting…" : "Request testnet KUNA"}
      </button>
      {message ? <p>{message}</p> : null}
      {error ? <p className="error">{error}</p> : null}
    </section>
  );
}
