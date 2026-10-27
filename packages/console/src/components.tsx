import { NavLink } from "react-router-dom";
import { formatKuna } from "@kovanica/signer";

import { rpcHost, type Network } from "./network";
import { useSession } from "./session";

export function Shell({ children }: { children: React.ReactNode }) {
  const session = useSession();
  return (
    <div className="app">
      <header className="topbar">
        <div className="brand-block">
          <NavLink to="/" className="brand">
            Kovanica Console
          </NavLink>
          <span className="chain-id">Chain ID {session.network.chainId}</span>
        </div>
        <nav className="nav">
          <NavLink to="/" end>
            Overview
          </NavLink>
          <NavLink to="/account">Account</NavLink>
          <NavLink to="/transfer">Transfer</NavLink>
          <NavLink to="/stake">Stake</NavLink>
          <NavLink to="/activity">Activity</NavLink>
          {session.network.faucetUrl ? <NavLink to="/faucet">Faucet</NavLink> : null}
        </nav>
        <div className="top-actions">
          <NetworkSwitch />
          <AccountChip />
        </div>
      </header>
      {session.notice ? (
        <p className="notice" role="status">
          {session.notice}
        </p>
      ) : null}
      <main className="page">{children}</main>
    </div>
  );
}

export function NetworkSwitch() {
  const { networks, network, selectNetwork } = useSession();
  return (
    <div className="switch" role="group" aria-label="Network">
      {networks.map((item) => (
        <button
          key={item.id}
          type="button"
          className={item.id === network.id ? "switch-item active" : "switch-item"}
          aria-pressed={item.id === network.id}
          onClick={() => selectNetwork(item.id)}
        >
          {item.label}
          {!item.enabled ? <span className="soon">Soon</span> : null}
        </button>
      ))}
    </div>
  );
}

function AccountChip() {
  const { key, lock } = useSession();
  if (!key) return <span className="chip muted">No key</span>;
  return (
    <span className="chip">
      <span className="mono">{shortAddress(key.address)}</span>
      <button type="button" className="linkish" onClick={lock}>
        Lock
      </button>
    </span>
  );
}

export function shortAddress(address: string): string {
  if (address.length <= 20) return address;
  return `${address.slice(0, 10)}…${address.slice(-8)}`;
}

export interface ReviewDetails {
  network: Network;
  action: string;
  amount: string | null;
  feeAtoms: bigint;
  nonce: bigint;
  detail: string | null;
}

export function ReviewSheet({
  details,
  busy,
  error,
  onConfirm,
  onCancel,
}: {
  details: ReviewDetails;
  busy: boolean;
  error: string | null;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  return (
    <div className="sheet-backdrop" role="presentation">
      <div className="sheet" role="dialog" aria-modal="true" aria-labelledby="review-title">
        <h2 id="review-title">Review transaction</h2>
        <dl className="review">
          <div>
            <dt>Network</dt>
            <dd>{details.network.label}</dd>
          </div>
          <div>
            <dt>Chain ID</dt>
            <dd>{details.network.chainId}</dd>
          </div>
          <div>
            <dt>RPC</dt>
            <dd className="mono">{rpcHost(details.network.rpcUrl)}</dd>
          </div>
          <div>
            <dt>Action</dt>
            <dd>{details.action}</dd>
          </div>
          {details.amount ? (
            <div>
              <dt>Amount</dt>
              <dd>{details.amount} KUNA</dd>
            </div>
          ) : null}
          {details.detail ? (
            <div>
              <dt>Detail</dt>
              <dd className="mono">{details.detail}</dd>
            </div>
          ) : null}
          <div>
            <dt>Fee</dt>
            <dd>{formatKuna(details.feeAtoms)} KUNA</dd>
          </div>
          <div>
            <dt>Nonce</dt>
            <dd>{details.nonce.toString()}</dd>
          </div>
        </dl>
        {error ? <p className="error">{error}</p> : null}
        <div className="row">
          <button type="button" className="btn primary" onClick={onConfirm} disabled={busy}>
            {busy ? "Signing…" : "Sign and send"}
          </button>
          <button type="button" className="btn" onClick={onCancel} disabled={busy}>
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
}
