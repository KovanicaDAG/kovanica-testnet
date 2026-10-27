import { useEffect, useRef, useState } from "react";
import type { LeaderSlot } from "@kovanica/api-client";
import { formatKuna } from "@kovanica/signer";

import { shortAddress } from "../components";
import { useSession } from "../session";

export function Overview() {
  const { client, network, key, height, online, headTick } = useSession();
  const [peers, setPeers] = useState<number | null>(null);
  const [validators, setValidators] = useState<number | null>(null);
  const [leaders, setLeaders] = useState<LeaderSlot[]>([]);
  const [account, setAccount] = useState<{ balance: bigint; nonce: bigint; stake: bigint } | null>(
    null,
  );
  const [error, setError] = useState<string | null>(null);
  const [reload, setReload] = useState(0);
  const lastLoad = useRef(0);
  const force = useRef(true);

  useEffect(() => {
    let cancel = false;
    const elapsed = Date.now() - lastLoad.current;
    const wait = force.current || lastLoad.current === 0 ? 0 : Math.max(0, 12_000 - elapsed);
    const timer = window.setTimeout(() => {
      force.current = false;
      lastLoad.current = Date.now();
      void (async () => {
        try {
          const [health, committee, schedule] = await Promise.all([
            client.health(),
            client.getCommittee(),
            client.getLeaderSchedule(5),
          ]);
          if (cancel) return;
          setPeers(health.peerCount);
          setValidators(committee.length);
          setLeaders(schedule);
          setError(null);
          if (key) {
            const [balance, nonce, stake] = await Promise.all([
              client.getBalance(key.address),
              client.getNonce(key.address),
              client.getStake(key.address),
            ]);
            if (!cancel) setAccount({ balance, nonce, stake });
          } else if (!cancel) {
            setAccount(null);
          }
        } catch (err) {
          if (!cancel) setError(err instanceof Error ? err.message : "Could not reach the node");
        }
      })();
    }, wait);
    return () => {
      cancel = true;
      window.clearTimeout(timer);
    };
  }, [client, headTick, key, reload]);

  return (
    <section>
      <div className="page-head">
        <h1>Overview</h1>
        <button
          type="button"
          className="btn"
          onClick={() => {
            force.current = true;
            setReload((n) => n + 1);
          }}
        >
          Refresh
        </button>
      </div>
      <p className="lede">
        {network.label} · {online ? "Live heads" : "Waiting for the node"} · {rpcLabel(network.rpcUrl)}
      </p>
      {error ? <p className="error">{error}</p> : null}
      <div className="stats">
        <Stat label="Height" value={height === null ? "—" : height.toString()} />
        <Stat label="Peers" value={peers === null ? "—" : String(peers)} />
        <Stat label="Committee" value={validators === null ? "—" : String(validators)} />
        {key && account ? (
          <>
            <Stat label="Balance" value={`${formatKuna(account.balance)} KUNA`} />
            <Stat label="Nonce" value={account.nonce.toString()} />
            <Stat label="Stake" value={`${formatKuna(account.stake)} KUNA`} />
          </>
        ) : null}
      </div>
      <h2>Next leaders</h2>
      {leaders.length === 0 ? (
        <p className="muted">No schedule yet.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Round</th>
              <th>Leader</th>
            </tr>
          </thead>
          <tbody>
            {leaders.map((slot) => (
              <tr key={slot.round.toString()}>
                <td className="mono">{slot.round.toString()}</td>
                <td className="mono">{shortAddress(slot.leaderAddress)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="stat">
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
    </div>
  );
}

function rpcLabel(rpcUrl: string): string {
  try {
    return new URL(rpcUrl).host;
  } catch {
    return rpcUrl;
  }
}
