import { useEffect, useRef, useState } from "react";

import { useSession } from "../session";

export interface Figures {
  balance: bigint | null;
  nonce: bigint | null;
  stake: bigint | null;
  rewards: bigint | null;
  error: string | null;
}

export function useAccountFigures(): Figures {
  const { client, key, headTick } = useSession();
  const [figures, setFigures] = useState<Figures>({
    balance: null,
    nonce: null,
    stake: null,
    rewards: null,
    error: null,
  });
  const lastLoad = useRef(0);

  useEffect(() => {
    lastLoad.current = 0;
  }, [key?.address]);

  useEffect(() => {
    if (!key) {
      setFigures({ balance: null, nonce: null, stake: null, rewards: null, error: null });
      return;
    }
    const address = key.address;
    let cancel = false;
    const elapsed = Date.now() - lastLoad.current;
    const wait = lastLoad.current === 0 ? 0 : Math.max(0, 12_000 - elapsed);
    const timer = window.setTimeout(() => {
      lastLoad.current = Date.now();
      void (async () => {
        try {
          const [balance, nonce, stake, rewards] = await Promise.all([
            client.getBalance(address),
            client.getNonce(address),
            client.getStake(address),
            client.getRewards(address),
          ]);
          if (!cancel) setFigures({ balance, nonce, stake, rewards, error: null });
        } catch (err) {
          if (!cancel) {
            setFigures((current) => ({
              ...current,
              error: err instanceof Error ? err.message : "Could not read the account",
            }));
          }
        }
      })();
    }, wait);
    return () => {
      cancel = true;
      window.clearTimeout(timer);
    };
  }, [client, headTick, key]);

  return figures;
}
