import { useEffect, useState } from "react";

import { loadActivity, saveActivity, type ActivityItem } from "../activity";
import { useSession } from "../session";

export function Activity() {
  const { network, client, headTick } = useSession();
  const [items, setItems] = useState<ActivityItem[]>(() => loadActivity(network.id));

  useEffect(() => {
    setItems(loadActivity(network.id));
  }, [network.id]);

  useEffect(() => {
    const pending = items.filter((item) => item.status === "pending");
    if (pending.length === 0) return;
    let cancel = false;
    void (async () => {
      const next = await Promise.all(
        items.map(async (item) => {
          if (item.status !== "pending") return item;
          try {
            const receipt = await client.getTransactionReceipt(item.hash);
            return receipt ? { ...item, status: "committed" as const } : item;
          } catch {
            return item;
          }
        }),
      );
      if (cancel) return;
      if (next.some((item, index) => item.status !== items[index]?.status)) {
        saveActivity(network.id, next);
        setItems(next);
      }
    })();
    return () => {
      cancel = true;
    };
  }, [client, headTick, items, network.id]);

  return (
    <section>
      <h1>Activity</h1>
      <p className="lede">
        Transactions this browser submitted on {network.label}. The node does not list the mempool,
        so only these local submissions are shown.
      </p>
      {items.length === 0 ? (
        <p className="muted">Nothing submitted from this browser on {network.label} yet.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>When</th>
              <th>Summary</th>
              <th>Status</th>
              <th>Hash</th>
            </tr>
          </thead>
          <tbody>
            {items.map((item) => (
              <tr key={item.hash}>
                <td>{new Date(item.submittedAt).toLocaleString()}</td>
                <td>
                  {item.summary}
                  <div className="muted">fee {item.fee} KUNA</div>
                </td>
                <td>{item.status === "committed" ? "In a block" : "Pending"}</td>
                <td className="mono">{item.hash}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
