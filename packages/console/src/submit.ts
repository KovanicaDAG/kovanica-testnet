import type { KovanicaRpcClient } from "@kovanica/api-client";
import {
  encodeRawTransaction,
  feeForRate,
  formatKuna,
  signTransaction,
  type AccountKey,
  type TxKind,
} from "@kovanica/signer";

import { rememberActivity } from "./activity";
import type { Network } from "./network";

export interface Submitted {
  hash: string;
  fee: bigint;
}

/** Read the nonce and fee rate, sign locally, and submit the raw transaction. */
export async function submitTransaction(input: {
  client: KovanicaRpcClient;
  network: Network;
  key: AccountKey;
  kind: TxKind;
  summary: string;
  /** Nonce shown on the review sheet. Sending stops if the account moved on. */
  nonce?: bigint;
}): Promise<Submitted> {
  const [nonce, rate] = await Promise.all([
    input.client.getNonce(input.key.address),
    input.client.estimateFee(),
  ]);
  if (input.nonce !== undefined && nonce !== input.nonce) {
    throw new Error("nonce changed, review the transaction again");
  }
  const fee = feeForRate(
    { sender: input.key.publicKey, nonce, kind: input.kind },
    rate < 1n ? 1n : rate,
  );
  const signed = await signTransaction(
    { sender: input.key.publicKey, nonce, kind: input.kind, fee },
    input.network.chainId,
    input.key.seed,
  );
  const hash = await input.client.sendRawTransaction(encodeRawTransaction(signed));
  rememberActivity({
    hash,
    networkId: input.network.id,
    summary: input.summary,
    fee: formatKuna(fee),
    submittedAt: Date.now(),
    status: "pending",
  });
  return { hash, fee };
}
