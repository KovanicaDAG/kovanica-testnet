import { KovanicaRpcClient } from "../src/index.js";
import {
  generateKey,
  signTransaction,
  encodeRawTransaction,
  parseKuna,
  formatKuna,
} from "../../signer/src/index.js";

const RPC_URL = process.env.KOVANICA_RPC_URL || "https://rpc-testnet.kovanica.online/rpc";
const FAUCET_URL = process.env.KOVANICA_FAUCET_URL || "https://seed3.kovanica.online/faucet";

async function waitForBalance(client: KovanicaRpcClient, address: string, minBalance: bigint, timeoutSecs = 40): Promise<bigint> {
  const start = Date.now();
  while (Date.now() - start < timeoutSecs * 1000) {
    const bal = await client.getBalance(address);
    if (bal >= minBalance) {
      return bal;
    }
    await new Promise(r => setTimeout(r, 2000));
  }
  return await client.getBalance(address);
}

async function main() {
  console.log("=================================================");
  console.log("   KOVANICA CHAIN 4 TESTNET ECOSYSTEM TEST");
  console.log("=================================================");
  console.log(`RPC Endpoint: ${RPC_URL}`);
  console.log(`Faucet: ${FAUCET_URL}`);

  const client = new KovanicaRpcClient(RPC_URL);

  // 1. Block number
  const height = await client.blockNumber();
  console.log(`[1] Current block height: ${height}`);

  // 2. Validators
  const validators = await client.getValidators();
  console.log(`[2] Active validators count: ${validators.length}`);
  for (const v of validators) {
    console.log(`    - Validator: ${v.address.slice(0, 16)}... | Stake: ${formatKuna(v.stake)} KUNA | Active: ${v.active}`);
  }

  // 3. Generate test key
  const senderKey = await generateKey();
  console.log(`[3] Generated test sender address: ${senderKey.address}`);

  const initialBalance = await client.getBalance(senderKey.address);
  console.log(`    Initial balance: ${formatKuna(initialBalance)} KUNA`);

  // 4. Request from faucet
  console.log(`[4] Requesting 10 KUNA from faucet (${FAUCET_URL})...`);
  const faucetRes = await fetch(FAUCET_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ address: senderKey.address })
  });
  const faucetJson = await faucetRes.json();
  console.log(`    Faucet response:`, faucetJson);

  // Poll for funded balance
  console.log("    Waiting for block inclusion across cluster...");
  const fundedBalance = await waitForBalance(client, senderKey.address, parseKuna("10.0"));
  console.log(`[5] Funded balance: ${formatKuna(fundedBalance)} KUNA`);
  if (fundedBalance < parseKuna("10.0")) {
    throw new Error(`Expected at least 10 KUNA, got ${fundedBalance}`);
  }

  // 6. Generate recipient and send 1 KUNA
  const recipientKey = await generateKey();
  console.log(`[6] Generated recipient address: ${recipientKey.address}`);

  const nonce = await client.getNonce(senderKey.address);
  console.log(`    Current sender nonce: ${nonce}`);

  const unsignedTx = {
    sender: senderKey.publicKey,
    nonce: nonce,
    fee: 10_000n,
    kind: {
      type: "transfer" as const,
      to: recipientKey.publicKey,
      amount: parseKuna("1.0")
    }
  };

  const signed = await signTransaction(unsignedTx, 4, senderKey.seed);
  const rawTxHex = encodeRawTransaction(signed);
  console.log(`[7] Signed tx with hash: 0x${Buffer.from(signed.hash).toString("hex")}`);

  console.log(`    Submitting raw tx via sendRawTransaction...`);
  const txHash = await client.sendRawTransaction(rawTxHex);
  console.log(`    Broadcasted successfully! Returned tx hash: ${txHash}`);

  console.log("    Waiting for transaction inclusion in DAG...");
  const recipientBalance = await waitForBalance(client, recipientKey.address, parseKuna("1.0"));
  console.log(`[8] Recipient final balance: ${formatKuna(recipientBalance)} KUNA`);
  const senderFinalBalance = await client.getBalance(senderKey.address);
  console.log(`    Sender final balance: ${formatKuna(senderFinalBalance)} KUNA`);

  if (recipientBalance >= parseKuna("1.0")) {
    console.log("=================================================");
    console.log("   ALL ECOSYSTEM TESTS PASSED 100%!");
    console.log("=================================================");
  } else {
    throw new Error("Recipient balance did not receive 1.0 KUNA");
  }
}

main().catch(err => {
  console.error("Test failed:", err);
  process.exit(1);
});
