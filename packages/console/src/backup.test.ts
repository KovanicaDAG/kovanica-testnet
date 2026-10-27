import { generateKey } from "@kovanica/signer";
import { describe, expect, it } from "vitest";

import { BACKUP_ITERATIONS, decryptBackup, encryptBackup } from "./backup";

describe("encrypted backup", () => {
  it("round-trips a seed and rejects the wrong passphrase", async () => {
    expect(BACKUP_ITERATIONS).toBe(600_000);
    const key = await generateKey();
    const file = await encryptBackup(key.seed, "correct horse", key.address, 1_000);
    expect(file.kdf).toBe("PBKDF2-SHA256");
    expect(file.address).toBe(key.address);
    const opened = await decryptBackup(file, "correct horse");
    expect(opened).toEqual(key.seed);
    await expect(decryptBackup(file, "wrong horse")).rejects.toThrow(/passphrase/);
    key.seed.fill(0);
    opened.fill(0);
  });
});
