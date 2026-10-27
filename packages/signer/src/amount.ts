const DECIMALS = 9;
const ATOM = 1_000_000_000n;

/** Parse a decimal KUNA string into base units (9 decimals). */
export function parseKuna(input: string): bigint {
  const text = input.trim();
  if (!/^\d+(\.\d+)?$/.test(text)) {
    throw new Error("enter a KUNA amount");
  }
  const [whole, frac = ""] = text.split(".");
  if (frac.length > DECIMALS) {
    throw new Error("KUNA has 9 decimal places");
  }
  return BigInt(whole) * ATOM + BigInt(frac.padEnd(DECIMALS, "0"));
}

/** Format base units as a KUNA decimal, trimming trailing zeros. */
export function formatKuna(atoms: bigint): string {
  if (atoms < 0n) {
    throw new Error("amount is negative");
  }
  const whole = atoms / ATOM;
  const frac = atoms % ATOM;
  if (frac === 0n) return whole.toString();
  const fracText = frac.toString().padStart(DECIMALS, "0").replace(/0+$/, "");
  return `${whole}.${fracText}`;
}
