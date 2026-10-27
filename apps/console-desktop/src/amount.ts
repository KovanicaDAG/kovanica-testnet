/**
 * KUNA amounts as integer atoms.
 *
 * One KUNA is 10^9 atoms. This module never uses floating point and never
 * parses an address.
 */

const ATOM_SCALE = 1_000_000_000n;
const MAX_ATOMS = 18446744073709551615n;
const DECIMALS = 9;

/** Parse a KUNA amount into atoms. More than 9 decimal places is an error. */
export function parseKunaAtoms(text: string): bigint {
  const raw = text.trim();
  if (raw.length === 0 || raw === ".") {
    throw new Error("Enter a KUNA amount.");
  }
  let dot = -1;
  for (let index = 0; index < raw.length; index += 1) {
    const code = raw.charCodeAt(index);
    if (code === 46) {
      if (dot !== -1) throw new Error("Enter a KUNA amount.");
      dot = index;
      continue;
    }
    if (code < 48 || code > 57) throw new Error("Enter a KUNA amount.");
  }
  const whole = dot === -1 ? raw : raw.slice(0, dot);
  const frac = dot === -1 ? "" : raw.slice(dot + 1);
  if (frac.length > DECIMALS) {
    throw new Error("KUNA amounts use at most 9 decimal places.");
  }
  const wholeAtoms = (whole.length === 0 ? 0n : BigInt(whole)) * ATOM_SCALE;
  const fracAtoms = BigInt((frac + "000000000").slice(0, DECIMALS));
  const total = wholeAtoms + fracAtoms;
  if (total > MAX_ATOMS) throw new Error("That amount is larger than KUNA can send.");
  return total;
}

/** Format atoms as a KUNA decimal. Trailing fractional zeros are omitted. */
export function formatKunaAtoms(atoms: bigint): string {
  if (atoms < 0n || atoms > MAX_ATOMS) {
    throw new Error("That amount is larger than KUNA can send.");
  }
  const whole = atoms / ATOM_SCALE;
  const frac = atoms % ATOM_SCALE;
  if (frac === 0n) return whole.toString();
  let digits = frac.toString().padStart(DECIMALS, "0");
  while (digits.endsWith("0")) digits = digits.slice(0, -1);
  return `${whole.toString()}.${digits}`;
}
