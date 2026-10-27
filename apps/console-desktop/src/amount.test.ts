import { describe, expect, it } from "vitest";

import { formatKunaAtoms, parseKunaAtoms } from "./amount";

describe("KUNA atoms", () => {
  it("parses and formats 0, 1 atom, 1 KUNA, and the max value", () => {
    expect(parseKunaAtoms("0")).toBe(0n);
    expect(parseKunaAtoms("0.000000001")).toBe(1n);
    expect(parseKunaAtoms("1")).toBe(1_000_000_000n);
    expect(parseKunaAtoms("18446744073.709551615")).toBe(18446744073709551615n);
    expect(formatKunaAtoms(0n)).toBe("0");
    expect(formatKunaAtoms(1n)).toBe("0.000000001");
    expect(formatKunaAtoms(1_000_000_000n)).toBe("1");
    expect(formatKunaAtoms(18446744073709551615n)).toBe("18446744073.709551615");
  });

  it("rejects more than 9 decimal places", () => {
    expect(() => parseKunaAtoms("0.0000000001")).toThrow(/9 decimal places/);
    expect(() => parseKunaAtoms("1.0000000001")).toThrow(/9 decimal places/);
    expect(() => parseKunaAtoms("1e9")).toThrow(/KUNA amount/);
    expect(() => parseKunaAtoms("-1")).toThrow(/KUNA amount/);
    expect(() => parseKunaAtoms("18446744073.709551616")).toThrow(/larger/);
  });
});
