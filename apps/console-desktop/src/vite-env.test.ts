import { describe, expect, it } from "vitest";

import config from "../vite.config";

function prefixes(value: string | readonly string[] | undefined): string[] {
  if (value === undefined) return [];
  return typeof value === "string" ? [value] : [...value];
}

describe("vite client env", () => {
  it("does not expose TAURI_SIGNING variables to the bundle", () => {
    const allowed = prefixes(config.envPrefix);
    expect(allowed).toEqual(["VITE_", "TAURI_ENV_"]);
    for (const name of ["TAURI_SIGNING_PRIVATE_KEY", "TAURI_SIGNING_PRIVATE_KEY_PASSWORD"]) {
      expect(allowed.some((prefix) => name.startsWith(prefix))).toBe(false);
    }
    expect(allowed.some((prefix) => "TAURI_ENV_PLATFORM".startsWith(prefix))).toBe(true);
    expect(allowed.some((prefix) => "VITE_RPC_URL".startsWith(prefix))).toBe(true);
  });
});
