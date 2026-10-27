// @vitest-environment happy-dom

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { invoke } from "@tauri-apps/api/core";

import htmlSource from "../index.html?raw";
import { WALLET_LOCKED_EVENT } from "./wallet";
import { mountWallet } from "./wallet-view";

const eventHandlers = vi.hoisted(() => new Map<string, () => void>());

vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
}));

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn(async (event: string, handler: () => void) => {
    eventHandlers.set(event, handler);
    return () => {
      eventHandlers.delete(event);
    };
  }),
}));

/** Shown on the screen, then removed. This is not a wallet seed. */
const PHRASE = "screen-phrase-marker";

type AddedListener = {
  target: EventTarget;
  type: string;
  listener: EventListenerOrEventListenerObject;
};

const added: AddedListener[] = [];

function rememberAdds(target: Document | Window): void {
  const original = target.addEventListener.bind(target);
  target.addEventListener = ((
    type: string,
    listener: EventListenerOrEventListenerObject,
    options?: boolean | AddEventListenerOptions,
  ) => {
    added.push({ target, type, listener });
    original(type, listener, options);
  }) as typeof target.addEventListener;
}

function pageMarkup(): string {
  const start = htmlSource.indexOf("<body>");
  const end = htmlSource.lastIndexOf("</body>");
  if (start < 0 || end < start) {
    throw new Error("The console page has no body.");
  }
  return htmlSource
    .slice(start + "<body>".length, end)
    .replace(/<script\b[\s\S]*?<\/script>/gi, "");
}

function installHidden(hidden: boolean): void {
  Object.defineProperty(document, "hidden", {
    configurable: true,
    get: () => hidden,
  });
}

async function showRecoveryPhrase(): Promise<void> {
  document.body.innerHTML = pageMarkup();
  vi.mocked(invoke).mockImplementation(async (cmd: string) => {
    if (cmd === "wallet_status") {
      return { phase: "locked", address: "kvnc-screen-address" };
    }
    if (cmd === "wallet_reveal") {
      return { address: "kvnc-screen-address", mnemonic: PHRASE };
    }
    if (cmd === "wallet_touch") {
      return null;
    }
    throw new Error(`unexpected command ${cmd}`);
  });
  mountWallet(() => null);
  await vi.waitFor(() => {
    expect(document.querySelector<HTMLElement>("#wallet-locked")?.hidden).toBe(false);
  });
  const password = document.querySelector<HTMLInputElement>("#unlock-password");
  const show = document.querySelector<HTMLButtonElement>("#show-phrase");
  if (!password || !show) {
    throw new Error("The locked screen is missing the reveal controls.");
  }
  password.value = "typed-password";
  show.click();
  await vi.waitFor(() => {
    expect(document.querySelector("#mnemonic-text")?.textContent).toBe(PHRASE);
  });
  expect(document.body.textContent).toContain(PHRASE);
}

function assertPhraseGone(): void {
  expect(document.body.textContent ?? "").not.toContain(PHRASE);
  expect(document.body.innerHTML).not.toContain(PHRASE);
  expect(document.querySelector("#mnemonic-text")?.textContent ?? "").toBe("");
  for (const field of document.querySelectorAll("input, textarea")) {
    expect((field as HTMLInputElement).value).not.toContain(PHRASE);
  }
}

describe("recovery phrase on screen", () => {
  beforeEach(() => {
    added.length = 0;
    rememberAdds(document);
    rememberAdds(window);
    vi.spyOn(window, "setInterval").mockImplementation(
      () => 0 as unknown as ReturnType<typeof window.setInterval>,
    );
  });

  afterEach(() => {
    for (const item of added) {
      item.target.removeEventListener(item.type, item.listener);
    }
    added.length = 0;
    eventHandlers.clear();
    document.body.innerHTML = "";
    vi.restoreAllMocks();
    vi.mocked(invoke).mockReset();
  });

  it("clears the shown phrase when the document becomes hidden", async () => {
    await showRecoveryPhrase();
    installHidden(true);
    document.dispatchEvent(new Event("visibilitychange"));
    assertPhraseGone();
  });

  it("clears the shown phrase when the window blurs", async () => {
    await showRecoveryPhrase();
    installHidden(false);
    window.dispatchEvent(new Event("blur"));
    assertPhraseGone();
  });

  it("leaves the phrase variable empty after lock when status still says open", async () => {
    await showRecoveryPhrase();
    vi.mocked(invoke).mockImplementation(async (cmd: string) => {
      if (cmd === "wallet_status") {
        return { phase: "open", address: "kvnc-screen-address" };
      }
      if (cmd === "wallet_balance") {
        return { atoms: "0", display: "0", label: "Balance (reported by node)" };
      }
      if (cmd === "wallet_history") {
        return { label: "History (reported by node)", transfers: [] };
      }
      if (cmd === "wallet_touch") {
        return null;
      }
      throw new Error(`unexpected command ${cmd}`);
    });
    const locked = eventHandlers.get(WALLET_LOCKED_EVENT);
    if (!locked) {
      throw new Error("The screen is not listening for the lock.");
    }
    locked();
    await vi.waitFor(() => {
      expect(document.querySelector<HTMLElement>("#wallet-open")?.hidden).toBe(false);
    });
    assertPhraseGone();
    expect(document.querySelector<HTMLElement>("#wallet-mnemonic")?.hidden).toBe(true);
  });

  it("keeps the shown phrase when a visibility change leaves the document visible", async () => {
    await showRecoveryPhrase();
    installHidden(false);
    document.dispatchEvent(new Event("visibilitychange"));
    expect(document.querySelector("#mnemonic-text")?.textContent).toBe(PHRASE);
    expect(document.body.textContent).toContain(PHRASE);
  });

  it("shows the recovery phrase from the unlocked screen after the password", async () => {
    await showOpenWallet();
    const password = document.querySelector<HTMLInputElement>("#open-password");
    const show = document.querySelector<HTMLButtonElement>("#show-phrase-open");
    if (!password || !show) {
      throw new Error("The unlocked screen is missing the reveal controls.");
    }
    password.value = "typed-password";
    show.click();
    await vi.waitFor(() => {
      expect(document.querySelector("#mnemonic-text")?.textContent).toBe(PHRASE);
    });
    expect(document.querySelector<HTMLElement>("#wallet-mnemonic")?.hidden).toBe(false);
    expect(password.value).toBe("");
    expect(document.body.textContent).toContain(PHRASE);
    const revealCalls = vi.mocked(invoke).mock.calls.filter((call) => call[0] === "wallet_reveal");
    expect(revealCalls).toEqual([["wallet_reveal", { passphrase: "typed-password" }]]);
  });

  it("does not show the recovery phrase from the unlocked screen when the password is wrong", async () => {
    await showOpenWallet();
    const password = document.querySelector<HTMLInputElement>("#open-password");
    const show = document.querySelector<HTMLButtonElement>("#show-phrase-open");
    if (!password || !show) {
      throw new Error("The unlocked screen is missing the reveal controls.");
    }
    password.value = "not-the-password";
    show.click();
    await vi.waitFor(() => {
      const error = document.querySelector<HTMLElement>("#wallet-error");
      expect(error?.hidden).toBe(false);
      expect(error?.textContent).toBe("That password does not open this wallet.");
    });
    expect(password.value).toBe("");
    expect(document.body.textContent ?? "").not.toContain(PHRASE);
    expect(document.body.innerHTML).not.toContain(PHRASE);
    expect(document.querySelector<HTMLElement>("#wallet-mnemonic")?.hidden).toBe(true);
    expect(document.querySelector<HTMLElement>("#wallet-open")?.hidden).toBe(false);
    const revealCalls = vi.mocked(invoke).mock.calls.filter((call) => call[0] === "wallet_reveal");
    expect(revealCalls).toEqual([["wallet_reveal", { passphrase: "not-the-password" }]]);
  });
});

function passphraseArg(args: unknown): string {
  if (typeof args !== "object" || args === null || !("passphrase" in args)) {
    return "";
  }
  const value = args.passphrase;
  return typeof value === "string" ? value : "";
}

async function showOpenWallet(): Promise<void> {
  document.body.innerHTML = pageMarkup();
  vi.mocked(invoke).mockImplementation(async (cmd, args) => {
    if (cmd === "wallet_status") {
      return { phase: "open", address: "kvnc-open-address" };
    }
    if (cmd === "wallet_balance") {
      return { atoms: "0", display: "0", label: "Balance (reported by node)" };
    }
    if (cmd === "wallet_history") {
      return { label: "History (reported by node)", transfers: [] };
    }
    if (cmd === "wallet_touch") {
      return null;
    }
    if (cmd === "wallet_reveal") {
      if (passphraseArg(args) !== "typed-password") {
        throw "That password does not open this wallet.";
      }
      return { address: "kvnc-open-address", mnemonic: PHRASE };
    }
    throw new Error(`unexpected command ${cmd}`);
  });
  mountWallet(() => null);
  await vi.waitFor(() => {
    expect(document.querySelector<HTMLElement>("#wallet-open")?.hidden).toBe(false);
  });
  expect(document.body.textContent ?? "").not.toContain(PHRASE);
}
