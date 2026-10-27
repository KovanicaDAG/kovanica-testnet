import { describe, expect, it } from "vitest";

import htmlSource from "../index.html?raw";
import mainSource from "./main.ts?raw";
import {
  BALANCE_LABEL,
  EMPTY_HISTORY,
  HISTORY_HEADING,
  LISTEN_FAILURE,
  LOCK_WARNING,
  MNEMONIC_WARNING,
  PHRASE_STILL_IN_WALLET,
  SHOW_PHRASE_AGAIN,
  WALLET_LOCK_WARNING_EVENT,
  WALLET_LOCKED_EVENT,
  clearedImportFields,
  needsMainnetConfirm,
  ACTIVITY_EVENTS,
  PHRASE_COVER_EVENTS,
  passphraseAfterFailedReveal,
  phraseAfterCover,
  phraseLockWarning,
  phraseOnScreen,
  shouldCoverPhrase,
  reportListenFailure,
  revealedPhrase,
  shouldNoteActivity,
  reviewRows,
  secretsCleared,
  sendEnabled,
  type QuoteView,
} from "./wallet";
import walletSource from "./wallet.ts?raw";
import viewSource from "./wallet-view.ts?raw";

const quote: QuoteView = {
  recipient: "kvnc-from-rust",
  amountAtoms: "1000000000",
  amountDisplay: "1",
  feeAtoms: "42",
  feeDisplay: "0.000000042",
  chainId: "4",
  nonce: "7",
  feeRate: "1",
  draftRecipient: "typed-recipient",
  draftAmount: "1",
};

function enabled(overrides: Partial<Parameters<typeof sendEnabled>[0]> = {}): boolean {
  return sendEnabled({
    phase: "open",
    recipient: quote.draftRecipient,
    amount: quote.draftAmount,
    shownChainId: "4",
    quote,
    confirmMainnet: false,
    ...overrides,
  });
}

describe("wallet form", () => {
  it("lists the recipient, amount, fee, chain, and nonce before sending", () => {
    expect(reviewRows(quote)).toEqual([
      { label: "Recipient", value: "kvnc-from-rust" },
      { label: "Amount", value: "1 KUNA (1000000000 atoms)" },
      { label: "Fee", value: "0.000000042 KUNA (42 atoms)" },
      { label: "Chain id", value: "4" },
      { label: "Nonce", value: "7" },
    ]);
  });

  it("sends only when the quote matches the form and the chain", () => {
    expect(enabled()).toBe(true);
    expect(enabled({ phase: "locked" })).toBe(false);
    expect(enabled({ quote: null })).toBe(false);
    expect(enabled({ recipient: "other" })).toBe(false);
    expect(enabled({ amount: "2" })).toBe(false);
    expect(enabled({ shownChainId: null })).toBe(false);
    expect(enabled({ shownChainId: "1" })).toBe(false);
    const mainnet = { ...quote, chainId: "1" };
    expect(enabled({ quote: mainnet, shownChainId: "1", confirmMainnet: false })).toBe(false);
    expect(enabled({ quote: mainnet, shownChainId: "1", confirmMainnet: true })).toBe(true);
    expect(needsMainnetConfirm("1")).toBe(true);
    expect(needsMainnetConfirm("4")).toBe(false);
  });

  it("warns before the phrase leaves the screen", () => {
    expect(WALLET_LOCK_WARNING_EVENT).toBe("wallet-lock-warning");
    expect(phraseLockWarning("one two three", true)).toBe(LOCK_WARNING);
    expect(phraseLockWarning("one two three", false)).toBe("");
    expect(phraseLockWarning("", true)).toBe("");
    expect(LOCK_WARNING.includes("recovery phrase")).toBe(true);
    expect(htmlSource.includes('id="mnemonic-lock-warning"')).toBe(true);
    const warnAt = viewSource.indexOf("listen(WALLET_LOCK_WARNING_EVENT");
    const lockAt = viewSource.indexOf("listen(WALLET_LOCKED_EVENT");
    expect(warnAt).toBeGreaterThan(0);
    expect(lockAt).toBeGreaterThan(warnAt);
    const handler = viewSource.slice(warnAt, lockAt);
    expect(handler.includes("paintLockWarning(true)")).toBe(true);
    expect(handler.includes('mnemonicText.textContent = ""')).toBe(false);
    expect(handler.includes('phrase = ""')).toBe(false);
    const activity = viewSource.slice(
      viewSource.indexOf("const noteActivity"),
      viewSource.indexOf("document.addEventListener"),
    );
    expect(activity.includes("mnemonicLockWarning.hidden")).toBe(true);
    expect(activity.includes("wallet_touch")).toBe(true);
    expect(activity.includes("paintLockWarning(false)")).toBe(true);
  });

  it("clears secrets when the lock event arrives, before the next status poll", () => {
    expect(WALLET_LOCKED_EVENT).toBe("wallet-locked");
    expect(secretsCleared()).toEqual({ phrase: "", password: "" });
    const listenAt = viewSource.indexOf("listen(WALLET_LOCKED_EVENT");
    expect(listenAt).toBeGreaterThan(0);
    const handler = viewSource.slice(listenAt, viewSource.indexOf("setInterval"));
    const clearAt = handler.indexOf("clearSecretFields()");
    const refreshAt = handler.indexOf("refreshStatus");
    expect(clearAt).toBeGreaterThan(0);
    expect(refreshAt).toBeGreaterThan(clearAt);
    const clearer = viewSource.slice(viewSource.indexOf("function clearSecretFields"), listenAt);
    expect(clearer.includes("secretsCleared()")).toBe(true);
    expect(clearer.includes("mnemonicText.textContent = cleared.phrase")).toBe(true);
    expect(clearer.includes("importPhrase.value = cleared.phrase")).toBe(true);
    expect(clearer.includes("newPassword.value = cleared.password")).toBe(true);
    expect(clearer.includes("unlockPassword.value = cleared.password")).toBe(true);
    expect(clearer.includes("openPassword.value = cleared.password")).toBe(true);
    expect(clearer.includes("mnemonicPanel.hidden = true")).toBe(true);
  });

  it("sets the phrase variable to empty when the wallet locks", () => {
    expect(secretsCleared().phrase).toBe("");
    const clearer = viewSource.slice(
      viewSource.indexOf("function clearSecretFields"),
      viewSource.indexOf("function paintLockWarning"),
    );
    expect(clearer.includes("phrase = cleared.phrase")).toBe(true);
    expect(clearer.includes("phraseVariableAfterLock")).toBe(false);
    expect(clearer.includes("mnemonicText.textContent = cleared.phrase")).toBe(true);
    const listenAt = viewSource.indexOf("listen(WALLET_LOCKED_EVENT");
    const handler = viewSource.slice(listenAt, viewSource.indexOf("setInterval"));
    expect(handler.indexOf("clearSecretFields()")).toBeGreaterThan(0);
  });

  it("shows the recovery phrase again after the password", () => {
    expect(SHOW_PHRASE_AGAIN).toBe("Show recovery phrase again");
    expect(PHRASE_STILL_IN_WALLET).toContain("password");
    expect(revealedPhrase("one two three")).toEqual({
      phrase: "one two three",
      password: "",
    });
    expect(LOCK_WARNING).toContain(SHOW_PHRASE_AGAIN);
    expect(htmlSource.includes('id="show-phrase"')).toBe(true);
    expect(htmlSource.includes('id="show-phrase-open"')).toBe(true);
    expect(htmlSource.includes('id="open-password"')).toBe(true);
    expect(htmlSource.includes('id="locked-backup"')).toBe(true);
    expect(htmlSource.includes('id="open-backup"')).toBe(true);
    expect(viewSource.includes("PHRASE_STILL_IN_WALLET")).toBe(true);
    expect(viewSource.includes("SHOW_PHRASE_AGAIN")).toBe(true);
    const handler = viewSource.slice(
      viewSource.indexOf("showPhraseButton.addEventListener"),
      viewSource.indexOf("\n  lockButton.addEventListener"),
    );
    expect(handler.includes('"wallet_reveal"')).toBe(true);
    expect(handler.includes("revealedPhrase(revealed.mnemonic)")).toBe(true);
    expect(handler.includes('show("mnemonic")')).toBe(true);
    expect(handler.includes("passwordInput.value = shown.password")).toBe(true);
    expect(handler.includes("revealFrom(unlockPassword)")).toBe(true);
    expect(handler.includes("revealFrom(openPassword)")).toBe(true);
  });

  it("clears the passphrase after a failed reveal", () => {
    expect(passphraseAfterFailedReveal()).toBe("");
    const handler = viewSource.slice(
      viewSource.indexOf("showPhraseButton.addEventListener"),
      viewSource.indexOf("\n  lockButton.addEventListener"),
    );
    const catchAt = handler.indexOf("} catch");
    expect(catchAt).toBeGreaterThan(0);
    const failure = handler.slice(catchAt);
    expect(failure.includes("passwordInput.value = passphraseAfterFailedReveal()")).toBe(true);
    expect(failure.includes("showError(messageFrom(error))")).toBe(true);
    expect(handler.indexOf("passphraseAfterFailedReveal()")).toBeGreaterThan(catchAt);
    expect(handler.indexOf("passwordInput.value = shown.password")).toBeLessThan(catchAt);
  });

  it("clears the recovery phrase when the window is hidden or blurred", () => {
    expect(PHRASE_COVER_EVENTS).toEqual(["visibilitychange", "blur"]);
    expect(shouldCoverPhrase("visibilitychange", true)).toBe(true);
    expect(shouldCoverPhrase("visibilitychange", false)).toBe(false);
    expect(shouldCoverPhrase("blur", false)).toBe(true);
    expect(shouldCoverPhrase("blur", true)).toBe(true);
    expect(phraseAfterCover("one two three", true)).toBe("");
    expect(phraseAfterCover("one two three", false)).toBe("one two three");
    const start = viewSource.indexOf("function coverShownPhrase");
    const hiddenAt = viewSource.indexOf('addEventListener("visibilitychange"');
    const blurAt = viewSource.indexOf('addEventListener("blur"');
    expect(start).toBeGreaterThan(0);
    expect(hiddenAt).toBeGreaterThan(start);
    expect(blurAt).toBeGreaterThan(hiddenAt);
    const cover = viewSource.slice(start, hiddenAt);
    expect(cover.includes("shouldCoverPhrase")).toBe(true);
    const phraseAt = cover.indexOf("phrase = phraseAfterCover(phrase, true)");
    const textAt = cover.indexOf("mnemonicText.textContent = phrase");
    const refreshAt = cover.indexOf("refreshStatus");
    expect(phraseAt).toBeGreaterThan(0);
    expect(textAt).toBeGreaterThan(phraseAt);
    expect(refreshAt).toBeGreaterThan(textAt);
    expect(cover.includes("document.hidden")).toBe(false);
    expect(viewSource.slice(hiddenAt, blurAt).includes("document.hidden")).toBe(true);
    expect(viewSource.slice(blurAt).includes("document.hidden")).toBe(true);
  });

  it("clears the recovery phrase from the screen when the session locks", () => {
    expect(phraseOnScreen("open", "one two three")).toBe("one two three");
    expect(phraseOnScreen("locked", "one two three")).toBe("");
    expect(phraseOnScreen("absent", "one two three")).toBe("");
    expect(viewSource.includes("phrase = phraseOnScreen(phase, phrase)")).toBe(true);
    expect(viewSource.includes("mnemonicText.textContent = phrase")).toBe(true);
  });

  it("logs a listen failure and shows an error", () => {
    const logged: Array<{ message: string; detail: unknown }> = [];
    const shown: string[] = [];
    const failure = new Error("event plugin unavailable");
    reportListenFailure(
      failure,
      (message, detail) => {
        logged.push({ message, detail });
      },
      (message) => {
        shown.push(message);
      },
    );
    expect(shown).toEqual([LISTEN_FAILURE]);
    expect(logged).toEqual([{ message: LISTEN_FAILURE, detail: failure }]);
    const listened = viewSource.slice(viewSource.indexOf("const onListenError"));
    expect(listened.includes("reportListenFailure")).toBe(true);
    expect(listened.includes("console.error")).toBe(true);
    expect(listened.includes(".catch(onListenError)")).toBe(true);
    expect(listened.includes(".catch(() => undefined)")).toBe(false);
    const locked = viewSource.slice(viewSource.indexOf("listen(WALLET_LOCKED_EVENT"));
    expect(locked.includes(".catch(onListenError)")).toBe(true);
    expect(locked.includes(".catch(() => undefined)")).toBe(false);
  });

  it("counts a keydown as activity", () => {
    expect(ACTIVITY_EVENTS).toContain("keydown");
    expect(shouldNoteActivity({ now: 10_000, lastTouch: 0, warningVisible: false })).toBe(true);
    expect(shouldNoteActivity({ now: 14_999, lastTouch: 10_000, warningVisible: false })).toBe(
      false,
    );
    expect(shouldNoteActivity({ now: 15_000, lastTouch: 10_000, warningVisible: false })).toBe(
      true,
    );
    expect(shouldNoteActivity({ now: 10_001, lastTouch: 10_000, warningVisible: true })).toBe(
      true,
    );
    const registration = viewSource.slice(viewSource.indexOf("for (const eventName of ACTIVITY_EVENTS)"));
    expect(registration.includes("document.addEventListener(eventName, noteActivity)")).toBe(true);
    expect(viewSource.includes('addEventListener("keydown"')).toBe(false);
  });

  it("does not keep a second idle timer beside the Rust lock", () => {
    for (const text of [walletSource, viewSource]) {
      expect(text.includes("LOCK_AFTER_MS")).toBe(false);
      expect(text.includes("idleLocked")).toBe(false);
    }
  });

  it("does not offer to copy the phrase", () => {
    expect(MNEMONIC_WARNING).toContain("Write it down");
    expect(MNEMONIC_WARNING.includes("clipboard")).toBe(false);
    for (const text of [walletSource, viewSource, htmlSource]) {
      expect(text.includes("copy-mnemonic")).toBe(false);
      expect(text.includes("clipboard")).toBe(false);
      expect(text.includes("copyMnemonic")).toBe(false);
    }
  });

  it("clears import fields after a failed import", () => {
    expect(clearedImportFields()).toEqual({ phrase: "", password: "" });
    const handler = viewSource.slice(viewSource.indexOf("wallet_import"));
    const finallyAt = handler.indexOf("finally");
    expect(finallyAt).toBeGreaterThan(0);
    expect(handler.indexOf("clearedImportFields()")).toBeGreaterThan(finallyAt);
    expect(handler.includes('importPhrase.value = ""')).toBe(false);
    expect(handler.includes('importPassword.value = ""')).toBe(false);
  });

  it("labels unproven figures and does not keep secrets in the page", () => {
    expect(HISTORY_HEADING).toBe("History (reported by node)");
    expect(BALANCE_LABEL).toBe("Balance (reported by node)");
    expect(EMPTY_HISTORY).toBe("No transfers reported by the node.");
    for (const text of [walletSource, viewSource, mainSource, htmlSource]) {
      expect(text.includes("localStorage")).toBe(false);
      expect(text.includes("innerHTML")).toBe(false);
    }
  });
});
