/**
 * Wallet panels. The phrase lives in this closure until the user dismisses it.
 */

import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

import {
  EMPTY_HISTORY,
  HISTORY_HEADING,
  MNEMONIC_WARNING,
  PHRASE_STILL_IN_WALLET,
  reportListenFailure,
  SHOW_PHRASE_AGAIN,
  ACTIVITY_EVENTS,
  WALLET_LOCK_WARNING_EVENT,
  WALLET_LOCKED_EVENT,
  clearedImportFields,
  needsMainnetConfirm,
  phraseAfterCover,
  phraseLockWarning,
  passphraseAfterFailedReveal,
  phraseOnScreen,
  shouldCoverPhrase,
  reviewEnabled,
  revealedPhrase,
  reviewRows,
  secretsCleared,
  sendEnabled,
  shouldNoteActivity,
  type QuoteView,
} from "./wallet";

interface WalletStatus {
  phase: string;
  address: string | null;
}

interface NewWallet {
  address: string;
  mnemonic: string;
}

interface ReportedBalance {
  atoms: string;
  display: string;
  label: string;
}

interface TransferRow {
  direction: string;
  counterparty: string;
  amountAtoms: string;
  amountDisplay: string;
  height: string | null;
  transactionHash: string;
  pending: boolean;
}

interface HistoryPage {
  label: string;
  transfers: TransferRow[];
}

const STATUS_MS = 15_000;

function required<T extends Element>(id: string): T {
  const node = document.querySelector<T>(`#${id}`);
  if (!node) {
    throw new Error("Wallet screen is missing a control.");
  }
  return node;
}

function messageFrom(error: unknown): string {
  if (typeof error === "string" && error.trim() !== "") return error;
  if (error instanceof Error && error.message.trim() !== "") return error.message;
  return "The wallet could not be opened.";
}

/** Attach the wallet panels. `shownChainId` is the connection screen's chain. */
export function mountWallet(shownChainId: () => string | null): void {
  const absent = required<HTMLDivElement>("wallet-absent");
  const mnemonicPanel = required<HTMLDivElement>("wallet-mnemonic");
  const locked = required<HTMLDivElement>("wallet-locked");
  const open = required<HTMLDivElement>("wallet-open");
  const errorText = required<HTMLParagraphElement>("wallet-error");
  const newPassword = required<HTMLInputElement>("new-password");
  const createButton = required<HTMLButtonElement>("create-wallet");
  const importPhrase = required<HTMLTextAreaElement>("import-phrase");
  const importPassword = required<HTMLInputElement>("import-password");
  const importButton = required<HTMLButtonElement>("import-wallet");
  const mnemonicLockWarning = required<HTMLParagraphElement>("mnemonic-lock-warning");
  const mnemonicWarning = required<HTMLParagraphElement>("mnemonic-warning");
  const mnemonicText = required<HTMLParagraphElement>("mnemonic-text");
  const doneButton = required<HTMLButtonElement>("mnemonic-done");
  const lockedAddress = required<HTMLParagraphElement>("locked-address");
  const lockedBackup = required<HTMLParagraphElement>("locked-backup");
  const unlockPassword = required<HTMLInputElement>("unlock-password");
  const unlockButton = required<HTMLButtonElement>("unlock-wallet");
  const showPhraseButton = required<HTMLButtonElement>("show-phrase");
  const readout = required<HTMLDListElement>("wallet-readout");
  const openBackup = required<HTMLParagraphElement>("open-backup");
  const openPassword = required<HTMLInputElement>("open-password");
  const showPhraseOpenButton = required<HTMLButtonElement>("show-phrase-open");
  const lockButton = required<HTMLButtonElement>("lock-wallet");
  const refreshButton = required<HTMLButtonElement>("refresh-wallet");
  const recipient = required<HTMLInputElement>("recipient");
  const amount = required<HTMLInputElement>("amount");
  const reviewButton = required<HTMLButtonElement>("review-transfer");
  const review = required<HTMLDivElement>("review");
  const reviewList = required<HTMLDListElement>("review-rows");
  const confirmLabel = required<HTMLLabelElement>("mainnet-confirm-label");
  const confirmBox = required<HTMLInputElement>("mainnet-confirm");
  const sendButton = required<HTMLButtonElement>("send-transfer");
  const historyHeading = required<HTMLHeadingElement>("history-heading");
  const historyEmpty = required<HTMLParagraphElement>("history-empty");
  const historyList = required<HTMLUListElement>("history");

  let phrase = "";
  let phase = "absent";
  let quote: QuoteView | null = null;

  mnemonicWarning.textContent = MNEMONIC_WARNING;
  lockedBackup.textContent = PHRASE_STILL_IN_WALLET;
  openBackup.textContent = PHRASE_STILL_IN_WALLET;
  showPhraseButton.textContent = SHOW_PHRASE_AGAIN;
  showPhraseOpenButton.textContent = SHOW_PHRASE_AGAIN;
  historyHeading.textContent = HISTORY_HEADING;

  function showError(message: string): void {
    errorText.hidden = false;
    errorText.textContent = message;
  }

  function clearError(): void {
    errorText.hidden = true;
    errorText.textContent = "";
  }

  function show(which: "absent" | "mnemonic" | "locked" | "open"): void {
    absent.hidden = which !== "absent";
    mnemonicPanel.hidden = which !== "mnemonic";
    locked.hidden = which !== "locked";
    open.hidden = which !== "open";
  }

  function paintReadout(address: string, balance: ReportedBalance | null): void {
    readout.replaceChildren();
    const rows: Array<[string, string]> = [["Address", address]];
    if (balance) {
      rows.push([balance.label, `${balance.display} KUNA (${balance.atoms} atoms)`]);
    }
    for (const [label, value] of rows) {
      const term = document.createElement("dt");
      term.textContent = label;
      const data = document.createElement("dd");
      data.textContent = value;
      readout.append(term, data);
    }
  }

  function paintReview(): void {
    reviewList.replaceChildren();
    if (!quote) {
      review.hidden = true;
      confirmLabel.hidden = true;
      sendButton.disabled = true;
      return;
    }
    review.hidden = false;
    for (const row of reviewRows(quote)) {
      const term = document.createElement("dt");
      term.textContent = row.label;
      const data = document.createElement("dd");
      data.textContent = row.value;
      reviewList.append(term, data);
    }
    const mainnet = needsMainnetConfirm(quote.chainId);
    confirmLabel.hidden = !mainnet;
    if (!mainnet) confirmBox.checked = false;
    sendButton.disabled = !sendEnabled({
      phase,
      recipient: recipient.value,
      amount: amount.value,
      shownChainId: shownChainId(),
      quote,
      confirmMainnet: confirmBox.checked,
    });
  }

  function paintHistory(page: HistoryPage | null): void {
    historyHeading.textContent = page?.label ?? HISTORY_HEADING;
    historyList.replaceChildren();
    const transfers = page?.transfers ?? [];
    historyEmpty.hidden = transfers.length !== 0;
    historyEmpty.textContent = EMPTY_HISTORY;
    for (const row of transfers) {
      const item = document.createElement("li");
      const where = row.pending ? "pending" : `height ${row.height ?? ""}`;
      item.textContent = `${row.direction} ${row.amountDisplay} KUNA (${row.amountAtoms} atoms) ${row.counterparty} ${where} ${row.transactionHash}`;
      historyList.append(item);
    }
  }

  function syncButtons(): void {
    reviewButton.disabled = !reviewEnabled(phase, recipient.value, amount.value);
    paintReview();
  }

  function clearSecretFields(): void {
    const cleared = secretsCleared();
    phrase = cleared.phrase;
    mnemonicText.textContent = cleared.phrase;
    newPassword.value = cleared.password;
    importPhrase.value = cleared.phrase;
    importPassword.value = cleared.password;
    unlockPassword.value = cleared.password;
    openPassword.value = cleared.password;
    mnemonicPanel.hidden = true;
    quote = null;
    paintReview();
    paintLockWarning(false);
  }

  function paintLockWarning(warned: boolean): void {
    const text = phraseLockWarning(phrase, warned);
    mnemonicLockWarning.textContent = text;
    mnemonicLockWarning.hidden = text === "";
  }

  async function loadFigures(address: string): Promise<void> {
    const balance = await invoke<ReportedBalance>("wallet_balance");
    paintReadout(address, balance);
    const page = await invoke<HistoryPage>("wallet_history");
    paintHistory(page);
  }

  async function refreshStatus(): Promise<void> {
    const status = await invoke<WalletStatus>("wallet_status");
    phase = status.phase;
    phrase = phraseOnScreen(phase, phrase);
    mnemonicText.textContent = phrase;
    if (phrase === "") paintLockWarning(false);
    if (phrase !== "") {
      show("mnemonic");
      return;
    }
    if (status.phase === "open" && status.address) {
      show("open");
      await loadFigures(status.address);
      syncButtons();
      return;
    }
    quote = null;
    paintReview();
    if (status.phase === "locked") {
      show("locked");
      lockedAddress.textContent = status.address ?? "";
      return;
    }
    show("absent");
  }

  createButton.addEventListener("click", () => {
    void (async () => {
      clearError();
      try {
        const created = await invoke<NewWallet>("wallet_create", { passphrase: newPassword.value });
        newPassword.value = "";
        phrase = created.mnemonic;
        mnemonicText.textContent = phrase;
        paintLockWarning(false);
        phase = "open";
        show("mnemonic");
      } catch (error) {
        showError(messageFrom(error));
      }
    })();
  });

  importButton.addEventListener("click", () => {
    void (async () => {
      clearError();
      try {
        await invoke<WalletStatus>("wallet_import", {
          mnemonic: importPhrase.value,
          passphrase: importPassword.value,
        });
        phrase = "";
        await refreshStatus();
      } catch (error) {
        showError(messageFrom(error));
      } finally {
        const cleared = clearedImportFields();
        importPhrase.value = cleared.phrase;
        importPassword.value = cleared.password;
      }
    })();
  });

  doneButton.addEventListener("click", () => {
    phrase = "";
    mnemonicText.textContent = "";
    paintLockWarning(false);
    void refreshStatus().catch((error: unknown) => showError(messageFrom(error)));
  });

  unlockButton.addEventListener("click", () => {
    void (async () => {
      clearError();
      try {
        await invoke<WalletStatus>("wallet_unlock", { passphrase: unlockPassword.value });
        unlockPassword.value = "";
        await refreshStatus();
      } catch (error) {
        showError(messageFrom(error));
      }
    })();
  });

  showPhraseButton.addEventListener("click", () => {
    revealFrom(unlockPassword);
  });

  function revealFrom(passwordInput: HTMLInputElement): void {
    void (async () => {
      clearError();
      try {
        const revealed = await invoke<NewWallet>("wallet_reveal", {
          passphrase: passwordInput.value,
        });
        const shown = revealedPhrase(revealed.mnemonic);
        phrase = shown.phrase;
        passwordInput.value = shown.password;
        mnemonicText.textContent = phrase;
        paintLockWarning(false);
        phase = "open";
        show("mnemonic");
      } catch (error) {
        passwordInput.value = passphraseAfterFailedReveal();
        showError(messageFrom(error));
      }
    })();
  }

  showPhraseOpenButton.addEventListener("click", () => {
    revealFrom(openPassword);
  });

  lockButton.addEventListener("click", () => {
    void (async () => {
      clearError();
      quote = null;
      await invoke<WalletStatus>("wallet_lock");
      await refreshStatus();
    })().catch((error: unknown) => showError(messageFrom(error)));
  });

  refreshButton.addEventListener("click", () => {
    void refreshStatus().catch((error: unknown) => showError(messageFrom(error)));
  });

  reviewButton.addEventListener("click", () => {
    void (async () => {
      clearError();
      try {
        quote = await invoke<QuoteView>("wallet_quote", {
          shownChainId: shownChainId(),
          recipient: recipient.value,
          amount: amount.value,
        });
        confirmBox.checked = false;
        paintReview();
      } catch (error) {
        quote = null;
        paintReview();
        showError(messageFrom(error));
      }
    })();
  });

  sendButton.addEventListener("click", () => {
    void (async () => {
      clearError();
      if (
        !sendEnabled({
          phase,
          recipient: recipient.value,
          amount: amount.value,
          shownChainId: shownChainId(),
          quote,
          confirmMainnet: confirmBox.checked,
        })
      ) {
        return;
      }
      try {
        await invoke("wallet_send", {
          shownChainId: shownChainId(),
          confirmMainnet: confirmBox.checked,
          recipient: recipient.value,
          amount: amount.value,
        });
        quote = null;
        recipient.value = "";
        amount.value = "";
        confirmBox.checked = false;
        paintReview();
        await refreshStatus();
      } catch (error) {
        showError(messageFrom(error));
      }
    })();
  });

  for (const input of [recipient, amount]) {
    input.addEventListener("input", () => syncButtons());
  }
  confirmBox.addEventListener("change", () => syncButtons());

  let lastTouch = 0;
  const noteActivity = (): void => {
    const now = Date.now();
    const warningVisible = !mnemonicLockWarning.hidden;
    if (!shouldNoteActivity({ now, lastTouch, warningVisible })) return;
    lastTouch = now;
    if (warningVisible) paintLockWarning(false);
    void invoke("wallet_touch").catch(() => undefined);
  };
  for (const eventName of ACTIVITY_EVENTS) {
    document.addEventListener(eventName, noteActivity);
  }

  function coverShownPhrase(event: "visibilitychange" | "blur", documentHidden: boolean): void {
    if (!shouldCoverPhrase(event, documentHidden) || phrase === "") return;
    phrase = phraseAfterCover(phrase, true);
    mnemonicText.textContent = phrase;
    paintLockWarning(false);
    void refreshStatus().catch((error: unknown) => showError(messageFrom(error)));
  }
  document.addEventListener("visibilitychange", () => {
    coverShownPhrase("visibilitychange", document.hidden);
  });
  window.addEventListener("blur", () => {
    coverShownPhrase("blur", document.hidden);
  });

  const onListenError = (error: unknown): void => {
    reportListenFailure(
      error,
      (message, detail) => {
        console.error(message, detail);
      },
      showError,
    );
  };

  void listen(WALLET_LOCK_WARNING_EVENT, () => {
    paintLockWarning(true);
  }).catch(onListenError);

  void listen(WALLET_LOCKED_EVENT, () => {
    clearSecretFields();
    void refreshStatus().catch((error: unknown) => showError(messageFrom(error)));
  }).catch(onListenError);

  window.setInterval(() => {
    void refreshStatus().catch((error: unknown) => showError(messageFrom(error)));
  }, STATUS_MS);

  void refreshStatus().catch((error: unknown) => showError(messageFrom(error)));
}
