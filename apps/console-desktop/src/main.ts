import { invoke } from "@tauri-apps/api/core";

import {
  endpointLine,
  peerLines,
  statusRows,
  type ConnectionConfig,
  type NodeStatus,
  type StatusRow,
} from "./connection";
import { mountWallet } from "./wallet-view";
import "./styles.css";

let shownChainId: string | null = null;

const rpcInput = document.querySelector<HTMLInputElement>("#rpc");
const endpoint = document.querySelector<HTMLParagraphElement>("#endpoint");
const errorBox = document.querySelector<HTMLParagraphElement>("#error");
const statusList = document.querySelector<HTMLDListElement>("#status");
const peerList = document.querySelector<HTMLUListElement>("#peers");
const saveButton = document.querySelector<HTMLButtonElement>("#save");
const resetButton = document.querySelector<HTMLButtonElement>("#reset");
const refreshButton = document.querySelector<HTMLButtonElement>("#refresh");

if (
  !rpcInput ||
  !endpoint ||
  !errorBox ||
  !statusList ||
  !peerList ||
  !saveButton ||
  !resetButton ||
  !refreshButton
) {
  throw new Error("Connection screen is missing a control.");
}

const rpc: HTMLInputElement = rpcInput;
const endpointText: HTMLParagraphElement = endpoint;
const errorText: HTMLParagraphElement = errorBox;
const statusNode: HTMLDListElement = statusList;
const peersNode: HTMLUListElement = peerList;
const save: HTMLButtonElement = saveButton;
const reset: HTMLButtonElement = resetButton;
const refresh: HTMLButtonElement = refreshButton;

function showError(message: string): void {
  errorText.hidden = false;
  errorText.textContent = message;
}

function clearError(): void {
  errorText.hidden = true;
  errorText.textContent = "";
}

function clearNode(): void {
  statusNode.replaceChildren();
  peersNode.replaceChildren();
}

function fillRows(rows: StatusRow[]): void {
  statusNode.replaceChildren();
  for (const row of rows) {
    const term = document.createElement("dt");
    term.textContent = row.label;
    const value = document.createElement("dd");
    value.textContent = row.value;
    statusNode.append(term, value);
  }
}

function fillPeers(lines: string[]): void {
  peersNode.replaceChildren();
  for (const line of lines) {
    const item = document.createElement("li");
    item.textContent = line;
    peersNode.append(item);
  }
}

function applyConfig(config: ConnectionConfig): void {
  rpc.value = config.rpcUrl;
  endpointText.textContent = endpointLine(config.endpointLabel);
}

function messageFrom(error: unknown): string {
  if (typeof error === "string" && error.trim() !== "") return error;
  if (error instanceof Error && error.message.trim() !== "") return error.message;
  return "The node is not reachable.";
}

async function loadConfig(): Promise<void> {
  applyConfig(await invoke<ConnectionConfig>("connection_config"));
}

async function refreshStatus(): Promise<void> {
  refresh.disabled = true;
  clearError();
  try {
    const status = await invoke<NodeStatus>("node_status");
    shownChainId = status.chainId;
    fillRows(statusRows(status));
    fillPeers(peerLines(status.peers));
  } catch (error) {
    shownChainId = null;
    clearNode();
    showError(messageFrom(error));
  } finally {
    refresh.disabled = false;
  }
}

save.addEventListener("click", () => {
  void (async () => {
    clearError();
    try {
      applyConfig(await invoke<ConnectionConfig>("save_connection", { rpcUrl: rpc.value }));
      await refreshStatus();
    } catch (error) {
      showError(messageFrom(error));
    }
  })();
});

reset.addEventListener("click", () => {
  void (async () => {
    clearError();
    try {
      applyConfig(await invoke<ConnectionConfig>("reset_connection"));
      await refreshStatus();
    } catch (error) {
      showError(messageFrom(error));
    }
  })();
});

refresh.addEventListener("click", () => {
  void refreshStatus();
});

mountWallet(() => shownChainId);

void (async () => {
  try {
    await loadConfig();
    await refreshStatus();
  } catch (error) {
    showError(messageFrom(error));
  }
})();
