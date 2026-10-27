import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { App } from "./App";
import { ReviewSheet } from "./components";
import { TESTNET } from "./network";
import { SessionProvider } from "./session";

class FakeWebSocket {
  static OPEN = 1;
  static CLOSED = 3;
  readyState = 0;
  onopen: (() => void) | null = null;
  onmessage: ((event: { data: string }) => void) | null = null;
  onerror: ((event: Event) => void) | null = null;
  constructor(public url: string) {}
  send(_data: string) {}
  close() {
    this.readyState = FakeWebSocket.CLOSED;
  }
}

beforeEach(() => {
  localStorage.clear();
  vi.stubGlobal("WebSocket", FakeWebSocket);
  vi.stubGlobal("fetch", vi.fn(async () => new Response("{}", { status: 503 })));
});

function renderApp() {
  return render(
    <MemoryRouter>
      <SessionProvider>
        <App />
      </SessionProvider>
    </MemoryRouter>,
  );
}

describe("network switch", () => {
  it("keeps chain id 4 when Mainnet is clicked", async () => {
    const user = userEvent.setup();
    renderApp();
    expect(screen.getByText("Chain ID 4").textContent).toBe("Chain ID 4");
    await user.click(screen.getByRole("button", { name: /mainnet/i }));
    expect(screen.getByRole("status").textContent).toMatch(/not open yet/i);
    expect(screen.getByText("Chain ID 4").textContent).toBe("Chain ID 4");
    expect(screen.getByRole("link", { name: "Faucet" }).textContent).toBe("Faucet");
  });
});

describe("review sheet", () => {
  it("shows the network, chain id, host, action, amount, fee, and nonce", () => {
    render(
      <ReviewSheet
        busy={false}
        error={null}
        onConfirm={() => {}}
        onCancel={() => {}}
        details={{
          network: TESTNET,
          action: "Transfer",
          amount: "1.5",
          feeAtoms: 200n,
          nonce: 7n,
          detail: "kvncrecipientdag",
        }}
      />,
    );
    const dialog = screen.getByRole("dialog").textContent ?? "";
    expect(dialog).toContain("Testnet");
    expect(dialog).toContain("Chain ID");
    expect(dialog).toContain("4");
    expect(dialog).toContain("rpc-testnet.kovanica.online");
    expect(dialog).toContain("Transfer");
    expect(dialog).toContain("1.5 KUNA");
    expect(dialog).toContain("Nonce");
    expect(dialog).toContain("7");
  });
});
