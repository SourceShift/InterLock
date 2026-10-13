import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { Audit } from "./Audit";

const RECEIPTS_BODY = {
  total: 3,
  count_all: 3,
  receipts: [
    {
      index: 2,
      ts: 1700000002,
      action: "search",
      verdict: "ALLOW",
      reason: "fixture search",
      policy_id: "fixture",
      attributed_to: null,
      principal: "agent-1",
      span_id: null,
      phase: "call",
      args_digest: "0".repeat(64),
      observed: false,
      prev: "a".repeat(64),
      mac: "b".repeat(64),
    },
    {
      index: 1,
      ts: 1700000001,
      action: "http_post",
      verdict: "MODIFY",
      reason: "fixture http_post",
      policy_id: "fixture",
      attributed_to: null,
      principal: "agent-1",
      span_id: null,
      phase: "call",
      args_digest: "0".repeat(64),
      observed: false,
      prev: "c".repeat(64),
      mac: "a".repeat(64),
    },
    {
      index: 0,
      ts: 1700000000,
      action: "run_shell",
      verdict: "BLOCK",
      reason: "fixture run_shell",
      policy_id: "fixture",
      attributed_to: null,
      principal: "agent-1",
      span_id: null,
      phase: "call",
      args_digest: "0".repeat(64),
      observed: true,
      prev: "0".repeat(64),
      mac: "c".repeat(64),
    },
  ],
};

const VERIFY_BODY = { status: "intact", problem: null, count: 3, head: "b".repeat(64) };

function stubFetch(
  receiptsBody: unknown = RECEIPTS_BODY,
  verifyBody: unknown = VERIFY_BODY,
  receiptsOk = true
) {
  vi.stubGlobal(
    "fetch",
    vi.fn().mockImplementation((url: string) => {
      if (url === "/api/receipts") {
        if (!receiptsOk) {
          return Promise.resolve({
            ok: false,
            json: async () => receiptsBody,
          });
        }
        return Promise.resolve({ ok: true, json: async () => receiptsBody });
      }
      if (url === "/api/receipts/verify") {
        if (!receiptsOk) {
          return Promise.resolve({ ok: false, json: async () => receiptsBody });
        }
        return Promise.resolve({ ok: true, json: async () => verifyBody });
      }
      return Promise.resolve({
        ok: false,
        json: async () => ({ error: { code: "unknown_error", message: "unexpected" } }),
      });
    })
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("Audit", () => {
  it("renders one receipt-row per receipt, newest first, with a chain status", async () => {
    stubFetch();
    render(<Audit />);

    await waitFor(() => {
      expect(screen.getAllByTestId("receipt-row")).toHaveLength(3);
    });
    const rows = screen.getAllByTestId("receipt-row");
    expect(rows[0].textContent).toContain("search");
    expect(rows[2].textContent).toContain("run_shell");
    expect(screen.getByTestId("chain-status").textContent).toContain("intact");
    expect(screen.getByTestId("verdict-filter")).toBeTruthy();
  });

  it("filters rows by the selected verdict", async () => {
    stubFetch();
    render(<Audit />);

    await waitFor(() => {
      expect(screen.getAllByTestId("receipt-row")).toHaveLength(3);
    });

    fireEvent.change(screen.getByTestId("verdict-filter"), { target: { value: "BLOCK" } });

    await waitFor(() => {
      expect(screen.getAllByTestId("receipt-row")).toHaveLength(1);
    });
    expect(screen.getByTestId("receipt-row").textContent).toContain("run_shell");
  });

  it("shows a broken chain status with the problem text", async () => {
    stubFetch(RECEIPTS_BODY, { status: "broken", problem: "receipt 1: tampered", count: 3, head: "x" });
    render(<Audit />);

    await waitFor(() => {
      expect(screen.getByTestId("chain-status").textContent).toContain("broken");
    });
    expect(screen.getByTestId("chain-status").textContent).toContain("receipt 1: tampered");
  });

  it("renders a placeholder row for an unreadable receipt instead of failing the page", async () => {
    stubFetch({
      total: 4,
      count_all: 4,
      receipts: [{ index: 3, unreadable: true }, ...RECEIPTS_BODY.receipts],
    });
    render(<Audit />);

    await waitFor(() => {
      expect(screen.getAllByTestId("receipt-row")).toHaveLength(4);
    });
    const rows = screen.getAllByTestId("receipt-row");
    expect(rows[0].textContent).toContain("unreadable");
    expect(screen.getByTestId("chain-status")).toBeTruthy();
  });

  it("shows audit-empty when the console has no receipt log configured", async () => {
    stubFetch(
      { error: { code: "receipts_not_configured", message: "the console was started without --receipts" } },
      undefined,
      false
    );
    render(<Audit />);

    await waitFor(() => {
      expect(screen.getByTestId("audit-empty")).toBeTruthy();
    });
    expect(screen.getByTestId("audit-empty").textContent).toContain("--receipts");
    expect(screen.getByTestId("audit-empty").textContent).toContain("--key-file");
  });
});
