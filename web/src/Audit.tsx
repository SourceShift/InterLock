import { useEffect, useState } from "react";
import {
  ApiError,
  Receipt,
  VerifyResponse,
  fetchReceipts,
  fetchReceiptsVerify,
} from "./api";

type LoadState =
  | { kind: "loading" }
  | { kind: "empty" }
  | { kind: "error" }
  | { kind: "ready" };

const VERDICT_OPTIONS = ["ALL", "ALLOW", "BLOCK", "MODIFY"] as const;

function chainStatusText(verify: VerifyResponse | null): string {
  if (verify === null) {
    return "";
  }
  if (verify.status === "broken") {
    return `broken: ${verify.problem ?? ""}`;
  }
  return verify.status;
}

function shortDigest(digest: string): string {
  return digest.length > 12 ? `${digest.slice(0, 12)}…` : digest;
}

function localTime(ts: number): string {
  return new Date(ts * 1000).toLocaleString();
}

export function Audit() {
  const [state, setState] = useState<LoadState>({ kind: "loading" });
  const [receipts, setReceipts] = useState<Receipt[]>([]);
  const [verify, setVerify] = useState<VerifyResponse | null>(null);
  const [verdictFilter, setVerdictFilter] = useState<string>("ALL");
  const [live, setLive] = useState(true);
  const [liveConnected, setLiveConnected] = useState(false);

  useEffect(() => {
    let cancelled = false;
    Promise.all([fetchReceipts(), fetchReceiptsVerify()])
      .then(([receiptsResponse, verifyResponse]) => {
        if (cancelled) {
          return;
        }
        setReceipts(receiptsResponse.receipts);
        setVerify(verifyResponse);
        setState({ kind: "ready" });
      })
      .catch((error) => {
        if (cancelled) {
          return;
        }
        if (error instanceof ApiError && error.code === "receipts_not_configured") {
          setState({ kind: "empty" });
        } else {
          setState({ kind: "error" });
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (state.kind !== "ready" || !live || typeof EventSource === "undefined") {
      setLiveConnected(false);
      return;
    }
    const source = new EventSource("/api/receipts/stream");
    source.addEventListener("hello", () => setLiveConnected(true));
    source.addEventListener("receipt", (event) => {
      const fields = JSON.parse((event as MessageEvent).data) as Receipt;
      setReceipts((current) => [fields, ...current]);
    });
    source.addEventListener("reset", () => {
      fetchReceipts()
        .then((response) => setReceipts(response.receipts))
        .catch(() => {});
    });
    source.onerror = () => setLiveConnected(false);
    return () => {
      source.close();
      setLiveConnected(false);
    };
  }, [state.kind, live]);

  if (state.kind === "loading") {
    return (
      <section>
        <h1>Audit log</h1>
        <p>loading…</p>
      </section>
    );
  }

  if (state.kind === "empty") {
    return (
      <section>
        <h1>Audit log</h1>
        <p data-testid="audit-empty">
          No receipt log is configured. Start the console with{" "}
          <code className="mono">--receipts PATH</code> to point it at a receipt
          log, and <code className="mono">--key-file PATH</code> to verify its
          chain.
        </p>
      </section>
    );
  }

  if (state.kind === "error") {
    return (
      <section>
        <h1>Audit log</h1>
        <p>could not load the audit log.</p>
      </section>
    );
  }

  const visible = receipts.filter(
    (receipt) =>
      receipt.unreadable || verdictFilter === "ALL" || receipt.verdict === verdictFilter
  );

  return (
    <section>
      <h1>Audit log</h1>
      <p>
        Chain: <span data-testid="chain-status">{chainStatusText(verify)}</span>
        {" · "}
        Live:{" "}
        <span data-testid="live-indicator">{live && liveConnected ? "live" : "paused"}</span>{" "}
        <button type="button" data-testid="live-toggle" onClick={() => setLive((v) => !v)}>
          {live ? "Turn off" : "Turn on"}
        </button>
      </p>
      <label>
        Verdict:{" "}
        <select
          data-testid="verdict-filter"
          value={verdictFilter}
          onChange={(event) => setVerdictFilter(event.target.value)}
        >
          {VERDICT_OPTIONS.map((option) => (
            <option key={option} value={option}>
              {option}
            </option>
          ))}
        </select>
      </label>
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Action</th>
            <th>Verdict</th>
            <th>Reason</th>
            <th>Policy</th>
            <th>Principal</th>
            <th>Phase</th>
            <th>Digest</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {visible.map((receipt) =>
            receipt.unreadable ? (
              <tr key={receipt.index} data-testid="receipt-row">
                <td colSpan={9}>unreadable receipt at index {receipt.index}</td>
              </tr>
            ) : (
              <tr key={receipt.index} data-testid="receipt-row">
                <td>{localTime(receipt.ts)}</td>
                <td className="mono">{receipt.action}</td>
                <td>
                  <span data-testid="verdict-badge">{receipt.verdict}</span>
                </td>
                <td>{receipt.reason}</td>
                <td>{receipt.policy_id ?? ""}</td>
                <td>{receipt.principal ?? ""}</td>
                <td>{receipt.phase}</td>
                <td className="mono">{shortDigest(receipt.args_digest)}</td>
                <td data-testid="observed-marker">{receipt.observed ? "observed" : ""}</td>
              </tr>
            )
          )}
        </tbody>
      </table>
    </section>
  );
}
