/**
 * Panels the designer's file has no markup for, mounted at the
 * `<il-extra name="...">` points the converter inserts (scripts/console_design):
 * the call behind a receipt, real calls in the playground, a policy backtest,
 * and the detector sweep. Written in the design's own vocabulary - its
 * tokens, type sizes, chips and buttons - so they read as part of it.
 */
import type { CSSProperties, ReactNode } from "react";
import type { BacktestRow, CallReceipt, RealCall, SweepDetector } from "../api";
import { ago, chip, fmtDT, fmtT, num, tilde } from "../format";
import type { Data, State } from "../model";
import type { Actions } from "../vals";

const mono = "'Martian Mono',monospace";
const label: CSSProperties = { fontFamily: mono, fontSize: "10px", letterSpacing: ".06em", textTransform: "uppercase", color: "var(--il-dim)" };
const panel: CSSProperties = { background: "var(--il-panel)", border: "1px solid var(--il-rule)", borderRadius: "12px", padding: "14px 16px", display: "flex", flexDirection: "column", gap: "10px", minWidth: 0 };
const code: CSSProperties = { fontFamily: mono, fontSize: "10.5px", padding: "8px 10px", borderRadius: "7px", background: "var(--il-sunken)", border: "1px solid var(--il-rule)", overflowWrap: "anywhere", color: "var(--il-fg2)", margin: 0, whiteSpace: "pre-wrap" };
const btn: CSSProperties = { fontSize: "12.5px", padding: "6px 12px", borderRadius: "7px", border: "1px solid var(--il-rule2)", background: "var(--il-raised)", cursor: "pointer", color: "var(--il-fg)" };
const primary: CSSProperties = { fontSize: "12.5px", fontWeight: 600, padding: "6px 14px", borderRadius: "7px", border: 0, background: "var(--il-acc)", color: "var(--il-accfg)", cursor: "pointer" };
const dim: CSSProperties = { fontSize: "11.5px", color: "var(--il-dim)" };
const input: CSSProperties = { padding: "6px 9px", borderRadius: "7px", border: "1px solid var(--il-rule2)", background: "var(--il-sunken)", fontSize: "12.5px", minWidth: 0 };

function Chip({ verdict, observed, word }: { verdict: string | null | undefined; observed?: boolean; word?: string }) {
  const c = chip(verdict, observed);
  return (
    <span style={{ display: "inline-flex", gap: "5px", alignItems: "center", fontFamily: mono, fontSize: "10px", padding: "2px 7px", borderRadius: "5px", color: c.c, background: c.bg, border: `1px ${c.bs} ${c.bc}`, whiteSpace: "nowrap" }}>
      <span aria-hidden="true">{c.mark}</span>
      {word ?? c.word}
    </span>
  );
}

const MASK_NOTE = "Credentials are masked with the same patterns the guard uses.";

// --- the call behind a receipt (audit drawer) ------------------------------------------

function ReceiptCall({ S, D, A }: { S: State; D: Data; A: Actions }) {
  const idx = S.route.path === "audit" && S.route.q.r ? Number(S.route.q.r) : null;
  if (idx === null) return null;
  const receipt = D.receipts.find((r) => r.index === idx) ?? D.selReceipt;
  if (!receipt || receipt.unreadable || !receipt.call_id) return null;
  const d = D.callDetailFor === idx ? D.callDetail : null;
  const home = D.session?.home;
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "8px" }} data-testid="receipt-call">
      <span style={label}>The call</span>
      {!d ? (
        <span style={dim}>Looking for this call in the agent's transcript…</span>
      ) : !d.found ? (
        <span style={dim}>
          No transcript holds call {receipt.call_id} ({d.searched ?? 0} file{d.searched === 1 ? "" : "s"} searched). It may come from another
          agent, or its session's transcript was removed.
        </span>
      ) : (
        <>
          <div style={{ display: "flex", gap: "8px", alignItems: "baseline", flexWrap: "wrap" }}>
            <span style={{ fontFamily: mono, fontSize: "12px", color: "var(--il-fg)" }}>{d.tool}</span>
            {d.subagent ? <span style={{ ...dim, fontFamily: mono, fontSize: "10px" }}>subagent</span> : null}
            <span style={{ ...dim, fontFamily: mono, fontSize: "10px" }}>{d.ts ? fmtDT(d.ts * 1000) : ""}</span>
          </div>
          {d.target ? <code style={code}>{d.target}</code> : null}
          <span style={dim}>
            in {tilde(d.cwd, home) || "an unknown directory"} · transcript {tilde(d.transcript, home)}
          </span>
          {d.digest?.match === true ? (
            <span style={{ fontSize: "12px", color: "var(--il-allow)" }}>✓ The transcript's arguments reproduce this receipt's fingerprint: this is the recorded call.</span>
          ) : d.digest?.match === false ? (
            <span style={{ fontSize: "12px", color: "var(--il-rewrite)" }}>! The transcript's arguments don't reproduce the receipt's fingerprint.</span>
          ) : null}
          {d.receipts.length > 1 ? (
            <div style={{ display: "flex", gap: "6px", flexWrap: "wrap", alignItems: "center" }}>
              <span style={dim}>Receipts for this call:</span>
              {d.receipts.map((r: CallReceipt) => (
                <a key={r.index} href={"#/audit?r=" + r.index} style={{ textDecoration: "none" }} title={r.policy_id ?? ""}>
                  <Chip verdict={r.policy_verdict || r.verdict} word={r.phase + " · " + chip(r.policy_verdict || r.verdict).word} />
                </a>
              ))}
            </div>
          ) : null}
          {d.result !== null && d.result !== undefined ? (
            <>
              <span style={{ ...label, marginTop: "4px" }}>What the model saw</span>
              <pre style={{ ...code, maxHeight: "260px", overflow: "auto" }}>{d.result || "(empty)"}</pre>
              <span style={dim}>
                {num(d.result_len ?? 0)} chars{d.is_error ? " · the tool reported an error" : ""}. {MASK_NOTE}
              </span>
            </>
          ) : null}
          <div>
            <button style={btn} onClick={() => A.openInPlayground({ calls: [{ call_id: d.call_id, session: d.session, ts: d.ts }] })}>
              Open in playground
            </button>
          </div>
        </>
      )}
    </div>
  );
}

// --- mesh (the shared policy commons) ---------------------------------------------------

function MeshPanel({ D, A }: { D: Data; A: Actions }) {
  const m = D.mesh;
  if (D.meshErr) {
    return (
      <section style={panel} data-testid="mesh-panel">
        <span style={label}>Mesh</span>
        <span style={{ fontSize: "12.5px", color: "var(--il-block)" }}>✗ {D.meshErr}</span>
      </section>
    );
  }
  if (!m) {
    return (
      <section style={panel} data-testid="mesh-panel">
        <span style={label}>Mesh</span>
        <span style={dim}>Reading this node's mesh state…</span>
      </section>
    );
  }
  const packs = Object.entries(m.packs ?? {});
  const layers = m.report.layers;
  const lastSync = typeof m.last_sync === "number" ? fmtDT(m.last_sync * 1000) : "never";
  const enabled = typeof m.report.enabled_at === "number" ? fmtDT(m.report.enabled_at * 1000) : "";
  const splits = Array.isArray(m.split_views) ? m.split_views.length : 0;
  return (
    <section style={panel} data-testid="mesh-panel">
      <div style={{ display: "flex", alignItems: "baseline", gap: "10px", flexWrap: "wrap" }}>
        <h2 style={{ margin: 0, fontSize: "14px", fontWeight: 600 }}>Mesh</h2>
        <span style={{ ...dim, flex: 1 }}>
          {m.configured ? "a shared policy commons, verified against this node's pinned root" : "no commons on this node"}
        </span>
        <button style={btn} onClick={() => A.refreshMesh()}>Refresh</button>
      </div>

      {!m.configured ? (
        <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
          <span style={dim}>Reporting consent can be set without a commons; policy packs need one.</span>
          <code style={code}>interlock mesh init --root root.json --mirror https://commons.example.org</code>
        </div>
      ) : (
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(150px,1fr))", gap: "1px", background: "var(--il-rule)", border: "1px solid var(--il-rule)", borderRadius: "8px", overflow: "hidden" }}>
          {[
            { k: "root", v: m.root_version ? "v" + m.root_version : "—", c: m.timestamp_expired ? "var(--il-rewrite)" : "var(--il-fg)" },
            { k: "ring", v: m.ring ?? "—", c: "var(--il-fg)" },
            { k: "packs", v: num(packs.length), c: "var(--il-fg)" },
            { k: "last sync", v: lastSync, c: "var(--il-fg)" },
            { k: "timestamp expires", v: m.timestamp_expires ? fmtDT(Date.parse(m.timestamp_expires)) : "—", c: m.timestamp_expired ? "var(--il-rewrite)" : "var(--il-fg)" },
            { k: "split views", v: num(splits), c: splits ? "var(--il-block)" : "var(--il-allow)" },
          ].map((x) => (
            <div key={x.k} style={{ background: "var(--il-panel)", padding: "9px 11px", display: "flex", flexDirection: "column", gap: "1px" }}>
              <span style={{ fontSize: "14px", fontWeight: 600, fontVariantNumeric: "tabular-nums", color: x.c }}>{x.v}</span>
              <span style={{ fontFamily: mono, fontSize: "9.5px", color: "var(--il-dim)" }}>{x.k}</span>
            </div>
          ))}
        </div>
      )}

      {m.last_error ? <span style={{ fontSize: "12px", color: "var(--il-rewrite)" }}>! last sync: {m.last_error}</span> : null}
      {m.cache_error ? <span style={{ fontSize: "12px", color: "var(--il-block)" }}>✗ cache: {m.cache_error}</span> : null}

      {m.configured ? (
        <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
          <span style={label}>Verified packs</span>
          {packs.length === 0 ? <span style={dim}>No packs in the verified cache yet. Run <code style={{ fontFamily: mono }}>interlock mesh sync</code>.</span> : null}
          {packs.map(([path, info]) => {
            const status = typeof info.status === "string" ? info.status : null;
            const version = typeof info.version === "number" || typeof info.version === "string" ? String(info.version) : null;
            const sha = typeof info.sha256 === "string" ? info.sha256.slice(0, 12) : "";
            return (
              <div key={path} style={{ display: "flex", gap: "8px", alignItems: "center", borderTop: "1px solid var(--il-rule)", paddingTop: "6px", minWidth: 0 }}>
                <code style={{ fontFamily: mono, fontSize: "10.5px", flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{path}</code>
                {version ? <span style={{ ...dim, fontFamily: mono, fontSize: "10px" }}>v{version}</span> : null}
                {status ? <span style={{ fontFamily: mono, fontSize: "9.5px", padding: "1px 6px", borderRadius: "4px", border: "1px solid var(--il-rule2)", color: "var(--il-fg2)" }}>{status}</span> : null}
                <span style={{ fontFamily: mono, fontSize: "9.5px", color: "var(--il-dim)" }}>{sha}</span>
              </div>
            );
          })}
          <span style={dim}>
            {typeof m.capped === "number" && m.capped > 0 ? m.capped + " rule(s) capped to escalate by the node's grants. " : ""}
            {Object.keys(m.grants ?? {}).length} grant(s) in force.
          </span>
        </div>
      ) : null}

      <div style={{ display: "flex", flexDirection: "column", gap: "6px", borderTop: "1px solid var(--il-rule)", paddingTop: "10px" }}>
        <span style={label}>Reporting consent</span>
        {layers.length ? (
          <div style={{ display: "flex", gap: "5px", flexWrap: "wrap", alignItems: "center" }}>
            {layers.map((layer) => (
              <span key={layer} style={{ fontFamily: mono, fontSize: "10px", padding: "2px 7px", borderRadius: "5px", color: "var(--il-allow)", border: "1px solid color-mix(in oklch, var(--il-allow) 45%, transparent)" }}>{layer}</span>
            ))}
            <span style={dim}>since {enabled}; alpha {m.report.alpha}</span>
            {m.report.sample_rules.length ? <span style={dim}>samples for {m.report.sample_rules.join(", ")}</span> : null}
          </div>
        ) : (
          <span style={dim}>Off. Nothing leaves this node. Enable one layer at a time with <code style={{ fontFamily: mono }}>interlock mesh report enable</code>.</span>
        )}
      </div>

      <code style={code}>{m.configured ? "interlock mesh sync\ninterlock mesh status" : "interlock mesh init --root root.json --mirror URL"}</code>
    </section>
  );
}

// --- real calls in the playground --------------------------------------------------------

function RealCalls({ S, D, A }: { S: State; D: Data; A: Actions }) {
  if (S.pgPreset !== "real") return null;
  const calls = D.realCalls;
  const tools = Object.entries(D.realTools).slice(0, 12);
  return (
    <section style={panel} data-testid="real-calls">
      <div style={{ display: "flex", alignItems: "baseline", gap: "10px", flexWrap: "wrap" }}>
        <h2 style={{ margin: 0, fontSize: "14px", fontWeight: 600 }}>Real calls</h2>
        <span style={dim}>from your Claude Code transcripts, newest first. {MASK_NOTE}</span>
      </div>
      <div style={{ display: "flex", gap: "8px", flexWrap: "wrap", alignItems: "center" }}>
        <input style={{ ...input, flex: "1 1 220px" }} placeholder="Filter by file, command, directory…" value={S.rcQ} onChange={(e) => A.setRealFilter({ q: e.target.value })} aria-label="Filter real calls" />
        <select style={input} value={S.rcTool} onChange={(e) => A.setRealFilter({ tool: e.target.value })} aria-label="Tool">
          <option value="">every tool</option>
          {tools.map(([t, n]) => (
            <option key={t} value={t}>{t} ({n})</option>
          ))}
        </select>
        <label style={{ ...dim, display: "inline-flex", gap: "6px", alignItems: "center" }}>
          <input type="checkbox" checked={S.rcResults} onChange={(e) => A.set({ rcResults: e.target.checked })} /> include outputs
        </label>
      </div>
      {D.realErr ? <span style={{ fontSize: "12.5px", color: "var(--il-block)" }}>✗ {D.realErr}</span> : null}
      {!D.realAvailable ? <span style={dim}>No Claude Code transcripts on this machine (start the console with --transcripts DIR).</span> : null}
      <div style={{ maxHeight: "300px", overflow: "auto", border: "1px solid var(--il-rule)", borderRadius: "8px" }}>
        {calls === null ? (
          <div style={{ ...dim, padding: "10px" }}>Reading transcripts…</div>
        ) : calls.length === 0 ? (
          <div style={{ ...dim, padding: "10px" }}>No calls match.</div>
        ) : (
          calls.map((c: RealCall) => {
            const sel = S.rcSel.includes(c.call_id);
            const rec = c.receipts.find((r) => r.phase === "call");
            return (
              <label key={c.call_id} className="ilh-3" style={{ display: "grid", gridTemplateColumns: "auto 64px 70px minmax(0,1fr) auto", gap: "8px", alignItems: "center", padding: "6px 10px", borderBottom: "1px solid var(--il-rule)", cursor: "pointer", background: sel ? "var(--il-sel)" : "transparent" }}>
                <input type="checkbox" checked={sel} onChange={() => A.toggleRealCall(c.call_id)} />
                <span style={{ fontFamily: mono, fontSize: "10.5px", color: "var(--il-dim)" }}>{fmtT(c.ts * 1000)}</span>
                <span style={{ fontFamily: mono, fontSize: "11px" }}>{c.tool}</span>
                <span style={{ fontFamily: mono, fontSize: "11px", color: "var(--il-fg2)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{c.target || "—"}</span>
                {rec ? <Chip verdict={rec.policy_verdict || rec.verdict} /> : <span style={{ ...dim, fontFamily: mono, fontSize: "10px" }}>no receipt</span>}
              </label>
            );
          })
        )}
      </div>
      <div style={{ display: "flex", gap: "8px", alignItems: "center", flexWrap: "wrap" }}>
        <button style={{ ...primary, opacity: S.rcSel.length ? 1 : 0.4 }} disabled={!S.rcSel.length} onClick={() => A.addRealCalls(true)}>
          Use {S.rcSel.length || ""} as events
        </button>
        <button style={{ ...btn, opacity: S.rcSel.length ? 1 : 0.4 }} disabled={!S.rcSel.length} onClick={() => A.addRealCalls(false)}>
          Add to events
        </button>
        <span style={dim}>Each call becomes an event as the hook builds it{S.rcResults ? ", plus its output as a result event" : ""}.</span>
      </div>
    </section>
  );
}

// --- policy backtest ------------------------------------------------------------------------

function Backtest({ S, D, A }: { S: State; D: Data; A: Actions }) {
  if (S.polTab !== "backtest") return null;
  const r = D.backtest;
  const seg = (k: "draft" | "saved", l: string) => (
    <button key={k} onClick={() => A.set({ btSource: k })} aria-pressed={S.btSource === k} style={{ fontFamily: mono, fontSize: "10.5px", padding: "5px 12px", borderRadius: "6px", border: 0, cursor: "pointer", background: S.btSource === k ? "var(--il-sel)" : "transparent", color: S.btSource === k ? "var(--il-fg)" : "var(--il-fg2)" }}>
      {l}
    </button>
  );
  const kpi = (n: number | string, l: string, c = "var(--il-fg)") => (
    <div key={l} style={{ display: "flex", flexDirection: "column", gap: "2px" }}>
      <span style={{ fontFamily: mono, fontSize: "18px", color: c }}>{n}</span>
      <span style={{ ...label, fontSize: "9.5px" }}>{l}</span>
    </div>
  );
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "14px", padding: "18px 22px 40px", maxWidth: "1100px" }} data-testid="policy-backtest">
      <p style={{ margin: 0, fontSize: "13px", color: "var(--il-fg2)", maxWidth: "760px" }}>
        Run a policy over your agent's recent real calls, read from its transcripts, and compare with what the guard decided at the time. Nothing
        runs and no receipt is written. Calls from before the hook was installed have no receipt to compare with; they show what the policy would do.
      </p>
      <div style={{ display: "flex", gap: "10px", alignItems: "center", flexWrap: "wrap" }}>
        <div role="group" aria-label="Policy" style={{ display: "inline-flex", padding: "3px", borderRadius: "9px", background: "var(--il-sunken)", border: "1px solid var(--il-rule)" }}>
          {seg("draft", "the draft")}
          {seg("saved", "the saved file")}
        </div>
        <select style={input} value={S.btLimit} onChange={(e) => A.set({ btLimit: Number(e.target.value) })} aria-label="How many calls">
          {[100, 300, 1000, 2000].map((n) => (
            <option key={n} value={n}>last {n} calls</option>
          ))}
        </select>
        <button style={{ ...primary, opacity: S.btRunning ? 0.6 : 1 }} disabled={S.btRunning} onClick={A.runBacktest}>
          {S.btRunning ? "Testing…" : "Test on real calls"}
        </button>
        {r ? <span style={dim}>{r.source} · epoch {r.epoch} · {num(r.calls)} calls in {r.elapsed_ms} ms</span> : null}
      </div>
      {D.backtestErr ? <span style={{ fontSize: "12.5px", color: "var(--il-block)" }}>✗ {D.backtestErr}</span> : null}
      {r ? (
        <>
          <div style={{ ...panel, flexDirection: "row", gap: "28px", flexWrap: "wrap" }}>
            {kpi(num(r.calls), "calls")}
            {kpi(num(r.would.BLOCK ?? 0), "would block", "var(--il-block)")}
            {kpi(num(r.would.MODIFY ?? 0), "would rewrite", "var(--il-rewrite)")}
            {kpi(num(r.would.ESCALATE ?? 0), "would escalate", "var(--il-escalate)")}
            {kpi(num(r.recorded), "with a receipt")}
            {kpi(num(r.changed), "decided differently", r.changed ? "var(--il-acc)" : "var(--il-fg)")}
          </div>
          {r.rows.length === 0 ? (
            <div style={{ ...panel, fontSize: "13px" }}>✓ This policy lets every one of these calls through, the same way the guard did.</div>
          ) : (
            <div style={{ ...panel, padding: 0, gap: 0 }}>
              <div style={{ display: "grid", gridTemplateColumns: "88px 70px 64px minmax(0,1fr) auto", gap: "10px", padding: "8px 14px", borderBottom: "1px solid var(--il-rule)", ...label, fontSize: "9.5px" }}>
                <span>time</span><span>tool</span><span>phase</span><span>call</span><span>then → now</span>
              </div>
              {r.rows.map((row: BacktestRow) => (
                <div key={row.call_id + row.phase} style={{ display: "grid", gridTemplateColumns: "88px 70px 64px minmax(0,1fr) auto", gap: "10px", padding: "8px 14px", borderBottom: "1px solid var(--il-rule)", alignItems: "center", background: row.status === "changed" ? "color-mix(in oklch, var(--il-acc) 6%, transparent)" : "transparent" }}>
                  <span style={{ fontFamily: mono, fontSize: "10.5px", color: "var(--il-dim)" }} title={fmtDT(row.ts * 1000)}>{ago(S.now - row.ts * 1000)}</span>
                  <span style={{ fontFamily: mono, fontSize: "11px" }}>{row.tool}</span>
                  <span style={{ fontFamily: mono, fontSize: "10.5px", color: "var(--il-fg2)" }}>{row.phase}</span>
                  <div style={{ display: "flex", flexDirection: "column", gap: "2px", minWidth: 0 }}>
                    <span style={{ fontFamily: mono, fontSize: "11px", color: "var(--il-fg2)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{row.target || "—"}</span>
                    <span style={{ ...dim, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{row.would.policy_id && !row.would.reason.startsWith(row.would.policy_id) ? row.would.policy_id + ": " : ""}{row.would.reason}</span>
                  </div>
                  <span style={{ display: "inline-flex", gap: "6px", alignItems: "center" }}>
                    {row.actual?.verdict ? (
                      <a href={"#/audit?r=" + row.actual.index} style={{ textDecoration: "none" }}><Chip verdict={row.actual.verdict} /></a>
                    ) : (
                      <span style={{ ...dim, fontFamily: mono, fontSize: "10px" }}>no receipt</span>
                    )}
                    <span style={{ color: "var(--il-dim)" }}>→</span>
                    <Chip verdict={row.would.verdict} />
                    <button style={{ ...btn, fontSize: "11px", padding: "3px 8px" }} onClick={() => A.openInPlayground({ calls: [{ call_id: row.call_id, session: row.session, ts: row.ts }] })}>playground</button>
                  </span>
                </div>
              ))}
              {r.truncated ? <div style={{ ...dim, padding: "8px 14px" }}>Showing the first 300.</div> : null}
            </div>
          )}
          <span style={dim}>
            Result-phase rows replay the text the model saw, which can differ in shape from what the hook judged live. Overlays are not applied.
          </span>
        </>
      ) : null}
    </div>
  );
}

// --- detector sweep ------------------------------------------------------------------------

const NOISY: Record<string, string> = {
  "Provenance stamps": "stamps every call by design",
  "Budgets, rate limits, and loops": "replayed in one burst, so limits trip sooner than live",
};

function Sweep({ S, D, A }: { S: State; D: Data; A: Actions }) {
  if (S.route.path !== "catalog" || S.route.id) return null;
  const r = D.sweep;
  const category = (m: string) => D.catalog?.detectors.find((d) => d.module === m)?.category ?? "";
  return (
    <div style={{ ...panel, margin: "14px 0 0" }} data-testid="detector-sweep">
      <div style={{ display: "flex", alignItems: "baseline", gap: "10px", flexWrap: "wrap" }}>
        <h2 style={{ margin: 0, fontSize: "14px", fontWeight: 600 }}>Sweep your real calls</h2>
        <span style={dim}>Every detector, at its defaults, over your agent's recent calls and their outputs.</span>
      </div>
      <div style={{ display: "flex", gap: "8px", alignItems: "center", flexWrap: "wrap" }}>
        <select style={input} value={S.swLimit} onChange={(e) => A.set({ swLimit: Number(e.target.value) })} aria-label="How many calls">
          {[100, 200, 500, 1000].map((n) => (
            <option key={n} value={n}>last {n} calls</option>
          ))}
        </select>
        <button style={{ ...primary, opacity: S.swRunning ? 0.6 : 1 }} disabled={S.swRunning} onClick={A.runSweep}>
          {S.swRunning ? "Sweeping…" : "Run the sweep"}
        </button>
        {r ? <span style={dim}>{num(r.calls)} calls · {num(r.events)} events · {r.elapsed_ms} ms</span> : null}
      </div>
      {D.sweepErr ? <span style={{ fontSize: "12.5px", color: "var(--il-block)" }}>✗ {D.sweepErr}</span> : null}
      {r ? (
        <>
          <div style={{ display: "flex", flexDirection: "column", border: "1px solid var(--il-rule)", borderRadius: "8px", maxHeight: "420px", overflow: "auto" }}>
            {r.detectors.filter((d) => d.fired || d.errors).map((d: SweepDetector) => (
              <a key={d.module + d.factory} href={"#/catalog/" + d.module} className="ilh-3" style={{ display: "grid", gridTemplateColumns: "minmax(0,1fr) auto", gap: "8px", padding: "7px 10px", borderBottom: "1px solid var(--il-rule)", textDecoration: "none", color: "var(--il-fg)" }}>
                <span style={{ display: "flex", flexDirection: "column", minWidth: 0 }}>
                  <span style={{ fontFamily: mono, fontSize: "11.5px" }}>{d.module}{d.factory !== d.module ? " · " + d.factory : ""}</span>
                  {NOISY[category(d.module)] ? <span style={{ ...dim, fontSize: "11px" }}>{NOISY[category(d.module)]}</span> : null}
                </span>
                <span style={{ display: "inline-flex", gap: "6px", alignItems: "center" }}>
                  {Object.entries(d.verdicts).map(([v, n]) => (
                    <Chip key={v} verdict={v} word={chip(v).word + " " + n} />
                  ))}
                  {d.errors ? <span style={{ ...dim, fontFamily: mono, fontSize: "10px" }}>{d.errors} errors</span> : null}
                </span>
              </a>
            ))}
          </div>
          <span style={dim}>
            {r.detectors.filter((d) => !d.fired).length} detectors stayed quiet. {r.skipped.length} need configuration first
            ({r.skipped.slice(0, 4).map((s) => s.module).join(", ")}{r.skipped.length > 4 ? ", …" : ""}); try them in the playground.
          </span>
        </>
      ) : null}
    </div>
  );
}

function DetectorHits({ S, D, A }: { S: State; D: Data; A: Actions }) {
  const module = S.route.path === "catalog" ? S.route.id : null;
  if (!module || !D.sweep) return null;
  const hits = D.sweep.detectors.filter((d) => d.module === module);
  if (!hits.length) return null;
  return (
    <div style={{ ...panel, background: "var(--il-sunken)" }} data-testid="detector-hits">
      <span style={label}>On your real calls</span>
      {hits.map((h) => (
        <div key={h.factory} style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
          <span style={{ fontSize: "12.5px" }}>
            <span style={{ fontFamily: mono }}>{h.factory}</span> fired on {num(h.fired)} of {num(D.sweep!.events)} events
            {h.errors ? " (" + h.errors + " errors)" : ""}.
          </span>
          {h.examples.map((x) => (
            <div key={x.call_id + x.phase} style={{ display: "flex", gap: "8px", alignItems: "center", minWidth: 0 }}>
              <Chip verdict={x.verdict} />
              <span style={{ fontFamily: mono, fontSize: "10.5px" }}>{x.tool}</span>
              <span style={{ fontFamily: mono, fontSize: "10.5px", color: "var(--il-fg2)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1 }}>{x.target}</span>
            </div>
          ))}
          {h.examples.length ? (
            <div>
              <button style={btn} onClick={() => A.openInPlayground({ calls: h.examples.map((x) => ({ call_id: x.call_id, session: x.session, ts: x.ts })), module: h.module, factory: h.factory })}>
                Open these in the playground
              </button>
            </div>
          ) : null}
        </div>
      ))}
    </div>
  );
}

export interface Extras {
  receiptCall: ReactNode;
  realCalls: ReactNode;
  backtest: ReactNode;
  sweep: ReactNode;
  detectorHits: ReactNode;
  mesh: ReactNode;
}

export function renderExtras(S: State, D: Data, A: Actions): Extras {
  return {
    receiptCall: <ReceiptCall S={S} D={D} A={A} />,
    realCalls: <RealCalls S={S} D={D} A={A} />,
    backtest: <Backtest S={S} D={D} A={A} />,
    sweep: <Sweep S={S} D={D} A={A} />,
    detectorHits: <DetectorHits S={S} D={D} A={A} />,
    mesh: <MeshPanel D={D} A={A} />,
  };
}
