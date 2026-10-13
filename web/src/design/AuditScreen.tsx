// GENERATED from design/console/Interlock Console.dc.html by scripts/console_design/convert.py.
// Edit the view-model, not this markup: regenerate instead.
import { Fragment } from "react";
import type { Vals } from "../vals";

export function AuditScreen({ v }: { v: Vals }) {
  return (
    <>
      <div style={{ display: "flex", flexDirection: "column", height: "100%" }}>
        {v.chain.broken ? (
          <>
            <div role="alert" data-testid="chain-status" style={{ flex: "none", display: "flex", gap: "14px", alignItems: "flex-start", padding: "14px 18px", background: "color-mix(in oklch,var(--il-block) 16%,var(--il-bg))", borderBottom: "2px solid var(--il-block)", flexWrap: "wrap" }}>
              <span style={{ width: "34px", height: "34px", flex: "none", borderRadius: "8px", display: "grid", placeItems: "center", background: "var(--il-block)", color: "var(--il-bg)", fontFamily: "'Martian Mono',monospace", fontWeight: "500" }}>
                ✗
              </span>
              <div style={{ flex: "1", minWidth: "240px", display: "flex", flexDirection: "column", gap: "3px" }}>
                <strong style={{ fontSize: "15px", color: "var(--il-block)" }}>
                  Chain broken at receipt #
                  <span className="sc-interp">{v.chain.brokenAt}</span>
                </strong>
                <span style={{ fontSize: "13px", color: "var(--il-fg)" }}>
                  <span className="sc-interp">{v.chain.problem}</span>
                </span>
                <span style={{ fontSize: "12.5px", color: "var(--il-fg2)", textWrap: "pretty" }}>
                  Receipts at or after this point may have been edited, deleted or reordered. Treat every count that includes them as unproven until you find out why.
                </span>
              </div>
              <button onClick={v.jumpBroken} style={{ fontSize: "12.5px", fontWeight: "500", padding: "7px 12px", borderRadius: "7px", border: "1px solid var(--il-block)", background: "transparent", color: "var(--il-block)", cursor: "pointer" }}>
                Show receipt #
                <span className="sc-interp">{v.chain.brokenAt}</span>
              </button>
            </div>
          </>
        ) : null}
        <div style={{ flex: "none", display: "flex", alignItems: "center", gap: "8px", padding: "10px 18px", borderBottom: "1px solid var(--il-rule)", flexWrap: "wrap" }}>
          {v.chain.notBroken ? (
            <>
              <span data-testid="chain-status" title={v.chain.line} style={{ display: "inline-flex", alignItems: "center", gap: "6px", fontFamily: "'Martian Mono',monospace", fontSize: "10.5px", padding: "4px 9px", borderRadius: "6px", color: v.chain.c, background: v.chain.bg, border: `1px ${v.chain.bs} ${v.chain.bc}` }}>
                <span className="sc-interp">{v.chain.mark}</span>
                {" chain "}
                <span className="sc-interp">{v.chain.word}</span>
              </span>
            </>
          ) : null}
          <div role="group" aria-label="Verdict filter" data-testid="verdict-filter" style={{ display: "inline-flex", flexWrap: "wrap", gap: "4px" }}>
            {v.vfOpts.map((it_o: (typeof v.vfOpts)[number], i_o: number) => (
              <Fragment key={i_o}>
                <button onClick={it_o.on} aria-pressed={it_o.sel} style={{ display: "inline-flex", alignItems: "center", gap: "5px", fontFamily: "'Martian Mono',monospace", fontSize: "10.5px", padding: "4px 9px", borderRadius: "6px", cursor: "pointer", border: `1px ${it_o.bs} ${it_o.bc}`, background: it_o.bg, color: it_o.c }}>
                  <span className="sc-interp">{it_o.mark}</span>
                  {" "}
                  <span className="sc-interp">{it_o.l}</span>
                </button>
              </Fragment>
            ))}
          </div>
          <select ref={v.rfRef} value={v.rf} onChange={v.onRf} aria-label="Rule" style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10.5px", padding: "5px 8px", borderRadius: "6px", border: "1px solid var(--il-rule2)", background: "var(--il-panel)" }}>
            {v.ruleOpts.map((it_o: (typeof v.ruleOpts)[number], i_o: number) => (
              <Fragment key={i_o}>
                <option value={it_o.v}>
                  <span className="sc-interp">{it_o.l}</span>
                </option>
              </Fragment>
            ))}
          </select>
          <input value={v.q} onChange={v.onQ} placeholder="action, principal, span…" aria-label="Search receipts" style={{ flex: "1", minWidth: "140px", fontSize: "12.5px", padding: "5px 10px", borderRadius: "6px", border: "1px solid var(--il-rule2)", background: "var(--il-panel)" }} />
          <button onClick={v.toggleLive} data-testid="live-toggle" style={{ display: "inline-flex", alignItems: "center", gap: "8px", fontFamily: "'Martian Mono',monospace", fontSize: "10.5px", padding: "5px 10px", borderRadius: "6px", border: `1px solid ${v.tail.bc}`, background: "transparent", cursor: "pointer", color: v.tail.c }}>
            <span data-testid="live-indicator" style={{ width: "7px", height: "7px", borderRadius: "50%", background: v.tail.c, animation: v.tail.anim }}></span>
            <span className="sc-interp">{v.tail.label}</span>
          </button>
        </div>
        {v.tail.note ? (
          <>
            <div role="status" style={{ flex: "none", padding: "7px 18px", fontSize: "12.5px", color: "var(--il-fg2)", background: "var(--il-raised)", borderBottom: "1px solid var(--il-rule)" }}>
              <span className="sc-interp">{v.tail.note}</span>
            </div>
          </>
        ) : null}
        <div style={{ flex: "1", minHeight: "0", display: "flex" }}>
          {v.audShowList ? (
            <>
              <div style={{ flex: "1", minWidth: "0", overflow: "auto" }}>
                {v.receiptsMissing ? (
                  <>
                    <div style={{ padding: "40px 24px", maxWidth: "620px", display: "flex", flexDirection: "column", gap: "10px" }}>
                      <strong style={{ fontSize: "16px" }}>
                        No receipt log configured
                      </strong>
                      <span style={{ color: "var(--il-fg2)", fontSize: "13px", textWrap: "pretty" }}>
                        {"A receipt log is the signed record of every decision. Restart the console with "}
                        <code style={{ fontFamily: "'Martian Mono',monospace", fontSize: "11px" }}>
                          --receipts
                        </code>
                        {" (and "}
                        <code style={{ fontFamily: "'Martian Mono',monospace", fontSize: "11px" }}>
                          --key-file
                        </code>
                        {" to verify the chain)."}
                      </span>
                    </div>
                  </>
                ) : null}
                {" "}
                {v.aud.emptyLog ? (
                  <>
                    <div data-testid="audit-empty" style={{ padding: "40px 24px", maxWidth: "620px", display: "flex", flexDirection: "column", gap: "10px" }}>
                      <strong style={{ fontSize: "16px" }}>
                        Nothing decided yet
                      </strong>
                      <span style={{ color: "var(--il-fg2)", fontSize: "13px" }}>
                        {"The log exists but has no receipts. The guard may not have run. "}
                        <a href="#/ops">
                          Are your agent hooks installed?
                        </a>
                      </span>
                    </div>
                  </>
                ) : null}
                {" "}
                {v.aud.filteredEmpty ? (
                  <>
                    <div data-testid="audit-empty" style={{ padding: "40px 24px", display: "flex", flexDirection: "column", gap: "10px", alignItems: "flex-start" }}>
                      <strong style={{ fontSize: "15px" }}>
                        No receipts match these filters
                      </strong>
                      <span style={{ color: "var(--il-fg2)", fontSize: "13px" }}>
                        <span className="sc-interp">{v.aud.total}</span>
                        {" receipts in the log; your filters hide all of them."}
                      </span>
                      <button onClick={v.clearFilters} style={{ fontSize: "12.5px", padding: "6px 12px", borderRadius: "7px", border: "1px solid var(--il-rule2)", background: "var(--il-raised)", cursor: "pointer" }}>
                        Clear filters
                      </button>
                    </div>
                  </>
                ) : null}
                {" "}
                {v.aud.has ? (
                  <>
                    {" "}
                    <div role="table" aria-label="Receipts, newest first" style={{ minWidth: "0" }}>
                      <div role="row" style={{ position: "sticky", top: "0", zIndex: "1", display: "grid", gridTemplateColumns: v.audCols, gap: "10px", padding: "7px 18px", background: "var(--il-bg)", borderBottom: "1px solid var(--il-rule)", fontFamily: "'Martian Mono',monospace", fontSize: "9.5px", letterSpacing: ".06em", textTransform: "uppercase", color: "var(--il-dim)" }}>
                        <span role="columnheader">
                          time
                        </span>
                        <span role="columnheader">
                          verdict
                        </span>
                        <span role="columnheader">
                          action
                        </span>
                        {v.wide ? (
                          <>
                            <span role="columnheader">
                              rule
                            </span>
                            <span role="columnheader">
                              principal
                            </span>
                            <span role="columnheader" style={{ textAlign: "right" }}>
                              eval
                            </span>
                          </>
                        ) : null}
                      </div>
                      {" "}
                      {v.aud.rows.map((it_r: (typeof v.aud.rows)[number], i_r: number) => (
                        <Fragment key={i_r}>
                          {" "}
                          <div role="row" tabIndex={0} onClick={it_r.on} data-testid="receipt-row" style={{ display: "grid", gridTemplateColumns: v.audCols, gap: "10px", alignItems: "center", padding: "6px 18px", borderBottom: "1px solid var(--il-rule)", cursor: "pointer", background: it_r.bg, fontSize: "12.5px" }} className="ilh-3">
                            <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10.5px", color: "var(--il-dim)", fontVariantNumeric: "tabular-nums" }}>
                              <span className="sc-interp">{it_r.time}</span>
                            </span>
                            {it_r.unreadable ? (
                              <>
                                <span style={{ gridColumn: "2 / -1", fontFamily: "'Martian Mono',monospace", fontSize: "10.5px", color: "var(--il-rewrite)" }}>
                                  {"⚠ unreadable receipt at index "}
                                  <span className="sc-interp">{it_r.index}</span>
                                  : the line didn't parse (corrupt or partial write)
                                </span>
                              </>
                            ) : null}
                            {it_r.readable ? (
                              <>
                                <span style={{ display: "flex", alignItems: "center", gap: "4px", minWidth: "0" }}>
                                  {it_r.esc ? (
                                    <>
                                      <span title="policy asked to escalate" style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10px", color: "var(--il-escalate)" }}>
                                        ‖→
                                      </span>
                                    </>
                                  ) : null}
                                  <span data-testid={it_r.tid} style={{ display: "inline-flex", alignItems: "center", gap: "5px", fontFamily: "'Martian Mono',monospace", fontSize: "10px", padding: "1px 6px", borderRadius: "5px", whiteSpace: "nowrap", color: it_r.v.c, background: it_r.v.bg, border: `1px ${it_r.v.bs} ${it_r.v.bc}` }}>
                                    <span className="sc-interp">{it_r.v.mark}</span>
                                    {" "}
                                    <span className="sc-interp">{it_r.v.word}</span>
                                  </span>
                                </span>
                                <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "11px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                                  <span className="sc-interp">{it_r.action}</span>
                                  <span style={{ color: "var(--il-dim)" }}>
                                    <span className="sc-interp">{it_r.phaseTag}</span>
                                  </span>
                                </span>
                                {v.wide ? (
                                  <>
                                    <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10.5px", color: "var(--il-fg2)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                                      <span className="sc-interp">{it_r.rule}</span>
                                    </span>
                                    <span style={{ fontSize: "12px", color: "var(--il-fg2)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                                      <span className="sc-interp">{it_r.principal}</span>
                                    </span>
                                    <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10.5px", color: "var(--il-dim)", textAlign: "right", fontVariantNumeric: "tabular-nums" }}>
                                      <span className="sc-interp">{it_r.el}</span>
                                    </span>
                                  </>
                                ) : null}
                              </>
                            ) : null}
                          </div>
                          {" "}
                        </Fragment>
                      ))}
                      {" "}
                      <div style={{ display: "flex", alignItems: "center", gap: "12px", padding: "14px 18px", fontSize: "12.5px", color: "var(--il-dim)", flexWrap: "wrap" }}>
                        <span>
                          {"Showing "}
                          <span className="sc-interp">{v.aud.shownTxt}</span>
                          {" of "}
                          <span className="sc-interp">{v.aud.matchTxt}</span>
                          {" matching · "}
                          <span className="sc-interp">{v.aud.totalTxt}</span>
                          {" in the log"}
                        </span>
                        {v.aud.more ? (
                          <>
                            <button onClick={v.loadMore} style={{ fontSize: "12.5px", padding: "5px 12px", borderRadius: "7px", border: "1px solid var(--il-rule2)", background: "var(--il-raised)", cursor: "pointer" }}>
                              Load 200 more
                            </button>
                          </>
                        ) : null}
                      </div>
                    </div>
                    {" "}
                  </>
                ) : null}
              </div>
            </>
          ) : null}
          {v.rc.has ? (
            <>
              <aside aria-label="Receipt detail" style={{ width: v.drawerW, flex: "none", overflow: "auto", borderLeft: "1px solid var(--il-rule)", background: "var(--il-panel)" }}>
                <div style={{ padding: "16px 18px 32px", display: "flex", flexDirection: "column", gap: "16px" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                    <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10.5px", color: "var(--il-dim)", flex: "1" }}>
                      receipt #
                      <span className="sc-interp">{v.rc.index}</span>
                    </span>
                    <button onClick={v.closeReceipt} aria-label="Close" style={{ width: "28px", height: "28px", borderRadius: "6px", border: "1px solid var(--il-rule2)", background: "transparent", cursor: "pointer" }}>
                      ✕
                    </button>
                  </div>
                  <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                    <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "16px", fontWeight: "500" }}>
                      <span className="sc-interp">{v.rc.action}</span>
                    </span>
                    <span style={{ fontSize: "13.5px", color: "var(--il-fg2)", textWrap: "pretty" }}>
                      <span className="sc-interp">{v.rc.reason}</span>
                    </span>
                  </div>
                  <div style={{ display: "flex", alignItems: "center", gap: "6px", flexWrap: "wrap" }}>
                    {v.rc.story.map((it_s: (typeof v.rc.story)[number], i_s: number) => (
                      <Fragment key={i_s}>
                        <span style={{ display: "inline-flex", alignItems: "center", gap: "5px", fontFamily: "'Martian Mono',monospace", fontSize: "10.5px", padding: "3px 8px", borderRadius: "5px", color: it_s.c, background: it_s.bg, border: `1px ${it_s.bs} ${it_s.bc}` }}>
                          <span className="sc-interp">{it_s.mark}</span>
                          {" "}
                          <span className="sc-interp">{it_s.word}</span>
                        </span>
                        {it_s.arrow ? (
                          <>
                            <span style={{ color: "var(--il-dim)", fontSize: "12px" }}>
                              →
                            </span>
                          </>
                        ) : null}
                      </Fragment>
                    ))}
                  </div>
                  {v.rc.escLine ? (
                    <>
                      <p style={{ margin: "-6px 0 0", fontSize: "12px", color: "var(--il-dim)" }}>
                        <span className="sc-interp">{v.rc.escLine}</span>
                      </p>
                    </>
                  ) : null}
                  {v.extras.receiptCall}
                  <dl style={{ margin: "0", display: "grid", gridTemplateColumns: "110px minmax(0,1fr)", gap: "8px 12px", fontSize: "12.5px" }}>
                    {v.rc.fields.map((it_f: (typeof v.rc.fields)[number], i_f: number) => (
                      <Fragment key={i_f}>
                        <dt style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10px", color: "var(--il-dim)", paddingTop: "2px" }}>
                          <span className="sc-interp">{it_f.k}</span>
                        </dt>
                        <dd style={{ margin: "0", overflowWrap: "anywhere", fontFamily: it_f.ff, fontSize: it_f.fs, color: it_f.c }}>
                          {it_f.href ? (
                            <>
                              <a href={it_f.href}>
                                <span className="sc-interp">{it_f.v}</span>
                              </a>
                            </>
                          ) : null}
                          {it_f.plain ? (
                            <>
                              <span className="sc-interp">{it_f.v}</span>
                            </>
                          ) : null}
                        </dd>
                      </Fragment>
                    ))}
                  </dl>
                  <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                    <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10px", color: "var(--il-dim)" }}>
                      args_digest
                    </span>
                    <div style={{ display: "flex", gap: "6px", alignItems: "flex-start" }}>
                      <code style={{ flex: "1", fontFamily: "'Martian Mono',monospace", fontSize: "10.5px", padding: "8px 10px", borderRadius: "7px", background: "var(--il-sunken)", border: "1px solid var(--il-rule)", overflowWrap: "anywhere", color: "var(--il-fg2)" }}>
                        <span className="sc-interp">{v.rc.digest}</span>
                      </code>
                      <button onClick={v.copyDigest} style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10px", padding: "6px 9px", borderRadius: "6px", border: "1px solid var(--il-rule2)", background: "transparent", cursor: "pointer" }}>
                        <span className="sc-interp">{v.copyLabel}</span>
                      </button>
                    </div>
                    <span style={{ fontSize: "11.5px", color: "var(--il-dim)" }}>
                      A fingerprint of the arguments. Receipts never store the arguments themselves.
                    </span>
                  </div>
                </div>
              </aside>
            </>
          ) : null}
        </div>
      </div>
    </>
  );
}
