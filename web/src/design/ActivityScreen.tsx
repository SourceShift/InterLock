// GENERATED from design/console/Interlock Console.dc.html by scripts/console_design/convert.py.
// Edit the view-model, not this markup: regenerate instead.
import { Fragment } from "react";
import type { Vals } from "../vals";

export function ActivityScreen({ v }: { v: Vals }) {
  return (
    <>
      <div style={{ padding: "20px 22px 44px", display: "flex", flexDirection: "column", gap: "14px", maxWidth: "1320px" }}>
        {v.receiptsMissing ? (
          <>
            <div style={{ background: "var(--il-panel)", border: "1px solid var(--il-rule)", borderRadius: "12px", padding: "36px", display: "flex", flexDirection: "column", gap: "12px", alignItems: "flex-start", maxWidth: "680px" }}>
              <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10px", letterSpacing: ".06em", textTransform: "uppercase", color: "var(--il-dim)" }}>
                No receipt log · started without --receipts
              </span>
              <h2 style={{ margin: "0", fontSize: "22px", fontWeight: "600", letterSpacing: "-.02em" }}>
                Point the console at a receipt log
              </h2>
              <p style={{ margin: "0", color: "var(--il-fg2)", textWrap: "pretty" }}>
                Every decision interlock makes is written to a receipt log: one signed line per call. Activity, the audit log and chain verification all read from it. This console was started without one, so it has nothing to read.
              </p>
              <ol style={{ margin: "0", paddingLeft: "20px", display: "flex", flexDirection: "column", gap: "16px", color: "var(--il-fg2)", fontSize: "13px", lineHeight: "1.55" }}>
                <li style={{ paddingLeft: "2px" }}>
                  <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                    <span>
                      <strong style={{ color: "var(--il-fg)" }}>
                        Install the guard, once.
                      </strong>
                      {" It creates "}
                      <code style={{ fontFamily: "'Martian Mono',monospace", fontSize: "11px" }}>
                        ~/.interlock/receipts.key
                      </code>
                      {"; from then on the agent hooks write "}
                      <code style={{ fontFamily: "'Martian Mono',monospace", fontSize: "11px" }}>
                        ~/.interlock/receipts.jsonl
                      </code>
                      {" by default."}
                    </span>
                    <code style={{ fontFamily: "'Martian Mono',monospace", fontSize: "11.5px", padding: "9px 12px", borderRadius: "7px", background: "var(--il-sunken)", border: "1px solid var(--il-rule)", color: "var(--il-fg)", overflowWrap: "anywhere" }}>
                      interlock install-hook --for claude-code # or: codex, cursor, all
                    </code>
                    <span>
                      {"Already installed? "}
                      <a href="#/ops" style={{ color: "var(--il-acc)", textDecoration: "none", borderBottom: "1px dashed color-mix(in oklch,var(--il-acc) 55%,transparent)" }}>
                        Ops
                      </a>
                      {" shows the hook state for each agent."}
                    </span>
                  </div>
                </li>
                <li style={{ paddingLeft: "2px" }}>
                  <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                    <span>
                      <strong style={{ color: "var(--il-fg)" }}>
                        Let the agent make one guarded call.
                      </strong>
                      {" The log file is created by the first decision — until then there is nothing to point at. Any tool call the agent makes from now on appends its line."}
                    </span>
                  </div>
                </li>
                <li style={{ paddingLeft: "2px" }}>
                  <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                    <span>
                      <strong style={{ color: "var(--il-fg)" }}>
                        Restart the console with that log and its key.
                      </strong>
                      {" Stop this process, then:"}
                    </span>
                    <code style={{ fontFamily: "'Martian Mono',monospace", fontSize: "11.5px", padding: "9px 12px", borderRadius: "7px", background: "var(--il-sunken)", border: "1px solid var(--il-rule)", color: "var(--il-fg)", overflowWrap: "anywhere" }}>
                      python3 -m interlock.console --receipts ~/.interlock/receipts.jsonl --key-file ~/.interlock/receipts.key
                    </code>
                    <span>
                      {"Flags in short: "}
                      <code style={{ fontFamily: "'Martian Mono',monospace", fontSize: "11px" }}>
                        --receipts
                      </code>
                      {" is the log to read (the hook has its own "}
                      <code style={{ fontFamily: "'Martian Mono',monospace", fontSize: "11px" }}>
                        --receipts
                      </code>
                      {" — point both at the same file). "}
                      <code style={{ fontFamily: "'Martian Mono',monospace", fontSize: "11px" }}>
                        --key-file
                      </code>
                      {" only verifies the chain; without it the badge reads "}
                      <em>
                        unverified
                      </em>
                      {". Once you have run "}
                      <code style={{ fontFamily: "'Martian Mono',monospace", fontSize: "11px" }}>
                        interlock anchor
                      </code>
                      {", add "}
                      <code style={{ fontFamily: "'Martian Mono',monospace", fontSize: "11px" }}>
                        --receipts-head MAC
                      </code>
                      {" so a truncated log reads "}
                      <em>
                        broken
                      </em>
                      {" instead of "}
                      <em>
                        intact
                      </em>
                      .
                    </span>
                  </div>
                </li>
              </ol>
              <p style={{ margin: "0", color: "var(--il-fg2)", fontSize: "12.5px", textWrap: "pretty" }}>
                {"Trying it without touching your agent? "}
                <code style={{ fontFamily: "'Martian Mono',monospace", fontSize: "11px" }}>
                  scripts/console_traffic.py /tmp/il-demo
                </code>
                {" writes a real scratch log, queue and policy, then point "}
                <code style={{ fontFamily: "'Martian Mono',monospace", fontSize: "11px" }}>
                  --receipts
                </code>
                {" at "}
                <code style={{ fontFamily: "'Martian Mono',monospace", fontSize: "11px" }}>
                  /tmp/il-demo/receipts.jsonl
                </code>
                {". Full walkthrough: "}
                <a href="https://interlock.sourceshift.ai/docs/guides/console/" style={{ color: "var(--il-acc)", textDecoration: "none", borderBottom: "1px dashed color-mix(in oklch,var(--il-acc) 55%,transparent)" }}>
                  console guide
                </a>
                .
              </p>
            </div>
          </>
        ) : null}
        {v.receiptsOk ? (
          <>
            <section style={{ position: "relative", overflow: "hidden", border: "1px solid var(--il-rule)", borderRadius: "16px", background: `radial-gradient(640px 220px at 0% 0%,color-mix(in oklch,${v.act.bandC} 14%,transparent),transparent 70%),radial-gradient(520px 200px at 100% 100%,color-mix(in oklch,var(--il-escalate) ${v.act.waitGlow}%,transparent),transparent 70%),var(--il-panel)`, padding: "22px 24px", display: "flex", flexWrap: "wrap", gap: "18px 32px", alignItems: "center" }}>
              <div aria-hidden="true" style={{ position: "absolute", inset: "0", pointerEvents: "none", backgroundImage: "radial-gradient(color-mix(in oklch,var(--il-fg) 9%,transparent) 1px,transparent 1px)", backgroundSize: "16px 16px", WebkitMaskImage: "linear-gradient(90deg,#000,transparent 60%)", maskImage: "linear-gradient(90deg,#000,transparent 60%)" }}></div>
              <div style={{ position: "relative", flex: "1 1 460px", minWidth: "0", display: "flex", flexDirection: "column", gap: "10px" }}>
                <p style={{ margin: "0", fontSize: "clamp(19px,2.1vw,25px)", lineHeight: "1.35", letterSpacing: "-.02em", fontWeight: "500", textWrap: "balance" }}>
                  {"Protection is "}
                  <a href="#/ops" style={{ color: v.posture.c, textDecoration: "none", borderBottom: `1.5px dashed ${v.posture.bc}` }}>
                    <span className="sc-interp">{v.posture.mark}</span>
                    {" "}
                    <span className="sc-interp">{v.posture.word}</span>
                  </a>
                  {". The receipt chain is "}
                  <a href="#/audit" style={{ color: v.chain.c, textDecoration: "none", borderBottom: `1.5px dashed ${v.chain.bc}` }}>
                    <span className="sc-interp">{v.chain.mark}</span>
                    {" "}
                    <span className="sc-interp">{v.chain.word}</span>
                  </a>
                  {". "}
                  <a href="#/reviews" style={{ color: v.act.waitC, textDecoration: "none", borderBottom: `1.5px dashed ${v.act.waitBc}` }}>
                    <span className="sc-interp">{v.act.waitPhrase}</span>
                  </a>
                  .
                </p>
                <span style={{ fontSize: "13px", color: "var(--il-fg2)", textWrap: "pretty" }}>
                  <span className="sc-interp">{v.posture.line}</span>
                </span>
              </div>
              <div style={{ position: "relative", display: "flex", flexDirection: "column", gap: "10px", alignItems: "flex-end", marginLeft: "auto" }}>
                <div role="group" aria-label="Window" style={{ display: "inline-flex", padding: "3px", borderRadius: "9px", background: "var(--il-sunken)", border: "1px solid var(--il-rule)" }}>
                  {v.act.winOpts.map((it_o: (typeof v.act.winOpts)[number], i_o: number) => (
                    <Fragment key={i_o}>
                      <button onClick={it_o.on} aria-pressed={it_o.sel} style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10.5px", padding: "5px 13px", borderRadius: "6px", border: "0", cursor: "pointer", background: it_o.bg, color: it_o.c, transition: "background .2s" }}>
                        <span className="sc-interp">{it_o.l}</span>
                      </button>
                    </Fragment>
                  ))}
                </div>
                <span style={{ display: "inline-flex", alignItems: "center", gap: "8px", fontFamily: "'Martian Mono',monospace", fontSize: "10px", color: "var(--il-fg2)" }}>
                  <span style={{ width: "7px", height: "7px", borderRadius: "50%", background: v.tail.c, boxShadow: `0 0 0 3px color-mix(in oklch,${v.tail.c} 22%,transparent)`, animation: v.tail.anim }}></span>
                  <span className="sc-interp">{v.act.liveLine}</span>
                </span>
              </div>
            </section>
            <div style={{ display: "grid", gridTemplateColumns: v.act.mainCols, gap: "14px", alignItems: "start" }}>
              <section style={{ background: "var(--il-panel)", border: "1px solid var(--il-rule)", borderRadius: "14px", padding: "18px 18px 16px", display: "flex", flexDirection: "column", gap: "14px", minWidth: "0" }}>
                <div style={{ display: "flex", alignItems: "flex-start", gap: "12px 20px", flexWrap: "wrap" }}>
                  <div style={{ display: "flex", flexDirection: "column", gap: "2px", flex: "1", minWidth: "180px" }}>
                    <h2 style={{ margin: "0", fontSize: "14px", fontWeight: "600" }}>
                      Decisions
                    </h2>
                    <span style={{ fontSize: "12px", color: "var(--il-dim)" }}>
                      <span className="sc-interp">{v.act.scopeLine}</span>
                    </span>
                  </div>
                  <div style={{ display: "flex", gap: "18px", flexWrap: "wrap" }}>
                    {v.act.kpis.map((it_k: (typeof v.act.kpis)[number], i_k: number) => (
                      <Fragment key={i_k}>
                        <div style={{ display: "flex", flexDirection: "column", gap: "0" }}>
                          <span style={{ fontSize: "21px", lineHeight: "1.15", fontWeight: "600", letterSpacing: "-.02em", fontVariantNumeric: "tabular-nums", color: it_k.c }}>
                            <span className="sc-interp">{it_k.n}</span>
                          </span>
                          <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "9.5px", letterSpacing: ".07em", textTransform: "uppercase", color: "var(--il-dim)" }}>
                            <span className="sc-interp">{it_k.l}</span>
                          </span>
                        </div>
                      </Fragment>
                    ))}
                  </div>
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: "6px", flexWrap: "wrap" }}>
                  {v.act.legend.map((it_l: (typeof v.act.legend)[number], i_l: number) => (
                    <Fragment key={i_l}>
                      <button onClick={it_l.on} aria-pressed={it_l.sel} title={`Highlight ${it_l.word} across this page`} style={{ display: "inline-flex", alignItems: "center", gap: "7px", fontFamily: "'Martian Mono',monospace", fontSize: "10.5px", padding: "4px 10px", borderRadius: "999px", cursor: "pointer", color: it_l.c, background: it_l.bg, border: `1px solid ${it_l.bc}`, opacity: it_l.op, transition: "all .2s" }}>
                        <span className="sc-interp">{it_l.mark}</span>
                        {" "}
                        <span className="sc-interp">{it_l.word}</span>
                        <strong style={{ fontWeight: "500", color: "var(--il-fg)" }}>
                          <span className="sc-interp">{it_l.n}</span>
                        </strong>
                        <span style={{ color: "var(--il-dim)" }}>
                          <span className="sc-interp">{it_l.pct}</span>
                        </span>
                      </button>
                    </Fragment>
                  ))}
                  <span style={{ flex: "1" }}></span>
                  {v.act.hasSel ? (
                    <>
                      <button onClick={v.act.clearSel} style={{ display: "inline-flex", alignItems: "center", gap: "6px", fontFamily: "'Martian Mono',monospace", fontSize: "10.5px", padding: "4px 10px", borderRadius: "999px", border: "1px solid var(--il-acc)", color: "var(--il-acc)", background: "color-mix(in oklch,var(--il-acc) 10%,transparent)", cursor: "pointer" }}>
                        <span className="sc-interp">{v.act.selLabel}</span>
                        {" ✕"}
                      </button>
                    </>
                  ) : null}
                </div>
                <div style={{ position: "relative" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", gap: "10px", minHeight: "18px", fontFamily: "'Martian Mono',monospace", fontSize: "10.5px", color: "var(--il-fg2)", marginBottom: "6px" }}>
                    <span>
                      <span className="sc-interp">{v.act.hoverLine}</span>
                    </span>
                    <span style={{ color: "var(--il-dim)" }}>
                      <span className="sc-interp">{v.act.maxLabel}</span>
                    </span>
                  </div>
                  {" "}
                  <div aria-hidden="true" style={{ position: "absolute", left: "0", right: "0", top: "24px", height: "170px", display: "flex", flexDirection: "column", justifyContent: "space-between", pointerEvents: "none" }}>
                    <span style={{ borderTop: "1px dashed var(--il-rule)" }}></span>
                    <span style={{ borderTop: "1px dashed var(--il-rule)" }}></span>
                    <span style={{ borderTop: "1px dashed var(--il-rule)" }}></span>
                    <span style={{ borderTop: "1px solid var(--il-rule2)" }}></span>
                  </div>
                  {" "}
                  <div role="list" aria-label={v.act.chartAria} style={{ position: "relative", height: "170px", display: "flex", alignItems: "stretch", gap: "3px" }}>
                    {v.act.bars.map((it_b: (typeof v.act.bars)[number], i_b: number) => (
                      <Fragment key={i_b}>
                        <div role="listitem" tabIndex={0} aria-label={it_b.aria} onMouseEnter={it_b.enter} onMouseLeave={v.act.leaveB} onFocus={it_b.enter} onClick={it_b.click} style={{ flex: "1", minWidth: "0", display: "flex", flexDirection: "column", justifyContent: "flex-end", alignItems: "stretch", gap: "4px", cursor: "pointer", borderRadius: "5px", padding: "0 1px", background: it_b.bg, outline: it_b.outline, transition: "background .15s" }}>
                          {it_b.esc ? (
                            <>
                              <span title="escalated" style={{ alignSelf: "center", width: "6px", height: "6px", borderRadius: "50%", background: "var(--il-escalate)", boxShadow: "0 0 6px var(--il-escalate)", opacity: it_b.escOp }}></span>
                            </>
                          ) : null}
                          <div style={{ height: `${it_b.h}%`, minHeight: it_b.minH, display: "flex", flexDirection: "column-reverse", gap: "1px", borderRadius: "3px 3px 1px 1px", overflow: "hidden", opacity: it_b.op, transition: "height .45s cubic-bezier(.2,.7,.2,1),opacity .2s" }}>
                            {it_b.segs.map((it_s: (typeof it_b.segs)[number], i_s: number) => (
                              <Fragment key={i_s}>
                                <span style={{ flex: `${it_s.n} 0 0`, minHeight: "0", background: it_s.c, opacity: it_s.op, transition: "opacity .2s" }}></span>
                              </Fragment>
                            ))}
                          </div>
                        </div>
                      </Fragment>
                    ))}
                  </div>
                  {" "}
                  <div aria-hidden="true" style={{ display: "flex", gap: "3px", marginTop: "6px" }}>
                    {v.act.xlabels.map((it_x: (typeof v.act.xlabels)[number], i_x: number) => (
                      <Fragment key={i_x}>
                        <span style={{ flex: "1", minWidth: "0", fontFamily: "'Martian Mono',monospace", fontSize: "9px", color: "var(--il-dim)", whiteSpace: "nowrap", overflow: "visible" }}>
                          <span className="sc-interp">{it_x}</span>
                        </span>
                      </Fragment>
                    ))}
                  </div>
                </div>
                <div style={{ display: "flex", flexDirection: "column", gap: "8px", paddingTop: "12px", borderTop: "1px solid var(--il-rule)" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "10px", flexWrap: "wrap" }}>
                    <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "9.5px", letterSpacing: ".07em", textTransform: "uppercase", color: "var(--il-dim)" }}>
                      {"Live stream · last "}
                      <span className="sc-interp">{v.act.tickCount}</span>
                      {" decisions"}
                    </span>
                    <span style={{ flex: "1" }}></span>
                    <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10.5px", color: "var(--il-fg2)", minHeight: "16px" }}>
                      <span className="sc-interp">{v.act.tickLine}</span>
                    </span>
                  </div>
                  <div style={{ display: "flex", gap: "2px", alignItems: "flex-end", height: "34px" }}>
                    {v.act.ticks.map((it_t: (typeof v.act.ticks)[number], i_t: number) => (
                      <Fragment key={i_t}>
                        <a href={it_t.href} aria-label={it_t.aria} onMouseEnter={it_t.enter} onMouseLeave={v.act.leaveT} onFocus={it_t.enter} style={{ flex: "1", minWidth: "3px", height: it_t.h, borderRadius: "2px", background: it_t.bg, border: `1px ${it_t.bs} ${it_t.c}`, opacity: it_t.op, boxShadow: it_t.glow, transition: "opacity .2s,transform .15s" }} className="ilh-1"></a>
                      </Fragment>
                    ))}
                  </div>
                  <span style={{ fontSize: "11.5px", color: "var(--il-dim)" }}>
                    Oldest on the left, newest on the right. Click a mark to open its receipt.
                  </span>
                </div>
              </section>
              <section style={{ border: "1px solid var(--il-rule)", borderRadius: "14px", padding: "18px", display: "flex", flexDirection: "column", gap: "12px", minWidth: "0", borderColor: v.act.waitPanelBc, background: v.act.waitPanelBg }}>
                <div style={{ display: "flex", alignItems: "baseline", gap: "10px" }}>
                  <h2 style={{ margin: "0", fontSize: "14px", fontWeight: "600", flex: "1" }}>
                    Waiting on you
                  </h2>
                  <span style={{ fontSize: "26px", lineHeight: "1", fontWeight: "600", letterSpacing: "-.03em", color: v.act.waitC, fontVariantNumeric: "tabular-nums" }}>
                    <span className="sc-interp">{v.pendingCount}</span>
                  </span>
                </div>
                {v.act.noPending ? (
                  <>
                    <div style={{ display: "flex", flexDirection: "column", gap: "8px", alignItems: "flex-start", padding: "18px 0 6px" }}>
                      <span style={{ width: "38px", height: "38px", borderRadius: "10px", display: "grid", placeItems: "center", fontFamily: "'Martian Mono',monospace", color: "var(--il-allow)", background: "color-mix(in oklch,var(--il-allow) 14%,transparent)" }}>
                        ✓
                      </span>
                      <strong style={{ fontSize: "14px" }}>
                        Nothing is held for you
                      </strong>
                      <span style={{ fontSize: "12.5px", color: "var(--il-fg2)", textWrap: "pretty" }}>
                        When a rule escalates a call, it lands here with a countdown.
                      </span>
                    </div>
                  </>
                ) : null}
                {v.act.pend.map((it_p: (typeof v.act.pend)[number], i_p: number) => (
                  <Fragment key={i_p}>
                    <a href={it_p.href} style={{ display: "flex", gap: "12px", alignItems: "center", padding: "11px 12px", borderRadius: "11px", border: "1px solid var(--il-rule)", background: "var(--il-bg)", color: "var(--il-fg)", textDecoration: "none", transition: "border-color .2s,transform .2s" }} className="ilh-2">
                      <span style={{ position: "relative", width: "44px", height: "44px", flex: "none" }}>
                        <svg width="44" height="44" viewBox="0 0 44 44" aria-hidden="true">
                          <circle cx="22" cy="22" r="18" fill="none" stroke="var(--il-rule2)" strokeWidth="3"></circle>
                          <circle cx="22" cy="22" r="18" fill="none" stroke={it_p.ringC} strokeWidth="3" strokeLinecap="round" strokeDasharray="113.1" strokeDashoffset={it_p.off} transform="rotate(-90 22 22)" style={{ transition: "stroke-dashoffset 1s linear" }}></circle>
                        </svg>
                        <span style={{ position: "absolute", inset: "0", display: "grid", placeItems: "center", fontFamily: "'Martian Mono',monospace", fontSize: "9px", color: it_p.ringC, fontVariantNumeric: "tabular-nums" }}>
                          <span className="sc-interp">{it_p.short}</span>
                        </span>
                      </span>
                      <span style={{ flex: "1", minWidth: "0", display: "flex", flexDirection: "column", gap: "2px" }}>
                        <span style={{ display: "flex", gap: "8px", alignItems: "baseline" }}>
                          <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "12px", fontWeight: "500" }}>
                            <span className="sc-interp">{it_p.action}</span>
                          </span>
                          {it_p.multi ? (
                            <>
                              <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "9.5px", color: "var(--il-escalate)" }}>
                                <span className="sc-interp">{it_p.approvals}</span>
                              </span>
                            </>
                          ) : null}
                        </span>
                        <span style={{ fontSize: "12px", color: "var(--il-fg2)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                          <span className="sc-interp">{it_p.reason}</span>
                        </span>
                        <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "9.5px", color: "var(--il-dim)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                          <span className="sc-interp">{it_p.principal}</span>
                          {" · "}
                          <span className="sc-interp">{it_p.left}</span>
                          {" left"}
                        </span>
                      </span>
                      <span aria-hidden="true" style={{ color: "var(--il-dim)" }}>
                        →
                      </span>
                    </a>
                  </Fragment>
                ))}
                <a href="#/reviews" style={{ fontSize: "12.5px", marginTop: "2px" }}>
                  Open the review queue →
                </a>
                <div style={{ borderTop: "1px solid var(--il-rule)", paddingTop: "12px", display: "flex", flexDirection: "column", gap: "8px" }}>
                  <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "9.5px", letterSpacing: ".07em", textTransform: "uppercase", color: "var(--il-dim)" }}>
                    Escalations settled
                  </span>
                  {v.act.esc.map((it_e: (typeof v.act.esc)[number], i_e: number) => (
                    <Fragment key={i_e}>
                      <div style={{ display: "grid", gridTemplateColumns: "minmax(0,1fr) 34px", gap: "8px", alignItems: "center" }}>
                        <div style={{ display: "flex", flexDirection: "column", gap: "3px" }}>
                          <span style={{ fontSize: "12px", color: "var(--il-fg2)" }}>
                            <span className="sc-interp">{it_e.l}</span>
                          </span>
                          <span style={{ height: "4px", borderRadius: "2px", background: "var(--il-sunken)", overflow: "hidden" }}>
                            <span style={{ display: "block", height: "100%", width: `${it_e.w}%`, background: it_e.c, borderRadius: "2px", transition: "width .4s" }}></span>
                          </span>
                        </div>
                        <strong style={{ textAlign: "right", fontVariantNumeric: "tabular-nums", fontSize: "13px" }}>
                          <span className="sc-interp">{it_e.n}</span>
                        </strong>
                      </div>
                    </Fragment>
                  ))}
                </div>
              </section>
            </div>
            {v.act.empty ? (
              <>
                <div style={{ background: "var(--il-panel)", border: "1px solid var(--il-rule)", borderRadius: "14px", padding: "30px", display: "flex", flexDirection: "column", gap: "10px", alignItems: "flex-start" }}>
                  <h2 style={{ margin: "0", fontSize: "17px", fontWeight: "600" }}>
                    {"Nothing decided in the "}
                    <span className="sc-interp">{v.act.winLabel}</span>
                  </h2>
                  <p style={{ margin: "0", color: "var(--il-fg2)", maxWidth: "620px", textWrap: "pretty" }}>
                    {"The guard may simply not have run. "}
                    <span className="sc-interp">{v.act.lastSeen}</span>
                    {" If you expected activity, check that your agent's hook is installed."}
                  </p>
                  <div style={{ display: "flex", gap: "8px" }}>
                    <button onClick={v.widen} style={{ fontSize: "13px", padding: "7px 12px", borderRadius: "7px", border: "1px solid var(--il-rule2)", background: "var(--il-raised)", cursor: "pointer" }}>
                      Show the last 7 days
                    </button>
                    <a href="#/ops" style={{ fontSize: "13px", padding: "7px 12px", borderRadius: "7px", border: "1px solid var(--il-rule2)", color: "var(--il-fg)", textDecoration: "none" }}>
                      Check hooks in Ops
                    </a>
                  </div>
                </div>
              </>
            ) : null}
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(min(100%,340px),1fr))", gap: "14px" }}>
              <section style={{ background: "var(--il-panel)", border: "1px solid var(--il-rule)", borderRadius: "14px", padding: "18px", display: "flex", flexDirection: "column", gap: "10px", minWidth: "0" }}>
                <div style={{ display: "flex", alignItems: "baseline", gap: "10px" }}>
                  <h2 style={{ margin: "0", fontSize: "14px", fontWeight: "600", flex: "1" }}>
                    Who stopped what
                  </h2>
                  <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10px", color: "var(--il-dim)" }}>
                    <span className="sc-interp">{v.act.rulesNote}</span>
                  </span>
                </div>
                {v.act.noRules ? (
                  <>
                    <span style={{ fontSize: "12.5px", color: "var(--il-dim)", padding: "8px 0" }}>
                      {"No rule made a "}
                      <span className="sc-interp">{v.act.focusWord}</span>
                      {" decision here."}
                    </span>
                  </>
                ) : null}
                {v.act.rules.map((it_r: (typeof v.act.rules)[number], i_r: number) => (
                  <Fragment key={i_r}>
                    <a href={it_r.href} style={{ display: "flex", flexDirection: "column", gap: "6px", padding: "8px 8px", margin: "0 -8px", borderRadius: "8px", color: "var(--il-fg)", textDecoration: "none" }} className="ilh-3">
                      <span style={{ display: "flex", justifyContent: "space-between", gap: "10px" }}>
                        <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "11px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                          <span className="sc-interp">{it_r.id}</span>
                        </span>
                        <strong style={{ fontVariantNumeric: "tabular-nums", fontSize: "13px" }}>
                          <span className="sc-interp">{it_r.count}</span>
                        </strong>
                      </span>
                      <span style={{ display: "flex", height: "6px", borderRadius: "3px", overflow: "hidden", background: "var(--il-sunken)" }}>
                        <span style={{ display: "flex", width: `${it_r.w}%`, transition: "width .4s" }}>
                          {it_r.segs.map((it_s: (typeof it_r.segs)[number], i_s: number) => (
                            <Fragment key={i_s}>
                              <span style={{ flex: `${it_s.n} 0 0`, background: it_s.c, opacity: it_s.op }}></span>
                            </Fragment>
                          ))}
                        </span>
                      </span>
                    </a>
                  </Fragment>
                ))}
                <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "9.5px", letterSpacing: ".07em", textTransform: "uppercase", color: "var(--il-dim)", marginTop: "6px" }}>
                  Top blocked actions
                </span>
                <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
                  {v.act.blocked.map((it_b: (typeof v.act.blocked)[number], i_b: number) => (
                    <Fragment key={i_b}>
                      <a href={it_b.href} style={{ display: "inline-flex", gap: "8px", alignItems: "center", fontFamily: "'Martian Mono',monospace", fontSize: "10.5px", padding: "4px 9px", borderRadius: "6px", border: "1px solid color-mix(in oklch,var(--il-block) 32%,transparent)", background: "color-mix(in oklch,var(--il-block) 6%,transparent)", color: "var(--il-fg)", textDecoration: "none" }}>
                        <span className="sc-interp">{it_b.action}</span>
                        <span style={{ color: "var(--il-block)" }}>
                          {"✗ "}
                          <span className="sc-interp">{it_b.count}</span>
                        </span>
                      </a>
                    </Fragment>
                  ))}
                  {v.act.noBlocked ? (
                    <>
                      <span style={{ fontSize: "12.5px", color: "var(--il-dim)" }}>
                        Nothing blocked.
                      </span>
                    </>
                  ) : null}
                </div>
              </section>
              <section style={{ background: "var(--il-panel)", border: "1px solid var(--il-rule)", borderRadius: "14px", padding: "18px", display: "flex", flexDirection: "column", gap: "10px", minWidth: "0", borderStyle: "dashed", borderColor: "var(--il-rule2)" }}>
                <div style={{ display: "flex", alignItems: "baseline", gap: "10px" }}>
                  <h2 style={{ margin: "0", fontSize: "14px", fontWeight: "600", flex: "1" }}>
                    Would have
                  </h2>
                  <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10px", color: "var(--il-dim)" }}>
                    monitor mode · not enforced
                  </span>
                </div>
                <p style={{ margin: "0", fontSize: "12.5px", color: "var(--il-fg2)", textWrap: "pretty" }}>
                  These calls ran. Monitor-mode rules recorded what they would have done, so you can trial a rule before enforcing it.
                </p>
                {v.act.would.map((it_w: (typeof v.act.would)[number], i_w: number) => (
                  <Fragment key={i_w}>
                    <a href={it_w.href} style={{ display: "flex", alignItems: "center", gap: "10px", padding: "9px 10px", borderRadius: "9px", border: "1px dashed var(--il-rule2)", color: "var(--il-fg)", textDecoration: "none", flexWrap: "wrap" }} className="ilh-4">
                      <span style={{ display: "inline-flex", alignItems: "center", gap: "5px", fontFamily: "'Martian Mono',monospace", fontSize: "10.5px", padding: "2px 7px", borderRadius: "5px", color: it_w.v.c, border: `1px dashed ${it_w.v.bc}` }}>
                        <span className="sc-interp">{it_w.v.mark}</span>
                        {" "}
                        <span className="sc-interp">{it_w.v.word}</span>
                      </span>
                      <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "11px" }}>
                        <span className="sc-interp">{it_w.action}</span>
                      </span>
                      <span style={{ fontSize: "12px", color: "var(--il-dim)", flex: "1" }}>
                        <span className="sc-interp">{it_w.rule}</span>
                      </span>
                      <strong style={{ fontVariantNumeric: "tabular-nums" }}>
                        <span className="sc-interp">{it_w.count}</span>
                      </strong>
                    </a>
                  </Fragment>
                ))}
                {v.act.noWould ? (
                  <>
                    <span style={{ fontSize: "12.5px", color: "var(--il-dim)" }}>
                      No monitor-mode rules fired here.
                    </span>
                  </>
                ) : null}
                <a href="#/policy" style={{ fontSize: "12.5px", marginTop: "auto" }}>
                  Enforce a rule in Policy →
                </a>
              </section>
              <section style={{ background: "var(--il-panel)", border: "1px solid var(--il-rule)", borderRadius: "14px", padding: "18px", display: "flex", flexDirection: "column", gap: "12px", minWidth: "0" }}>
                <div style={{ display: "flex", alignItems: "baseline", gap: "10px" }}>
                  <h2 style={{ margin: "0", fontSize: "14px", fontWeight: "600", flex: "1" }}>
                    Evaluation latency
                  </h2>
                  <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10px", color: "var(--il-dim)" }}>
                    {"µs · "}
                    <span className="sc-interp">{v.act.latN}</span>
                    {" samples"}
                  </span>
                </div>
                <div style={{ position: "relative", height: "74px", display: "flex", alignItems: "flex-end", gap: "2px", paddingTop: "16px" }}>
                  {v.act.hist.map((it_x: (typeof v.act.hist)[number], i_x: number) => (
                    <Fragment key={i_x}>
                      <span title={it_x.t} style={{ flex: "1", height: `${it_x.h}%`, minHeight: "2px", borderRadius: "2px 2px 0 0", background: "color-mix(in oklch,var(--il-fg) 20%,transparent)" }}></span>
                    </Fragment>
                  ))}
                  {v.act.marks.map((it_m: (typeof v.act.marks)[number], i_m: number) => (
                    <Fragment key={i_m}>
                      <span style={{ position: "absolute", top: "0", bottom: "0", left: `${it_m.x}%`, borderLeft: `1px dashed ${it_m.c}` }}>
                        <span style={{ position: "absolute", top: "-2px", left: "3px", fontFamily: "'Martian Mono',monospace", fontSize: "9px", color: it_m.c, whiteSpace: "nowrap" }}>
                          <span className="sc-interp">{it_m.k}</span>
                        </span>
                      </span>
                    </Fragment>
                  ))}
                </div>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(5,minmax(0,1fr))", gap: "6px" }}>
                  {v.act.lat.map((it_l: (typeof v.act.lat)[number], i_l: number) => (
                    <Fragment key={i_l}>
                      <div style={{ display: "flex", flexDirection: "column", gap: "0" }}>
                        <span style={{ fontSize: "15px", fontWeight: "600", fontVariantNumeric: "tabular-nums" }}>
                          <span className="sc-interp">{it_l.v}</span>
                        </span>
                        <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "9.5px", letterSpacing: ".07em", textTransform: "uppercase", color: "var(--il-dim)" }}>
                          <span className="sc-interp">{it_l.k}</span>
                        </span>
                      </div>
                    </Fragment>
                  ))}
                </div>
                <div style={{ borderTop: "1px solid var(--il-rule)", paddingTop: "10px", display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(130px,1fr))", gap: "10px 14px" }}>
                  <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                    <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "9.5px", letterSpacing: ".07em", textTransform: "uppercase", color: "var(--il-dim)" }}>
                      Problems
                    </span>
                    {v.act.problems.map((it_p: (typeof v.act.problems)[number], i_p: number) => (
                      <Fragment key={i_p}>
                        <a href={it_p.href} style={{ display: "flex", justifyContent: "space-between", gap: "8px", fontSize: "12px", color: "var(--il-fg2)", textDecoration: "none" }}>
                          <span>
                            <span className="sc-interp">{it_p.l}</span>
                          </span>
                          <strong style={{ color: it_p.c, fontVariantNumeric: "tabular-nums" }}>
                            <span className="sc-interp">{it_p.n}</span>
                          </strong>
                        </a>
                      </Fragment>
                    ))}
                  </div>
                  <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                    <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "9.5px", letterSpacing: ".07em", textTransform: "uppercase", color: "var(--il-dim)" }}>
                      Masked values
                    </span>
                    {v.act.masked.map((it_m: (typeof v.act.masked)[number], i_m: number) => (
                      <Fragment key={i_m}>
                        <div style={{ display: "flex", justifyContent: "space-between", gap: "8px", fontSize: "12px", color: "var(--il-fg2)" }}>
                          <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10.5px" }}>
                            <span className="sc-interp">{it_m.l}</span>
                          </span>
                          <strong style={{ color: "var(--il-fg)", fontVariantNumeric: "tabular-nums" }}>
                            <span className="sc-interp">{it_m.n}</span>
                          </strong>
                        </div>
                      </Fragment>
                    ))}
                  </div>
                </div>
              </section>
            </div>
          </>
        ) : null}
      </div>
    </>
  );
}
