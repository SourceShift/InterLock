// GENERATED from design/console/Interlock Console.dc.html by scripts/console_design/convert.py.
// Edit the view-model, not this markup: regenerate instead.
import { Fragment } from "react";
import type { Vals } from "../vals";

export function PolicyScreen({ v }: { v: Vals }) {
  return (
    <>
      <div style={{ display: "flex", flexDirection: "column", height: "100%" }}>
        <div style={{ flex: "none", display: "flex", alignItems: "center", gap: "8px 18px", padding: "12px 18px", borderBottom: "1px solid var(--il-rule)", flexWrap: "wrap", fontSize: "12.5px" }}>
          <span style={{ display: "flex", gap: "6px", alignItems: "baseline" }}>
            <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "9.5px", letterSpacing: ".06em", textTransform: "uppercase", color: "var(--il-dim)" }}>
              file
            </span>
            <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "11px" }}>
              <span className="sc-interp">{v.pol.path}</span>
            </span>
          </span>
          <span style={{ display: "flex", gap: "6px", alignItems: "baseline" }}>
            <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "9.5px", letterSpacing: ".06em", textTransform: "uppercase", color: "var(--il-dim)" }}>
              extends
            </span>
            <button onClick={v.pol.toPack} style={{ fontFamily: "'Martian Mono',monospace", fontSize: "11px", color: "var(--il-acc)", background: "none", border: "0", padding: "0", cursor: "pointer" }}>
              <span className="sc-interp">{v.pol.extendsLabel}</span>
            </button>
          </span>
          <span style={{ display: "flex", gap: "6px", alignItems: "baseline" }} title="A short hash of the effective policy. Approvals are bound to it.">
            <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "9.5px", letterSpacing: ".06em", textTransform: "uppercase", color: "var(--il-dim)" }}>
              epoch
            </span>
            <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "11px", padding: "1px 6px", borderRadius: "4px", background: "var(--il-raised)" }}>
              <span className="sc-interp">{v.epoch}</span>
            </span>
          </span>
          <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10.5px", color: "var(--il-rewrite)" }}>
            <span className="sc-interp">{v.pol.statusLine}</span>
          </span>
          <span style={{ flex: "1" }}></span>
          <div role="tablist" aria-label="Policy views" style={{ display: "inline-flex", padding: "3px", borderRadius: "8px", background: "var(--il-panel)", border: "1px solid var(--il-rule)" }}>
            {v.pol.tabs.map((it_t: (typeof v.pol.tabs)[number], i_t: number) => (
              <Fragment key={i_t}>
                <button role="tab" aria-selected={it_t.sel} onClick={it_t.on} style={{ fontSize: "12.5px", padding: "5px 11px", borderRadius: "6px", border: "0", cursor: "pointer", background: it_t.bg, color: it_t.c }}>
                  <span className="sc-interp">{it_t.l}</span>
                  <span className="sc-interp">{it_t.dirty}</span>
                </button>
              </Fragment>
            ))}
          </div>
        </div>
        <div style={{ flex: "1", minHeight: "0", overflow: "auto" }}>
          {v.pol.tabRules ? (
            <>
              {" "}
              <div style={{ padding: "16px 18px 40px", display: "flex", flexDirection: "column", gap: "14px", maxWidth: "1100px" }}>
                {v.pol.quar.map((it_qq: (typeof v.pol.quar)[number], i_qq: number) => (
                  <Fragment key={i_qq}>
                    <div role="alert" style={{ display: "flex", gap: "10px", alignItems: "flex-start", padding: "10px 12px", borderRadius: "9px", border: "1px solid color-mix(in oklch,var(--il-rewrite) 40%,transparent)", background: "color-mix(in oklch,var(--il-rewrite) 8%,transparent)", fontSize: "13px" }}>
                      <span style={{ fontFamily: "'Martian Mono',monospace", color: "var(--il-rewrite)" }}>
                        ~
                      </span>
                      <span style={{ flex: "1", textWrap: "pretty" }}>
                        <strong style={{ fontWeight: "600" }}>
                          Quarantined:
                        </strong>
                        {" "}
                        <code style={{ fontFamily: "'Martian Mono',monospace", fontSize: "11px" }}>
                          <span className="sc-interp">{it_qq.msg}</span>
                        </code>
                        . The rest of the policy runs; this rule is skipped until it's fixed.
                      </span>
                      <button onClick={v.pol.toEdit} style={{ fontSize: "12px", padding: "4px 10px", borderRadius: "6px", border: "1px solid var(--il-rule2)", background: "transparent", cursor: "pointer" }}>
                        Fix in JSON
                      </button>
                    </div>
                  </Fragment>
                ))}
                <div style={{ border: "1px solid var(--il-rule)", borderRadius: "10px", overflow: "hidden", background: "var(--il-panel)" }}>
                  {v.pol.rules.map((it_r: (typeof v.pol.rules)[number], i_r: number) => (
                    <Fragment key={i_r}>
                      {" "}
                      <div style={{ display: "grid", gridTemplateColumns: v.pol.cols, gap: "6px 14px", alignItems: "center", padding: "11px 14px", borderBottom: "1px solid var(--il-rule)", opacity: it_r.op }}>
                        <div style={{ display: "flex", flexDirection: "column", gap: "3px", minWidth: "0" }}>
                          <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "11.5px", fontWeight: "500", textDecoration: it_r.strike }}>
                            <span className="sc-interp">{it_r.id}</span>
                          </span>
                          <span style={{ fontSize: "12.5px", color: "var(--il-fg2)" }}>
                            <span className="sc-interp">{it_r.reason}</span>
                          </span>
                          <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10px", color: "var(--il-dim)", overflowWrap: "anywhere" }}>
                            <span className="sc-interp">{it_r.cond}</span>
                          </span>
                        </div>
                        <span>
                          <span style={{ display: "inline-flex", alignItems: "center", gap: "5px", fontFamily: "'Martian Mono',monospace", fontSize: "10px", padding: "1px 6px", borderRadius: "5px", whiteSpace: "nowrap", color: it_r.v.c, background: it_r.v.bg, border: `1px ${it_r.v.bs} ${it_r.v.bc}` }}>
                            <span className="sc-interp">{it_r.v.mark}</span>
                            {" "}
                            <span className="sc-interp">{it_r.v.word}</span>
                          </span>
                        </span>
                        <div style={{ display: "flex", gap: "4px", flexWrap: "wrap" }}>
                          {it_r.tags.map((it_t: (typeof it_r.tags)[number], i_t: number) => (
                            <Fragment key={i_t}>
                              <span title={it_t.title} style={{ fontFamily: "'Martian Mono',monospace", fontSize: "9.5px", padding: "1px 6px", borderRadius: "4px", color: it_t.c, border: `1px ${it_t.bs} ${it_t.bc}` }}>
                                <span className="sc-interp">{it_t.l}</span>
                              </span>
                            </Fragment>
                          ))}
                        </div>
                        <a href={it_r.href} style={{ fontSize: "12px", whiteSpace: "nowrap" }}>
                          receipts →
                        </a>
                      </div>
                      {" "}
                    </Fragment>
                  ))}
                </div>
              </div>
              {" "}
            </>
          ) : null}
          {" "}
          {v.pol.tabEdit ? (
            <>
              {" "}
              <div style={{ display: "flex", flexWrap: "wrap", gap: "16px", padding: "16px 18px 40px", alignItems: "flex-start" }}>
                <div style={{ flex: "2 1 460px", minWidth: "0", display: "flex", flexDirection: "column", gap: "8px" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "10px", fontSize: "12px", color: "var(--il-dim)" }}>
                    <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10.5px" }}>
                      <span className="sc-interp">{v.pol.fileName}</span>
                    </span>
                    {v.pol.dirty ? (
                      <>
                        <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10px", color: "var(--il-acc)" }}>
                          ● unsaved changes
                        </span>
                      </>
                    ) : null}
                    <span style={{ flex: "1" }}></span>
                    <button onClick={v.pol.revert} disabled={v.pol.clean} style={{ fontSize: "12px", padding: "3px 9px", borderRadius: "6px", border: "1px solid var(--il-rule2)", background: "transparent", cursor: "pointer", opacity: v.pol.revertOp }}>
                      Revert
                    </button>
                  </div>
                  <div style={{ display: "flex", border: `1px solid ${v.pol.edBc}`, borderRadius: "9px", overflow: "hidden", background: "var(--il-sunken)" }}>
                    <pre aria-hidden="true" style={{ margin: "0", padding: "12px 8px 12px 12px", fontFamily: "'Martian Mono',monospace", fontSize: "11px", lineHeight: "1.7", color: "var(--il-dim)", textAlign: "right", userSelect: "none", borderRight: "1px solid var(--il-rule)" }}>
                      <span className="sc-interp">{v.pol.lineNums}</span>
                    </pre>
                    <textarea value={v.policyText} onChange={v.pol.onText} spellCheck={false} aria-label="Policy JSON" style={{ flex: "1", minWidth: "0", minHeight: "520px", resize: "vertical", padding: "12px", border: "0", outline: "none", background: "transparent", fontFamily: "'Martian Mono',monospace", fontSize: "11px", lineHeight: "1.7", whiteSpace: "pre", overflow: "auto" }} />
                  </div>
                </div>
                <div style={{ flex: "1 1 300px", minWidth: "0", display: "flex", flexDirection: "column", gap: "12px" }}>
                  <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
                    <button onClick={v.pol.doCheck} style={{ fontSize: "13px", fontWeight: "500", padding: "8px 14px", borderRadius: "7px", border: "1px solid var(--il-rule2)", background: "var(--il-raised)", cursor: "pointer" }}>
                      Check draft
                    </button>
                    <button onClick={v.pol.doSaveClick} disabled={v.pol.saveDisabled} style={{ display: "inline-flex", alignItems: "center", gap: "7px", fontSize: "13px", fontWeight: "600", padding: "8px 14px", borderRadius: "7px", border: "0", background: "var(--il-acc)", color: "var(--il-accfg)", cursor: "pointer", opacity: v.pol.saveOp }}>
                      <span className="sc-interp">{v.pol.saveLabel}</span>
                    </button>
                  </div>
                  <span style={{ fontSize: "12px", color: "var(--il-dim)", textWrap: "pretty" }}>
                    <span className="sc-interp">{v.pol.saveHint}</span>
                  </span>
                  <div style={{ border: "1px solid var(--il-rule)", borderRadius: "10px", background: "var(--il-panel)", overflow: "hidden" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "8px", padding: "9px 12px", borderBottom: "1px solid var(--il-rule)" }}>
                      <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10px", letterSpacing: ".05em", textTransform: "uppercase", color: "var(--il-dim)", flex: "1" }}>
                        Problems
                      </span>
                      <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10px", color: v.pol.probC }}>
                        <span className="sc-interp">{v.pol.probCount}</span>
                      </span>
                    </div>
                    {" "}
                    {v.pol.parseErr ? (
                      <>
                        <div role="alert" style={{ padding: "10px 12px", fontSize: "12.5px", display: "flex", flexDirection: "column", gap: "4px" }}>
                          <span style={{ color: "var(--il-block)", fontFamily: "'Martian Mono',monospace", fontSize: "11px" }}>
                            {"✗ "}
                            <span className="sc-interp">{v.pol.parseMsg}</span>
                          </span>
                          <span style={{ color: "var(--il-fg2)" }}>
                            {"The file doesn't load. The guard keeps running the last good policy (epoch "}
                            <span className="sc-interp">{v.epoch}</span>
                            ) until this is fixed.
                          </span>
                        </div>
                      </>
                    ) : null}
                    {" "}
                    {v.pol.problems.map((it_p: (typeof v.pol.problems)[number], i_p: number) => (
                      <Fragment key={i_p}>
                        <div style={{ display: "flex", gap: "8px", padding: "9px 12px", borderTop: "1px solid var(--il-rule)", fontSize: "12.5px" }}>
                          <span style={{ fontFamily: "'Martian Mono',monospace", color: it_p.c }}>
                            <span className="sc-interp">{it_p.mark}</span>
                          </span>
                          <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10.5px", overflowWrap: "anywhere", color: "var(--il-fg)" }}>
                            <span className="sc-interp">{it_p.msg}</span>
                          </span>
                        </div>
                      </Fragment>
                    ))}
                    {" "}
                    {v.pol.noProblems ? (
                      <>
                        <div style={{ padding: "10px 12px", fontSize: "12.5px", color: "var(--il-allow)" }}>
                          ✓ No problems in the draft.
                        </div>
                      </>
                    ) : null}
                  </div>
                  {v.pol.checked ? (
                    <>
                      <div style={{ border: "1px solid var(--il-rule)", borderRadius: "10px", background: "var(--il-panel)", padding: "12px", display: "flex", flexDirection: "column", gap: "8px", fontSize: "12.5px" }}>
                        <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10px", letterSpacing: ".05em", textTransform: "uppercase", color: "var(--il-dim)" }}>
                          Draft check
                        </span>
                        <div style={{ display: "flex", justifyContent: "space-between", gap: "8px" }}>
                          <span style={{ color: "var(--il-fg2)" }}>
                            rules that run
                          </span>
                          <strong>
                            <span className="sc-interp">{v.pol.ck.rules}</span>
                          </strong>
                        </div>
                        <div style={{ display: "flex", justifyContent: "space-between", gap: "8px" }}>
                          <span style={{ color: "var(--il-fg2)" }}>
                            locked (inherited)
                          </span>
                          <strong>
                            <span className="sc-interp">{v.pol.ck.locked}</span>
                          </strong>
                        </div>
                        <div style={{ display: "flex", justifyContent: "space-between", gap: "8px" }}>
                          <span style={{ color: "var(--il-fg2)" }}>
                            quarantined
                          </span>
                          <strong style={{ color: v.pol.ck.qc }}>
                            <span className="sc-interp">{v.pol.ck.quar}</span>
                          </strong>
                        </div>
                        <div style={{ display: "flex", justifyContent: "space-between", gap: "8px" }}>
                          <span style={{ color: "var(--il-fg2)" }}>
                            overlays applied
                          </span>
                          <strong>
                            <span className="sc-interp">{v.pol.ck.overlays}</span>
                          </strong>
                        </div>
                        <div style={{ display: "flex", justifyContent: "space-between", gap: "8px", alignItems: "center" }}>
                          <span style={{ color: "var(--il-fg2)" }}>
                            epoch if saved
                          </span>
                          <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "11px", padding: "1px 6px", borderRadius: "4px", background: "color-mix(in oklch,var(--il-acc) 14%,transparent)", color: "var(--il-acc)" }}>
                            <span className="sc-interp">{v.pol.ck.epoch}</span>
                          </span>
                        </div>
                      </div>
                    </>
                  ) : null}
                </div>
              </div>
              {" "}
            </>
          ) : null}
          {" "}
          {v.pol.tabOverlays ? (
            <>
              {" "}
              <div style={{ padding: "16px 18px 40px", display: "flex", flexDirection: "column", gap: "12px", maxWidth: "1000px" }}>
                <p style={{ margin: "0", fontSize: "13px", color: "var(--il-fg2)", maxWidth: "720px", textWrap: "pretty" }}>
                  {"A project can add its own "}
                  <code style={{ fontFamily: "'Martian Mono',monospace", fontSize: "11px" }}>
                    .interlock/policy.json
                  </code>
                  {" that only "}
                  <strong style={{ color: "var(--il-fg)" }}>
                    tightens
                  </strong>
                  {" the base. It's ignored until you trust its exact content. Editing the file revokes trust. An overlay that tries to loosen the base is ignored whole."}
                </p>
                {v.pol.overlays.map((it_o: (typeof v.pol.overlays)[number], i_o: number) => (
                  <Fragment key={i_o}>
                    <div style={{ border: "1px solid var(--il-rule)", borderRadius: "10px", background: "var(--il-panel)", padding: "12px 14px", display: "flex", flexDirection: "column", gap: "8px" }}>
                      <div style={{ display: "flex", alignItems: "center", gap: "10px", flexWrap: "wrap" }}>
                        <span style={{ display: "inline-flex", alignItems: "center", gap: "5px", fontFamily: "'Martian Mono',monospace", fontSize: "10px", padding: "1px 7px", borderRadius: "5px", color: it_o.st.c, background: it_o.st.bg, border: `1px ${it_o.st.bs} ${it_o.st.bc}` }}>
                          <span className="sc-interp">{it_o.st.mark}</span>
                          {" "}
                          <span className="sc-interp">{it_o.st.word}</span>
                        </span>
                        <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "11px", flex: "1", minWidth: "0", overflowWrap: "anywhere" }}>
                          <span className="sc-interp">{it_o.path}</span>
                        </span>
                      </div>
                      <span style={{ fontSize: "12.5px", color: "var(--il-fg2)" }}>
                        <span className="sc-interp">{it_o.line}</span>
                      </span>
                      {it_o.cmd ? (
                        <>
                          <div style={{ display: "flex", gap: "6px", alignItems: "center" }}>
                            <code style={{ flex: "1", minWidth: "0", fontFamily: "'Martian Mono',monospace", fontSize: "10.5px", padding: "7px 10px", borderRadius: "7px", background: "var(--il-sunken)", border: "1px solid var(--il-rule)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                              <span className="sc-interp">{it_o.cmd}</span>
                            </code>
                            <button onClick={it_o.copy} style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10px", padding: "6px 9px", borderRadius: "6px", border: "1px solid var(--il-rule2)", background: "transparent", cursor: "pointer" }}>
                              <span className="sc-interp">{it_o.copyLabel}</span>
                            </button>
                          </div>
                          <span style={{ fontSize: "11.5px", color: "var(--il-dim)" }}>
                            Run this in your own terminal, outside the agent.
                          </span>
                        </>
                      ) : null}
                    </div>
                  </Fragment>
                ))}
              </div>
              {" "}
            </>
          ) : null}
          {" "}
          {v.pol.tabPack ? (
            <>
              {" "}
              <div style={{ padding: "16px 18px 40px", display: "flex", flexDirection: "column", gap: "12px", maxWidth: "1000px" }}>
                <p style={{ margin: "0", fontSize: "13px", color: "var(--il-fg2)" }}>
                  {"Read-only. These are the rules your policy inherits from "}
                  <code style={{ fontFamily: "'Martian Mono',monospace", fontSize: "11px" }}>
                    <span className="sc-interp">{v.pol.extendsLabel}</span>
                  </code>
                  . Locked rules can't be disabled by anything that extends them.
                </p>
                <div style={{ border: "1px solid var(--il-rule)", borderRadius: "10px", overflow: "hidden", background: "var(--il-panel)" }}>
                  {v.pol.pack.map((it_r: (typeof v.pol.pack)[number], i_r: number) => (
                    <Fragment key={i_r}>
                      <div style={{ display: "grid", gridTemplateColumns: v.pol.cols, gap: "6px 14px", alignItems: "center", padding: "11px 14px", borderBottom: "1px solid var(--il-rule)" }}>
                        <div style={{ display: "flex", flexDirection: "column", gap: "3px", minWidth: "0" }}>
                          <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "11.5px", fontWeight: "500" }}>
                            <span className="sc-interp">{it_r.id}</span>
                          </span>
                          <span style={{ fontSize: "12.5px", color: "var(--il-fg2)" }}>
                            <span className="sc-interp">{it_r.reason}</span>
                          </span>
                          <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10px", color: "var(--il-dim)" }}>
                            <span className="sc-interp">{it_r.cond}</span>
                          </span>
                        </div>
                        <span>
                          <span style={{ display: "inline-flex", gap: "5px", fontFamily: "'Martian Mono',monospace", fontSize: "10px", padding: "1px 6px", borderRadius: "5px", color: it_r.v.c, background: it_r.v.bg, border: `1px solid ${it_r.v.bc}` }}>
                            <span className="sc-interp">{it_r.v.mark}</span>
                            {" "}
                            <span className="sc-interp">{it_r.v.word}</span>
                          </span>
                        </span>
                        <div style={{ display: "flex", gap: "4px", flexWrap: "wrap" }}>
                          {it_r.tags.map((it_t: (typeof it_r.tags)[number], i_t: number) => (
                            <Fragment key={i_t}>
                              <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "9.5px", padding: "1px 6px", borderRadius: "4px", color: it_t.c, border: `1px ${it_t.bs} ${it_t.bc}` }}>
                                <span className="sc-interp">{it_t.l}</span>
                              </span>
                            </Fragment>
                          ))}
                        </div>
                        {it_r.det ? (
                          <>
                            <a href={it_r.det} style={{ fontSize: "12px", whiteSpace: "nowrap" }}>
                              detector →
                            </a>
                          </>
                        ) : null}
                      </div>
                    </Fragment>
                  ))}
                </div>
              </div>
              {" "}
            </>
          ) : null}
        </div>
      </div>
    </>
  );
}
