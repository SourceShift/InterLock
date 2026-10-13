// GENERATED from design/console/Interlock Console.dc.html by scripts/console_design/convert.py.
// Edit the view-model, not this markup: regenerate instead.
import { Fragment } from "react";
import type { Vals } from "../vals";

export function ReviewsScreen({ v }: { v: Vals }) {
  return (
    <>
      <div style={{ display: "flex", flexDirection: "column", height: "100%" }}>
        <div style={{ flex: "none", display: "flex", alignItems: "center", gap: "10px", padding: "12px 18px", borderBottom: "1px solid var(--il-rule)", flexWrap: "wrap" }}>
          <div role="tablist" aria-label="Review status" style={{ display: "inline-flex", padding: "3px", borderRadius: "8px", background: "var(--il-panel)", border: "1px solid var(--il-rule)" }}>
            {v.revTabs.map((it_t: (typeof v.revTabs)[number], i_t: number) => (
              <Fragment key={i_t}>
                <button role="tab" aria-selected={it_t.sel} onClick={it_t.on} style={{ display: "inline-flex", gap: "7px", alignItems: "center", fontSize: "12.5px", padding: "5px 11px", borderRadius: "6px", border: "0", cursor: "pointer", background: it_t.bg, color: it_t.c }}>
                  <span className="sc-interp">{it_t.l}</span>
                  <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10px", color: "var(--il-dim)" }}>
                    <span className="sc-interp">{it_t.n}</span>
                  </span>
                </button>
              </Fragment>
            ))}
          </div>
          <span style={{ flex: "1" }}></span>
          <button onClick={v.openKeys} style={{ display: "inline-flex", alignItems: "center", gap: "8px", fontSize: "12px", color: "var(--il-fg2)", padding: "5px 10px", borderRadius: "7px", border: "1px solid var(--il-rule)", background: "transparent", cursor: "pointer" }}>
            <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10px", padding: "0 5px", border: "1px solid var(--il-rule2)", borderRadius: "4px" }}>
              ?
            </span>
            Shortcuts
          </button>
        </div>
        <div style={{ flex: "none", display: "flex", gap: "12px", alignItems: "flex-start", padding: "10px 18px", borderBottom: "1px solid var(--il-rule)", background: "color-mix(in oklch,var(--il-escalate) 7%,var(--il-bg))", fontSize: "12.5px", color: "var(--il-fg2)" }}>
          <span style={{ fontFamily: "'Martian Mono',monospace", color: "var(--il-escalate)", flex: "none" }}>
            ‖
          </span>
          <span style={{ textWrap: "pretty" }}>
            <strong style={{ color: "var(--il-fg)", fontWeight: "600" }}>
              Approving doesn't run anything.
            </strong>
            {" It lets the agent's next "}
            <em>
              identical
            </em>
            {" call through, once, within 15 minutes. If the agent changes even one argument, that call files its own review."}
          </span>
        </div>
        <div style={{ flex: "1", minHeight: "0", display: "flex" }}>
          {v.revShowList ? (
            <>
              <div role="listbox" aria-label="Reviews" style={{ width: v.listW, flex: "none", overflow: "auto", borderRight: "1px solid var(--il-rule)" }}>
                {v.revEmpty ? (
                  <>
                    {" "}
                    <div style={{ padding: "40px 24px", display: "flex", flexDirection: "column", gap: "10px", alignItems: "flex-start" }}>
                      <span style={{ width: "36px", height: "36px", borderRadius: "9px", display: "grid", placeItems: "center", color: "var(--il-allow)", background: "color-mix(in oklch,var(--il-allow) 14%,transparent)", fontFamily: "'Martian Mono',monospace" }}>
                        ✓
                      </span>
                      <strong style={{ fontSize: "15px" }}>
                        <span className="sc-interp">{v.revEmptyTitle}</span>
                      </strong>
                      <span style={{ fontSize: "13px", color: "var(--il-fg2)", textWrap: "pretty" }}>
                        <span className="sc-interp">{v.revEmptyLine}</span>
                      </span>
                    </div>
                    {" "}
                  </>
                ) : null}
                {" "}
                {v.revList.map((it_r: (typeof v.revList)[number], i_r: number) => (
                  <Fragment key={i_r}>
                    {" "}
                    <a href={it_r.href} role="option" aria-selected={it_r.sel} data-testid="reviews-item" style={{ display: "flex", flexDirection: "column", gap: "6px", padding: "12px 16px", borderBottom: "1px solid var(--il-rule)", borderLeft: `3px solid ${it_r.bar}`, background: it_r.bg, color: "var(--il-fg)", textDecoration: "none" }} className="ilh-3">
                      <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                        <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "12px", fontWeight: "500", flex: "1", minWidth: "0", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                          <span className="sc-interp">{it_r.action}</span>
                        </span>
                        <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10.5px", color: it_r.clockC, fontVariantNumeric: "tabular-nums" }}>
                          <span className="sc-interp">{it_r.clock}</span>
                        </span>
                      </div>
                      <span style={{ fontSize: "12.5px", color: "var(--il-fg2)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                        <span className="sc-interp">{it_r.reason}</span>
                      </span>
                      <div style={{ display: "flex", alignItems: "center", gap: "8px", fontFamily: "'Martian Mono',monospace", fontSize: "10px", color: "var(--il-dim)", flexWrap: "wrap" }}>
                        <span>
                          <span className="sc-interp">{it_r.rule}</span>
                        </span>
                        <span>
                          ·
                        </span>
                        <span>
                          <span className="sc-interp">{it_r.principal}</span>
                        </span>
                        {it_r.multi ? (
                          <>
                            <span style={{ color: "var(--il-escalate)" }}>
                              {"· "}
                              <span className="sc-interp">{it_r.approvalsTxt}</span>
                            </span>
                          </>
                        ) : null}
                        {it_r.statusTag ? (
                          <>
                            <span style={{ color: it_r.statusC }}>
                              {"· "}
                              <span className="sc-interp">{it_r.statusTag}</span>
                            </span>
                          </>
                        ) : null}
                      </div>
                    </a>
                    {" "}
                  </Fragment>
                ))}
              </div>
            </>
          ) : null}
          {v.revShowDetail ? (
            <>
              <div style={{ flex: "1", minWidth: "0", overflow: "auto" }}>
                {v.revNoSel ? (
                  <>
                    <div style={{ padding: "48px 28px", color: "var(--il-dim)", fontSize: "13px" }}>
                      Select a review to see the call, the rule and the evidence.
                    </div>
                  </>
                ) : null}
                {" "}
                {v.rv.has ? (
                  <>
                    {" "}
                    <div style={{ padding: "20px 24px 40px", display: "flex", flexDirection: "column", gap: "18px", maxWidth: "860px" }}>
                      {v.narrow ? (
                        <>
                          <a href="#/reviews" style={{ fontSize: "12.5px", color: "var(--il-fg2)" }}>
                            ← All reviews
                          </a>
                        </>
                      ) : null}
                      <div style={{ display: "flex", alignItems: "flex-start", gap: "12px", flexWrap: "wrap" }}>
                        <div style={{ flex: "1", minWidth: "0", display: "flex", flexDirection: "column", gap: "6px" }}>
                          <div style={{ display: "flex", alignItems: "center", gap: "10px", flexWrap: "wrap" }}>
                            <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "18px", fontWeight: "500", letterSpacing: "-.01em" }}>
                              <span className="sc-interp">{v.rv.action}</span>
                            </span>
                            <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10px", color: "var(--il-dim)", border: "1px solid var(--il-rule2)", borderRadius: "4px", padding: "1px 6px" }}>
                              <span className="sc-interp">{v.rv.phase}</span>
                            </span>
                            <span style={{ display: "inline-flex", alignItems: "center", gap: "5px", fontFamily: "'Martian Mono',monospace", fontSize: "10.5px", padding: "2px 8px", borderRadius: "5px", color: v.rv.st.c, background: v.rv.st.bg, border: `1px solid ${v.rv.st.bc}` }}>
                              <span className="sc-interp">{v.rv.st.mark}</span>
                              {" "}
                              <span className="sc-interp">{v.rv.st.word}</span>
                            </span>
                          </div>
                          <p style={{ margin: "0", fontSize: "15px", color: "var(--il-fg)", textWrap: "pretty" }}>
                            <span className="sc-interp">{v.rv.reason}</span>
                          </p>
                        </div>
                        <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10.5px", color: "var(--il-dim)" }}>
                          <span className="sc-interp">{v.rv.id}</span>
                        </span>
                      </div>
                      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(170px,1fr))", gap: "1px", background: "var(--il-rule)", border: "1px solid var(--il-rule)", borderRadius: "10px", overflow: "hidden" }}>
                        {v.rv.meta.map((it_m: (typeof v.rv.meta)[number], i_m: number) => (
                          <Fragment key={i_m}>
                            <div style={{ background: "var(--il-panel)", padding: "10px 12px", display: "flex", flexDirection: "column", gap: "2px", minWidth: "0" }}>
                              <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "9.5px", letterSpacing: ".05em", textTransform: "uppercase", color: "var(--il-dim)" }}>
                                <span className="sc-interp">{it_m.k}</span>
                              </span>
                              {it_m.href ? (
                                <>
                                  <a href={it_m.href} style={{ fontFamily: "'Martian Mono',monospace", fontSize: "11.5px", overflowWrap: "anywhere" }}>
                                    <span className="sc-interp">{it_m.v}</span>
                                  </a>
                                </>
                              ) : null}
                              {it_m.plain ? (
                                <>
                                  <span style={{ fontSize: "13px", color: it_m.c, overflowWrap: "anywhere", fontVariantNumeric: "tabular-nums" }}>
                                    <span className="sc-interp">{it_m.v}</span>
                                  </span>
                                </>
                              ) : null}
                            </div>
                          </Fragment>
                        ))}
                      </div>
                      {v.rv.multi ? (
                        <>
                          <div style={{ display: "flex", alignItems: "center", gap: "12px", flexWrap: "wrap" }}>
                            <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10px", letterSpacing: ".05em", textTransform: "uppercase", color: "var(--il-dim)" }}>
                              Approvals
                            </span>
                            <div style={{ display: "flex", gap: "4px" }}>
                              {v.rv.slots.map((it_s: (typeof v.rv.slots)[number], i_s: number) => (
                                <Fragment key={i_s}>
                                  <span style={{ width: "28px", height: "6px", borderRadius: "3px", background: it_s.c }}></span>
                                </Fragment>
                              ))}
                            </div>
                            <span style={{ fontSize: "13px", color: "var(--il-fg2)" }}>
                              <span className="sc-interp">{v.rv.approvalsTxt}</span>
                            </span>
                          </div>
                        </>
                      ) : null}
                      <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                          <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10px", letterSpacing: ".05em", textTransform: "uppercase", color: "var(--il-dim)" }}>
                            Argument preview
                          </span>
                          <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "9.5px", padding: "1px 6px", borderRadius: "4px", color: "var(--il-rewrite)", border: "1px solid color-mix(in oklch,var(--il-rewrite) 40%,transparent)" }}>
                            may contain secrets
                          </span>
                          <span style={{ flex: "1" }}></span>
                          <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10px", color: "var(--il-dim)" }}>
                            <span className="sc-interp">{v.rv.previewLen}</span>
                          </span>
                        </div>
                        <pre style={{ margin: "0", padding: "14px 16px", borderRadius: "9px", background: "var(--il-sunken)", border: "1px solid var(--il-rule)", fontFamily: "'Martian Mono',monospace", fontSize: "11.5px", lineHeight: "1.7", whiteSpace: "pre-wrap", overflowWrap: "anywhere", color: "var(--il-fg)" }}>
                          <span className="sc-interp">{v.rv.preview}</span>
                        </pre>
                        <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10px", color: "var(--il-dim)", overflowWrap: "anywhere" }}>
                          {"args digest "}
                          <span className="sc-interp">{v.rv.digest}</span>
                        </span>
                      </div>
                      <div style={{ border: "1px solid var(--il-rule2)", borderRadius: "12px", background: "var(--il-panel)", padding: "16px", display: "flex", flexDirection: "column", gap: "12px" }}>
                        <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10px", letterSpacing: ".05em", textTransform: "uppercase", color: "var(--il-dim)" }}>
                          Decision
                        </span>
                        {v.rv.showLocked ? (
                          <>
                            <div style={{ display: "flex", gap: "12px", alignItems: "flex-start", flexWrap: "wrap" }}>
                              <span style={{ flex: "1", minWidth: "240px", fontSize: "13px", color: "var(--il-fg2)", textWrap: "pretty" }}>
                                <strong style={{ color: "var(--il-fg)", fontWeight: "600" }}>
                                  Read-only.
                                </strong>
                                {" Writes are locked so an agent on this machine can't approve its own calls through the console. Unlock with the link printed in the console's terminal."}
                              </span>
                              <button onClick={v.openUnlock} style={{ fontSize: "13px", fontWeight: "500", padding: "8px 14px", borderRadius: "7px", border: "1px solid var(--il-acc)", background: "transparent", color: "var(--il-acc)", cursor: "pointer" }}>
                                Unlock writes
                              </button>
                            </div>
                          </>
                        ) : null}
                        {v.rv.showFourEyes ? (
                          <>
                            <div style={{ display: "flex", gap: "10px", alignItems: "flex-start", fontSize: "13px", color: "var(--il-fg2)", padding: "10px 12px", borderRadius: "8px", background: "var(--il-raised)" }}>
                              <span style={{ fontFamily: "'Martian Mono',monospace", color: "var(--il-escalate)" }}>
                                ‖
                              </span>
                              <span style={{ textWrap: "pretty" }}>
                                <strong style={{ color: "var(--il-fg)", fontWeight: "600" }}>
                                  You filed this one.
                                </strong>
                                {" Four-eyes is on for this console, so someone other than "}
                                <span className="sc-interp">{v.me}</span>
                                {" has to approve it. You can still reject it."}
                              </span>
                            </div>
                          </>
                        ) : null}
                        {v.rv.showPendingActions ? (
                          <>
                            <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
                              <textarea value={v.rejectReason} onChange={v.onReject} disabled={v.locked} rows={2} placeholder="Reason for rejecting. The agent is told this." aria-label="Rejection reason" data-testid="reviews-reject-reason" style={{ resize: "vertical", padding: "9px 11px", borderRadius: "8px", border: "1px solid var(--il-rule2)", background: "var(--il-sunken)", fontSize: "13px", opacity: v.lockedOpacity }} />
                              <div style={{ display: "flex", gap: "8px", flexWrap: "wrap", alignItems: "center" }}>
                                <button onClick={v.approve} disabled={v.rv.approveDisabled} data-testid="reviews-approve" style={{ display: "inline-flex", alignItems: "center", gap: "8px", fontSize: "13px", fontWeight: "600", padding: "8px 16px", borderRadius: "7px", border: "0", background: "var(--il-allow)", color: "var(--il-bg)", cursor: "pointer", opacity: v.rv.approveOpacity }}>
                                  {"✓ "}
                                  <span className="sc-interp">{v.rv.approveLabel}</span>
                                  <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10px", opacity: ".7", border: "1px solid currentColor", borderRadius: "3px", padding: "0 4px" }}>
                                    a
                                  </span>
                                </button>
                                <button onClick={v.reject} disabled={v.rv.rejectDisabled} data-testid="reviews-reject" style={{ display: "inline-flex", alignItems: "center", gap: "8px", fontSize: "13px", fontWeight: "600", padding: "8px 16px", borderRadius: "7px", border: "1px solid var(--il-block)", background: "transparent", color: "var(--il-block)", cursor: "pointer", opacity: v.rv.rejectOpacity }}>
                                  {"✗ "}
                                  <span className="sc-interp">{v.rv.rejectLabel}</span>
                                  <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10px", opacity: ".7", border: "1px solid currentColor", borderRadius: "3px", padding: "0 4px" }}>
                                    r
                                  </span>
                                </button>
                                <span style={{ fontSize: "12px", color: "var(--il-dim)" }}>
                                  <span className="sc-interp">{v.rv.hint}</span>
                                </span>
                              </div>
                            </div>
                          </>
                        ) : null}
                        {v.rv.showApproved ? (
                          <>
                            <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
                              <div style={{ display: "flex", alignItems: "center", gap: "14px", flexWrap: "wrap" }}>
                                <span style={{ fontSize: "26px", fontWeight: "600", letterSpacing: "-.02em", fontVariantNumeric: "tabular-nums", color: "var(--il-allow)" }}>
                                  <span className="sc-interp">{v.rv.retryClock}</span>
                                </span>
                                <span style={{ fontSize: "13px", color: "var(--il-fg2)", flex: "1", minWidth: "220px", textWrap: "pretty" }}>
                                  {"left for the agent to retry the "}
                                  <strong style={{ color: "var(--il-fg)" }}>
                                    identical
                                  </strong>
                                  {" call. It goes through once, then this review is marked executed. A different call files a new review."}
                                </span>
                              </div>
                              <div>
                                <button onClick={v.revoke} disabled={v.locked} data-testid="reviews-revoke" style={{ fontSize: "13px", fontWeight: "500", padding: "7px 14px", borderRadius: "7px", border: "1px solid var(--il-rule2)", background: "transparent", cursor: "pointer", opacity: v.lockedOpacity }}>
                                  <span className="sc-interp">{v.rv.revokeLabel}</span>
                                </button>
                              </div>
                            </div>
                          </>
                        ) : null}
                        {v.rv.showDone ? (
                          <>
                            <p style={{ margin: "0", fontSize: "13px", color: "var(--il-fg2)" }}>
                              <span className="sc-interp">{v.rv.doneLine}</span>
                            </p>
                          </>
                        ) : null}
                        {v.flash ? (
                          <>
                            <div role="status" style={{ fontSize: "12.5px", padding: "8px 10px", borderRadius: "7px", background: "var(--il-raised)", color: "var(--il-fg)" }}>
                              <span className="sc-interp">{v.flash}</span>
                            </div>
                          </>
                        ) : null}
                      </div>
                      <div style={{ display: "flex", gap: "14px", flexWrap: "wrap", fontSize: "12.5px" }}>
                        <a href={v.rv.auditHref}>
                          Matching receipts in the audit log →
                        </a>
                        <a href="#/policy">
                          {"Rule "}
                          <span className="sc-interp">{v.rv.rule}</span>
                          {" in the policy →"}
                        </a>
                      </div>
                    </div>
                    {" "}
                  </>
                ) : null}
              </div>
            </>
          ) : null}
        </div>
      </div>
    </>
  );
}
