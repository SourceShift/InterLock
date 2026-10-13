// GENERATED from design/console/Interlock Console.dc.html by scripts/console_design/convert.py.
// Edit the view-model, not this markup: regenerate instead.
import { Fragment } from "react";
import type { Vals } from "../vals";

export function InspectorScreen({ v }: { v: Vals }) {
  return (
    <>
      <div style={{ display: "flex", flexWrap: "wrap", gap: "16px", padding: "16px 18px 40px", alignItems: "flex-start" }}>
        <div style={{ flex: "1 1 420px", minWidth: "0", display: "flex", flexDirection: "column", gap: "12px" }}>
          <label style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
            <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10px", letterSpacing: ".05em", textTransform: "uppercase", color: "var(--il-dim)" }}>
              Scope document
            </span>
            <textarea value={v.insDoc} onChange={v.ins.onDoc} spellCheck={false} data-testid="scope-doc-editor" style={{ minHeight: "300px", resize: "vertical", fontFamily: "'Martian Mono',monospace", fontSize: "10.5px", lineHeight: "1.6", padding: "10px 12px", borderRadius: "8px", border: `1px solid ${v.ins.docBc}`, background: "var(--il-sunken)", whiteSpace: "pre" }} />
          </label>
          <div style={{ display: "flex", gap: "10px", flexWrap: "wrap" }}>
            <label style={{ flex: "1 1 180px", display: "flex", flexDirection: "column", gap: "6px" }}>
              <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10px", letterSpacing: ".05em", textTransform: "uppercase", color: "var(--il-dim)" }}>
                Principal
              </span>
              <input value={v.insPrincipal} onChange={v.ins.onPrincipal} data-testid="principal-input" style={{ fontFamily: "'Martian Mono',monospace", fontSize: "11px", padding: "7px 10px", borderRadius: "7px", border: "1px solid var(--il-rule2)", background: "var(--il-sunken)" }} />
            </label>
          </div>
          <label style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
            <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10px", letterSpacing: ".05em", textTransform: "uppercase", color: "var(--il-dim)" }}>
              {"Event "}
              <span style={{ textTransform: "none", letterSpacing: "0" }}>
                (optional)
              </span>
            </span>
            <textarea value={v.insEvent} onChange={v.ins.onEvent} spellCheck={false} rows={4} data-testid="scope-event-editor" style={{ resize: "vertical", fontFamily: "'Martian Mono',monospace", fontSize: "10.5px", lineHeight: "1.6", padding: "10px 12px", borderRadius: "8px", border: "1px solid var(--il-rule2)", background: "var(--il-sunken)" }} />
          </label>
          <div style={{ display: "flex", gap: "10px", alignItems: "center" }}>
            <button onClick={v.ins.resolve} data-testid="resolve-button" style={{ fontSize: "13px", fontWeight: "600", padding: "9px 18px", borderRadius: "7px", border: "0", background: "var(--il-acc)", color: "var(--il-accfg)", cursor: "pointer" }}>
              Resolve
            </button>
            <span style={{ fontSize: "12px", color: "var(--il-dim)" }}>
              Computes the plan only. Nothing runs.
            </span>
          </div>
          {v.ins.err ? (
            <>
              <span data-testid="scope-error" role="alert" style={{ fontFamily: "'Martian Mono',monospace", fontSize: "11px", color: "var(--il-block)" }}>
                {"✗ "}
                <span className="sc-interp">{v.ins.err}</span>
              </span>
            </>
          ) : null}
        </div>
        <div style={{ flex: "1.2 1 440px", minWidth: "0", display: "flex", flexDirection: "column", gap: "12px" }}>
          {v.ins.idle ? (
            <>
              <div style={{ border: "1px dashed var(--il-rule2)", borderRadius: "10px", padding: "28px 18px", fontSize: "13px", color: "var(--il-dim)", textAlign: "center" }}>
                Resolve to see the parameters, the sandbox profile and what this host can actually enforce.
              </div>
            </>
          ) : null}
          {v.ins.has ? (
            <>
              {v.ins.gap ? (
                <>
                  <div role="alert" style={{ display: "flex", gap: "12px", padding: "12px 14px", borderRadius: "10px", border: "1px solid var(--il-rewrite)", background: "color-mix(in oklch,var(--il-rewrite) 10%,transparent)" }}>
                    <span style={{ fontFamily: "'Martian Mono',monospace", color: "var(--il-rewrite)", fontSize: "15px" }}>
                      !
                    </span>
                    <div style={{ display: "flex", flexDirection: "column", gap: "3px", fontSize: "13px" }}>
                      <strong style={{ fontWeight: "600" }}>
                        The profile promises more than this host can enforce
                      </strong>
                      <span style={{ color: "var(--il-fg2)", textWrap: "pretty" }}>
                        <span className="sc-interp">{v.ins.gapLine}</span>
                      </span>
                    </div>
                  </div>
                </>
              ) : null}
              <div data-testid="resolved-params" style={{ border: "1px solid var(--il-rule)", borderRadius: "10px", background: "var(--il-panel)", padding: "12px 14px", display: "flex", flexDirection: "column", gap: "6px" }}>
                <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10px", letterSpacing: ".05em", textTransform: "uppercase", color: "var(--il-dim)" }}>
                  Resolved
                </span>
                <span data-testid="resolved-template" style={{ fontFamily: "'Martian Mono',monospace", fontSize: "12px" }}>
                  {"template "}
                  <span className="sc-interp">{v.ins.template}</span>
                </span>
                {v.ins.params.map((it_p: (typeof v.ins.params)[number], i_p: number) => (
                  <Fragment key={i_p}>
                    <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "11px", color: "var(--il-fg2)" }}>
                      <span className="sc-interp">{it_p.k}</span>
                      {" = "}
                      <span style={{ color: "var(--il-fg)" }}>
                        <span className="sc-interp">{it_p.v}</span>
                      </span>
                    </span>
                  </Fragment>
                ))}
              </div>
              <div data-testid="sandbox-profile" style={{ border: "1px solid var(--il-rule)", borderRadius: "10px", background: "var(--il-panel)", overflow: "hidden" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "10px", padding: "10px 14px", borderBottom: "1px solid var(--il-rule)" }}>
                  <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10px", letterSpacing: ".05em", textTransform: "uppercase", color: "var(--il-dim)", flex: "1" }}>
                    Sandbox profile
                  </span>
                  <span style={{ fontSize: "12px", color: "var(--il-fg2)" }}>
                    {"backend "}
                    <span data-testid="backend-name" style={{ fontFamily: "'Martian Mono',monospace", fontSize: "11px", color: "var(--il-fg)" }}>
                      <span className="sc-interp">{v.ins.backend}</span>
                    </span>
                  </span>
                </div>
                {" "}
                {v.ins.rows.map((it_r: (typeof v.ins.rows)[number], i_r: number) => (
                  <Fragment key={i_r}>
                    <div style={{ display: "grid", gridTemplateColumns: "130px minmax(0,1fr) auto", gap: "12px", alignItems: "baseline", padding: "8px 14px", borderBottom: "1px solid var(--il-rule)" }}>
                      <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10.5px", color: "var(--il-dim)" }}>
                        <span className="sc-interp">{it_r.k}</span>
                      </span>
                      <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "11px", overflowWrap: "anywhere" }}>
                        <span className="sc-interp">{it_r.v}</span>
                      </span>
                      <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10px", whiteSpace: "nowrap", color: it_r.c }}>
                        <span className="sc-interp">{it_r.mark}</span>
                        {" "}
                        <span className="sc-interp">{it_r.state}</span>
                      </span>
                    </div>
                  </Fragment>
                ))}
              </div>
              <div style={{ display: "flex", gap: "10px", flexWrap: "wrap" }}>
                <div data-testid="enforced-tokens" style={{ flex: "1 1 200px", border: "1px solid var(--il-rule)", borderRadius: "10px", background: "var(--il-panel)", padding: "10px 12px", display: "flex", flexDirection: "column", gap: "6px" }}>
                  <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10px", color: "var(--il-allow)" }}>
                    ✓ ENFORCED ON THIS HOST
                  </span>
                  <div style={{ display: "flex", gap: "4px", flexWrap: "wrap" }}>
                    {v.ins.enforced.map((it_t: (typeof v.ins.enforced)[number], i_t: number) => (
                      <Fragment key={i_t}>
                        <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10px", padding: "1px 6px", borderRadius: "4px", border: "1px solid var(--il-rule2)" }}>
                          <span className="sc-interp">{it_t}</span>
                        </span>
                      </Fragment>
                    ))}
                  </div>
                </div>
                <div data-testid="not-enforced-tokens" style={{ flex: "1 1 200px", border: `1px solid ${v.ins.neBc}`, borderRadius: "10px", background: v.ins.neBg, padding: "10px 12px", display: "flex", flexDirection: "column", gap: "6px" }}>
                  <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10px", color: "var(--il-rewrite)" }}>
                    ! NOT ENFORCED
                  </span>
                  <div style={{ display: "flex", gap: "4px", flexWrap: "wrap" }}>
                    {v.ins.notEnforced.map((it_t: (typeof v.ins.notEnforced)[number], i_t: number) => (
                      <Fragment key={i_t}>
                        <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10px", padding: "1px 6px", borderRadius: "4px", border: "1px dashed var(--il-rewrite)", color: "var(--il-rewrite)" }}>
                          <span className="sc-interp">{it_t}</span>
                        </span>
                      </Fragment>
                    ))}
                  </div>
                </div>
              </div>
              <div data-testid="scope-verdict" style={{ border: "1px solid var(--il-rule)", borderRadius: "10px", background: "var(--il-panel)", padding: "12px 14px", display: "flex", flexDirection: "column", gap: "6px" }}>
                <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10px", letterSpacing: ".05em", textTransform: "uppercase", color: "var(--il-dim)" }}>
                  Verdict for the event
                </span>
                {v.ins.hasVerdict ? (
                  <>
                    <div style={{ display: "flex", gap: "8px", alignItems: "center", flexWrap: "wrap" }}>
                      <span style={{ display: "inline-flex", gap: "5px", fontFamily: "'Martian Mono',monospace", fontSize: "10.5px", padding: "2px 7px", borderRadius: "5px", color: v.ins.v.c, background: v.ins.v.bg, border: `1px solid ${v.ins.v.bc}` }}>
                        <span className="sc-interp">{v.ins.v.mark}</span>
                        {" "}
                        <span className="sc-interp">{v.ins.v.word}</span>
                      </span>
                      <span style={{ fontSize: "12.5px", color: "var(--il-fg2)" }}>
                        <span className="sc-interp">{v.ins.vReason}</span>
                      </span>
                    </div>
                  </>
                ) : null}
                {v.ins.noVerdict ? (
                  <>
                    <span style={{ fontSize: "12.5px", color: "var(--il-dim)" }}>
                      Add an event to see whether this principal's profile would allow it.
                    </span>
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
