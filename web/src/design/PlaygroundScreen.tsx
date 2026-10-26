// GENERATED from design/console/Interlock Console.dc.html by scripts/console_design/convert.py.
// Edit the view-model, not this markup: regenerate instead.
import { Fragment } from "react";
import type { Vals } from "../vals";
import { DetectorPicker } from "../components/DetectorPicker";

export function PlaygroundScreen({ v }: { v: Vals }) {
  return (
    <>
      <div style={{ display: "flex", flexWrap: "wrap", gap: "16px", padding: "16px 18px 40px", alignItems: "flex-start" }}>
        <div style={{ flex: "1 1 440px", minWidth: "0", display: "flex", flexDirection: "column", gap: "14px" }}>
          <div style={{ display: "flex", gap: "8px", alignItems: "center", flexWrap: "wrap" }}>
            <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10px", letterSpacing: ".05em", textTransform: "uppercase", color: "var(--il-dim)" }}>
              Preset
            </span>
            <select ref={v.pgv.selRef} value={v.pgv.preset} onChange={v.pgv.onPreset} data-testid="preset-select" style={{ fontSize: "12.5px", padding: "6px 9px", borderRadius: "7px", border: "1px solid var(--il-rule2)", background: "var(--il-panel)" }}>
              {v.pgv.presets.map((it_o: (typeof v.pgv.presets)[number], i_o: number) => (
                <Fragment key={i_o}>
                  <option value={it_o.v}>
                    <span className="sc-interp">{it_o.l}</span>
                  </option>
                </Fragment>
              ))}
            </select>
            <span style={{ flex: "1" }}></span>
            <span style={{ fontSize: "12px", color: "var(--il-dim)" }}>
              Runs only catalog detectors. Never evaluates code.
            </span>
          </div>
          {v.extras.realCalls}
          <section data-testid="rules-editor" style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <h2 style={{ margin: "0", fontSize: "13.5px", fontWeight: "600", flex: "1" }}>
                Rules
              </h2>
              <button onClick={v.pgv.addRule} style={{ fontSize: "12px", padding: "4px 10px", borderRadius: "6px", border: "1px solid var(--il-rule2)", background: "transparent", cursor: "pointer" }}>
                + Add rule
              </button>
            </div>
            {v.pgv.rules.map((it_r: (typeof v.pgv.rules)[number], i_r: number) => (
              <Fragment key={i_r}>
                <div style={{ border: "1px solid var(--il-rule)", borderRadius: "10px", background: "var(--il-panel)", padding: "12px", display: "flex", flexDirection: "column", gap: "10px" }}>
                  <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
                    <DetectorPicker value={it_r.module} onChange={it_r.onModule} options={v.pgv.detOpts} aria-label="Detector" />
                    <button onClick={it_r.remove} aria-label="Remove rule" style={{ width: "28px", height: "28px", borderRadius: "6px", border: "1px solid var(--il-rule2)", background: "transparent", cursor: "pointer" }}>
                      ✕
                    </button>
                  </div>
                  <code style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10.5px", color: "var(--il-fg2)", overflowWrap: "anywhere" }}>
                    <span className="sc-interp">{it_r.sig}</span>
                  </code>
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(180px,1fr))", gap: "8px" }}>
                    {it_r.params.map((it_p: (typeof it_r.params)[number], i_p: number) => (
                      <Fragment key={i_p}>
                        <label style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
                          <span style={{ display: "flex", gap: "6px", alignItems: "baseline", fontFamily: "'Martian Mono',monospace", fontSize: "10.5px" }}>
                            <span style={{ color: "var(--il-fg)" }}>
                              <span className="sc-interp">{it_p.name}</span>
                            </span>
                            <span style={{ color: "var(--il-dim)" }}>
                              <span className="sc-interp">{it_p.ann}</span>
                            </span>
                            {it_p.required ? (
                              <>
                                <span style={{ color: "var(--il-block)" }}>
                                  required
                                </span>
                              </>
                            ) : null}
                          </span>
                          <input value={it_p.value} onChange={it_p.on} placeholder={it_p.ph} style={{ fontFamily: "'Martian Mono',monospace", fontSize: "11px", padding: "6px 8px", borderRadius: "6px", border: "1px solid var(--il-rule2)", background: "var(--il-sunken)" }} />
                        </label>
                      </Fragment>
                    ))}
                  </div>
                </div>
              </Fragment>
            ))}
          </section>
          <section data-testid="events-editor" style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <h2 style={{ margin: "0", fontSize: "13.5px", fontWeight: "600", flex: "1" }}>
                Events
              </h2>
              <button onClick={v.pgv.addEvent} style={{ fontSize: "12px", padding: "4px 10px", borderRadius: "6px", border: "1px solid var(--il-rule2)", background: "transparent", cursor: "pointer" }}>
                + Add event
              </button>
            </div>
            {v.pgv.events.map((it_e: (typeof v.pgv.events)[number], i_e: number) => (
              <Fragment key={i_e}>
                <div style={{ border: `1px solid ${it_e.bc}`, borderRadius: "10px", background: "var(--il-panel)", padding: "10px 12px", display: "flex", flexDirection: "column", gap: "8px" }}>
                  <div style={{ display: "flex", gap: "6px", alignItems: "center", flexWrap: "wrap" }}>
                    <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10px", color: "var(--il-dim)", width: "22px" }}>
                      #
                      <span className="sc-interp">{it_e.n}</span>
                    </span>
                    <input value={it_e.action} onChange={it_e.onAction} aria-label="Action" style={{ flex: "1", minWidth: "100px", fontFamily: "'Martian Mono',monospace", fontSize: "11px", padding: "5px 8px", borderRadius: "6px", border: "1px solid var(--il-rule2)", background: "var(--il-sunken)" }} />
                    <select ref={it_e.selRef} value={it_e.phase} onChange={it_e.onPhase} aria-label="Phase" style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10.5px", padding: "5px 6px", borderRadius: "6px", border: "1px solid var(--il-rule2)", background: "var(--il-sunken)" }}>
                      <option value="call">
                        call
                      </option>
                      <option value="result">
                        result
                      </option>
                    </select>
                    <input value={it_e.principal} onChange={it_e.onPrincipal} aria-label="Principal" style={{ width: "120px", fontFamily: "'Martian Mono',monospace", fontSize: "11px", padding: "5px 8px", borderRadius: "6px", border: "1px solid var(--il-rule2)", background: "var(--il-sunken)" }} />
                    <button onClick={it_e.remove} aria-label="Remove event" style={{ width: "26px", height: "26px", borderRadius: "6px", border: "1px solid var(--il-rule2)", background: "transparent", cursor: "pointer" }}>
                      ✕
                    </button>
                  </div>
                  <textarea value={it_e.args} onChange={it_e.onArgs} spellCheck={false} rows={it_e.rows} aria-label="Arguments JSON" style={{ resize: "vertical", fontFamily: "'Martian Mono',monospace", fontSize: "11px", lineHeight: "1.6", padding: "8px 10px", borderRadius: "7px", border: "1px solid var(--il-rule2)", background: "var(--il-sunken)" }} />
                  {it_e.err ? (
                    <>
                      <span data-testid="editor-error" role="alert" style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10.5px", color: "var(--il-block)" }}>
                        ✗ event #
                        <span className="sc-interp">{it_e.n}</span>
                        {" arguments, line "}
                        <span className="sc-interp">{it_e.errLine}</span>
                        {": "}
                        <span className="sc-interp">{it_e.err}</span>
                      </span>
                    </>
                  ) : null}
                </div>
              </Fragment>
            ))}
          </section>
          <div style={{ display: "flex", gap: "10px", alignItems: "center" }}>
            <button onClick={v.pgv.run} data-testid="evaluate-button" style={{ fontSize: "13px", fontWeight: "600", padding: "9px 18px", borderRadius: "7px", border: "0", background: "var(--il-acc)", color: "var(--il-accfg)", cursor: "pointer" }}>
              Evaluate
            </button>
            <span style={{ fontSize: "12px", color: "var(--il-dim)" }}>
              <span className="sc-interp">{v.pgv.runHint}</span>
            </span>
          </div>
        </div>
        <div style={{ flex: "1 1 380px", minWidth: "0", display: "flex", flexDirection: "column", gap: "10px", position: "sticky", top: "16px" }}>
          <h2 style={{ margin: "0", fontSize: "13.5px", fontWeight: "600" }}>
            Results
          </h2>
          {v.pgv.idle ? (
            <>
              <div style={{ border: "1px dashed var(--il-rule2)", borderRadius: "10px", padding: "28px 18px", fontSize: "13px", color: "var(--il-dim)", textAlign: "center" }}>
                Press Evaluate to see one verdict per event. After that, results update as you edit.
              </div>
            </>
          ) : null}
          {v.pgv.blocked ? (
            <>
              <div role="alert" style={{ border: "1px solid color-mix(in oklch,var(--il-block) 40%,transparent)", borderRadius: "10px", padding: "12px 14px", fontSize: "12.5px", color: "var(--il-fg2)" }}>
                Fix the JSON in the highlighted event before results can update.
              </div>
            </>
          ) : null}
          <div data-testid="results" style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
            {v.pgv.results.map((it_x: (typeof v.pgv.results)[number], i_x: number) => (
              <Fragment key={i_x}>
                <div data-testid="result-row" style={{ border: "1px solid var(--il-rule)", borderLeft: `3px solid ${it_x.v.c}`, borderRadius: "10px", background: "var(--il-panel)", padding: "10px 12px", display: "flex", flexDirection: "column", gap: "6px" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "8px", flexWrap: "wrap" }}>
                    <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10px", color: "var(--il-dim)" }}>
                      #
                      <span className="sc-interp">{it_x.n}</span>
                    </span>
                    <span data-testid="verdict-badge" style={{ display: "inline-flex", gap: "5px", fontFamily: "'Martian Mono',monospace", fontSize: "10px", padding: "1px 6px", borderRadius: "5px", color: it_x.v.c, background: it_x.v.bg, border: `1px solid ${it_x.v.bc}` }}>
                      <span className="sc-interp">{it_x.v.mark}</span>
                      {" "}
                      <span className="sc-interp">{it_x.v.word}</span>
                    </span>
                    <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "11px", flex: "1" }}>
                      <span className="sc-interp">{it_x.action}</span>
                    </span>
                    <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10px", color: "var(--il-dim)" }}>
                      <span className="sc-interp">{it_x.rule}</span>
                    </span>
                  </div>
                  <span data-testid="result-reason" style={{ fontSize: "12.5px", color: "var(--il-fg2)" }}>
                    <span className="sc-interp">{it_x.reason}</span>
                  </span>
                  {it_x.blamed ? (
                    <>
                      <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10px", color: "var(--il-dim)" }}>
                        {"blamed argument: "}
                        <span style={{ color: "var(--il-fg)" }}>
                          <span className="sc-interp">{it_x.blamed}</span>
                        </span>
                      </span>
                    </>
                  ) : null}
                  {it_x.diff ? (
                    <>
                      <div data-testid="modified-args" style={{ borderRadius: "7px", overflow: "hidden", border: "1px solid var(--il-rule)", fontFamily: "'Martian Mono',monospace", fontSize: "10.5px", lineHeight: "1.6" }}>
                        <div style={{ padding: "5px 9px", background: "color-mix(in oklch,var(--il-block) 9%,transparent)", color: "var(--il-fg2)", overflowWrap: "anywhere" }}>
                          {"− "}
                          <span className="sc-interp">{it_x.before}</span>
                        </div>
                        <div style={{ padding: "5px 9px", background: "color-mix(in oklch,var(--il-allow) 9%,transparent)", color: "var(--il-fg)", overflowWrap: "anywhere" }}>
                          {"+ "}
                          <span className="sc-interp">{it_x.after}</span>
                        </div>
                      </div>
                    </>
                  ) : null}
                </div>
              </Fragment>
            ))}
          </div>
        </div>
      </div>
    </>
  );
}
