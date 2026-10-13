// GENERATED from design/console/Interlock Console.dc.html by scripts/console_design/convert.py.
// Edit the view-model, not this markup: regenerate instead.
import { Fragment } from "react";
import type { Vals } from "../vals";

export function OpsScreen({ v }: { v: Vals }) {
  return (
    <>
      <div style={{ padding: "18px 18px 40px", display: "flex", flexDirection: "column", gap: "16px", maxWidth: "1180px" }}>
        <section style={{ border: `1px solid ${v.posture.bc}`, borderRadius: "12px", background: "var(--il-panel)", overflow: "hidden" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "12px", padding: "14px 16px", borderBottom: "1px solid var(--il-rule)", background: v.posture.bg, flexWrap: "wrap" }}>
            <span style={{ width: "32px", height: "32px", borderRadius: "8px", display: "grid", placeItems: "center", fontFamily: "'Martian Mono',monospace", color: v.posture.c, border: `1px solid ${v.posture.bc}` }}>
              <span className="sc-interp">{v.posture.mark}</span>
            </span>
            <div style={{ flex: "1", minWidth: "200px", display: "flex", flexDirection: "column" }}>
              <strong style={{ fontSize: "15px", color: v.posture.c }}>
                {"Protection: "}
                <span className="sc-interp">{v.posture.word}</span>
              </strong>
              <span style={{ fontSize: "12.5px", color: "var(--il-fg2)" }}>
                {"From "}
                <code style={{ fontFamily: "'Martian Mono',monospace", fontSize: "11px" }}>
                  interlock doctor
                </code>
                : host- and file-level checks the console can see.
              </span>
            </div>
          </div>
          {" "}
          {v.ops.checks.map((it_c: (typeof v.ops.checks)[number], i_c: number) => (
            <Fragment key={i_c}>
              <div style={{ display: "grid", gridTemplateColumns: v.ops.checkCols, gap: "8px 14px", alignItems: "center", padding: "10px 16px", borderBottom: "1px solid var(--il-rule)" }}>
                <span style={{ display: "inline-flex", gap: "5px", alignItems: "center", fontFamily: "'Martian Mono',monospace", fontSize: "10px", padding: "1px 7px", borderRadius: "5px", justifySelf: "start", color: it_c.t.c, background: it_c.t.bg, border: `1px solid ${it_c.t.bc}` }}>
                  <span className="sc-interp">{it_c.t.mark}</span>
                  {" "}
                  <span className="sc-interp">{it_c.status}</span>
                </span>
                <span style={{ fontSize: "13px", minWidth: "0" }}>
                  <span className="sc-interp">{it_c.summary}</span>
                </span>
                {it_c.fix ? (
                  <>
                    <div style={{ display: "flex", gap: "6px", alignItems: "center", minWidth: "0" }}>
                      <code style={{ flex: "1", minWidth: "0", fontFamily: "'Martian Mono',monospace", fontSize: "10.5px", padding: "5px 8px", borderRadius: "6px", background: "var(--il-sunken)", border: "1px solid var(--il-rule)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                        <span className="sc-interp">{it_c.fix}</span>
                      </code>
                      <button onClick={it_c.copy} style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10px", padding: "5px 8px", borderRadius: "6px", border: "1px solid var(--il-rule2)", background: "transparent", cursor: "pointer" }}>
                        <span className="sc-interp">{it_c.copyLabel}</span>
                      </button>
                    </div>
                  </>
                ) : null}
                {it_c.noFix ? (
                  <>
                    <span></span>
                  </>
                ) : null}
              </div>
            </Fragment>
          ))}
        </section>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(min(100%,340px),1fr))", gap: "12px" }}>
          <section style={{ border: "1px solid var(--il-rule)", borderRadius: "12px", background: "var(--il-panel)", overflow: "hidden" }}>
            <div style={{ padding: "12px 16px", borderBottom: "1px solid var(--il-rule)", display: "flex", justifyContent: "space-between", gap: "10px" }}>
              <h2 style={{ margin: "0", fontSize: "14px", fontWeight: "600" }}>
                Coding-agent hooks
              </h2>
              <span style={{ fontSize: "12px", color: "var(--il-dim)" }}>
                install from your own terminal
              </span>
            </div>
            {" "}
            {v.ops.hooks.map((it_h: (typeof v.ops.hooks)[number], i_h: number) => (
              <Fragment key={i_h}>
                <div style={{ display: "flex", flexDirection: "column", gap: "6px", padding: "11px 16px", borderBottom: "1px solid var(--il-rule)" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                    <strong style={{ fontSize: "13px", fontWeight: "600", flex: "1" }}>
                      <span className="sc-interp">{it_h.name}</span>
                    </strong>
                    <span style={{ display: "inline-flex", gap: "5px", fontFamily: "'Martian Mono',monospace", fontSize: "10px", padding: "1px 7px", borderRadius: "5px", color: it_h.t.c, background: it_h.t.bg, border: `1px ${it_h.t.bs} ${it_h.t.bc}` }}>
                      <span className="sc-interp">{it_h.t.mark}</span>
                      {" "}
                      <span className="sc-interp">{it_h.state}</span>
                    </span>
                  </div>
                  <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10.5px", color: "var(--il-dim)" }}>
                    <span className="sc-interp">{it_h.where}</span>
                  </span>
                  {it_h.cmd ? (
                    <>
                      <div style={{ display: "flex", gap: "6px", alignItems: "center" }}>
                        <code style={{ flex: "1", minWidth: "0", fontFamily: "'Martian Mono',monospace", fontSize: "10.5px", padding: "5px 8px", borderRadius: "6px", background: "var(--il-sunken)", border: "1px solid var(--il-rule)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                          <span className="sc-interp">{it_h.cmd}</span>
                        </code>
                        <button onClick={it_h.copy} style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10px", padding: "5px 8px", borderRadius: "6px", border: "1px solid var(--il-rule2)", background: "transparent", cursor: "pointer" }}>
                          <span className="sc-interp">{it_h.copyLabel}</span>
                        </button>
                      </div>
                    </>
                  ) : null}
                </div>
              </Fragment>
            ))}
          </section>
          <section style={{ border: "1px solid var(--il-rule)", borderRadius: "12px", background: "var(--il-panel)", overflow: "hidden" }}>
            <div style={{ padding: "12px 16px", borderBottom: "1px solid var(--il-rule)", display: "flex", justifyContent: "space-between", alignItems: "center", gap: "10px" }}>
              <h2 style={{ margin: "0", fontSize: "14px", fontWeight: "600" }}>
                Sidecar
              </h2>
              <span style={{ display: "inline-flex", gap: "5px", fontFamily: "'Martian Mono',monospace", fontSize: "10px", padding: "1px 7px", borderRadius: "5px", color: v.ops.sc.t.c, background: v.ops.sc.t.bg, border: `1px ${v.ops.sc.t.bs} ${v.ops.sc.t.bc}` }}>
                <span className="sc-interp">{v.ops.sc.t.mark}</span>
                {" "}
                <span className="sc-interp">{v.ops.sc.state}</span>
              </span>
            </div>
            {" "}
            <p style={{ margin: "0", padding: "10px 16px 0", fontSize: "12.5px", color: "var(--il-fg2)", textWrap: "pretty" }}>
              <span className="sc-interp">{v.ops.sc.line}</span>
            </p>
            {" "}
            {v.ops.sc.healthy ? (
              <>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(120px,1fr))", gap: "1px", margin: "12px 16px 16px", background: "var(--il-rule)", border: "1px solid var(--il-rule)", borderRadius: "8px", overflow: "hidden" }}>
                  {v.ops.sc.stats.map((it_s: (typeof v.ops.sc.stats)[number], i_s: number) => (
                    <Fragment key={i_s}>
                      <div style={{ background: "var(--il-panel)", padding: "9px 11px", display: "flex", flexDirection: "column", gap: "1px" }}>
                        <span style={{ fontSize: "15px", fontWeight: "600", fontVariantNumeric: "tabular-nums", color: it_s.c }}>
                          <span className="sc-interp">{it_s.v}</span>
                        </span>
                        <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "9.5px", color: "var(--il-dim)" }}>
                          <span className="sc-interp">{it_s.k}</span>
                        </span>
                      </div>
                    </Fragment>
                  ))}
                </div>
              </>
            ) : null}
            {" "}
            {v.ops.sc.notHealthy ? (
              <>
                <div style={{ height: "14px" }}></div>
              </>
            ) : null}
          </section>
          <section style={{ border: "1px solid var(--il-rule)", borderRadius: "12px", background: "var(--il-panel)", overflow: "hidden" }}>
            <div style={{ padding: "12px 16px", borderBottom: "1px solid var(--il-rule)" }}>
              <h2 style={{ margin: "0", fontSize: "14px", fontWeight: "600" }}>
                Receipt log
              </h2>
            </div>
            {" "}
            {v.ops.log.map((it_l: (typeof v.ops.log)[number], i_l: number) => (
              <Fragment key={i_l}>
                <div style={{ display: "flex", justifyContent: "space-between", gap: "12px", padding: "8px 16px", borderBottom: "1px solid var(--il-rule)", fontSize: "12.5px" }}>
                  <span style={{ color: "var(--il-fg2)" }}>
                    <span className="sc-interp">{it_l.k}</span>
                  </span>
                  <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "11px", color: it_l.c, textAlign: "right", overflowWrap: "anywhere" }}>
                    <span className="sc-interp">{it_l.v}</span>
                  </span>
                </div>
              </Fragment>
            ))}
          </section>
        </div>
        <section style={{ border: "1px solid var(--il-rule)", borderRadius: "12px", background: "var(--il-panel)", overflow: "hidden" }}>
          <div style={{ padding: "12px 16px", borderBottom: "1px solid var(--il-rule)", display: "flex", alignItems: "center", gap: "10px", flexWrap: "wrap" }}>
            <h2 style={{ margin: "0", fontSize: "14px", fontWeight: "600" }}>
              MCP servers
            </h2>
            <span style={{ fontSize: "12px", color: "var(--il-dim)", flex: "1" }}>
              <span className="sc-interp">{v.ops.mcpLine}</span>
            </span>
            <a href="#/policy/starter" style={{ fontSize: "12.5px", fontWeight: "500", padding: "6px 11px", borderRadius: "7px", border: "1px solid var(--il-rule2)", color: "var(--il-fg)", textDecoration: "none" }}>
              Review starter policy
            </a>
          </div>
          {" "}
          {v.ops.cfgWarn.map((it_w: (typeof v.ops.cfgWarn)[number], i_w: number) => (
            <Fragment key={i_w}>
              <div role="alert" style={{ padding: "8px 16px", borderBottom: "1px solid var(--il-rule)", fontSize: "12.5px", color: "var(--il-rewrite)", background: "color-mix(in oklch,var(--il-rewrite) 7%,transparent)" }}>
                {"⚠ "}
                <code style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10.5px" }}>
                  <span className="sc-interp">{it_w.path}</span>
                </code>
                {" didn't parse ("}
                <span className="sc-interp">{it_w.why}</span>
                ). Servers in it are not listed.
              </div>
            </Fragment>
          ))}
          {" "}
          {v.ops.mcp.map((it_m: (typeof v.ops.mcp)[number], i_m: number) => (
            <Fragment key={i_m}>
              <div style={{ display: "grid", gridTemplateColumns: v.ops.mcpCols, gap: "6px 14px", alignItems: "start", padding: "11px 16px", borderBottom: "1px solid var(--il-rule)" }}>
                <div style={{ display: "flex", flexDirection: "column", gap: "2px", minWidth: "0" }}>
                  <strong style={{ fontFamily: "'Martian Mono',monospace", fontSize: "11.5px", fontWeight: "500" }}>
                    <span className="sc-interp">{it_m.name}</span>
                  </strong>
                  <span style={{ fontSize: "12px", color: "var(--il-fg2)" }}>
                    <span className="sc-interp">{it_m.client}</span>
                    {" · "}
                    <span className="sc-interp">{it_m.scope}</span>
                    {" · "}
                    <span className="sc-interp">{it_m.transport}</span>
                  </span>
                </div>
                <div style={{ display: "flex", flexDirection: "column", gap: "3px", minWidth: "0" }}>
                  <code style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10.5px", overflowWrap: "anywhere", color: "var(--il-fg)" }}>
                    <span className="sc-interp">{it_m.cmd}</span>
                  </code>
                  <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10px", color: "var(--il-dim)" }}>
                    <span className="sc-interp">{it_m.env}</span>
                  </span>
                </div>
                <div style={{ display: "flex", gap: "4px", flexWrap: "wrap" }}>
                  {it_m.risks.map((it_r: (typeof it_m.risks)[number], i_r: number) => (
                    <Fragment key={i_r}>
                      <span title={it_r.why} style={{ fontFamily: "'Martian Mono',monospace", fontSize: "9.5px", padding: "2px 7px", borderRadius: "4px", color: "var(--il-rewrite)", border: "1px solid color-mix(in oklch,var(--il-rewrite) 45%,transparent)", background: "color-mix(in oklch,var(--il-rewrite) 8%,transparent)" }}>
                        {"! "}
                        <span className="sc-interp">{it_r.tag}</span>
                      </span>
                    </Fragment>
                  ))}
                  {it_m.clean ? (
                    <>
                      <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "9.5px", color: "var(--il-dim)" }}>
                        no risk tags
                      </span>
                    </>
                  ) : null}
                </div>
              </div>
            </Fragment>
          ))}
        </section>
      </div>
    </>
  );
}
