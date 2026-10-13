// GENERATED from design/console/Interlock Console.dc.html by scripts/console_design/convert.py.
// Edit the view-model, not this markup: regenerate instead.
import { Fragment } from "react";
import type { Vals } from "../vals";

export function CatalogScreen({ v }: { v: Vals }) {
  return (
    <>
      <div style={{ display: "flex", height: "100%" }}>
        {v.cat.showList ? (
          <>
            <div style={{ width: v.cat.listW, flex: "none", display: "flex", flexDirection: "column", borderRight: "1px solid var(--il-rule)", minHeight: "0" }}>
              <div style={{ flex: "none", padding: "12px 14px", display: "flex", flexDirection: "column", gap: "8px", borderBottom: "1px solid var(--il-rule)" }}>
                <input value={v.catQ} onChange={v.cat.onQ} placeholder="Search module, summary, factory…" data-testid="catalog-search" aria-label="Search detectors" style={{ fontSize: "13px", padding: "7px 10px", borderRadius: "7px", border: "1px solid var(--il-rule2)", background: "var(--il-panel)" }} />
                <div style={{ display: "flex", gap: "4px", flexWrap: "wrap" }}>
                  {v.cat.cats.map((it_c: (typeof v.cat.cats)[number], i_c: number) => (
                    <Fragment key={i_c}>
                      <button onClick={it_c.on} aria-pressed={it_c.sel} style={{ fontSize: "11.5px", padding: "3px 8px", borderRadius: "6px", border: `1px solid ${it_c.bc}`, background: it_c.bg, color: it_c.c, cursor: "pointer" }}>
                        <span className="sc-interp">{it_c.short}</span>
                        {" "}
                        <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "9.5px", color: "var(--il-dim)" }}>
                          <span className="sc-interp">{it_c.n}</span>
                        </span>
                      </button>
                    </Fragment>
                  ))}
                </div>
              </div>
              <div style={{ flex: "1", overflow: "auto" }}>
                {v.cat.none ? (
                  <>
                    <div style={{ padding: "28px 16px", display: "flex", flexDirection: "column", gap: "8px", alignItems: "flex-start", fontSize: "13px" }}>
                      <span>
                        No detector matches '
                        <span className="sc-interp">{v.catQ}</span>
                        '.
                      </span>
                      <button onClick={v.cat.clear} style={{ fontSize: "12px", padding: "4px 10px", borderRadius: "6px", border: "1px solid var(--il-rule2)", background: "transparent", cursor: "pointer" }}>
                        Clear search
                      </button>
                    </div>
                  </>
                ) : null}
                {" "}
                {v.cat.groups.map((it_g: (typeof v.cat.groups)[number], i_g: number) => (
                  <Fragment key={i_g}>
                    {" "}
                    <div data-testid="category-header" style={{ position: "sticky", top: "0", display: "flex", justifyContent: "space-between", padding: "8px 14px", background: "var(--il-bg)", borderBottom: "1px solid var(--il-rule)", fontFamily: "'Martian Mono',monospace", fontSize: "9.5px", letterSpacing: ".05em", textTransform: "uppercase", color: "var(--il-dim)" }}>
                      <span>
                        <span className="sc-interp">{it_g.label}</span>
                      </span>
                      <span>
                        <span className="sc-interp">{it_g.n}</span>
                      </span>
                    </div>
                    {" "}
                    {it_g.items.map((it_d: (typeof it_g.items)[number], i_d: number) => (
                      <Fragment key={i_d}>
                        <a href={it_d.href} data-testid="detector-row" style={{ display: "flex", flexDirection: "column", gap: "3px", padding: "9px 14px", borderBottom: "1px solid var(--il-rule)", textDecoration: "none", color: "var(--il-fg)", background: it_d.bg, borderLeft: `3px solid ${it_d.bar}` }} className="ilh-3">
                          <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "11px" }}>
                            <span className="sc-interp">{it_d.module}</span>
                          </span>
                          <span style={{ fontSize: "12px", color: "var(--il-fg2)" }}>
                            <span className="sc-interp">{it_d.summary}</span>
                          </span>
                        </a>
                      </Fragment>
                    ))}
                    {" "}
                  </Fragment>
                ))}
              </div>
            </div>
          </>
        ) : null}
        {v.cat.showDetail ? (
          <>
            <div style={{ flex: "1", minWidth: "0", overflow: "auto" }}>
              {v.cat.noSel ? (
                <>
                  <div style={{ padding: "48px 28px", fontSize: "13px", color: "var(--il-dim)" }}>
                    Pick a detector to see what it catches and how to configure it.
                  </div>
                </>
              ) : null}
              {" "}
              {v.cd.has ? (
                <>
                  {" "}
                  <div data-testid="detector-detail" style={{ padding: "20px 24px 40px", display: "flex", flexDirection: "column", gap: "16px", maxWidth: "820px" }}>
                    {v.narrow ? (
                      <>
                        <a href="#/catalog" style={{ fontSize: "12.5px", color: "var(--il-fg2)" }}>
                          ← All detectors
                        </a>
                      </>
                    ) : null}
                    <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                      <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10px", letterSpacing: ".05em", textTransform: "uppercase", color: "var(--il-dim)" }}>
                        <span className="sc-interp">{v.cd.catLabel}</span>
                      </span>
                      <h2 style={{ margin: "0", fontFamily: "'Martian Mono',monospace", fontSize: "17px", fontWeight: "500", overflowWrap: "anywhere" }}>
                        <span className="sc-interp">{v.cd.module}</span>
                      </h2>
                      <p style={{ margin: "0", fontSize: "14.5px", color: "var(--il-fg)", textWrap: "pretty" }}>
                        <span className="sc-interp">{v.cd.summary}</span>
                      </p>
                    </div>
                    <div style={{ display: "flex", gap: "6px", flexWrap: "wrap", alignItems: "center" }}>
                      <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10px", padding: "2px 7px", borderRadius: "5px", border: "1px solid var(--il-rule2)", color: "var(--il-fg2)" }}>
                        {"sees: "}
                        <span className="sc-interp">{v.cd.scope}</span>
                      </span>
                      {v.cd.verdicts.map((it_v: (typeof v.cd.verdicts)[number], i_v: number) => (
                        <Fragment key={i_v}>
                          <span style={{ display: "inline-flex", gap: "5px", fontFamily: "'Martian Mono',monospace", fontSize: "10px", padding: "2px 7px", borderRadius: "5px", color: it_v.c, background: it_v.bg, border: `1px solid ${it_v.bc}` }}>
                            <span className="sc-interp">{it_v.mark}</span>
                            {" "}
                            <span className="sc-interp">{it_v.word}</span>
                          </span>
                        </Fragment>
                      ))}
                      <span style={{ flex: "1" }}></span>
                      <a href={v.cd.tryHref} data-testid="try-in-playground" style={{ fontSize: "12.5px", fontWeight: "600", padding: "7px 12px", borderRadius: "7px", background: "var(--il-acc)", color: "var(--il-accfg)", textDecoration: "none" }}>
                        Try in playground →
                      </a>
                    </div>
                    {v.cd.factories.map((it_f: (typeof v.cd.factories)[number], i_f: number) => (
                      <Fragment key={i_f}>
                        <div style={{ border: "1px solid var(--il-rule)", borderRadius: "10px", overflow: "hidden", background: "var(--il-panel)" }}>
                          <code data-testid="factory-signature" style={{ display: "block", padding: "10px 12px", fontFamily: "'Martian Mono',monospace", fontSize: "11px", background: "var(--il-sunken)", borderBottom: "1px solid var(--il-rule)", overflowWrap: "anywhere" }}>
                            <span className="sc-interp">{it_f.sig}</span>
                          </code>
                          {" "}
                          {it_f.params.map((it_p: (typeof it_f.params)[number], i_p: number) => (
                            <Fragment key={i_p}>
                              <div style={{ display: "grid", gridTemplateColumns: "minmax(0,1fr) minmax(0,1fr) auto", gap: "10px", padding: "8px 12px", borderBottom: "1px solid var(--il-rule)", fontSize: "12px", alignItems: "baseline" }}>
                                <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "11px", overflowWrap: "anywhere" }}>
                                  <span className="sc-interp">{it_p.name}</span>
                                </span>
                                <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10.5px", color: "var(--il-fg2)" }}>
                                  <span className="sc-interp">{it_p.annotation}</span>
                                </span>
                                <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10px", color: it_p.c }}>
                                  <span className="sc-interp">{it_p.req}</span>
                                </span>
                              </div>
                            </Fragment>
                          ))}
                        </div>
                      </Fragment>
                    ))}
                    <div style={{ display: "flex", flexDirection: "column", gap: "10px", fontSize: "14px", lineHeight: "1.65", color: "var(--il-fg2)", maxWidth: "680px" }}>
                      {v.cd.doc.map((it_p: (typeof v.cd.doc)[number], i_p: number) => (
                        <Fragment key={i_p}>
                          {it_p.isP ? (
                            <>
                              <p style={{ margin: "0", textWrap: "pretty" }}>
                                <span className="sc-interp">{it_p.t}</span>
                              </p>
                            </>
                          ) : null}
                          {it_p.isCode ? (
                            <>
                              <pre style={{ margin: "0", padding: "10px 12px", borderRadius: "7px", background: "var(--il-sunken)", border: "1px solid var(--il-rule)", fontFamily: "'Martian Mono',monospace", fontSize: "11px", color: "var(--il-fg)", whiteSpace: "pre-wrap" }}>
                                <span className="sc-interp">{it_p.t}</span>
                              </pre>
                            </>
                          ) : null}
                          {it_p.isH ? (
                            <>
                              <h3 style={{ margin: "6px 0 0", fontSize: "13px", fontWeight: "600", color: "var(--il-fg)" }}>
                                <span className="sc-interp">{it_p.t}</span>
                              </h3>
                            </>
                          ) : null}
                        </Fragment>
                      ))}
                    </div>
                  </div>
                  {" "}
                </>
              ) : null}
            </div>
          </>
        ) : null}
      </div>
    </>
  );
}
