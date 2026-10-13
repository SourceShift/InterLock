// GENERATED from design/console/Interlock Console.dc.html by scripts/console_design/convert.py.
// Edit the view-model, not this markup: regenerate instead.
import { Fragment } from "react";
import type { Vals } from "../vals";

export function NavDrawer({ v }: { v: Vals }) {
  return (
    <>
      <div onClick={v.toggleNav} style={{ position: "absolute", inset: "0", zIndex: "30", background: "rgba(0,0,0,.45)" }}></div>
      <nav aria-label="Console" style={{ position: "absolute", zIndex: "31", left: "0", top: "0", bottom: "0", width: "260px", background: "var(--il-panel)", borderRight: "1px solid var(--il-rule)", padding: "16px 10px", display: "flex", flexDirection: "column", gap: "4px", overflow: "auto" }}>
        {v.drawerItems.map((it_d: (typeof v.drawerItems)[number], i_d: number) => (
          <Fragment key={i_d}>
            {it_d.group ? (
              <>
                <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "9.5px", letterSpacing: ".08em", textTransform: "uppercase", color: "var(--il-dim)", padding: "12px 10px 4px" }}>
                  <span className="sc-interp">{it_d.l}</span>
                </span>
              </>
            ) : null}
            {it_d.link ? (
              <>
                <a href={it_d.href} onClick={v.toggleNav} style={{ display: "flex", justifyContent: "space-between", padding: "8px 10px", borderRadius: "7px", textDecoration: "none", color: it_d.c, background: it_d.bg }}>
                  <span className="sc-interp">{it_d.l}</span>
                  <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10px", color: "var(--il-escalate)" }}>
                    <span className="sc-interp">{it_d.badge}</span>
                  </span>
                </a>
              </>
            ) : null}
          </Fragment>
        ))}
        <span style={{ marginTop: "auto", padding: "12px 10px 0", fontFamily: "'Martian Mono',monospace", fontSize: "10px", color: "var(--il-dim)", overflowWrap: "anywhere" }}>
          <span className="sc-interp">{v.logPath}</span>
        </span>
      </nav>
    </>
  );
}
