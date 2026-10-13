// GENERATED from design/console/Interlock Console.dc.html by scripts/console_design/convert.py.
// Edit the view-model, not this markup: regenerate instead.
import { Fragment } from "react";
import type { Vals } from "../vals";

export function KeysDialog({ v }: { v: Vals }) {
  return (
    <>
      <div onClick={v.closeKeys} style={{ position: "absolute", inset: "0", zIndex: "40", background: "rgba(0,0,0,.55)", display: "grid", placeItems: "center", padding: "20px" }}>
        <div role="dialog" aria-modal="true" aria-label="Keyboard shortcuts" style={{ width: "100%", maxWidth: "420px", background: "var(--il-panel)", border: "1px solid var(--il-rule2)", borderRadius: "14px", padding: "20px", display: "flex", flexDirection: "column", gap: "10px" }}>
          <h2 style={{ margin: "0 0 4px", fontSize: "16px", fontWeight: "600" }}>
            Keyboard
          </h2>
          {v.keymap.map((it_k: (typeof v.keymap)[number], i_k: number) => (
            <Fragment key={i_k}>
              <div style={{ display: "flex", justifyContent: "space-between", gap: "12px", fontSize: "13px", paddingTop: "7px", borderTop: "1px solid var(--il-rule)" }}>
                <span style={{ color: "var(--il-fg2)" }}>
                  <span className="sc-interp">{it_k.l}</span>
                </span>
                <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10.5px", padding: "1px 7px", border: "1px solid var(--il-rule2)", borderRadius: "4px" }}>
                  <span className="sc-interp">{it_k.k}</span>
                </span>
              </div>
            </Fragment>
          ))}
        </div>
      </div>
    </>
  );
}
