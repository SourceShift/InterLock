// GENERATED from design/console/Interlock Console.dc.html by scripts/console_design/convert.py.
// Edit the view-model, not this markup: regenerate instead.
import type { Vals } from "../vals";

export function SaveDialog({ v }: { v: Vals }) {
  return (
    <>
      <div style={{ position: "absolute", inset: "0", zIndex: "40", background: "rgba(0,0,0,.55)", display: "grid", placeItems: "center", padding: "20px" }}>
        <div role="dialog" aria-modal="true" aria-label="Save policy" style={{ width: "100%", maxWidth: "520px", background: "var(--il-panel)", border: "1px solid var(--il-rule2)", borderRadius: "14px", padding: "22px", display: "flex", flexDirection: "column", gap: "14px" }}>
          <h2 style={{ margin: "0", fontSize: "17px", fontWeight: "600" }}>
            Save policy and change the epoch?
          </h2>
          <div style={{ display: "flex", alignItems: "center", gap: "10px", fontFamily: "'Martian Mono',monospace", fontSize: "12px" }}>
            <span style={{ padding: "3px 8px", borderRadius: "5px", background: "var(--il-raised)", textDecoration: "line-through", color: "var(--il-dim)" }}>
              <span className="sc-interp">{v.epoch}</span>
            </span>
            <span>
              →
            </span>
            <span style={{ padding: "3px 8px", borderRadius: "5px", background: "color-mix(in oklch,var(--il-acc) 16%,transparent)", color: "var(--il-acc)" }}>
              <span className="sc-interp">{v.draftEpoch}</span>
            </span>
          </div>
          <p style={{ margin: "0", fontSize: "13.5px", color: "var(--il-fg)", textWrap: "pretty" }}>
            {"A new epoch voids every outstanding approval. "}
            <strong>
              <span className="sc-interp">{v.voidLine}</span>
            </strong>
            {" The agent will have to ask again."}
          </p>
          <p style={{ margin: "0", fontSize: "12.5px", color: "var(--il-fg2)" }}>
            {"This replaces "}
            <code style={{ fontFamily: "'Martian Mono',monospace", fontSize: "11px" }}>
              <span className="sc-interp">{v.pol.path}</span>
            </code>
            . Hooks read the file on every call, so the change applies to the next call.
          </p>
          <div style={{ display: "flex", gap: "8px", justifyContent: "flex-end" }}>
            <button onClick={v.closeSave} style={{ fontSize: "13px", padding: "8px 14px", borderRadius: "7px", border: "1px solid var(--il-rule2)", background: "transparent", cursor: "pointer" }}>
              Keep editing
            </button>
            <button onClick={v.doSave} style={{ fontSize: "13px", fontWeight: "600", padding: "8px 14px", borderRadius: "7px", border: "0", background: "var(--il-acc)", color: "var(--il-accfg)", cursor: "pointer" }}>
              Save and void approvals
            </button>
          </div>
        </div>
      </div>
    </>
  );
}
