// GENERATED from design/console/Interlock Console.dc.html by scripts/console_design/convert.py.
// Edit the view-model, not this markup: regenerate instead.
import type { Vals } from "../vals";

export function NotFoundScreen({ v }: { v: Vals }) {
  return (
    <>
      <div style={{ padding: "60px 28px", display: "flex", flexDirection: "column", gap: "10px", alignItems: "flex-start" }}>
        <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "11px", color: "var(--il-dim)" }}>
          #/
          <span className="sc-interp">{v.notFoundPath}</span>
        </span>
        <h2 style={{ margin: "0", fontSize: "20px", fontWeight: "600" }}>
          There's no page here
        </h2>
        <a href="#/">
          Go to Activity →
        </a>
      </div>
    </>
  );
}
