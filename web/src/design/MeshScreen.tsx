// GENERATED from design/console/Interlock Console.dc.html by scripts/console_design/convert.py.
// Edit the view-model, not this markup: regenerate instead.
import type { Vals } from "../vals";

export function MeshScreen({ v }: { v: Vals }) {
  return (
    <>
      <div style={{ padding: "18px 18px 40px", display: "flex", flexDirection: "column", gap: "16px", maxWidth: "1180px" }}>
        {v.extras.mesh}
      </div>
    </>
  );
}
