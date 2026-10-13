// GENERATED from design/console/Interlock Console.dc.html by scripts/console_design/convert.py.
// Edit the view-model, not this markup: regenerate instead.
import type { Vals } from "../vals";

export function UnlockDialog({ v }: { v: Vals }) {
  return (
    <>
      <div style={{ position: "absolute", inset: "0", zIndex: "40", background: "rgba(0,0,0,.55)", display: "grid", placeItems: "center", padding: "20px" }}>
        <div role="dialog" aria-modal="true" aria-label="Unlock writes" style={{ width: "100%", maxWidth: "520px", background: "var(--il-panel)", border: "1px solid var(--il-rule2)", borderRadius: "14px", padding: "22px", display: "flex", flexDirection: "column", gap: "14px", boxShadow: "0 30px 80px -20px rgba(0,0,0,.6)" }}>
          <h2 style={{ margin: "0", fontSize: "17px", fontWeight: "600" }}>
            Unlock writes
          </h2>
          <p style={{ margin: "0", fontSize: "13px", color: "var(--il-fg2)", textWrap: "pretty" }}>
            When the console started, it printed a one-time unlock link to its own terminal. Only that terminal has it, so an agent on this machine can't unlock writes for itself. Open the link, or paste it here.
          </p>
          <pre style={{ margin: "0", padding: "12px 14px", borderRadius: "8px", background: "var(--il-sunken)", border: "1px solid var(--il-rule)", fontFamily: "'Martian Mono',monospace", fontSize: "10.5px", lineHeight: "1.7", color: "var(--il-fg2)", whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>
            {"$ "}
            <span className="sc-interp">{v.unlockCmd}</span>
            {"\ninterlock console on "}
            <span className="sc-interp">{v.baseUrl}</span>
            {" (read-only)\nunlock writes: "}
            <span className="sc-interp">{v.baseUrl}</span>
            {"/#/unlock/"}
            <span style={{ color: "var(--il-acc)" }}>
              {"xxxx-xxxx-xxxx"}
            </span>
          </pre>
          <input value={v.unlockVal} onChange={v.onUnlockVal} placeholder="Paste the unlock link or code" aria-label="Unlock link or code" style={{ padding: "9px 11px", borderRadius: "8px", border: `1px solid ${v.unlockBc}`, background: "var(--il-sunken)", fontFamily: "'Martian Mono',monospace", fontSize: "11.5px" }} />
          {v.unlockErr ? (
            <>
              <span role="alert" style={{ fontSize: "12.5px", color: "var(--il-block)" }}>
                <span className="sc-interp">{v.unlockErr}</span>
              </span>
            </>
          ) : null}
          <div style={{ display: "flex", gap: "8px", justifyContent: "flex-end" }}>
            <button onClick={v.closeUnlock} style={{ fontSize: "13px", padding: "8px 14px", borderRadius: "7px", border: "1px solid var(--il-rule2)", background: "transparent", cursor: "pointer" }}>
              Stay read-only
            </button>
            <button onClick={v.doUnlock} style={{ fontSize: "13px", fontWeight: "600", padding: "8px 14px", borderRadius: "7px", border: "0", background: "var(--il-acc)", color: "var(--il-accfg)", cursor: "pointer" }}>
              Unlock
            </button>
          </div>
        </div>
      </div>
    </>
  );
}
