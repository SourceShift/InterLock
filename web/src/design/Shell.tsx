// GENERATED from design/console/Interlock Console.dc.html by scripts/console_design/convert.py.
// Edit the view-model, not this markup: regenerate instead.
import type { Vals } from "../vals";
import { ActivityScreen } from "./ActivityScreen";
import { AuditScreen } from "./AuditScreen";
import { CatalogScreen } from "./CatalogScreen";
import { InspectorScreen } from "./InspectorScreen";
import { KeysDialog } from "./KeysDialog";
import { MeshScreen } from "./MeshScreen";
import { NavDrawer } from "./NavDrawer";
import { NotFoundScreen } from "./NotFoundScreen";
import { OpsScreen } from "./OpsScreen";
import { PlaygroundScreen } from "./PlaygroundScreen";
import { PolicyScreen } from "./PolicyScreen";
import { ReviewsScreen } from "./ReviewsScreen";
import { SaveDialog } from "./SaveDialog";
import { UnlockDialog } from "./UnlockDialog";

export function Shell({ v }: { v: Vals }) {
  return (
    <>
    <div style={{ height: "100vh", display: "flex", justifyContent: "center", background: "var(--il-sunken)", color: "var(--il-fg)", fontFamily: "'Instrument Sans',system-ui,sans-serif", fontSize: "14px", lineHeight: "1.5" }}>
      <div ref={v.rootRef} style={{ position: "relative", width: "100%", maxWidth: v.frameMax, height: "100%", display: "flex", background: "var(--il-bg)", overflow: "hidden", borderLeft: v.frameBorder, borderRight: v.frameBorder }}>
        {v.wide ? (
          <>
            <aside style={{ width: "228px", flex: "none", display: "flex", flexDirection: "column", borderRight: "1px solid var(--il-rule)", background: "var(--il-panel)" }}>
              <a href="#/" style={{ display: "flex", alignItems: "center", gap: "10px", padding: "16px 18px 18px", color: "var(--il-fg)", textDecoration: "none" }}>
                <svg width="26" height="22" viewBox="0 0 28 24" fill="none" aria-hidden="true">
                  <rect x="2" y="2" width="15" height="15" rx="4" stroke="var(--il-acc)" strokeWidth="2.4"></rect>
                  <rect x="11" y="7" width="15" height="15" rx="4" stroke="var(--il-panel)" strokeWidth="6"></rect>
                  <rect x="11" y="7" width="15" height="15" rx="4" stroke="var(--il-fg)" strokeWidth="2.4"></rect>
                  <line x1="17" y1="4.6" x2="17" y2="9.4" stroke="var(--il-panel)" strokeWidth="6"></line>
                  <line x1="17" y1="4" x2="17" y2="10" stroke="var(--il-acc)" strokeWidth="2.4"></line>
                </svg>
                <span style={{ fontWeight: "600", fontSize: "16px", letterSpacing: "-.01em" }}>
                  interlock
                </span>
                <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "9.5px", color: "var(--il-dim)", border: "1px solid var(--il-rule2)", borderRadius: "4px", padding: "1px 5px" }}>
                  console
                </span>
              </a>
              <nav aria-label="Console" style={{ flex: "1", overflow: "auto", padding: "0 10px", display: "flex", flexDirection: "column", gap: "18px" }}>
                <div style={{ display: "flex", flexDirection: "column", gap: "2px" }}>
                  <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "9.5px", letterSpacing: ".08em", textTransform: "uppercase", color: "var(--il-dim)", padding: "0 10px 6px" }}>
                    Monitor
                  </span>
                  <a href="#/" data-testid="nav-activity" style={{ display: "flex", alignItems: "center", gap: "10px", padding: "7px 10px", borderRadius: "7px", textDecoration: "none", color: v.nav.activity.c, background: v.nav.activity.bg }} className="ilh-3">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                      <path d="M22 12h-4l-3 9L9 3l-3 9H2"></path>
                    </svg>
                    <span style={{ flex: "1" }}>
                      Activity
                    </span>
                  </a>
                  <a href="#/reviews" data-testid="nav-reviews" style={{ display: "flex", alignItems: "center", gap: "10px", padding: "7px 10px", borderRadius: "7px", textDecoration: "none", color: v.nav.reviews.c, background: v.nav.reviews.bg }} className="ilh-3">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                      <path d="M22 12h-6l-2 3h-4l-2-3H2"></path>
                      <path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"></path>
                    </svg>
                    <span style={{ flex: "1" }}>
                      Reviews
                    </span>
                    {v.hasPending ? (
                      <>
                        <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10px", fontWeight: "500", minWidth: "20px", textAlign: "center", padding: "1px 6px", borderRadius: "999px", background: "var(--il-escalate)", color: "var(--il-bg)" }}>
                          <span className="sc-interp">{v.pendingCount}</span>
                        </span>
                      </>
                    ) : null}
                  </a>
                  <a href="#/audit" data-testid="nav-audit" style={{ display: "flex", alignItems: "center", gap: "10px", padding: "7px 10px", borderRadius: "7px", textDecoration: "none", color: v.nav.audit.c, background: v.nav.audit.bg }} className="ilh-3">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                      <path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"></path>
                    </svg>
                    <span style={{ flex: "1" }}>
                      Audit log
                    </span>
                  </a>
                </div>
                <div style={{ display: "flex", flexDirection: "column", gap: "2px" }}>
                  <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "9.5px", letterSpacing: ".08em", textTransform: "uppercase", color: "var(--il-dim)", padding: "0 10px 6px" }}>
                    Author
                  </span>
                  <a href="#/policy" data-testid="nav-policy" style={{ display: "flex", alignItems: "center", gap: "10px", padding: "7px 10px", borderRadius: "7px", textDecoration: "none", color: v.nav.policy.c, background: v.nav.policy.bg }} className="ilh-3">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                      <path d="M8 3H7a2 2 0 0 0-2 2v5a2 2 0 0 1-2 2 2 2 0 0 1 2 2v5c0 1.1.9 2 2 2h1"></path>
                      <path d="M16 21h1a2 2 0 0 0 2-2v-5c0-1.1.9-2 2-2a2 2 0 0 1-2-2V5a2 2 0 0 0-2-2h-1"></path>
                    </svg>
                    <span style={{ flex: "1" }}>
                      Policy
                    </span>
                    {v.policyQuarantined ? (
                      <>
                        <span title="quarantined rules" style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10px", color: "var(--il-rewrite)" }}>
                          ~
                          <span className="sc-interp">{v.quarCount}</span>
                        </span>
                      </>
                    ) : null}
                  </a>
                  <a href="#/playground" data-testid="nav-playground" style={{ display: "flex", alignItems: "center", gap: "10px", padding: "7px 10px", borderRadius: "7px", textDecoration: "none", color: v.nav.playground.c, background: v.nav.playground.bg }} className="ilh-3">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                      <path d="M9 3h6"></path>
                      <path d="M10 3v6L4.2 18.6A1 1 0 0 0 5.1 20h13.8a1 1 0 0 0 .9-1.4L14 9V3"></path>
                      <path d="M7 15h10"></path>
                    </svg>
                    <span style={{ flex: "1" }}>
                      Playground
                    </span>
                  </a>
                  <a href="#/catalog" data-testid="nav-catalog" style={{ display: "flex", alignItems: "center", gap: "10px", padding: "7px 10px", borderRadius: "7px", textDecoration: "none", color: v.nav.catalog.c, background: v.nav.catalog.bg }} className="ilh-3">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                      <circle cx="11" cy="11" r="8"></circle>
                      <path d="m21 21-4.3-4.3"></path>
                      <path d="m9 9-2 2 2 2"></path>
                      <path d="m13 13 2-2-2-2"></path>
                    </svg>
                    <span style={{ flex: "1" }}>
                      Detectors
                    </span>
                    <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10px", color: "var(--il-dim)" }}>
                      <span className="sc-interp">{v.detCount}</span>
                    </span>
                  </a>
                  <a href="#/inspector" data-testid="nav-inspector" style={{ display: "flex", alignItems: "center", gap: "10px", padding: "7px 10px", borderRadius: "7px", textDecoration: "none", color: v.nav.inspector.c, background: v.nav.inspector.bg }} className="ilh-3">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                      <path d="M21 8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16Z"></path>
                      <path d="m3.3 7 8.7 5 8.7-5"></path>
                      <path d="M12 22V12"></path>
                    </svg>
                    <span style={{ flex: "1" }}>
                      {"Scopes & sandbox"}
                    </span>
                  </a>
                </div>
                <div style={{ display: "flex", flexDirection: "column", gap: "2px" }}>
                  <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "9.5px", letterSpacing: ".08em", textTransform: "uppercase", color: "var(--il-dim)", padding: "0 10px 6px" }}>
                    Operate
                  </span>
                  <a href="#/ops" data-testid="nav-ops" style={{ display: "flex", alignItems: "center", gap: "10px", padding: "7px 10px", borderRadius: "7px", textDecoration: "none", color: v.nav.ops.c, background: v.nav.ops.bg }} className="ilh-3">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                      <path d="m12 14 4-4"></path>
                      <path d="M3.34 19a10 10 0 1 1 17.32 0"></path>
                    </svg>
                    <span style={{ flex: "1" }}>
                      Ops
                    </span>
                    <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10px", color: v.posture.c }}>
                      <span className="sc-interp">{v.posture.mark}</span>
                    </span>
                  </a>
                  <a href="#/mesh" data-testid="nav-mesh" style={{ display: "flex", alignItems: "center", gap: "10px", padding: "7px 10px", borderRadius: "7px", textDecoration: "none", color: v.nav.mesh.c, background: v.nav.mesh.bg }} className="ilh-3">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                      <path d="M12 3v6"></path>
                      <path d="M12 15v6"></path>
                      <path d="M3 12h6"></path>
                      <path d="M15 12h6"></path>
                      <circle cx="12" cy="12" r="3"></circle>
                    </svg>
                    <span style={{ flex: "1" }}>
                      Mesh
                    </span>
                    <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10px", color: v.posture.c }}>
                      <span className="sc-interp">{v.posture.mark}</span>
                    </span>
                  </a>
                </div>
              </nav>
              <div style={{ padding: "14px 18px 16px", borderTop: "1px solid var(--il-rule)", display: "flex", flexDirection: "column", gap: "6px", fontFamily: "'Martian Mono',monospace", fontSize: "10px", color: "var(--il-dim)" }}>
                <span style={{ textTransform: "uppercase", letterSpacing: ".06em", fontSize: "9.5px" }}>
                  Receipt log
                </span>
                <span style={{ color: "var(--il-fg2)", overflowWrap: "anywhere" }}>
                  <span className="sc-interp">{v.logPath}</span>
                </span>
                <span data-testid="health-status" style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                  <span style={{ width: "6px", height: "6px", borderRadius: "50%", background: v.conn.c }}></span>
                  <span className="sc-interp">{v.conn.short}</span>
                </span>
              </div>
            </aside>
          </>
        ) : null}
        <div style={{ flex: "1", minWidth: "0", display: "flex", flexDirection: "column" }}>
          <header style={{ flex: "none", display: "flex", alignItems: "center", gap: "10px", padding: "10px 18px", borderBottom: "1px solid var(--il-rule)", background: "var(--il-bg)", flexWrap: "wrap", minHeight: "56px" }}>
            {v.narrow ? (
              <>
                <button onClick={v.toggleNav} aria-label="Menu" style={{ width: "34px", height: "34px", display: "grid", placeItems: "center", borderRadius: "7px", border: "1px solid var(--il-rule2)", background: "transparent", cursor: "pointer" }}>
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden="true">
                    <path d="M4 6h16M4 12h16M4 18h16"></path>
                  </svg>
                </button>
              </>
            ) : null}
            <div style={{ flex: "1", minWidth: "0", display: "flex", alignItems: "baseline", gap: "10px" }}>
              <h1 style={{ margin: "0", fontSize: "17px", fontWeight: "600", letterSpacing: "-.01em", whiteSpace: "nowrap" }}>
                <span className="sc-interp">{v.pageTitle}</span>
              </h1>
              <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10px", color: "var(--il-dim)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                <span className="sc-interp">{v.pageSub}</span>
              </span>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: "6px", flexWrap: "wrap" }}>
              <a href="#/ops" title="Protection posture from interlock doctor" style={{ display: "inline-flex", alignItems: "center", gap: "7px", padding: "5px 10px", borderRadius: "7px", border: `1px solid ${v.posture.bc}`, background: v.posture.bg, color: v.posture.c, fontFamily: "'Martian Mono',monospace", fontSize: "10.5px", textDecoration: "none" }}>
                <span aria-hidden="true">
                  <span className="sc-interp">{v.posture.mark}</span>
                </span>
                <span className="sc-interp">{v.posture.word}</span>
              </a>
              <a href="#/reviews" title="Reviews waiting on you" style={{ display: "inline-flex", alignItems: "center", gap: "7px", padding: "5px 10px", borderRadius: "7px", border: `1px solid ${v.pendPill.bc}`, background: v.pendPill.bg, color: v.pendPill.c, fontFamily: "'Martian Mono',monospace", fontSize: "10.5px", textDecoration: "none" }}>
                <span aria-hidden="true">
                  ‖
                </span>
                <span className="sc-interp">{v.pendPill.label}</span>
              </a>
              <button onClick={v.lockClick} title={v.lockPill.title} data-testid="shell-lock" style={{ display: "inline-flex", alignItems: "center", gap: "7px", padding: "5px 10px", borderRadius: "7px", border: `1px solid ${v.lockPill.bc}`, background: v.lockPill.bg, color: v.lockPill.c, fontFamily: "'Martian Mono',monospace", fontSize: "10.5px", cursor: "pointer" }}>
                {v.locked ? (
                  <>
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                      <path d="m10 10-6.157 6.162a2 2 0 0 0-.5.833l-1.322 4.36a.5.5 0 0 0 .622.624l4.358-1.323a2 2 0 0 0 .83-.5L14 13.982"></path>
                      <path d="m12.829 7.172 4.359-4.346a1 1 0 1 1 3.986 3.986l-4.353 4.353"></path>
                      <path d="m2 2 20 20"></path>
                    </svg>
                  </>
                ) : null}
                {v.unlocked ? (
                  <>
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                      <path d="M17 3a2.85 2.83 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5Z"></path>
                    </svg>
                  </>
                ) : null}
                {" "}
                <span className="sc-interp">{v.lockPill.label}</span>
              </button>
              <button onClick={v.toggleTheme} aria-label="Toggle light and dark" title="Toggle light and dark" style={{ width: "30px", height: "30px", display: "grid", placeItems: "center", borderRadius: "7px", border: "1px solid var(--il-rule2)", background: "transparent", cursor: "pointer", color: "var(--il-fg2)" }}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden="true">
                  <circle cx="12" cy="12" r="4"></circle>
                  <path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"></path>
                </svg>
              </button>
            </div>
          </header>
          {v.unlocked ? (
            <>
              <div role="status" style={{ flex: "none", display: "flex", alignItems: "center", gap: "12px", padding: "7px 18px", background: "repeating-linear-gradient(-45deg,color-mix(in oklch,var(--il-acc) 16%,transparent) 0 8px,color-mix(in oklch,var(--il-acc) 9%,transparent) 8px 16px)", borderBottom: "1px solid color-mix(in oklch,var(--il-acc) 45%,transparent)", fontSize: "12.5px" }}>
                <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10.5px", color: "var(--il-acc)", fontWeight: "500" }}>
                  WRITES UNLOCKED
                </span>
                <span style={{ flex: "1", color: "var(--il-fg2)", minWidth: "0" }}>
                  Approvals, policy saves and trust changes are live for this tab until you re-lock or the console restarts.
                </span>
                <button onClick={v.relock} style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10.5px", padding: "4px 10px", borderRadius: "6px", border: "1px solid var(--il-acc)", background: "transparent", color: "var(--il-acc)", cursor: "pointer" }}>
                  Re-lock
                </button>
              </div>
            </>
          ) : null}
          {v.conn.down ? (
            <>
              <div role="alert" style={{ flex: "none", display: "flex", alignItems: "center", gap: "12px", padding: "9px 18px", background: "color-mix(in oklch,var(--il-block) 12%,var(--il-bg))", borderBottom: "1px solid color-mix(in oklch,var(--il-block) 45%,transparent)", fontSize: "13px", flexWrap: "wrap" }}>
                <span style={{ fontFamily: "'Martian Mono',monospace", fontSize: "10.5px", color: "var(--il-block)" }}>
                  ✗ CONSOLE STOPPED
                </span>
                <span style={{ flex: "1", minWidth: "220px", color: "var(--il-fg2)" }}>
                  {"The console process isn't answering. What you see is the last data it sent, marked stale. Restart it with "}
                  <code style={{ fontFamily: "'Martian Mono',monospace", fontSize: "11px", color: "var(--il-fg)" }}>
                    python3 -m interlock.console
                  </code>
                  . Retrying every 5 s.
                </span>
              </div>
            </>
          ) : null}
          <main style={{ flex: "1", minHeight: "0", overflow: "auto", opacity: v.staleOpacity }}>
            {v.is.activity ? <ActivityScreen v={v} /> : null}
            {" "}
            {v.is.reviews ? <ReviewsScreen v={v} /> : null}
            {" "}
            {v.is.audit ? <AuditScreen v={v} /> : null}
            {" "}
            {v.is.policy ? <PolicyScreen v={v} /> : null}
            {" "}
            {v.is.playground ? <PlaygroundScreen v={v} /> : null}
            {" "}
            {v.is.catalog ? <CatalogScreen v={v} /> : null}
            {" "}
            {v.is.inspector ? <InspectorScreen v={v} /> : null}
            {" "}
            {v.is.ops ? <OpsScreen v={v} /> : null}
            {" "}
            {v.is.mesh ? <MeshScreen v={v} /> : null}
            {" "}
            {v.is.notfound ? <NotFoundScreen v={v} /> : null}
          </main>
        </div>
        {v.navOpen ? <NavDrawer v={v} /> : null}
        {v.unlockOpen ? <UnlockDialog v={v} /> : null}
        {v.keysOpen ? <KeysDialog v={v} /> : null}
        {v.saveOpen ? <SaveDialog v={v} /> : null}
      </div>
    </div>
    </>
  );
}
