/**
 * The view-model: every value the designed screens bind to, computed from the
 * person's `State` and the server's `Data`. A port of the design prototype's
 * own render logic, fed by real API responses instead of its mock data. The
 * generated markup in `design/` reads nothing else, so TypeScript checks every
 * binding in it against what this returns.
 */
import type { PolicyRule, ReadableReceipt, Review, VerifyResponse } from "./api";
import {
  V,
  ago,
  chip,
  docBlocks,
  duration,
  faint,
  fmtDT,
  fmtT,
  hm,
  left,
  muted,
  num,
  prettyAnn,
  shortDefault,
  signature,
  tilde,
  tone,
  vk,
  type VerdictKey,
} from "./format";
import { renderExtras } from "./extras";
import type { Data, State } from "./model";

/**
 * Where a rule value in a receipt or review should link.
 *
 * A receipt's `policy_id` is the id the deciding rule reported, which is not the
 * policy screen's rule id: the coding-agent rules are detector rules that stamp
 * their own `POLICY_ID` (`tool_result_injection`), while the policy screen lists
 * the rule id (`result-injection`). The detector catalog carries the stamped id,
 * so resolve it to the module and link to that detector's detail page. An id the
 * catalog does not know - a plain intent rule like `force-push`, whose id the
 * policy screen does list - keeps the old `#/policy` target instead of a link to
 * nowhere.
 */
export function ruleDetailHref(D: Data, policyId: string | null | undefined): string {
  if (!policyId) return "";
  const detector = (D.catalog?.detectors ?? []).find((d) => d.policy_id === policyId);
  return detector ? "#/catalog/" + detector.module : "#/policy";
}

export interface Actions {
  set(patch: Partial<State>): void;
  rootRef(el: HTMLDivElement | null): void;
  setWin(win: State["win"]): void;
  focusBucket(index: number | null): void;
  setFilter(f: { vf?: string; rf?: string }): void;
  setQuery(q: string): void;
  loadMore(): void;
  clearFilters(): void;
  openReceipt(index: number): void;
  closeReceipt(): void;
  toggleLive(): void;
  decide(kind: "approve" | "reject" | "revoke"): void;
  doUnlock(): void;
  lockClick(): void;
  relock(): void;
  toggleTheme(): void;
  copy(key: string, text: string): void;
  setPolicyText(text: string): void;
  checkDraft(): void;
  saveDraft(): void;
  setPreset(id: string): void;
  updPg(fn: (pg: State["pg"]) => void): void;
  runPg(): void;
  resolveScope(): void;
  // real data
  loadRealCalls(): void;
  setRealFilter(f: { q?: string; tool?: string }): void;
  toggleRealCall(callId: string): void;
  addRealCalls(replace: boolean): void;
  openInPlayground(o: { calls: { call_id: string; session?: string | null; ts?: number }[]; module?: string; factory?: string }): void;
  runBacktest(): void;
  runSweep(): void;
}

const WIN_LABEL = { "30m": "last 30 minutes", "24h": "last 24 hours", "7d": "last 7 days" } as const;
const CATS: Record<string, [string, string]> = {
  "Prompt injection and jailbreaks": ["Prompt injection and jailbreaks", "Injection"],
  "Secrets and personal data": ["Secrets and personal data", "Secrets"],
  "Classic injection in arguments": ["Classic injection in arguments", "Arguments"],
  "Code execution and host access": ["Code execution and host access", "Host"],
  "MCP servers and tools": ["MCP servers and tools", "MCP"],
  "Data leaving the system": ["Data leaving the system", "Egress"],
  "Budgets, rate limits, and loops": ["Budgets, rate limits and loops", "Budgets"],
  "Provenance stamps": ["Provenance stamps", "Provenance"],
  "Tool allow and deny lists": ["Tool allow/deny lists", "Lists"],
  "Agent-to-agent (A2A)": ["Agent-to-agent (A2A)", "A2A"],
};
const PROFILE_TOKENS: Record<string, string | null> = {
  read_paths: "fs-ro",
  write_paths: "fs-rw",
  allow_network: "net",
  allowed_hosts: "net",
  env_keys: "env",
  cpu_seconds: "rlimit",
  memory_mb: "rlimit",
  unshare_pid: "pid",
  workdir: null,
};
const TOKEN_MEANING: Record<string, string> = {
  "fs-ro": "read-only paths",
  "fs-rw": "write paths",
  net: "the network rules",
  env: "the environment allowlist",
  pid: "PID isolation",
  rlimit: "CPU and memory limits",
};

const ms = (seconds: number | null | undefined) => (seconds ? seconds * 1000 : 0);
const readable = (r: { unreadable?: boolean }): r is ReadableReceipt => !r.unreadable;

export interface ChainVals {
  c: string;
  bg: string;
  bc: string;
  bs: string;
  mark: string;
  word: string;
  line: string;
  broken: boolean;
  notBroken: boolean;
  brokenAt: string;
  problem: string;
}

/**
 * The chain badge, plus the underlying server status (`ck`).
 *
 * `verifyStale` means a receipt has arrived since the last successful verify,
 * so an `intact` answer no longer describes the bytes on disk. It must never
 * read "verified" then: the stale variant says the log changed since the last
 * check. A broken chain still wins, and no answer at all keeps checking.
 */
export function chainVals(
  verify: VerifyResponse | null,
  verifyStale: boolean,
  receiptsMissing: boolean,
): { ck: string; chain: ChainVals } {
  const problemText = verify?.problem ? verify.problem.replace(/^receipt \d+:\s*/, "") : "";
  const brokenAt = verify?.broken_index != null
    ? num(verify.broken_index)
    : verify?.problem ? (/^receipt (\d+)/.exec(verify.problem)?.[1] ?? "?") : "?";
  const ck = receiptsMissing ? "unverified" : !verify ? "checking" : verify.status === "intact" ? "verified" : verify.status;
  const shown = ck === "verified" && verifyStale ? "stale" : ck;
  const base: Record<string, Omit<ChainVals, "broken" | "notBroken" | "brokenAt" | "problem">> = {
    verified: { ...tone("var(--il-allow)"), mark: "✓", word: "verified", bs: "solid", line: "Every receipt is signed and linked. Nothing was edited, deleted or reordered." },
    stale: {
      ...tone("var(--il-rewrite)"), mark: "!", word: "changed since last check", bs: "solid",
      line: "A receipt arrived after the last verification. Re-checking the chain now; until it finishes, the badge describes the log as it was.",
    },
    unverified: {
      c: "var(--il-fg2)", bg: "transparent", bc: "var(--il-rule2)", bs: "dashed", mark: "?", word: "unverified",
      line: receiptsMissing ? "No receipt log: the console was started without --receipts." : "Can't tell: the console was started without --key-file.",
    },
    broken: { ...tone("var(--il-block)"), mark: "✗", word: "broken", bs: "solid", line: "Broken at receipt #" + brokenAt + ": " + problemText + "." },
    checking: { c: "var(--il-fg2)", bg: "transparent", bc: "var(--il-rule2)", bs: "dashed", mark: "…", word: "checking", line: "Verifying the receipt chain…" },
  };
  const chain: ChainVals = {
    ...base[shown],
    broken: ck === "broken",
    notBroken: ck !== "broken",
    brokenAt,
    problem: problemText ? problemText.charAt(0).toUpperCase() + problemText.slice(1) + "." : "",
  };
  return { ck, chain };
}

export function computeVals(S: State, D: Data, A: Actions) {
  const route = S.route;
  const path = route.path;
  const home = D.session?.home;
  const narrow = S.w < 760;
  const wide = !narrow;
  const known = ["activity", "reviews", "audit", "policy", "playground", "catalog", "inspector", "ops"] as const;
  const is = {
    activity: path === "activity",
    reviews: path === "reviews",
    audit: path === "audit",
    policy: path === "policy",
    playground: path === "playground",
    catalog: path === "catalog",
    inspector: path === "inspector",
    ops: path === "ops",
    notfound: !(known as readonly string[]).includes(path) && path !== "unlock",
  };
  const navOf = (k: string) => ({ c: path === k ? "var(--il-fg)" : "var(--il-fg2)", bg: path === k ? "var(--il-sel)" : "transparent" });
  const nav = {
    activity: navOf("activity"), reviews: navOf("reviews"), audit: navOf("audit"), policy: navOf("policy"),
    playground: navOf("playground"), catalog: navOf("catalog"), inspector: navOf("inspector"), ops: navOf("ops"),
  };
  const titles: Record<string, string> = {
    activity: "Activity", reviews: "Reviews", audit: "Audit log", policy: "Policy", playground: "Playground",
    catalog: "Detectors", inspector: "Scopes & sandbox", ops: "Ops", unlock: "Activity",
  };
  const baseUrl = window.location.origin;
  const connDown = D.connDown;
  const conn = connDown
    ? { c: "var(--il-block)", short: "console unreachable", down: true }
    : { c: "var(--il-allow)", short: "api ok · v" + (D.session?.version ?? "…") + " · " + window.location.host, down: false };
  const receiptsMissing = !!D.session && !D.session.receipts_path;
  const pendingList = D.reviews.filter((r) => r.status === "pending").sort((a, b) => a.pending_until - b.pending_until);
  const pendingCount = pendingList.length;

  // --- posture (doctor) and chain (verify) ----------------------------------------
  const doc = D.doctor;
  const warnN = doc ? doc.checks.filter((c) => c.status === "warn").length : 0;
  const failN = doc ? doc.checks.filter((c) => c.status === "fail").length : 0;
  const posture = !doc
    ? { ...muted, mark: "…", word: "checking", line: "Running interlock doctor…" }
    : {
        enforced: { ...tone("var(--il-allow)"), mark: "✓", word: "enforced", line: "Every check passed. Calls are being ruled on." },
        degraded: {
          ...tone("var(--il-rewrite)"), mark: "!", word: "degraded",
          line: warnN + (warnN === 1 ? " setting weakens" : " settings weaken") + " protection. See the fix in Ops.",
        },
        unprotected: {
          ...tone("var(--il-block)"), mark: "✗", word: "unprotected",
          line: failN + (failN === 1 ? " check" : " checks") + " failed: calls may not be guarded.",
        },
      }[doc.level];
  const { ck, chain } = chainVals(D.verify, S.verifyStale, receiptsMissing);

  const pendPill = pendingCount
    ? { ...tone("var(--il-escalate)"), label: pendingCount + " waiting" }
    : { c: "var(--il-fg2)", bg: "transparent", bc: "var(--il-rule2)", label: "0 waiting" };
  const locked = !D.session || D.session.locked;
  const lockPill = locked
    ? { c: "var(--il-fg2)", bg: "transparent", bc: "var(--il-rule2)", label: "read-only", title: "Writes are locked. Click to unlock." }
    : { ...tone("var(--il-acc)"), label: "writes on", title: "Writes are unlocked. Click to re-lock." };

  // --- live tail ------------------------------------------------------------------
  const tailK = connDown ? "disconnected" : !S.live ? "paused" : S.tail === "paused" ? "live" : S.tail;
  const tail = {
    live: { c: "var(--il-allow)", bc: "color-mix(in oklch, var(--il-allow) 40%, transparent)", label: "live", anim: "il-blink 1.6s ease-in-out infinite", note: "" },
    paused: {
      c: "var(--il-fg2)", bc: "var(--il-rule2)", label: "paused" + (S.pausedNew ? " · " + S.pausedNew + " new" : ""), anim: "none",
      note: S.pausedNew ? S.pausedNew + " receipts arrived while paused. Resume to show them." : "",
    },
    connecting: { c: "var(--il-rewrite)", bc: "color-mix(in oklch, var(--il-rewrite) 40%, transparent)", label: "connecting…", anim: "il-blink .8s ease-in-out infinite", note: "" },
    disconnected: {
      c: "var(--il-block)", bc: "color-mix(in oklch, var(--il-block) 45%, transparent)", label: "disconnected · retrying", anim: "il-blink 1.2s ease-in-out infinite",
      note: "The live stream dropped. Rows below are what arrived before it did. The browser reconnects on its own; you will see \"live\" again when it does.",
    },
    reset: {
      c: "var(--il-rewrite)", bc: "color-mix(in oklch, var(--il-rewrite) 45%, transparent)", label: "log reset", anim: "none",
      note: "The receipt log was truncated or rotated, so the list was reloaded from the start. If nobody rotated it on purpose, check the chain: this can also mean tampering.",
    },
  }[tailK];

  const act = activityVals(S, D, A, { pendingList, posture, ck, chain, tailK, wide, roomy: wide && S.w >= 1100 });
  const rev = reviewVals(S, D, A, { locked, wide, me: D.session?.me ?? "you", pendingCount });
  const aud = auditVals(S, D, A, { wide, receiptsMissing });
  const more = moreVals(S, D, A, { wide, locked, home });

  const detCount = D.catalog?.count ?? 0;
  const policyQuarantined = !!(D.policy?.analysis.ok && D.policy.analysis.quarantined.length);
  const quarCount = D.policy?.analysis.ok ? D.policy.analysis.quarantined.length : 0;
  const drawerItems = [
    { group: true, l: "Monitor" },
    ["activity", "#/", "Activity"],
    ["reviews", "#/reviews", "Reviews", pendingCount ? "‖ " + pendingCount : ""],
    ["audit", "#/audit", "Audit log"],
    { group: true, l: "Author" },
    ["policy", "#/policy", "Policy"],
    ["playground", "#/playground", "Playground"],
    ["catalog", "#/catalog", "Detectors"],
    ["inspector", "#/inspector", "Scopes & sandbox"],
    { group: true, l: "Operate" },
    ["ops", "#/ops", "Ops"],
  ].map((d) =>
    Array.isArray(d)
      ? { link: true, group: false, href: d[1], l: d[2], badge: d[3] || "", c: path === d[0] ? "var(--il-fg)" : "var(--il-fg2)", bg: path === d[0] ? "var(--il-sel)" : "transparent" }
      : { ...d, link: false },
  );
  const subs: Record<string, string> = {
    activity: act.hasData ? WIN_LABEL[S.win] : "",
    reviews: pendingCount + " pending",
    audit: num(D.receiptsAll) + " receipts",
    policy: tilde(D.policy?.path ?? D.session?.policy_path, home),
    playground: "detector rules only",
    catalog: D.catalog ? D.catalog.count + " detectors · " + D.catalog.categories.length + " categories" : "",
    inspector: "computes the plan, never runs it",
    ops: "doctor · hooks · MCP · sidecar",
  };

  return {
    ...more,
    rootRef: A.rootRef,
    wide, narrow, frameMax: "100%", frameBorder: "0",
    act, is, nav, conn, posture, chain, pendingCount, hasPending: pendingCount > 0, pendPill,
    locked, unlocked: !locked, lockPill, lockedOpacity: locked ? 0.45 : 1,
    pageTitle: titles[path] || "Not found", pageSub: subs[path] || "",
    logPath: receiptsMissing ? "none: started without --receipts" : tilde(D.session?.receipts_path, home) || "…",
    staleOpacity: connDown ? 0.6 : 1,
    receiptsMissing, receiptsOk: !receiptsMissing,
    widen: () => A.setWin("7d"),
    ...rev,
    ...aud,
    tail,
    drawerItems, navOpen: S.navOpen && narrow, toggleNav: () => A.set({ navOpen: !S.navOpen }),
    unlockOpen: S.unlockOpen, unlockVal: S.unlockVal, unlockErr: S.unlockErr,
    unlockBc: S.unlockErr ? "var(--il-block)" : "var(--il-rule2)",
    unlockCmd: "python3 -m interlock.console" + (D.session?.receipts_path ? " --receipts " + tilde(D.session.receipts_path, home) : ""),
    baseUrl,
    onUnlockVal: (e: { target: { value: string } }) => A.set({ unlockVal: e.target.value, unlockErr: "" }),
    openUnlock: () => A.set({ unlockOpen: true }),
    closeUnlock: () => A.set({ unlockOpen: false, unlockVal: "", unlockErr: "" }),
    doUnlock: A.doUnlock, lockClick: A.lockClick, relock: A.relock, toggleTheme: A.toggleTheme,
    keysOpen: S.keysOpen, openKeys: () => A.set({ keysOpen: true }), closeKeys: () => A.set({ keysOpen: false }),
    keymap: [
      { l: "Next review", k: "j / ↓" }, { l: "Previous review", k: "k / ↑" }, { l: "Approve", k: "a" },
      { l: "Reject (focus reason, then confirm)", k: "r" }, { l: "Close dialog", k: "Esc" }, { l: "This list", k: "?" },
    ],
    saveOpen: S.saveOpen,
    epoch: D.policy?.analysis.ok ? D.policy.analysis.epoch : "—",
    policyQuarantined, quarCount, detCount,
    extras: renderExtras(S, D, A),
  };
}

export type Vals = ReturnType<typeof computeVals>;

// --- Activity --------------------------------------------------------------------------

interface ActivityCtx {
  pendingList: Review[];
  posture: { c: string; bc: string };
  ck: string;
  chain: { word: string };
  tailK: string;
  wide: boolean;
  roomy: boolean;
}

function activityVals(S: State, D: Data, A: Actions, c: ActivityCtx) {
  const now = S.now;
  const win = S.win;
  const data = D.activity;
  const B = data?.timeline ?? [];
  const nB = B.length;
  const tot = (b: (typeof B)[number]) => b.ALLOW + b.MODIFY + b.BLOCK;
  const max = Math.max(1, ...B.map(tot));
  const fv = S.focusV;
  const sel = S.selB != null && S.selB < nB ? B[S.selB] : null;
  const dayN = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
  const lab = (b: (typeof B)[number]) =>
    win === "7d"
      ? dayN[new Date(ms(b.from)).getDay()] + " " + hm(ms(b.from)) + "–" + hm(ms(b.to))
      : hm(ms(b.from)) + "–" + hm(ms(b.to));
  const segOp = (k: string) => (!fv ? 1 : fv === k ? 1 : 0.14);
  const VKS = ["ALLOW", "MODIFY", "BLOCK"] as const;
  const hov = S.hovB != null && S.hovB < nB ? B[S.hovB] : null;
  const bars = B.map((b, i) => {
    const t = tot(b);
    return {
      h: (t / max) * 100, minH: t ? "3px" : "0", op: 1, esc: b.ESC > 0, escOp: !fv || fv === "ESCALATE" ? 1 : 0.25,
      segs: VKS.filter((k) => b[k]).map((k) => ({ n: b[k], c: V[k].c, op: fv === "ESCALATE" ? 0.22 : segOp(k) })),
      bg: sel && S.selB === i ? "color-mix(in oklch, var(--il-acc) 14%, transparent)" : hov && S.hovB === i ? "var(--il-hover)" : "transparent",
      outline: sel && S.selB === i ? "1px solid color-mix(in oklch, var(--il-acc) 55%, transparent)" : "none",
      aria: lab(b) + ": " + t + " decisions, " + b.BLOCK + " blocked, " + b.MODIFY + " rewritten, " + b.ESC + " escalated",
      enter: () => A.set({ hovB: i }),
      click: () => A.focusBucket(S.selB === i ? null : i),
    };
  });
  const every = { "30m": 5, "24h": 4, "7d": 4 }[win];
  const xlabels = B.map((b, i) =>
    i % every === 0 ? (win === "7d" ? dayN[new Date(ms(b.from)).getDay()] + " " + hm(ms(b.from)) : hm(ms(b.from))) : "",
  );
  const rp = (sel && D.focusAct ? D.focusAct.summary : data?.summary) ?? null;
  const decN = rp?.decisions || 1;
  const kpis = [
    { n: num(rp?.decisions ?? 0), l: "decisions", c: "var(--il-fg)" },
    { n: (((rp?.verdicts.BLOCK ?? 0) / decN) * 100).toFixed(1) + "%", l: "block rate", c: "var(--il-block)" },
    { n: num(rp?.escalated ?? 0), l: "escalated", c: "var(--il-escalate)" },
    { n: num(rp?.sessions ?? 0), l: "sessions", c: "var(--il-fg)" },
    { n: num(rp?.principals ?? 0), l: "principals", c: "var(--il-fg)" },
  ];
  const counts: [VerdictKey, number][] = [
    ["ALLOW", rp?.verdicts.ALLOW ?? 0], ["MODIFY", rp?.verdicts.MODIFY ?? 0], ["BLOCK", rp?.verdicts.BLOCK ?? 0], ["ESCALATE", rp?.escalated ?? 0],
  ];
  const legend = counts.map(([k, n]) => {
    const m = V[k];
    const on = fv === k;
    return {
      mark: m.mark, word: k === "ESCALATE" ? "escalated" : m.word, n: num(n), pct: k === "ESCALATE" ? "" : ((n / decN) * 100).toFixed(1) + "%",
      sel: on, c: m.c, bg: on ? "color-mix(in oklch, " + m.c + " 16%, transparent)" : "transparent",
      bc: on ? m.c : "color-mix(in oklch, " + m.c + " 32%, transparent)", op: fv && !on ? 0.55 : 1,
      on: () => A.set({ focusV: on ? null : k }),
    };
  });
  const winLabel = WIN_LABEL[win];
  const hoverLine = hov
    ? lab(hov) + " · " + tot(hov) + " decisions · ✓ " + hov.ALLOW + "  ~ " + hov.MODIFY + "  ✗ " + hov.BLOCK + (hov.ESC ? "  ‖ " + hov.ESC : "") + " · click to focus"
    : "Hover a bar for detail, click to focus the page on that slot.";
  // live stream: the newest decisions, oldest on the left
  const recent = data?.recent ?? [];
  const tk = S.hovR != null ? recent.find((r) => r.index === S.hovR) : null;
  const ticks = recent.map((r, i) => {
    const esc = r.policy_verdict === "ESCALATE";
    const k = esc ? "ESCALATE" : r.verdict;
    const col = esc ? V.ESCALATE.c : V[vk(r.verdict)].c;
    const isLast = i === recent.length - 1;
    const dim = fv && fv !== k;
    return {
      href: "#/audit?r=" + r.index,
      h: r.verdict === "BLOCK" ? "100%" : esc ? "88%" : r.verdict === "MODIFY" ? "74%" : "46%",
      bg: r.observed ? "transparent" : col, bs: r.observed ? "dashed" : "solid", c: col,
      op: dim ? 0.15 : r.verdict === "ALLOW" && !r.observed ? 0.55 : 1,
      glow: isLast ? "0 0 0 2px var(--il-bg), 0 0 0 3px " + col : "none",
      aria: fmtT(ms(r.ts)) + " " + r.action + " " + (r.observed ? "would " : "") + V[vk(r.verdict)].word,
      enter: () => A.set({ hovR: r.index }),
    };
  });
  const newest = recent[recent.length - 1];
  const tickLine = tk
    ? fmtT(ms(tk.ts)) + " · " + tk.action + " · " + (tk.observed ? "would " : "") + V[vk(tk.verdict)].word + (tk.policy_id ? " · " + tk.policy_id : "") + " · " + (tk.principal ?? "")
    : newest ? "newest: " + newest.action + " · " + ago(now - ms(newest.ts)) : "";
  // rules
  const rulesAll = (rp?.rules ?? [])
    .map((o) => ({ ...o, fc: fv ? o.verdicts[fv] || 0 : o.count }))
    .filter((o) => o.fc > 0)
    .sort((a, b) => b.fc - a.fc)
    .slice(0, 6);
  const rmax = Math.max(1, ...rulesAll.map((o) => o.count));
  const rules = rulesAll.map((o) => ({
    id: o.id, count: num(fv ? o.fc : o.count), w: (o.count / rmax) * 100,
    href: "#/audit?policy=" + encodeURIComponent(o.id) + (fv ? "&verdict=" + fv : ""),
    segs: Object.entries(o.verdicts).map(([k, n]) => ({ n, c: V[vk(k)].c, op: fv && fv !== k ? 0.18 : 1 })),
  }));
  const blocked = (rp?.blocked ?? []).slice(0, 6).map((b) => ({
    action: b.action, count: b.count, href: "#/audit?verdict=BLOCK&q=" + encodeURIComponent(b.action),
  }));
  const would = (rp?.would ?? []).map((w) => ({
    rule: w.rule, action: w.action, v: chip(w.verdict, true), count: w.count,
    href: "#/audit?verdict=OBSERVED&policy=" + encodeURIComponent(w.rule),
  }));
  const escList: [string, string, string][] = [
    ["approved:once", "approved once", "var(--il-allow)"],
    ["approved:session", "approved for the session", "var(--il-allow)"],
    ["reused:session", "reused an approval", "var(--il-allow)"],
    ["declined", "declined", "var(--il-block)"],
    ["no-approver", "no approver available", "var(--il-rewrite)"],
  ];
  const escs = rp?.escalations ?? {};
  const MORE: Record<string, [string, string]> = {
    "approved:review": ["approved through a review", "var(--il-allow)"],
    "approved:ttl": ["approved for a while", "var(--il-allow)"],
    "reused:ttl": ["reused a timed approval", "var(--il-allow)"],
    pending: ["held for a review", "var(--il-escalate)"],
    delegated: ["asked in the agent's own prompt", "var(--il-fg2)"],
    "approver-error": ["approver failed", "var(--il-block)"],
  };
  for (const k of Object.keys(escs)) {
    if (!escList.some(([key]) => key === k)) {
      const [label, col] = MORE[k] ?? [k.replace(":", " · "), "var(--il-fg2)"];
      escList.push([k, label, col]);
    }
  }
  const emax = Math.max(1, ...escList.map(([k]) => escs[k] || 0));
  const esc = escList.map(([k, l, col]) => ({ l, n: escs[k] || 0, w: ((escs[k] || 0) / emax) * 100, c: col }));
  // latency
  const lat = rp?.latency;
  const lmax = Math.max(1, lat?.max ?? 1);
  const histRaw = lat?.hist ?? [];
  const hmax = Math.max(1, ...histRaw);
  const NB = histRaw.length || 24;
  const hist = histRaw.map((n, i) => ({
    h: (n / hmax) * 100,
    t: Math.round((i / NB) * lmax) + "–" + Math.round(((i + 1) / NB) * lmax) + " µs: " + n,
  }));
  const marks: { k: string; c: string; x: number }[] = lat && lat.samples
    ? ([["p50", lat.p50, "var(--il-fg2)"], ["p95", lat.p95, "var(--il-rewrite)"], ["p99", lat.p99, "var(--il-block)"]] as const).map(
        ([k, v, col]) => ({ k, c: col, x: Math.min(97, (v / lmax) * 100) }),
      )
    : [];
  // waiting on you
  const pend = c.pendingList.slice(0, 3).map((r) => {
    const leftMs = Math.max(0, ms(r.pending_until) - now);
    const totT = Math.max(1, ms(r.pending_until) - ms(r.created));
    const frac = leftMs / totT;
    const soon = leftMs < 15 * 60e3;
    const mm = Math.floor(leftMs / 60e3);
    return {
      href: "#/reviews/" + r.id, action: r.action, reason: r.reason ?? "", principal: r.principal ?? "",
      left: left(leftMs), short: mm >= 60 ? Math.floor(mm / 60) + "h" : mm + "m",
      off: (113.1 * (1 - frac)).toFixed(2), ringC: soon ? "var(--il-rewrite)" : "var(--il-escalate)",
      multi: r.min_approvals > 1, approvals: r.approvers.length + " of " + r.min_approvals,
    };
  });
  const pc = c.pendingList.length;
  const lastTs = data?.last_ts ? ms(data.last_ts) : 0;
  const inWin = data?.summary.receipts ?? 0;
  return {
    hasData: !!data && inWin > 0,
    bandC: c.posture.c, waitGlow: pc ? 12 : 0,
    waitPhrase: pc ? (pc === 1 ? "1 call is waiting on you" : pc + " calls are waiting on you") : "Nothing is waiting on you",
    waitC: pc ? "var(--il-escalate)" : "var(--il-allow)",
    waitBc: pc ? "color-mix(in oklch, var(--il-escalate) 50%, transparent)" : "color-mix(in oklch, var(--il-allow) 50%, transparent)",
    waitPanelBc: pc ? "color-mix(in oklch, var(--il-escalate) 40%, transparent)" : "var(--il-rule)",
    waitPanelBg: pc ? "linear-gradient(180deg, color-mix(in oklch, var(--il-escalate) 7%, var(--il-panel)), var(--il-panel) 40%)" : "var(--il-panel)",
    liveLine: (c.tailK === "live" ? "live" : c.tailK) + (lastTs ? " · last decision " + ago(now - lastTs) : ""),
    winOpts: (["30m", "24h", "7d"] as const).map((w) => ({
      l: w, sel: win === w, bg: win === w ? "var(--il-sel)" : "transparent", c: win === w ? "var(--il-fg)" : "var(--il-fg2)",
      on: () => A.setWin(w),
    })),
    mainCols: c.roomy ? "minmax(0,2.1fr) minmax(300px,1fr)" : "minmax(0,1fr)",
    scopeLine: (sel ? lab(sel) : winLabel) + (c.ck !== "verified" && c.ck !== "checking" ? " · from an " + c.chain.word + " log" : ""),
    kpis, legend, hasSel: !!sel, selLabel: sel ? "focused on " + lab(sel) : "", clearSel: () => A.focusBucket(null),
    hoverLine, maxLabel: "peak " + max + " / slot", bars, xlabels, leaveB: () => A.set({ hovB: null }),
    chartAria: "Decisions per time slot, " + winLabel,
    ticks, tickCount: recent.length, tickLine, leaveT: () => A.set({ hovR: null }),
    rules, noRules: rules.length === 0,
    rulesNote: fv ? "showing " + (fv === "ESCALATE" ? "escalated" : V[vk(fv)].word) + " only" : "top rules",
    focusWord: fv ? (fv === "ESCALATE" ? "escalated" : V[vk(fv)].word) : "",
    blocked, noBlocked: blocked.length === 0, would, noWould: would.length === 0, esc,
    hist, marks, latN: num(lat?.samples ?? 0),
    lat: (["p50", "p90", "p95", "p99", "max"] as const).map((k) => ({ k, v: lat ? lat[k] : 0 })),
    problems: [
      { l: "failed after allow", n: rp?.failed ?? 0, c: rp?.failed ? "var(--il-rewrite)" : "var(--il-fg)", href: "#/audit" },
      { l: "unreadable", n: data?.unreadable ?? 0, c: data?.unreadable ? "var(--il-rewrite)" : "var(--il-fg)", href: "#/audit" },
      { l: "dropped", n: rp?.dropped ?? 0, c: rp?.dropped ? "var(--il-rewrite)" : "var(--il-fg)", href: "#/ops" },
    ],
    masked: Object.entries(rp?.masked ?? {}).length ? Object.entries(rp?.masked ?? {}).map(([l, n]) => ({ l, n })) : [{ l: "none", n: 0 }],
    pend, noPending: pend.length === 0,
    empty: !!data && inWin === 0, winLabel,
    lastSeen: lastTs ? "The last receipt was " + ago(now - lastTs) + "." : "There are no receipts in the log at all.",
  };
}

// --- Reviews ---------------------------------------------------------------------------

function reviewVals(S: State, D: Data, A: Actions, c: { locked: boolean; wide: boolean; me: string; pendingCount: number }) {
  const now = S.now;
  const route = S.route;
  const tab = S.revTab;
  const all = D.reviews;
  let list = all.filter((r) =>
    tab === "pending" ? r.status === "pending" : tab === "approved" ? r.status === "approved" : !["pending", "approved"].includes(r.status),
  );
  if (tab === "pending") list = list.slice().sort((a, b) => a.pending_until - b.pending_until);
  const rid = route.path === "reviews" ? route.id : null;
  const counts = {
    pending: c.pendingCount,
    approved: all.filter((r) => r.status === "approved").length,
    history: all.filter((r) => !["pending", "approved"].includes(r.status)).length,
  };
  const revTabs = ([["pending", "Pending"], ["approved", "Awaiting retry"], ["history", "History"]] as const).map(([k, l]) => ({
    l, n: counts[k], sel: tab === k, bg: tab === k ? "var(--il-sel)" : "transparent", c: tab === k ? "var(--il-fg)" : "var(--il-fg2)",
    on: () => A.set({ revTab: k, flash: "" }),
  }));
  const stMeta = {
    pending: { ...tone("var(--il-escalate)"), mark: "‖", word: "pending" },
    approved: { ...tone("var(--il-allow)"), mark: "✓", word: "approved · awaiting retry" },
    executed: { ...tone("var(--il-allow)"), mark: "✓", word: "executed" },
    rejected: { ...tone("var(--il-block)"), mark: "✗", word: "rejected" },
    expired: { ...muted, mark: "◷", word: "expired" },
    revoked: { ...muted, mark: "↺", word: "revoked" },
  };
  const revList = list.map((r) => {
    const msLeft = r.status === "pending" ? ms(r.pending_until) - now : r.status === "approved" ? ms(r.approval_until) - now : null;
    return {
      href: "#/reviews/" + r.id, sel: r.id === rid, bg: r.id === rid ? "var(--il-sel)" : "transparent",
      bar: r.id === rid ? "var(--il-escalate)" : "transparent", action: r.action, reason: r.reason ?? "", rule: r.policy_id ?? "",
      principal: r.principal ?? "", multi: r.min_approvals > 1 && r.status === "pending",
      approvalsTxt: r.approvers.length + " of " + r.min_approvals,
      clock: msLeft !== null ? left(msLeft) : ago(now - ms(r.decided || r.executed || r.pending_until)),
      clockC: msLeft !== null && msLeft < 15 * 60e3 ? "var(--il-rewrite)" : "var(--il-dim)",
      statusTag: tab === "history" ? r.status : "", statusC: stMeta[r.status].c,
    };
  });
  const R = all.find((x) => x.id === rid);
  let rv: ReviewVM = EMPTY_REVIEW;
  if (R) {
    const four = !R.self_ok && R.requester === c.me && R.status === "pending";
    const mine = R.approvers.includes(c.me);
    const preview = R.preview ? prettyPreview(R.preview) : "(no preview stored)";
    const pendingHours = Math.round((ms(R.pending_until) - ms(R.created)) / 3600e3);
    // The rule links to its detector's detail page when one exists. `plain` has
    // to track `href`: the renderer shows the link OR the plain text, never both,
    // so a `plain: false` with an empty href would draw nothing at all.
    const ruleLink = ruleDetailHref(D, R.policy_id);
    rv = {
      has: true, id: R.id, action: R.action, phase: R.phase, reason: R.reason ?? "", rule: R.policy_id ?? "",
      st: stMeta[R.status], preview, previewLen: num((R.preview ?? "").length) + " of 4,000 chars", digest: R.args_digest ?? "",
      meta: [
        { k: "rule", v: R.policy_id ?? "—", href: ruleLink, plain: !ruleLink, c: "var(--il-fg)" },
        { k: "principal", v: R.principal ?? "—", href: "", plain: true, c: "var(--il-fg)" },
        { k: "requester", v: (R.requester ?? "—") + (R.requester === c.me ? " (you)" : ""), href: "", plain: true, c: "var(--il-fg)" },
        { k: "filed", v: ago(now - ms(R.created)), href: "", plain: true, c: "var(--il-fg)" },
        R.status === "pending"
          ? { k: "expires in", v: left(ms(R.pending_until) - now), href: "", plain: true, c: ms(R.pending_until) - now < 15 * 60e3 ? "var(--il-rewrite)" : "var(--il-fg)" }
          : { k: "decided", v: R.decided ? ago(now - ms(R.decided)) + " by " + R.decided_by : "never", href: "", plain: true, c: "var(--il-fg)" },
        { k: "approvals", v: R.approvers.length + " of " + R.min_approvals + (R.approvers.length ? " · " + R.approvers.join(", ") : ""), href: "", plain: true, c: "var(--il-fg)" },
      ],
      multi: R.min_approvals > 1,
      approvalsTxt: R.approvers.length + " of " + R.min_approvals + " approvals" + (R.approvers.length ? " · " + R.approvers.join(", ") : ""),
      slots: Array.from({ length: R.min_approvals }, (_, i) => ({ c: i < R.approvers.length ? "var(--il-allow)" : "var(--il-rule2)" })),
      showLocked: c.locked && (R.status === "pending" || R.status === "approved"), showFourEyes: four,
      showPendingActions: R.status === "pending", showApproved: R.status === "approved",
      showDone: !["pending", "approved"].includes(R.status),
      approveDisabled: c.locked || four || mine || !!S.busy, approveOpacity: c.locked || four || mine ? 0.4 : 1,
      approveLabel: S.busy === "approve" ? "Approving…" : mine ? "You approved" : "Approve",
      rejectDisabled: c.locked || !!S.busy, rejectOpacity: c.locked ? 0.4 : 1, rejectLabel: S.busy === "reject" ? "Rejecting…" : "Reject",
      hint: c.locked ? "Unlock writes to decide." : four ? "Approval needs a second person."
        : R.min_approvals > 1 ? "Needs " + (R.min_approvals - R.approvers.length) + " more approval to release." : "Approving lets the identical retry through once.",
      retryClock: R.approval_until ? left(ms(R.approval_until) - now) : "",
      revokeLabel: S.busy === "revoke" ? "Revoking…" : "Revoke approval",
      doneLine: ({
        executed: "Executed " + (R.executed ? ago(now - ms(R.executed)) : "") + ". The agent retried the identical call and it went through once. Approved by " + (R.decided_by ?? "—") + ".",
        rejected: "Rejected by " + (R.decided_by ?? "—") + " " + (R.decided ? ago(now - ms(R.decided)) : "") + '. The agent was told: "' + (R.rejection_reason ?? "") + '"',
        expired: "Expired: nobody decided within " + (pendingHours === 1 ? "an hour" : pendingHours + " hours") + ". The agent was told to stop.",
        revoked: R.decided_by === "epoch change"
          ? "Revoked by a policy change: the approval was bound to the old epoch, so it could never match."
          : "Revoked by " + (R.decided_by ?? "—") + " before the agent used it.",
      } as Record<string, string>)[R.status] || "",
      auditHref: "#/audit?policy=" + encodeURIComponent(R.policy_id ?? "") + "&q=" + encodeURIComponent(R.action),
    };
  }
  const empty = revList.length === 0;
  return {
    revTabs, revList, rv, me: c.me, rejectReason: S.rejectReason, flash: S.flash,
    revEmpty: empty,
    revEmptyTitle: !D.reviewsConfigured && tab === "pending" ? "Nothing is waiting on you" : tab === "pending" ? "Nothing is waiting on you" : tab === "approved" ? "No approvals waiting to be used" : "No history yet",
    revEmptyLine: tab === "pending"
      ? "When a rule holds a call for a human, it shows up here with a countdown. Recent decisions are under History."
      : tab === "approved" ? "Approved calls wait here until the agent retries them or the 15 minutes run out."
      : "Rejected, revoked, expired and executed reviews appear here.",
    revShowList: c.wide || !R, revShowDetail: c.wide || !!R, revNoSel: !R, listW: c.wide ? "360px" : "100%",
    onReject: (e: { target: { value: string } }) => A.set({ rejectReason: e.target.value }),
    approve: () => A.decide("approve"), reject: () => A.decide("reject"), revoke: () => A.decide("revoke"),
  };
}

const EMPTY_REVIEW: ReviewVM = {
  has: false, id: "", action: "", phase: "", reason: "", rule: "", st: { ...muted, mark: "", word: "" }, preview: "", previewLen: "",
  digest: "", meta: [], multi: false, approvalsTxt: "", slots: [], showLocked: false, showFourEyes: false, showPendingActions: false,
  showApproved: false, showDone: false, approveDisabled: true, approveOpacity: 0.4, approveLabel: "", rejectDisabled: true,
  rejectOpacity: 0.4, rejectLabel: "", hint: "", retryClock: "", revokeLabel: "", doneLine: "", auditHref: "",
};

/** The view of one review; `has` false means nothing is selected. */
export interface ReviewVM {
  has: boolean;
  id: string;
  action: string;
  phase: string;
  reason: string;
  rule: string;
  st: { c: string; bg: string; bc: string; mark: string; word: string };
  preview: string;
  previewLen: string;
  digest: string;
  meta: { k: string; v: string; href: string; plain: boolean; c: string }[];
  multi: boolean;
  approvalsTxt: string;
  slots: { c: string }[];
  showLocked: boolean;
  showFourEyes: boolean;
  showPendingActions: boolean;
  showApproved: boolean;
  showDone: boolean;
  approveDisabled: boolean;
  approveOpacity: number;
  approveLabel: string;
  rejectDisabled: boolean;
  rejectOpacity: number;
  rejectLabel: string;
  hint: string;
  retryClock: string;
  revokeLabel: string;
  doneLine: string;
  auditHref: string;
}

function prettyPreview(preview: string): string {
  try {
    return JSON.stringify(JSON.parse(preview), null, 2);
  } catch {
    return preview;
  }
}

// --- Audit -------------------------------------------------------------------------------

function auditVals(S: State, D: Data, A: Actions, c: { wide: boolean; receiptsMissing: boolean }) {
  const route = S.route;
  const vfOpts = ([
    ["all", "all", "", null], ["ALLOW", "allow", "✓", "ALLOW"], ["MODIFY", "rewrite", "~", "MODIFY"], ["BLOCK", "block", "✗", "BLOCK"],
    ["ESCALATE", "escalate", "‖", "ESCALATE"], ["OBSERVED", "observed", "◌", null],
  ] as const).map(([k, l, mark, key]) => {
    const sel = S.vf === k;
    const col = key ? V[key].c : "var(--il-fg2)";
    return {
      l, mark, sel, c: sel ? (key ? col : "var(--il-fg)") : "var(--il-fg2)",
      bg: sel ? (key ? "color-mix(in oklch, " + col + " 14%, transparent)" : "var(--il-sel)") : "transparent",
      bc: sel ? (key ? "color-mix(in oklch, " + col + " 45%, transparent)" : "var(--il-rule2)") : "var(--il-rule)",
      bs: k === "OBSERVED" ? "dashed" : "solid", on: () => A.setFilter({ vf: k }),
    };
  });
  const ruleOpts = [{ v: "all", l: "any rule" }, ...D.receiptRules.map((id) => ({ v: id, l: id }))];
  const selIdx = route.path === "audit" && route.q.r ? Number(route.q.r) : null;
  const rows = D.receipts.map((r) =>
    !readable(r)
      ? { unreadable: true, readable: false, index: r.index, time: "—", bg: "color-mix(in oklch, var(--il-rewrite) 6%, transparent)", on: () => A.openReceipt(r.index), v: chip("ALLOW"), tid: "verdict-badge", esc: false, action: "", phaseTag: "", rule: "", principal: "", el: "" }
      : {
          readable: true, unreadable: false, index: r.index, time: fmtT(ms(r.ts)), v: chip(r.verdict, !!r.observed),
          tid: r.observed ? "observed-marker" : "verdict-badge", esc: r.policy_verdict === "ESCALATE", action: r.action,
          phaseTag: r.phase !== "call" ? " · " + r.phase : "", rule: r.policy_id || "—", principal: r.principal ?? "—",
          el: r.elapsed_us != null ? r.elapsed_us + " µs" : "—",
          bg: r.index === selIdx ? "var(--il-sel)" : "transparent",
          on: () => A.openReceipt(r.index),
        },
  );
  const filtering = S.vf !== "all" || S.rf !== "all" || !!S.q.trim();
  const aud = {
    has: rows.length > 0, emptyLog: !c.receiptsMissing && D.receiptsLoaded && D.receiptsAll === 0,
    filteredEmpty: D.receiptsAll > 0 && D.receiptsLoaded && D.receiptsTotal === 0 && filtering,
    rows, total: num(D.receiptsAll), shownTxt: num(rows.length), matchTxt: num(D.receiptsTotal), totalTxt: num(D.receiptsAll),
    more: D.receiptsTotal > rows.length,
  };
  const sr = selIdx !== null
    ? (D.receipts.find((r) => r.index === selIdx) ?? (D.selReceipt && D.selReceipt.index === selIdx ? D.selReceipt : null))
    : null;
  let rc: ReceiptVM = EMPTY_RECEIPT;
  if (sr && readable(sr)) {
    const story: ReceiptVM["story"] = sr.policy_verdict
      ? [
          { ...chip(sr.policy_verdict), word: "policy: " + V[vk(sr.policy_verdict)].word, arrow: true },
          { mark: "•", word: sr.approval ?? "—", c: "var(--il-fg2)", bg: "transparent", bc: "var(--il-rule2)", bs: "solid", arrow: true },
          { ...chip(sr.verdict), word: "enforced: " + V[vk(sr.verdict)].word, arrow: false },
        ]
      : [{ ...chip(sr.verdict, !!sr.observed), arrow: false }];
    const reviewFor = D.reviews.find((x) => x.args_digest === sr.args_digest && x.action === sr.action && x.policy_id === sr.policy_id);
    const currentEpoch = D.policy?.analysis.ok ? D.policy.analysis.epoch : null;
    const F = (k: string, v: unknown, o: { mono?: boolean; c?: string; href?: string } = {}) => ({
      k, v: v === null || v === undefined || v === "" ? "—" : String(v),
      ff: o.mono ? "'Martian Mono', monospace" : "inherit", fs: o.mono ? "11px" : "12.5px", c: o.c || "var(--il-fg)",
      href: o.href || "", plain: !o.href,
    });
    const fields = [
      F("time", fmtDT(ms(sr.ts))), F("phase", sr.phase, { mono: true }),
      F("rule", sr.policy_id, { mono: true, href: ruleDetailHref(D, sr.policy_id) }), F("blamed arg", sr.attributed_to, { mono: true }),
      F("principal", sr.principal, { mono: true }),
      F("session", sr.span_id, { mono: true, href: sr.span_id ? "#/audit?q=" + encodeURIComponent(sr.span_id) : "" }),
      F("call_id", sr.call_id, { mono: true }),
      F("epoch", sr.policy_epoch, { mono: true, c: sr.policy_epoch && sr.policy_epoch === currentEpoch ? "var(--il-fg)" : "var(--il-dim)" }),
      F("enforcer", sr.enforcer, { mono: true }), F("outcome", sr.outcome, { mono: true, c: sr.outcome ? "var(--il-rewrite)" : "var(--il-fg)" }),
      F("eval time", sr.elapsed_us != null ? sr.elapsed_us + " µs" : null, { mono: true }),
      F("masked", sr.masked ? Object.entries(sr.masked).map(([k, v]) => k + " × " + v).join(", ") : null, { mono: true }),
      F("observed", sr.observed ? "yes: monitor mode, not enforced" : "no"),
    ];
    if (sr.policy_verdict === "ESCALATE" && reviewFor) fields.push(F("review", reviewFor.id, { mono: true, href: "#/reviews/" + reviewFor.id }));
    fields.push(F("prev", sr.prev.slice(0, 16) + "…", { mono: true, c: "var(--il-dim)" }), F("mac", sr.mac.slice(0, 16) + "…", { mono: true, c: "var(--il-dim)" }));
    rc = {
      has: true, index: sr.index, action: sr.action, reason: sr.reason, story,
      escLine: sr.policy_verdict ? "The policy asked for a human. How it was settled decided what was enforced." : "",
      fields, digest: sr.args_digest,
    };
  }
  return {
    vfOpts, ruleOpts, rf: S.rf,
    rfRef: (el: HTMLSelectElement | null) => {
      if (el && el.value !== S.rf) el.value = S.rf;
    },
    q: S.q,
    onRf: (e: { target: { value: string } }) => A.setFilter({ rf: e.target.value }),
    onQ: (e: { target: { value: string } }) => A.setQuery(e.target.value),
    aud, rc, audShowList: c.wide || !rc.has,
    audCols: c.wide ? "70px 132px minmax(0,1.3fr) minmax(0,1fr) minmax(0,.8fr) 60px" : "62px 112px minmax(0,1fr)",
    drawerW: c.wide ? "400px" : "100%",
    toggleLive: A.toggleLive, loadMore: A.loadMore, clearFilters: A.clearFilters, closeReceipt: A.closeReceipt,
    jumpBroken: () => D.verify?.broken_index != null && A.openReceipt(D.verify.broken_index),
    copyDigest: () => A.copy("digest", String(rc.digest ?? "")), copyLabel: S.copied === "digest" ? "copied" : "copy",
  };
}

const EMPTY_RECEIPT: ReceiptVM = { has: false, index: 0, action: "", reason: "", story: [], escLine: "", fields: [], digest: "" };

export interface ReceiptVM {
  has: boolean;
  index: number;
  action: string;
  reason: string;
  story: { mark: string; word: string; c: string; bg: string; bc: string; bs: string; arrow: boolean }[];
  escLine: string;
  fields: { k: string; v: string; ff: string; fs: string; c: string; href: string; plain: boolean }[];
  digest: string;
}

// --- Policy, playground, catalog, inspector, ops -------------------------------------------

function moreVals(S: State, D: Data, A: Actions, c: { wide: boolean; locked: boolean; home?: string }) {
  const route = S.route;
  const tag = (l: string, col: string, title?: string, dashed?: boolean) => ({
    l, c: col, bc: "color-mix(in oklch, " + col + " 45%, transparent)", bs: dashed ? "dashed" : "solid", title: title || "",
  });

  // Policy
  const policy = D.policy;
  const saved = policy?.analysis;
  const savedOk = saved && saved.ok ? saved : null;
  const ruleRow = (r: PolicyRule) => {
    const tags = [tag(r.source === "own" ? "own" : "inherited", r.source === "own" ? "var(--il-fg2)" : "var(--il-dim)")];
    if (r.locked) tags.push(tag("locked", "var(--il-acc)", "can't be disabled by anything that extends it"));
    if (r.quarantined) tags.push(tag("quarantined", "var(--il-rewrite)", r.quarantined));
    if (r.disabled) tags.push(tag("disabled", "var(--il-fg2)", "disabled in your policy", true));
    return {
      id: r.id ?? "?", reason: r.reason, cond: r.cond, v: chip(r.verdict), tags,
      op: r.quarantined ? 0.7 : r.disabled ? 0.5 : 1, strike: r.disabled ? "line-through" : "none",
      href: "#/audit?policy=" + encodeURIComponent(r.id ?? ""), det: r.detector ? "#/catalog/" + r.detector : "",
    };
  };
  const draft = D.draft;
  const savedText = policy?.text ?? "";
  const dirty = !!policy && S.policyText !== savedText;
  const problems = draft && draft.ok ? draft.quarantined.map((msg) => ({ mark: "~", c: "var(--il-rewrite)", msg })) : [];
  const parseErr = !!draft && !draft.ok;
  const approvedN = D.reviews.filter((r) => r.status === "approved");
  const ovSt = {
    ok: [tone("var(--il-allow)"), "✓", "trusted"],
    untrusted: [muted, "?", "untrusted · ignored"],
    changed: [tone("var(--il-rewrite)"), "~", "changed · ignored"],
    loosens: [tone("var(--il-block)"), "✗", "ignored · tries to loosen"],
    missing: [faint, "◌", "missing"],
  } as const;
  const overlays = D.overlays.map((o, i) => {
    const [t, mark, word] = ovSt[o.status];
    const trusted = o.status === "ok" && o.trusted_at ? "Trusted " + ago(S.now - ms(o.trusted_at)).replace(" ago", "") + " ago. " : "";
    return {
      path: tilde(o.path, c.home), status: o.status, line: trusted + o.line, cmd: o.cmd,
      st: { ...t, bs: o.status === "untrusted" || o.status === "missing" ? "dashed" : "solid", mark, word },
      copy: () => A.copy("ov" + i, o.cmd), copyLabel: S.copied === "ov" + i ? "copied" : "copy",
    };
  });
  const tabs = ([["rules", "Rules"], ["edit", "Edit JSON"], ["overlays", "Overlays"], ["pack", "Built-in pack"], ["backtest", "Test on real calls"]] as const).map(([k, l]) => ({
    l, dirty: k === "edit" && dirty ? " ●" : "", sel: S.polTab === k, bg: S.polTab === k ? "var(--il-sel)" : "transparent",
    c: S.polTab === k ? "var(--il-fg)" : "var(--il-fg2)", on: () => A.set({ polTab: k }),
  }));
  const draftOk = !!draft && draft.ok;
  const probN = parseErr ? 1 : problems.length;
  const policyPath = policy?.path ?? D.session?.policy_path ?? "";
  const pol = {
    tabs, tabRules: S.polTab === "rules", tabEdit: S.polTab === "edit", tabOverlays: S.polTab === "overlays", tabPack: S.polTab === "pack",
    toPack: () => A.set({ polTab: "pack" }), toEdit: () => A.set({ polTab: "edit" }),
    path: tilde(policyPath, c.home), fileName: policyPath.split("/").pop() || "policy.json",
    extendsLabel: savedOk?.extends ?? "nothing",
    statusLine: !policy ? "loading…" : savedOk
      ? savedOk.rules.length + " rules · " + savedOk.quarantined.length + " quarantined" + (policy.exists ? "" : " · file not created yet")
      : "last good policy running",
    quar: (savedOk?.quarantined ?? []).map((msg) => ({ msg })),
    rules: (savedOk?.rules ?? []).map(ruleRow),
    pack: (savedOk?.pack ?? []).map((r) => ({ ...ruleRow({ ...r, disabled: false }), strike: "none", op: 1 })),
    cols: c.wide ? "minmax(0,1fr) 128px minmax(0,190px) 76px" : "minmax(0,1fr) auto",
    dirty, clean: !dirty, revertOp: dirty ? 1 : 0.4, revert: () => A.setPolicyText(savedText),
    lineNums: S.policyText.split("\n").map((_, i) => i + 1).join("\n"), edBc: parseErr ? "var(--il-block)" : "var(--il-rule2)",
    onText: (e: { target: { value: string } }) => A.setPolicyText(e.target.value),
    parseErr, parseMsg: draft && !draft.ok ? draft.parse_error + (draft.line ? " (line " + draft.line + ")" : "") : "",
    problems, noProblems: draftOk && problems.length === 0,
    probCount: probN + " problem" + (probN === 1 ? "" : "s"),
    probC: parseErr ? "var(--il-block)" : problems.length ? "var(--il-rewrite)" : "var(--il-allow)",
    doCheck: A.checkDraft, checked: !!S.check && draftOk, ck: S.check ? { ...S.check, qc: S.check.quar ? "var(--il-rewrite)" : "var(--il-fg)" } : { rules: 0, locked: 0, quar: 0, overlays: "", epoch: "", qc: "" },
    saveDisabled: !c.locked && (!dirty || !draftOk || S.saving), saveOp: !c.locked && (!dirty || !draftOk) ? 0.4 : 1,
    saveLabel: c.locked ? "Unlock to save" : S.saving ? "Saving…" : "Save…",
    saveHint: S.policyNote ? S.policyNote : c.locked ? "Read-only. Saving needs writes unlocked."
      : parseErr ? "Fix the parse error first. The guard keeps the last good policy."
      : dirty ? "Saving replaces the file and changes the epoch, which voids outstanding approvals." : "No changes to save.",
    doSaveClick: () => (c.locked ? A.set({ unlockOpen: true }) : dirty && draftOk ? A.set({ saveOpen: true }) : undefined),
    overlays,
  };
  const draftEpoch = draft && draft.ok ? draft.epoch : "—";
  const voidLine = approvedN.length
    ? "This voids " + approvedN.length + " approved review" + (approvedN.length > 1 ? "s" : "") + " awaiting retry (" + approvedN.map((r) => r.id + " · " + r.action).join(", ") + ")."
    : "No approvals are outstanding right now, so nothing is voided.";

  // Playground
  const dets = D.catalog?.detectors ?? [];
  const facts = dets.flatMap((d) => d.factories.map((f) => ({ d, f, key: d.module + "." + f.name })));
  const byKey = new Map(facts.map((x) => [x.key, x]));
  const pgv = {
    selRef: (el: HTMLSelectElement | null) => {
      if (el && el.value !== S.pgPreset) el.value = S.pgPreset;
    },
    preset: S.pgPreset,
    presets: [...D.presets.map((p) => ({ v: p.id, l: p.title })), { v: "real", l: "Real calls…" }, { v: "custom", l: "Custom" }],
    onPreset: (e: { target: { value: string } }) => A.setPreset(e.target.value),
    detOpts: facts.map((x) => ({ v: x.key })),
    rules: S.pg.rules.map((r, i) => {
      const key = r.module + "." + r.factory;
      const x = byKey.get(key);
      const params = x?.f.params ?? [];
      return {
        selRef: (el: HTMLSelectElement | null) => {
          if (el && el.value !== key) el.value = key;
        },
        module: key,
        sig: signature(x?.f.name ?? r.factory, params),
        params: params.map((p) => ({
          name: p.name, ann: prettyAnn(p.annotation), required: p.required, value: r.params[p.name] ?? "",
          ph: p.required ? "required" : shortDefault(p.default),
          on: (e: { target: { value: string } }) => {
            const v = e.target.value;
            A.updPg((pg) => {
              pg.rules[i].params[p.name] = v;
            });
          },
        })),
        onModule: (e: { target: { value: string } }) => {
          const [module, ...rest] = e.target.value.split(".");
          A.updPg((pg) => {
            pg.rules[i] = { module, factory: rest.join("."), params: {} };
          });
        },
        remove: () => A.updPg((pg) => {
          pg.rules.splice(i, 1);
        }),
      };
    }),
    events: S.pg.events.map((e, i) => {
      const er = D.pgErrs[i];
      return {
        selRef: (el: HTMLSelectElement | null) => {
          if (el && el.value !== e.phase) el.value = e.phase;
        },
        n: i + 1, action: e.action, phase: e.phase, principal: e.principal, args: e.args,
        rows: Math.min(8, e.args.split("\n").length + 1), bc: er ? "var(--il-block)" : "var(--il-rule)",
        err: er ? er.msg : "", errLine: er ? er.line : "",
        onAction: (ev: { target: { value: string } }) => { const v = ev.target.value; A.updPg((pg) => { pg.events[i].action = v; }); },
        onPhase: (ev: { target: { value: string } }) => { const v = ev.target.value as "call" | "result"; A.updPg((pg) => { pg.events[i].phase = v; }); },
        onPrincipal: (ev: { target: { value: string } }) => { const v = ev.target.value; A.updPg((pg) => { pg.events[i].principal = v; }); },
        onArgs: (ev: { target: { value: string } }) => { const v = ev.target.value; A.updPg((pg) => { pg.events[i].args = v; }); },
        remove: () => A.updPg((pg) => { pg.events.splice(i, 1); }),
      };
    }),
    addRule: () => A.updPg((pg) => {
      const first = facts.find((x) => x.f.name === "network_egress_guard") ?? facts[0];
      if (first) pg.rules.push({ module: first.d.module, factory: first.f.name, params: {} });
    }),
    addEvent: () => A.updPg((pg) => {
      pg.events.push({ action: "http_post", phase: "call", principal: "claude-code", args: '{\n  "url": "https://api.acme.com/notes",\n  "body": ""\n}' });
    }),
    run: A.runPg, runHint: S.pgRan ? "Re-evaluates as you edit." : "",
    idle: !S.pgRan, blocked: S.pgRan && Object.keys(D.pgErrs).length > 0,
    results: S.pgRan && D.pgResults && !Object.keys(D.pgErrs).length
      ? D.pgResults.map((x, i) => {
          const ev = S.pg.events[i];
          const diff = diffArgs(ev?.args ?? "{}", x.modified_args, x.modified_result, ev?.phase);
          return {
            n: i + 1, action: ev?.action ?? "", v: chip(x.verdict), reason: x.reason, rule: x.policy_id ?? "—",
            blamed: x.attributed_to ?? "", diff: !!diff, before: diff?.before ?? "", after: diff?.after ?? "",
          };
        })
      : [],
  };
  if (D.pgApiErr && S.pgRan) {
    pgv.results = [{ n: 0, action: "", v: chip("BLOCK"), reason: D.pgApiErr, rule: "playground refused", blamed: "", diff: false, before: "", after: "" }];
  }

  // Catalog
  const q = S.catQ.trim().toLowerCase();
  const catOf = (name: string) => CATS[name] ?? [name, name.split(" ")[0]];
  const shown = dets.filter((d) =>
    (S.catCat === "all" || d.category === S.catCat) &&
    (!q || (d.module + " " + d.summary + " " + d.factories.map((f) => f.name).join(" ")).toLowerCase().includes(q)),
  );
  const selMod = route.path === "catalog" ? route.id : null;
  const categories = D.catalog?.categories ?? [];
  const groups = categories
    .map((cat) => {
      const items = shown.filter((d) => d.category === cat.name);
      const total = dets.filter((d) => d.category === cat.name).length;
      return {
        label: catOf(cat.name)[0], n: items.length + " of " + total,
        items: items.map((d) => ({
          module: d.module, summary: d.summary, href: "#/catalog/" + d.module,
          bg: d.module === selMod ? "var(--il-sel)" : "transparent", bar: d.module === selMod ? "var(--il-acc)" : "transparent",
        })),
      };
    })
    .filter((g) => g.items.length);
  const cats = [{ k: "all", short: "All", n: dets.length }, ...categories.map((cat) => ({ k: cat.name, short: catOf(cat.name)[1], n: dets.filter((d) => d.category === cat.name).length }))]
    .map((x) => ({
      ...x, sel: S.catCat === x.k, bg: S.catCat === x.k ? "var(--il-sel)" : "transparent",
      bc: S.catCat === x.k ? "var(--il-rule2)" : "var(--il-rule)", c: S.catCat === x.k ? "var(--il-fg)" : "var(--il-fg2)",
      on: () => A.set({ catCat: x.k }),
    }));
  const Dd = selMod ? D.details[selMod] : undefined;
  const cd = Dd
    ? {
        has: true, module: Dd.module, summary: Dd.summary, scope: Dd.scope, catLabel: catOf(Dd.category)[0],
        verdicts: Dd.verdicts.map((v) => chip(v)), tryHref: "#/playground?detector=" + Dd.module,
        factories: Dd.factories.map((f) => ({
          sig: signature(f.name, f.params),
          params: f.params.map((p) => ({
            name: p.name, annotation: prettyAnn(p.annotation), required: p.required,
            req: p.required ? "required" : "default " + shortDefault(p.default), c: p.required ? "var(--il-block)" : "var(--il-dim)",
          })),
        })),
        doc: docBlocks(Dd.doc),
      }
    : { has: false, module: "", summary: "", scope: "", catLabel: "", verdicts: [], tryHref: "", factories: [], doc: [] };
  const cat = {
    showList: c.wide || !Dd, showDetail: c.wide || !!Dd, noSel: !Dd, listW: c.wide ? "380px" : "100%", none: !!D.catalog && shown.length === 0,
    groups, cats, onQ: (e: { target: { value: string } }) => A.set({ catQ: e.target.value }), clear: () => A.set({ catQ: "", catCat: "all" }),
  };

  // Inspector
  const io = S.insOut;
  let ins: InspectorVM = {
    idle: !io, has: !!io, err: S.insErr, docBc: S.insErr && /scope document/.test(S.insErr) ? "var(--il-block)" : "var(--il-rule2)",
    onDoc: (e: { target: { value: string } }) => A.set({ insDoc: e.target.value }),
    onPrincipal: (e: { target: { value: string } }) => A.set({ insPrincipal: e.target.value }),
    onEvent: (e: { target: { value: string } }) => A.set({ insEvent: e.target.value }),
    resolve: A.resolveScope,
    template: "", params: [], backend: "", rows: [], enforced: [], notEnforced: [], gap: false, gapLine: "", neBc: "", neBg: "",
    hasVerdict: false, noVerdict: true, v: chip("ALLOW"), vReason: "",
  };
  if (io) {
    const pf = io.sandbox.profile;
    const notEnforced = new Set(io.sandbox.not_enforced);
    const fmt = (v: unknown) => (Array.isArray(v) ? (v.length ? v.join(", ") : "(none)") : typeof v === "boolean" ? (v ? "on" : "off") : String(v));
    const order = ["read_paths", "write_paths", "allow_network", "allowed_hosts", "env_keys", "cpu_seconds", "memory_mb", "unshare_pid", "workdir"]
      .filter((k) => k in pf && pf[k] !== null);
    const rows = order.map((k) => {
      const token = PROFILE_TOKENS[k];
      const ne = !!token && notEnforced.has(token);
      return {
        k, v: k === "memory_mb" ? pf[k] + " MB" : k === "cpu_seconds" ? pf[k] + " s" : fmt(pf[k]),
        c: ne ? "var(--il-rewrite)" : "var(--il-allow)", mark: ne ? "!" : "✓", state: ne ? "not enforced" : "enforced",
      };
    });
    const gapTokens = io.sandbox.not_enforced;
    const others = io.sandbox.available_backends.filter((b) => b !== io.sandbox.backend);
    const templates = Object.keys(io.resolved);
    ins = {
      ...ins,
      template: templates.length ? templates.join(", ") : "(none bound for this principal)",
      params: Object.entries(io.resolved).flatMap(([t, params]) => Object.entries(params).map(([k, x]) => ({ k: templates.length > 1 ? t + "." + k : k, v: fmt(x) }))),
      backend: io.sandbox.backend, rows, enforced: io.sandbox.enforced, notEnforced: gapTokens, gap: gapTokens.length > 0,
      gapLine: io.sandbox.backend + " on this host can't enforce " + gapTokens.map((t) => TOKEN_MEANING[t] ?? t).join(", ") +
        ". Treat those lines as intent, not protection." + (others.length ? " Other backends here: " + others.join(", ") + "." : ""),
      neBc: gapTokens.length ? "var(--il-rewrite)" : "var(--il-rule)",
      neBg: gapTokens.length ? "color-mix(in oklch, var(--il-rewrite) 6%, var(--il-panel))" : "var(--il-panel)",
      hasVerdict: !!io.decision, noVerdict: !io.decision, v: io.decision ? chip(io.decision.verdict) : chip("ALLOW"),
      vReason: io.decision?.reason ?? "",
    };
  }

  // Ops
  const ST = {
    ok: [tone("var(--il-allow)"), "✓"], info: [muted, "i"], warn: [tone("var(--il-rewrite)"), "!"], fail: [tone("var(--il-block)"), "✗"],
  } as const;
  const rank = { fail: 0, warn: 1, info: 2, ok: 3 };
  const checks = (D.doctor?.checks ?? [])
    .slice()
    .sort((a, b) => rank[a.status] - rank[b.status])
    .map((chk, i) => ({
      ...chk, t: { ...ST[chk.status][0], mark: ST[chk.status][1] }, noFix: !chk.fix,
      copy: () => A.copy("ck" + i, chk.fix), copyLabel: S.copied === "ck" + i ? "copied" : "copy",
    }));
  const hookT = {
    installed: { ...tone("var(--il-allow)"), mark: "✓", bs: "solid" },
    "monitor mode": { ...tone("var(--il-rewrite)"), mark: "◌", bs: "dashed" },
    "not installed": { ...tone("var(--il-rewrite)"), mark: "!", bs: "solid" },
    "not on this machine": { ...faint, mark: "◌", bs: "dashed" },
  };
  const hooks = D.hooks.map((h, i) => ({
    name: h.name, state: h.state, where: h.where, t: hookT[h.state], cmd: h.cmd,
    copy: () => A.copy("hk" + i, h.cmd), copyLabel: S.copied === "hk" + i ? "copied" : "copy",
  }));
  const side = D.sidecar;
  const scBase = {
    healthy: {
      state: "healthy", t: { ...tone("var(--il-allow)"), mark: "✓", bs: "solid" },
      line: "Guard daemon on " + (side?.socket ?? "") + ", ruling for agents outside this Python process. Rule ids only; patterns never leave it." +
        (side?.admin ? "" : " Start it with --admin HOST:PORT and pass the same to the console's --sidecar-admin to see its stats."),
    },
    unreachable: {
      state: "unreachable", t: { ...tone("var(--il-rewrite)"), mark: "!", bs: "solid" },
      line: "Configured but not answering (" + (side?.detail ?? side?.socket ?? "") + "). Clients now deny, fall back or allow according to their own fallback setting. Check that the daemon is running: interlock-sidecar --admin.",
    },
    "not configured": {
      state: "not configured", t: { ...faint, mark: "◌", bs: "dashed" },
      line: "No sidecar is set up. You only need one to guard agents outside this Python process, such as Node.js agents.",
    },
    checking: { state: "checking", t: { ...faint, mark: "…", bs: "dashed" }, line: "Probing the guard daemon…" },
  }[side?.state ?? "checking"];
  const st = side?.stats;
  const by = st?.by_verdict ?? {};
  const stats = st
    ? [
        { k: "uptime", v: st.uptime_seconds != null ? duration(st.uptime_seconds) : "—", c: "var(--il-fg)" },
        { k: "decisions", v: num(st.decisions), c: "var(--il-fg)" },
        { k: "blocked", v: num((by.BLOCK ?? 0)), c: "var(--il-block)" },
        { k: "rewritten", v: num((by.MODIFY ?? 0)), c: "var(--il-rewrite)" },
        { k: "escalations", v: num(Object.values(st.escalations ?? {}).reduce((a, b) => a + b, 0)), c: "var(--il-escalate)" },
        { k: "dropped receipts", v: num(st.receipts_dropped ?? 0), c: "var(--il-fg)" },
        { k: "p99 latency", v: st.latency_us?.p99 != null ? "≤ " + st.latency_us.p99 + " µs" : "—", c: "var(--il-fg)" },
        { k: "epoch", v: side?.config?.epoch ?? "—", c: "var(--il-fg)" },
        { k: "fallback policy", v: side?.config ? (side.config.fallback_policy ? "published" : "none") : "—", c: "var(--il-fg)" },
      ]
    : [];
  const sc = { ...scBase, healthy: side?.state === "healthy" && stats.length > 0, notHealthy: !(side?.state === "healthy" && stats.length > 0), stats };
  const mcp = (D.mcp?.servers ?? []).map((m) => ({ ...m, clean: m.risks.length === 0 }));
  const log = D.receiptLog;
  const ops = {
    checks, checkCols: c.wide ? "96px minmax(0,1fr) minmax(0,320px)" : "auto minmax(0,1fr)", hooks, sc, mcp,
    mcpCols: c.wide ? "minmax(0,1fr) minmax(0,1.6fr) minmax(0,1fr)" : "minmax(0,1fr)",
    mcpLine: D.mcp ? mcp.length + " servers across " + D.mcp.clients_seen + " clients · " + mcp.filter((m) => m.risks.length).length + " with risk tags" : "scanning…",
    cfgWarn: (D.mcp?.warnings ?? []).map((w) => {
      const i = w.indexOf(": ");
      return i > 0 ? { path: tilde(w.slice(0, i), c.home), why: w.slice(i + 2) } : { path: w, why: "unreadable" };
    }),
    log: !log ? [] : !log.configured
      ? [{ k: "path", v: "not configured", c: "var(--il-fg)" }]
      : [
          { k: "path", v: log.path ?? "", c: "var(--il-fg)" },
          { k: "writable", v: log.writable ? "yes" : "no", c: log.writable ? "var(--il-allow)" : "var(--il-block)" },
          { k: "key present", v: log.key ? "yes" : "no", c: log.key ? "var(--il-allow)" : "var(--il-rewrite)" },
          { k: "single writer", v: "not checked from here", c: "var(--il-dim)" },
          { k: "dropped receipts", v: num(log.dropped ?? 0), c: log.dropped ? "var(--il-rewrite)" : "var(--il-fg)" },
        ],
  };

  return {
    pol, policyText: S.policyText, draftEpoch, voidLine, doSave: A.saveDraft, closeSave: () => A.set({ saveOpen: false }),
    pgv, cat, cd, catQ: S.catQ, ins, insDoc: S.insDoc, insPrincipal: S.insPrincipal, insEvent: S.insEvent,
    ops, notFoundPath: route.path,
  };
}

export interface InspectorVM {
  idle: boolean;
  has: boolean;
  err: string | null;
  docBc: string;
  onDoc: (e: { target: { value: string } }) => void;
  onPrincipal: (e: { target: { value: string } }) => void;
  onEvent: (e: { target: { value: string } }) => void;
  resolve: () => void;
  template: string;
  params: { k: string; v: string }[];
  backend: string;
  rows: { k: string; v: string; c: string; mark: string; state: string }[];
  enforced: string[];
  notEnforced: string[];
  gap: boolean;
  gapLine: string;
  neBc: string;
  neBg: string;
  hasVerdict: boolean;
  noVerdict: boolean;
  v: ReturnType<typeof chip>;
  vReason: string;
}

/** The one argument a rewrite changed, as before/after lines. */
function diffArgs(argsText: string, modifiedArgs: unknown, modifiedResult: unknown, phase?: string) {
  let before: Record<string, unknown> = {};
  try {
    before = JSON.parse(argsText || "{}");
  } catch {
    return null;
  }
  const show = (v: unknown) => (typeof v === "string" ? v : JSON.stringify(v));
  if (phase === "result" && modifiedResult !== null && modifiedResult !== undefined) {
    return { before: "result: " + show(before.content ?? before), after: "result: " + show(modifiedResult) };
  }
  if (!modifiedArgs || typeof modifiedArgs !== "object") return null;
  const after = modifiedArgs as Record<string, unknown>;
  for (const k of new Set([...Object.keys(before), ...Object.keys(after)])) {
    if (JSON.stringify(before[k]) !== JSON.stringify(after[k])) {
      return { before: k + ": " + show(before[k]), after: k + ": " + show(after[k]) };
    }
  }
  return null;
}
