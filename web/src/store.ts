/**
 * The console's store: owns `State` and `Data`, talks to the API, and keeps
 * both current - polling what changes on its own (the review queue, the
 * protection check, the console's own health), following the receipt log over
 * SSE, and loading what each route needs when the route is opened.
 *
 * The design prototype held the same responsibilities in one component class
 * with mock data; this is that class, with the mocks replaced by the server.
 */
import * as api from "./api";
import { ApiError } from "./api";
import { THEMES, jsonErrorLine, paramText, paramValue, type ThemeName } from "./format";
import { initialData, initialState, parseHash, type Data, type Pg, type State } from "./model";
import type { Actions } from "./vals";

const POLL_FAST = 5000;
const POLL_DOCTOR = 15000;
const POLL_ACTIVITY = 10000;

function debounce<A extends unknown[]>(fn: (...args: A) => void, ms: number) {
  let t: ReturnType<typeof setTimeout> | undefined;
  return (...args: A) => {
    if (t) clearTimeout(t);
    t = setTimeout(() => fn(...args), ms);
  };
}

const errText = (e: unknown) => (e instanceof ApiError ? e.message : e instanceof Error ? e.message : String(e));

export class ConsoleStore {
  S: State = initialState();
  D: Data = initialData();
  version = 0;
  private listeners = new Set<() => void>();
  private timers: ReturnType<typeof setInterval>[] = [];
  private source: EventSource | null = null;
  private ro: ResizeObserver | null = null;
  private rootEl: HTMLDivElement | null = null;
  private copyT: ReturnType<typeof setTimeout> | undefined;
  private started = false;

  subscribe = (fn: () => void) => {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  };

  getVersion = () => this.version;

  private emit() {
    this.version++;
    this.listeners.forEach((fn) => fn());
  }

  set = (patch: Partial<State>) => {
    this.S = { ...this.S, ...patch };
    this.emit();
  };

  private data(patch: Partial<Data>) {
    this.D = { ...this.D, ...patch };
    this.emit();
  }

  // --- lifecycle -----------------------------------------------------------------

  start() {
    if (this.started) return;
    this.started = true;
    window.addEventListener("hashchange", this.onHash);
    window.addEventListener("keydown", this.onKey);
    this.timers.push(setInterval(() => this.set({ now: Date.now() }), 1000));
    this.timers.push(setInterval(() => this.poll(), POLL_FAST));
    this.timers.push(setInterval(() => this.loadDoctor(), POLL_DOCTOR));
    this.timers.push(setInterval(() => this.S.route.path === "activity" && this.loadActivity(), POLL_ACTIVITY));
    this.applyTheme();
    void this.boot();
  }

  stop() {
    this.started = false;
    window.removeEventListener("hashchange", this.onHash);
    window.removeEventListener("keydown", this.onKey);
    this.timers.forEach(clearInterval);
    this.timers = [];
    this.source?.close();
    this.source = null;
    this.ro?.disconnect();
  }

  private async boot() {
    await this.loadSession();
    void this.loadDoctor();
    void this.loadReviews();
    void this.loadPolicy();
    void this.loadCatalog();
    void this.loadPresets();
    void this.loadScopeExample();
    if (this.D.session?.receipts_path) {
      void this.loadVerify();
      this.connectStream();
    }
    this.onHash();
  }

  private async poll() {
    await this.loadSession();
    if (!this.D.connDown) void this.loadReviews();
  }

  // --- routing -----------------------------------------------------------------------

  private onHash = () => {
    const route = parseHash(window.location.hash);
    const s: Partial<State> = { route, navOpen: false };
    if (route.path !== this.S.route.path || route.id !== this.S.route.id) s.flash = "";
    if (route.path === "audit") {
      s.vf = route.q.verdict || "all";
      s.rf = route.q.policy || "all";
      s.q = route.q.q ?? route.q.action ?? (route.q.r ? this.S.q : "");
    }
    if (route.path === "catalog" && route.q.q) s.catQ = route.q.q;
    this.set(s);
    this.loadRoute();
  };

  private loadRoute() {
    const { path, id, q } = this.S.route;
    if (path === "unlock" && id) {
      this.set({ unlockOpen: true, unlockVal: window.location.href });
      window.history.replaceState(null, "", "#/");
      this.set({ route: parseHash("#/") });
      void this.doUnlock();
      this.loadRoute();
      return;
    }
    if (path === "activity") void this.loadActivity();
    if (path === "audit") {
      void this.loadReceipts(false);
      if (q.r) void this.loadSelected(Number(q.r)).then(() => this.loadCallDetail(Number(q.r)));
    }
    if (path === "reviews") void this.loadReviews();
    if (path === "policy") {
      if (id === "starter") void this.addStarter();
      else void this.loadPolicy();
      void this.loadTrust();
    }
    if (path === "catalog" && id) void this.loadDetail(id);
    if (path === "playground") this.preparePlayground(q.detector ?? null);
    if (path === "ops") {
      void this.loadDoctor();
      void this.loadOps();
    }
  }

  private hashFor(path: string) {
    window.location.hash = path;
  }

  // --- loaders -------------------------------------------------------------------------

  private async loadSession() {
    try {
      const session = await api.fetchSession();
      if (session.locked && api.unlockToken()) api.setUnlockToken(null); // console restarted
      const wasDown = this.D.connDown;
      this.data({ session, connDown: false });
      if (wasDown) {
        this.loadRoute();
        if (session.receipts_path && !this.source) this.connectStream();
      }
    } catch {
      this.data({ connDown: true });
    }
  }

  private async loadDoctor() {
    try {
      this.data({ doctor: await api.fetchDoctor() });
    } catch {
      // keep the last answer; the shell marks the whole page stale when down
    }
  }

  private async loadReviews() {
    try {
      const r = await api.fetchReviews();
      this.data({ reviews: r.reviews, reviewsConfigured: r.configured });
    } catch {
      /* stale is fine: polled again */
    }
  }

  private async loadVerify() {
    try {
      this.data({ verify: await api.fetchVerify() });
    } catch {
      /* unconfigured or down */
    }
  }

  private async loadActivity() {
    if (!this.D.session?.receipts_path) return;
    try {
      const activity = await api.fetchActivity(this.S.win);
      this.data({ activity, activityErr: null });
      const sel = this.S.selB;
      if (sel != null && activity.timeline[sel]) {
        const b = activity.timeline[sel];
        this.data({ focusAct: await api.fetchActivity(this.S.win, b.from, b.to) });
      }
    } catch (e) {
      this.data({ activityErr: errText(e) });
    }
  }

  private receiptQuery() {
    const S = this.S;
    return {
      verdict: S.vf === "all" ? null : S.vf,
      policy: S.rf === "all" ? null : S.rf,
      q: S.q.trim() || null,
    };
  }

  private async loadReceipts(append: boolean) {
    if (!this.D.session?.receipts_path) return;
    try {
      const offset = append ? this.D.receipts.length : 0;
      const limit = append ? 200 : Math.min(500, this.S.shown);
      const r = await api.fetchReceipts({ ...this.receiptQuery(), offset, limit });
      this.data({
        receipts: append ? [...this.D.receipts, ...r.receipts] : r.receipts,
        receiptsTotal: r.total, receiptsAll: r.count_all, receiptRules: r.rules, receiptsErr: null, receiptsLoaded: true,
      });
    } catch (e) {
      this.data({ receiptsErr: errText(e), receiptsLoaded: true });
    }
  }

  private reloadReceiptsSoon = debounce(() => void this.loadReceipts(false), 250);
  private refreshAfterReceipt = debounce(() => {
    if (this.S.route.path === "activity") void this.loadActivity();
    if (this.S.route.path === "audit" && this.S.live) void this.loadReceipts(false);
  }, 700);

  private async loadSelected(index: number) {
    if (this.D.receipts.some((r) => r.index === index)) return;
    try {
      const r = await api.fetchReceipts({ index });
      this.data({ selReceipt: r.receipts[0] ?? null });
    } catch {
      this.data({ selReceipt: null });
    }
  }

  // --- real calls ---------------------------------------------------------------------

  private async loadCallDetail(index: number) {
    const r = this.D.receipts.find((x) => x.index === index) ?? this.D.selReceipt;
    if (!r || r.unreadable || r.index !== index || !r.call_id) {
      this.data({ callDetail: null, callDetailFor: index });
      return;
    }
    if (this.D.callDetailFor === index && this.D.callDetail) return;
    this.data({ callDetail: null, callDetailFor: index });
    try {
      const detail = await api.fetchCall(r.call_id, r.span_id, r.ts);
      if (this.D.callDetailFor === index) this.data({ callDetail: detail });
    } catch {
      /* the drawer says the call couldn't be found */
    }
  }

  private async loadRealCalls() {
    try {
      const r = await api.fetchCalls(200, this.S.rcTool || undefined, this.S.rcQ.trim() || undefined);
      this.data({ realCalls: r.calls, realTools: r.tools, realAvailable: r.available, realErr: null });
    } catch (e) {
      this.data({ realErr: errText(e) });
    }
  }

  private realCallsSoon = debounce(() => void this.loadRealCalls(), 300);

  private eventsOf(c: { tool: string; args: Record<string, unknown>; result?: unknown }, withResult: boolean): Pg["events"] {
    const out: Pg["events"] = [{ action: c.tool, phase: "call", principal: "claude-code", args: JSON.stringify(c.args, null, 2) }];
    if (withResult && c.result !== undefined && c.result !== null) {
      const payload = typeof c.result === "string" ? { result: c.result } : c.result;
      out.push({ action: c.tool, phase: "result", principal: "claude-code", args: JSON.stringify(payload, null, 2) });
    }
    return out;
  }

  private async openInPlayground(o: { calls: { call_id: string; session?: string | null; ts?: number }[]; module?: string; factory?: string }) {
    const events: Pg["events"] = [];
    for (const ref of o.calls) {
      const known = this.D.realCalls?.find((c) => c.call_id === ref.call_id);
      if (known) {
        events.push(...this.eventsOf(known, true));
        continue;
      }
      try {
        const d = await api.fetchCall(ref.call_id, ref.session, ref.ts);
        if (d.found && d.tool && d.args) events.push(...this.eventsOf({ tool: d.tool, args: d.args, result: d.result ?? undefined }, true));
      } catch {
        /* skip a call that can't be read */
      }
    }
    const rules = o.module && o.factory ? [{ module: o.module, factory: o.factory, params: {} }] : this.S.pg.rules;
    this.set({ pg: { rules, events }, pgPreset: "custom", pgRan: true });
    this.hashFor("#/playground");
    this.evaluateSoon();
  }

  private async runBacktest() {
    if (this.S.btRunning) return;
    this.set({ btRunning: true });
    try {
      const text = this.S.btSource === "draft" ? this.S.policyText : undefined;
      this.data({ backtest: await api.runBacktest(this.S.btLimit, text), backtestErr: null });
    } catch (e) {
      this.data({ backtestErr: errText(e) });
    }
    this.set({ btRunning: false });
  }

  private async runSweep() {
    if (this.S.swRunning) return;
    this.set({ swRunning: true });
    try {
      this.data({ sweep: await api.runSweep(this.S.swLimit), sweepErr: null });
    } catch (e) {
      this.data({ sweepErr: errText(e) });
    }
    this.set({ swRunning: false });
  }

  private async loadPolicy() {
    try {
      const policy = await api.fetchPolicy();
      const keepDraft = this.D.policy && this.S.policyText !== this.D.policy.text;
      this.data({ policy, draft: keepDraft ? this.D.draft : policy.analysis });
      if (!keepDraft) this.set({ policyText: policy.text });
    } catch {
      /* shown as loading */
    }
  }

  private async loadTrust() {
    try {
      this.data({ overlays: (await api.fetchTrust()).overlays });
    } catch {
      /* keep */
    }
  }

  private async loadCatalog() {
    try {
      this.data({ catalog: await api.fetchDetectors() });
      if (this.S.route.path === "playground") this.preparePlayground(this.S.route.q.detector ?? null);
    } catch {
      /* retried on next visit */
    }
  }

  private async loadDetail(module: string) {
    if (this.D.details[module]) return;
    try {
      const detail = await api.fetchDetector(module);
      this.data({ details: { ...this.D.details, [module]: detail } });
    } catch {
      /* unknown module: the screen shows its empty detail */
    }
  }

  private async loadPresets() {
    try {
      this.data({ presets: (await api.fetchPresets()).presets });
      if (this.S.route.path === "playground") this.preparePlayground(this.S.route.q.detector ?? null);
    } catch {
      /* the picker offers Custom only */
    }
  }

  private async loadScopeExample() {
    try {
      const ex = await api.fetchScopeExample();
      if (!this.S.insDoc) {
        this.set({
          insDoc: JSON.stringify(ex.document, null, 2),
          insPrincipal: ex.principal,
          insEvent: ex.event == null ? "" : JSON.stringify(ex.event, null, 2),
        });
      }
    } catch {
      /* the editors stay empty */
    }
  }

  private async loadOps() {
    const [hooks, mcp, sidecar, receiptLog] = await Promise.allSettled([
      api.fetchHooks(), api.fetchMcp(), api.fetchSidecar(), api.fetchReceiptLog(),
    ]);
    this.data({
      hooks: hooks.status === "fulfilled" ? hooks.value.hooks : this.D.hooks,
      mcp: mcp.status === "fulfilled" ? mcp.value : this.D.mcp,
      sidecar: sidecar.status === "fulfilled" ? sidecar.value : this.D.sidecar,
      receiptLog: receiptLog.status === "fulfilled" ? receiptLog.value : this.D.receiptLog,
    });
  }

  // --- live tail ---------------------------------------------------------------------------

  private connectStream() {
    if (typeof EventSource === "undefined") return;
    this.source?.close();
    const source = new EventSource("/api/receipts/stream");
    this.source = source;
    this.set({ tail: "connecting" });
    source.addEventListener("hello", () => this.set({ tail: "live" }));
    source.addEventListener("receipt", () => {
      if (this.S.tail !== "reset") this.set({ tail: "live" });
      if (!this.S.live) {
        this.set({ pausedNew: this.S.pausedNew + 1 });
        if (this.S.route.path === "activity") this.refreshAfterReceipt();
        return;
      }
      this.refreshAfterReceipt();
    });
    source.addEventListener("reset", () => {
      this.set({ tail: "reset" });
      void this.loadReceipts(false);
      void this.loadVerify();
      void this.loadActivity();
    });
    source.onerror = () => this.set({ tail: "disconnected" });
  }

  // --- theme ------------------------------------------------------------------------------

  private theme(): ThemeName {
    return this.S.themeOverride ?? "dark";
  }

  applyTheme() {
    const t = THEMES[this.theme()];
    const style = document.documentElement.style;
    Object.entries(t).forEach(([k, v]) => style.setProperty("--il-" + k, v));
    style.colorScheme = this.theme();
  }

  // --- keyboard ---------------------------------------------------------------------------

  private onKey = (e: KeyboardEvent) => {
    const tag = ((e.target as HTMLElement | null)?.tagName || "").toLowerCase();
    if (tag === "input" || tag === "textarea" || tag === "select" || e.metaKey || e.ctrlKey || e.altKey) return;
    if (e.key === "Escape") {
      this.set({ keysOpen: false, unlockOpen: false, saveOpen: false, navOpen: false });
      return;
    }
    if (e.key === "?") {
      this.set({ keysOpen: true });
      return;
    }
    if (this.S.route.path === "reviews") {
      const list = this.reviewList();
      const i = list.findIndex((x) => x.id === this.S.route.id);
      if (e.key === "j" || e.key === "ArrowDown") {
        const n = list[Math.min(list.length - 1, i + 1)];
        if (n) this.hashFor("#/reviews/" + n.id);
        e.preventDefault();
      }
      if (e.key === "k" || e.key === "ArrowUp") {
        const n = list[Math.max(0, i - 1)];
        if (n) this.hashFor("#/reviews/" + n.id);
        e.preventDefault();
      }
      if (e.key === "a") this.decide("approve");
      if (e.key === "r") {
        const t = document.querySelector<HTMLTextAreaElement>('[data-testid="reviews-reject-reason"]');
        if (t && !this.S.rejectReason) {
          t.focus();
          e.preventDefault();
        } else this.decide("reject");
      }
    }
  };

  private reviewList() {
    const tab = this.S.revTab;
    const l = this.D.reviews.filter((r) =>
      tab === "pending" ? r.status === "pending" : tab === "approved" ? r.status === "approved" : !["pending", "approved"].includes(r.status),
    );
    return tab === "pending" ? l.slice().sort((a, b) => a.pending_until - b.pending_until) : l;
  }

  // --- actions ----------------------------------------------------------------------------

  private copy(key: string, text: string) {
    try {
      void navigator.clipboard.writeText(text);
    } catch {
      /* clipboard blocked: the label still confirms the click */
    }
    this.set({ copied: key });
    if (this.copyT) clearTimeout(this.copyT);
    this.copyT = setTimeout(() => this.set({ copied: "" }), 1400);
  }

  private auditHash(over: { vf?: string; rf?: string; r?: number | null; q?: string }) {
    const vf = over.vf ?? this.S.vf;
    const rf = over.rf ?? this.S.rf;
    const q = over.q ?? this.S.q;
    const parts: string[] = [];
    if (vf !== "all") parts.push("verdict=" + vf);
    if (rf !== "all") parts.push("policy=" + encodeURIComponent(rf));
    if (q.trim()) parts.push("q=" + encodeURIComponent(q.trim()));
    if (over.r != null) parts.push("r=" + over.r);
    return "#/audit" + (parts.length ? "?" + parts.join("&") : "");
  }

  private async decide(kind: "approve" | "reject" | "revoke") {
    const id = this.S.route.id;
    const rv = this.D.reviews.find((x) => x.id === id);
    const me = this.D.session?.me;
    if (!rv || this.S.busy) return;
    if (!this.D.session || this.D.session.locked) {
      this.set({ flash: "Read-only: unlock writes first." });
      return;
    }
    if (kind === "approve" && (rv.status !== "pending" || (!rv.self_ok && rv.requester === me) || rv.approvers.includes(me ?? ""))) return;
    if (kind === "reject" && rv.status !== "pending") return;
    if (kind === "reject" && !this.S.rejectReason.trim()) {
      this.set({ flash: "Add a reason. The agent is told why it was rejected." });
      return;
    }
    if (kind === "revoke" && rv.status !== "approved") return;
    this.set({ busy: kind, flash: "" });
    try {
      const reason = this.S.rejectReason.trim();
      const { review } = await api.decideReview(rv.id, kind, kind === "reject" ? reason : undefined);
      this.data({ reviews: this.D.reviews.map((x) => (x.id === review.id ? review : x)) });
      const msg = kind === "approve"
        ? review.status === "approved"
          ? "Approved. Waiting for the agent to retry the identical call."
          : "Your approval is recorded. " + review.approvers.length + " of " + review.min_approvals + "."
        : kind === "reject" ? 'Rejected. The agent was told: "' + reason + '"' : "Approval revoked. The agent will have to ask again.";
      this.set({ busy: null, rejectReason: kind === "reject" ? "" : this.S.rejectReason, flash: msg });
    } catch (e) {
      if (e instanceof ApiError && e.code === "locked") void this.loadSession();
      this.set({ busy: null, flash: errText(e) });
      void this.loadReviews();
    }
  }

  private async doUnlock() {
    const value = this.S.unlockVal.trim();
    if (!value) {
      this.set({ unlockErr: "Paste the link or code from the console terminal." });
      return;
    }
    try {
      const { token } = await api.unlock(value);
      api.setUnlockToken(token);
      await this.loadSession();
      this.set({ unlockOpen: false, unlockVal: "", unlockErr: "", flash: "" });
    } catch (e) {
      this.set({ unlockOpen: true, unlockErr: errText(e) });
    }
  }

  private async relock() {
    try {
      await api.lock();
    } catch {
      /* the token is dropped below either way */
    }
    api.setUnlockToken(null);
    await this.loadSession();
  }

  private draftCheck = debounce(async (text: string) => {
    try {
      const { analysis } = await api.checkPolicy(text);
      if (text === this.S.policyText) this.data({ draft: analysis });
    } catch {
      /* the last check stays shown */
    }
  }, 350);

  private async saveDraft() {
    const policy = this.D.policy;
    if (!policy || this.S.saving) return;
    this.set({ saving: true });
    try {
      const saved = await api.savePolicy(this.S.policyText, policy.sha);
      this.data({ policy: saved, draft: saved.analysis });
      const voided = saved.voided?.length ?? 0;
      this.set({
        saving: false, saveOpen: false, check: null, policyText: saved.text,
        policyNote: "Saved, epoch " + (saved.analysis.ok ? saved.analysis.epoch : "?") + "." +
          (voided ? " " + voided + " approval" + (voided > 1 ? "s were" : " was") + " voided by the new epoch." : ""),
      });
      void this.loadReviews();
      void this.loadDoctor();
    } catch (e) {
      this.set({ saving: false, saveOpen: false, policyNote: errText(e) });
      if (e instanceof ApiError && e.code === "locked") void this.loadSession();
    }
  }

  private async addStarter() {
    await this.loadPolicy();
    try {
      const { rule } = await api.fetchMcpStarter();
      if (!rule) {
        this.set({ polTab: "edit" });
      } else {
        let doc: { rules?: unknown[] } & Record<string, unknown>;
        try {
          doc = JSON.parse(this.S.policyText || "{}");
        } catch {
          doc = { version: 1, extends: "builtin:coding-agent" };
        }
        const rules = Array.isArray(doc.rules) ? doc.rules : [];
        const id = (rule as { id?: string }).id;
        if (!rules.some((r) => (r as { id?: string })?.id === id)) rules.push(rule);
        doc.rules = rules;
        this.actions.setPolicyText(JSON.stringify(doc, null, 2) + "\n");
        this.set({ polTab: "edit" });
      }
    } catch {
      this.set({ polTab: "edit" });
    }
    window.history.replaceState(null, "", "#/policy");
    this.set({ route: parseHash("#/policy") });
  }

  // playground

  private presetToPg(preset: api.Preset): Pg {
    return {
      rules: preset.rules.map((r) => ({
        module: r.detector, factory: r.factory,
        params: Object.fromEntries(Object.entries(r.kwargs ?? {}).map(([k, v]) => [k, paramText(v)])),
      })),
      events: preset.events.map((e) => ({
        action: e.action, phase: e.phase ?? "call", principal: e.principal ?? "claude-code",
        args: JSON.stringify(e.args ?? {}, null, 2),
      })),
    };
  }

  private preparePlayground(detector: string | null) {
    const presets = this.D.presets;
    if (detector) {
      const hit = presets.find((p) => p.rules.some((r) => r.detector === detector));
      if (hit) {
        this.set({ pgPreset: hit.id, pg: this.presetToPg(hit) });
      } else {
        const det = this.D.catalog?.detectors.find((d) => d.module === detector);
        if (!det) return;
        this.set({
          pgPreset: "custom",
          pg: {
            rules: [{ module: det.module, factory: det.factories[0]?.name ?? "", params: {} }],
            events: [{ action: "shell", phase: det.scope === "result" ? "result" : "call", principal: "claude-code", args: '{\n  "command": "echo hello"\n}' }],
          },
        });
      }
      window.history.replaceState(null, "", "#/playground");
      this.set({ route: parseHash("#/playground") });
      if (this.S.pgRan) this.evaluateSoon();
      return;
    }
    if (!this.S.pg.rules.length && !this.S.pg.events.length && presets.length) {
      this.set({ pgPreset: presets[0].id, pg: this.presetToPg(presets[0]) });
    }
  }

  private evaluateSoon = debounce(() => void this.evaluate(), 300);

  private async evaluate() {
    const pg = this.S.pg;
    const errs: Data["pgErrs"] = {};
    const events: api.PresetEvent[] = [];
    pg.events.forEach((e, i) => {
      try {
        const args = JSON.parse(e.args || "{}");
        events.push({ action: e.action, phase: e.phase, principal: e.principal || null, args });
      } catch (err) {
        errs[i] = jsonErrorLine(e.args, err);
      }
    });
    if (Object.keys(errs).length) {
      this.data({ pgErrs: errs, pgResults: null, pgApiErr: null });
      return;
    }
    const facts = new Map((this.D.catalog?.detectors ?? []).flatMap((d) => d.factories.map((f) => [d.module + "." + f.name, f] as const)));
    const rules: api.PresetRule[] = pg.rules.map((r) => {
      const f = facts.get(r.module + "." + r.factory);
      const kwargs: Record<string, unknown> = {};
      for (const [name, text] of Object.entries(r.params)) {
        const parsed = paramValue(text, f?.params.find((p) => p.name === name));
        if (parsed.set) kwargs[name] = parsed.value;
      }
      return { detector: r.module, factory: r.factory, kwargs };
    });
    try {
      const { results } = await api.evaluate(rules, events);
      this.data({ pgErrs: {}, pgResults: results, pgApiErr: null });
    } catch (e) {
      this.data({ pgErrs: {}, pgResults: null, pgApiErr: e instanceof ApiError ? e.code + ": " + e.message : errText(e) });
    }
  }

  private async resolveScope() {
    const S = this.S;
    let doc: unknown;
    let ev: unknown = null;
    try {
      doc = JSON.parse(S.insDoc);
    } catch (e) {
      this.set({ insErr: "scope document: " + jsonErrorLine(S.insDoc, e).msg, insOut: null });
      return;
    }
    if (S.insEvent.trim()) {
      try {
        ev = JSON.parse(S.insEvent);
      } catch (e) {
        this.set({ insErr: "event: " + jsonErrorLine(S.insEvent, e).msg, insOut: null });
        return;
      }
    }
    try {
      this.set({ insOut: await api.resolveScope(doc, S.insPrincipal.trim(), ev), insErr: null });
    } catch (e) {
      this.set({ insErr: e instanceof ApiError ? e.code + ": " + e.message : errText(e), insOut: null });
    }
  }

  actions: Actions = {
    set: this.set,
    rootRef: (el) => {
      if (el === this.rootEl) return;
      this.ro?.disconnect();
      this.rootEl = el;
      if (el && typeof ResizeObserver !== "undefined") {
        this.ro = new ResizeObserver(() => {
          const w = el.getBoundingClientRect().width;
          if (Math.abs(w - this.S.w) > 0.5) this.set({ w });
        });
        this.ro.observe(el);
      }
    },
    setWin: (win) => {
      this.set({ win, selB: null, hovB: null });
      this.data({ focusAct: null });
      void this.loadActivity();
    },
    focusBucket: (index) => {
      this.set({ selB: index });
      this.data({ focusAct: null });
      const b = index != null ? this.D.activity?.timeline[index] : null;
      if (b) void api.fetchActivity(this.S.win, b.from, b.to).then((focusAct) => this.S.selB === index && this.data({ focusAct }));
    },
    setFilter: (f) => {
      this.set({ vf: f.vf ?? this.S.vf, rf: f.rf ?? this.S.rf, shown: 200 });
      this.hashFor(this.auditHash({}));
    },
    setQuery: (q) => {
      this.set({ q, shown: 200 });
      this.reloadReceiptsSoon();
    },
    loadMore: () => {
      this.set({ shown: this.S.shown + 200 });
      void this.loadReceipts(true);
    },
    clearFilters: () => {
      this.set({ vf: "all", rf: "all", q: "" });
      this.hashFor("#/audit");
    },
    openReceipt: (index) => {
      this.hashFor(this.auditHash({ r: index }));
      void this.loadCallDetail(index);
    },
    closeReceipt: () => this.hashFor(this.auditHash({})),
    toggleLive: () => {
      if (this.S.live) this.set({ live: false });
      else {
        this.set({ live: true, pausedNew: 0, tail: this.S.tail === "disconnected" ? "disconnected" : "live" });
        void this.loadReceipts(false);
      }
    },
    decide: (kind) => void this.decide(kind),
    doUnlock: () => void this.doUnlock(),
    lockClick: () => (this.D.session && !this.D.session.locked ? void this.relock() : this.set({ unlockOpen: true })),
    relock: () => void this.relock(),
    toggleTheme: () => {
      const next: ThemeName = this.theme() === "dark" ? "light" : "dark";
      try {
        localStorage.setItem("interlock.theme", next);
      } catch {
        /* not persisted */
      }
      this.set({ themeOverride: next });
      this.applyTheme();
    },
    copy: (key, text) => this.copy(key, text),
    setPolicyText: (text) => {
      this.set({ policyText: text, check: null, policyNote: "" });
      this.draftCheck(text);
    },
    checkDraft: () => {
      const d = this.D.draft;
      if (!d || !d.ok) {
        this.set({ check: null });
        return;
      }
      const applied = this.D.overlays.filter((o) => o.status === "ok").length;
      this.set({
        check: { rules: d.effective, locked: d.locked.length, quar: d.quarantined.length, overlays: applied + " of " + this.D.overlays.length, epoch: d.epoch },
      });
    },
    saveDraft: () => void this.saveDraft(),
    setPreset: (id) => {
      if (id === "real") {
        this.set({ pgPreset: "real" });
        if (!this.D.realCalls) void this.loadRealCalls();
        return;
      }
      if (id === "custom") return;
      const preset = this.D.presets.find((p) => p.id === id);
      if (!preset) return;
      this.set({ pgPreset: id, pg: this.presetToPg(preset) });
      if (this.S.pgRan) this.evaluateSoon();
    },
    updPg: (fn) => {
      const pg: Pg = JSON.parse(JSON.stringify(this.S.pg));
      fn(pg);
      this.set({ pg, pgPreset: "custom" });
      if (this.S.pgRan) this.evaluateSoon();
    },
    runPg: () => {
      this.set({ pgRan: true });
      void this.evaluate();
    },
    resolveScope: () => void this.resolveScope(),
    loadRealCalls: () => void this.loadRealCalls(),
    setRealFilter: (f) => {
      this.set({ rcQ: f.q ?? this.S.rcQ, rcTool: f.tool ?? this.S.rcTool });
      this.realCallsSoon();
    },
    toggleRealCall: (callId) => {
      const sel = this.S.rcSel.includes(callId) ? this.S.rcSel.filter((x) => x !== callId) : [...this.S.rcSel, callId];
      this.set({ rcSel: sel });
    },
    addRealCalls: (replace) => {
      const chosen = (this.D.realCalls ?? []).filter((c) => this.S.rcSel.includes(c.call_id));
      const events = chosen.flatMap((c) => this.eventsOf(c, this.S.rcResults));
      if (!events.length) return;
      this.set({ pg: { rules: this.S.pg.rules, events: replace ? events : [...this.S.pg.events, ...events] }, rcSel: [], pgPreset: "custom" });
      if (this.S.pgRan) this.evaluateSoon();
    },
    openInPlayground: (o) => void this.openInPlayground(o),
    runBacktest: () => void this.runBacktest(),
    runSweep: () => void this.runSweep(),
  };
}
