/**
 * Typed calls to the console's own `/api/` - the only data source the page has.
 *
 * Every endpoint answers its own body or the shared error shape
 * `{"error": {"code", "message"}}`; `ApiError` carries that through. Writes send
 * the tab's unlock token (`X-Interlock-Unlock`), which lives in this tab's
 * `sessionStorage` only: another tab, or a restart of the console, is locked.
 */

export class ApiError extends Error {
  readonly code: string;
  readonly status: number;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
    this.name = "ApiError";
  }
}

const TOKEN_KEY = "interlock.unlock";

export function unlockToken(): string | null {
  try {
    return sessionStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

export function setUnlockToken(token: string | null): void {
  try {
    if (token) sessionStorage.setItem(TOKEN_KEY, token);
    else sessionStorage.removeItem(TOKEN_KEY);
  } catch {
    // storage disabled: the tab simply stays read-only
  }
}

async function call<T>(path: string, init?: { method?: string; body?: unknown }): Promise<T> {
  const headers: Record<string, string> = {};
  const token = unlockToken();
  if (token) headers["X-Interlock-Unlock"] = token;
  if (init?.body !== undefined) headers["Content-Type"] = "application/json";
  let response: Response;
  try {
    response = await fetch(path, {
      method: init?.method ?? "GET",
      headers,
      body: init?.body !== undefined ? JSON.stringify(init.body) : undefined,
    });
  } catch {
    throw new ApiError(0, "unreachable", "the console is not answering");
  }
  let body: unknown = null;
  try {
    body = await response.json();
  } catch {
    // a non-JSON body (a proxy page, a crash) falls through to the error below
  }
  if (!response.ok) {
    const err = (body as { error?: { code?: string; message?: string } } | null)?.error;
    throw new ApiError(response.status, err?.code ?? "http_" + response.status, err?.message ?? "the request failed");
  }
  return body as T;
}

const q = (params: Record<string, string | number | null | undefined>): string => {
  const parts = Object.entries(params)
    .filter(([, value]) => value !== null && value !== undefined && value !== "")
    .map(([key, value]) => encodeURIComponent(key) + "=" + encodeURIComponent(String(value)));
  return parts.length ? "?" + parts.join("&") : "";
};

// --- session and the write gate ---------------------------------------------

export interface Session {
  version: string;
  me: string;
  locked: boolean;
  unlock_shut: boolean;
  four_eyes: boolean;
  receipts_path: string | null;
  key: boolean;
  policy_path: string;
  reviews_db: string;
  home: string;
}

export const fetchSession = () => call<Session>("/api/session");
export const unlock = (code: string) => call<{ token: string }>("/api/unlock", { method: "POST", body: { code } });
export const lock = () => call<{ locked: boolean }>("/api/lock", { method: "POST", body: {} });

// --- receipts -----------------------------------------------------------------

export type Verdict = "ALLOW" | "MODIFY" | "BLOCK" | "ESCALATE";

export interface ReadableReceipt {
  index: number;
  ts: number;
  action: string;
  verdict: Exclude<Verdict, "ESCALATE">;
  reason: string;
  policy_id: string | null;
  attributed_to: string | null;
  principal: string | null;
  span_id: string | null;
  phase: string;
  args_digest: string;
  prev: string;
  mac: string;
  observed?: boolean;
  call_id?: string | null;
  policy_epoch?: string | null;
  policy_verdict?: Verdict | null;
  approval?: string | null;
  outcome?: string | null;
  enforcer?: string | null;
  elapsed_us?: number | null;
  masked?: Record<string, number> | null;
  unreadable?: false;
}

export interface UnreadableReceipt {
  index: number;
  unreadable: true;
}

export type Receipt = ReadableReceipt | UnreadableReceipt;

export interface ReceiptsResponse {
  total: number;
  count_all: number;
  receipts: Receipt[];
  rules: string[];
}

export interface ReceiptQuery {
  verdict?: string | null;
  policy?: string | null;
  q?: string | null;
  offset?: number;
  limit?: number;
  index?: number | null;
}

export const fetchReceipts = (query: ReceiptQuery) => call<ReceiptsResponse>("/api/receipts" + q({ ...query }));

export interface VerifyResponse {
  status: "intact" | "broken" | "unverified";
  problem: string | null;
  count: number;
  head: string;
  broken_index: number | null;
}

export const fetchVerify = () => call<VerifyResponse>("/api/receipts/verify");

export interface ActivitySummary {
  receipts: number;
  decisions: number;
  calls: number;
  results: number;
  sessions: number;
  principals: number;
  verdicts: { ALLOW: number; MODIFY: number; BLOCK: number };
  escalated: number;
  rules: { id: string; count: number; verdicts: Record<string, number> }[];
  blocked: { action: string; count: number }[];
  would: { rule: string; action: string; verdict: Verdict; count: number }[];
  escalations: Record<string, number>;
  failed: number;
  dropped: number;
  masked: Record<string, number>;
  latency: { samples: number; max: number; p50: number; p90: number; p95: number; p99: number; hist: number[] };
  first_ts: number | null;
  last_ts: number | null;
}

export interface Bucket {
  from: number;
  to: number;
  ALLOW: number;
  MODIFY: number;
  BLOCK: number;
  ESC: number;
}

export interface Tick {
  index: number;
  ts: number;
  action: string;
  verdict: Exclude<Verdict, "ESCALATE">;
  policy_verdict: Verdict | null;
  observed: boolean | null;
  policy_id: string | null;
  principal: string | null;
}

export interface ActivityResponse {
  window: string;
  now: number;
  start: number;
  focus: { from: number; to: number } | null;
  summary: ActivitySummary;
  unreadable: number;
  timeline: Bucket[];
  recent: Tick[];
  last_ts: number | null;
  total: number;
}

export const fetchActivity = (window: string, from?: number, to?: number) =>
  call<ActivityResponse>("/api/activity" + q({ window, from, to }));

// --- reviews --------------------------------------------------------------------

export interface Review {
  id: string;
  status: "pending" | "approved" | "rejected" | "revoked" | "expired" | "executed";
  action: string;
  phase: string;
  principal: string | null;
  requester: string | null;
  policy_id: string | null;
  reason: string | null;
  args_digest: string | null;
  preview: string | null;
  created: number;
  pending_until: number;
  decided: number | null;
  approval_until: number | null;
  executed: number | null;
  decided_by: string | null;
  rejection_reason: string | null;
  min_approvals: number;
  approvers: string[];
  next: string;
  self_ok: boolean;
}

export const fetchReviews = () => call<{ configured: boolean; path: string; reviews: Review[] }>("/api/reviews");
export const decideReview = (id: string, action: "approve" | "reject" | "revoke", reason?: string) =>
  call<{ review: Review }>("/api/reviews/" + encodeURIComponent(id) + "/" + action, {
    method: "POST",
    body: reason !== undefined ? { reason } : {},
  });

// --- policy ------------------------------------------------------------------------

export interface PolicyRule {
  id: string | null;
  verdict: string;
  reason: string;
  cond: string;
  detector: string | null;
  phase: string;
  source: "own" | "inherited";
  locked: boolean;
  disabled: boolean;
  quarantined: string | null;
}

export type Analysis =
  | {
      ok: true;
      extends: string | null;
      rules: PolicyRule[];
      pack: PolicyRule[];
      quarantined: string[];
      locked: string[];
      disabled: string[];
      effective: number;
      epoch: string;
    }
  | { ok: false; parse_error: string; line: number | null };

export interface PolicyResponse {
  path: string;
  exists: boolean;
  text: string;
  sha: string | null;
  analysis: Analysis;
  voided?: string[];
}

export const fetchPolicy = () => call<PolicyResponse>("/api/policy");
export const checkPolicy = (text: string) => call<{ analysis: Analysis }>("/api/policy/check", { method: "POST", body: { text } });
export const savePolicy = (text: string, base_sha: string | null) =>
  call<PolicyResponse>("/api/policy", { method: "PUT", body: { text, base_sha } });

export interface Overlay {
  path: string;
  status: "ok" | "untrusted" | "changed" | "missing" | "loosens";
  line: string;
  cmd: string;
  trusted_at: number | null;
  sha: string | null;
}

export const fetchTrust = () => call<{ overlays: Overlay[]; trust_path: string }>("/api/trust");

// --- ops -----------------------------------------------------------------------------

export interface DoctorCheck {
  id: string;
  status: "ok" | "info" | "warn" | "fail";
  summary: string;
  fix: string;
}

export const fetchDoctor = () => call<{ level: "enforced" | "degraded" | "unprotected"; checks: DoctorCheck[] }>("/api/doctor");

export interface Hook {
  agent: string;
  name: string;
  state: "installed" | "monitor mode" | "not installed" | "not on this machine";
  where: string;
  path: string;
  command: string | null;
  cmd: string;
}

export const fetchHooks = () => call<{ hooks: Hook[] }>("/api/hooks");

export interface McpServer {
  name: string;
  client: string;
  scope: string;
  transport: string;
  cmd: string;
  config: string;
  env: string;
  risks: { tag: string; why: string }[];
}

export const fetchMcp = () =>
  call<{ servers: McpServer[]; warnings: string[]; clients_seen: number; clients_known: number }>("/api/mcp");
export const fetchMcpStarter = () => call<{ rule: Record<string, unknown> }>("/api/mcp/starter");

export interface SidecarState {
  state: "healthy" | "unreachable" | "not configured";
  socket: string;
  detail?: string;
  admin: string | null;
  stats?: {
    since: number;
    uptime_seconds?: number;
    decisions: number;
    by_verdict: Record<string, number>;
    escalations: Record<string, number>;
    receipts_dropped: number;
    latency_us: { p99?: number | null; mean?: number | null };
  } | null;
  config?: { epoch?: string | null; fallback_policy?: boolean; rules?: unknown } | null;
}

export const fetchSidecar = () => call<SidecarState>("/api/sidecar");

export interface ReceiptLog {
  configured: boolean;
  path?: string;
  exists?: boolean;
  writable?: boolean;
  key?: boolean;
  dropped?: number;
}

export const fetchReceiptLog = () => call<ReceiptLog>("/api/receipt-log");

// --- catalog, playground, inspector ---------------------------------------------------

export interface DetectorParam {
  name: string;
  kind: string;
  required: boolean;
  default: unknown;
  annotation: string | null;
  default_repr?: boolean;
}

export interface DetectorFactory {
  name: string;
  signature: string;
  params: DetectorParam[];
}

export interface Detector {
  module: string;
  category: string;
  summary: string;
  factories: DetectorFactory[];
  verdicts: string[];
  scope: string;
  configurable: boolean;
}

export interface DetectorDetail extends Detector {
  doc: string;
}

export interface DetectorsResponse {
  count: number;
  categories: { name: string; description: string; modules: string[] }[];
  detectors: Detector[];
}

export const fetchDetectors = () => call<DetectorsResponse>("/api/detectors");
export const fetchDetector = (module: string) => call<DetectorDetail>("/api/detectors/" + encodeURIComponent(module));

export interface PresetRule {
  detector: string;
  factory: string;
  kwargs?: Record<string, unknown>;
}

export interface PresetEvent {
  action: string;
  args?: Record<string, unknown>;
  phase?: "call" | "result";
  principal?: string | null;
}

export interface Preset {
  id: string;
  title: string;
  description: string;
  rules: PresetRule[];
  events: PresetEvent[];
}

export const fetchPresets = () => call<{ presets: Preset[] }>("/api/presets");

export interface EvaluateResult {
  index: number;
  verdict: Verdict;
  verdict_code: number;
  reason: string;
  policy_id: string | null;
  attributed_to: string | null;
  modified_args: unknown;
  modified_result: unknown;
}

export const evaluate = (rules: PresetRule[], events: PresetEvent[]) =>
  call<{ results: EvaluateResult[] }>("/api/evaluate", { method: "POST", body: { rules, events } });

export interface ScopeResolveResponse {
  scope: string[];
  scope_backend: string;
  resolved: Record<string, Record<string, unknown>>;
  sandbox: {
    profile: Record<string, unknown>;
    backend: string;
    enforced: string[];
    not_enforced: string[];
    available_backends: string[];
  };
  decision: EvaluateResult | null;
}

export const fetchScopeExample = () =>
  call<{ document: unknown; principal: string; event: unknown }>("/api/scopes/example");
export const resolveScope = (document: unknown, principal: string, event: unknown) =>
  call<ScopeResolveResponse>("/api/scopes/resolve", { method: "POST", body: { document, principal, event } });

// --- real calls from the agent's transcripts -----------------------------------------

export interface CallReceipt {
  index: number;
  phase: string;
  verdict: string;
  policy_verdict?: string | null;
  policy_id: string | null;
  reason?: string;
  approval?: string | null;
  masked?: Record<string, number> | null;
}

export interface RealCall {
  call_id: string;
  ts: number;
  tool: string;
  target: string;
  cwd: string | null;
  session: string;
  subagent: boolean;
  args: Record<string, unknown>;
  result?: Record<string, unknown>;
  has_result: boolean;
  is_error: boolean;
  result_len: number;
  receipts: CallReceipt[];
}

export const fetchCalls = (limit: number, tool?: string, text?: string) =>
  call<{ root: string; available: boolean; files?: number; calls: RealCall[]; tools: Record<string, number> }>(
    "/api/calls" + q({ limit, tool, q: text }),
  );

export interface CallDetail {
  found: boolean;
  call_id: string;
  searched?: number;
  tool?: string;
  target?: string;
  ts?: number;
  cwd?: string | null;
  session?: string;
  subagent?: boolean;
  transcript?: string;
  args?: Record<string, unknown>;
  result?: string | null;
  result_len?: number;
  is_error?: boolean;
  digest?: { computed: string | null; receipt: string | null; match: boolean | null };
  receipts: CallReceipt[];
}

export const fetchCall = (callId: string, session?: string | null, ts?: number) =>
  call<CallDetail>("/api/calls/" + encodeURIComponent(callId) + q({ session, ts }));

export interface BacktestRow {
  call_id: string;
  ts: number;
  tool: string;
  target: string;
  session: string;
  phase: "call" | "result";
  status: "changed" | "unrecorded";
  would: { verdict: string; policy_id: string | null; reason: string };
  actual: { verdict: string | null; policy_id: string | null; index: number | null } | null;
}

export interface BacktestResult {
  source: "draft" | "saved";
  epoch: string;
  calls: number;
  would: Record<string, number>;
  recorded: number;
  changed: number;
  unrecorded: number;
  rows: BacktestRow[];
  truncated: boolean;
  elapsed_ms: number;
}

export const runBacktest = (limit: number, text?: string) =>
  call<BacktestResult>("/api/policy/backtest", { method: "POST", body: text === undefined ? { limit } : { limit, text } });

export interface SweepDetector {
  module: string;
  factory: string;
  fired: number;
  verdicts: Record<string, number>;
  errors: number;
  examples: { call_id: string; ts: number; tool: string; target: string; phase: string; verdict: string; reason: string; session: string }[];
}

export interface SweepResult {
  calls: number;
  events: number;
  detectors: SweepDetector[];
  skipped: { module: string; factory: string; needs: string[]; error?: string }[];
  elapsed_ms: number;
}

export const runSweep = (limit: number) => call<SweepResult>("/api/detectors/sweep", { method: "POST", body: { limit } });
