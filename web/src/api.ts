/**
 * Typed fetch helpers for the console's `/api/` surface.
 *
 * Every endpoint answers either a body of its own shape or the shared error
 * shape `{"error": {"code", "message"}}` (see specs/console/01-console-server.md).
 * `ApiError` turns that body into something a page can show a user directly.
 */

export interface HealthResponse {
  status: string;
  version: string;
}

interface ApiErrorBody {
  error: {
    code: string;
    message: string;
  };
}

export class ApiError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.code = code;
    this.name = "ApiError";
  }
}

async function parseJsonResponse<T>(response: Response): Promise<T> {
  const body = (await response.json()) as unknown;
  if (!response.ok) {
    const errorBody = body as ApiErrorBody;
    throw new ApiError(
      errorBody.error?.code ?? "unknown_error",
      errorBody.error?.message ?? "the request failed"
    );
  }
  return body as T;
}

export async function fetchHealth(): Promise<HealthResponse> {
  const response = await fetch("/api/health");
  return parseJsonResponse<HealthResponse>(response);
}

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

export interface DetectorCategory {
  name: string;
  description: string;
  modules: string[];
}

export interface DetectorsResponse {
  count: number;
  categories: DetectorCategory[];
  detectors: Detector[];
}

export async function fetchDetectors(): Promise<DetectorsResponse> {
  const response = await fetch("/api/detectors");
  return parseJsonResponse<DetectorsResponse>(response);
}

export async function fetchDetectorDetail(module: string): Promise<DetectorDetail> {
  const response = await fetch(`/api/detectors/${module}`);
  return parseJsonResponse<DetectorDetail>(response);
}

export interface ReadableReceipt {
  index: number;
  ts: number;
  action: string;
  verdict: string;
  reason: string;
  policy_id: string | null;
  attributed_to: string | null;
  principal: string | null;
  span_id: string | null;
  phase: string;
  args_digest: string;
  observed: boolean;
  prev: string;
  mac: string;
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
}

export interface VerifyResponse {
  status: string;
  problem: string | null;
  count: number;
  head: string;
}

export async function fetchReceipts(): Promise<ReceiptsResponse> {
  const response = await fetch("/api/receipts");
  return parseJsonResponse<ReceiptsResponse>(response);
}

export async function fetchReceiptsVerify(): Promise<VerifyResponse> {
  const response = await fetch("/api/receipts/verify");
  return parseJsonResponse<VerifyResponse>(response);
}

export interface PlaygroundRuleSpec {
  detector: string;
  factory: string;
  kwargs?: Record<string, unknown>;
}

export interface PlaygroundEventSpec {
  action: string;
  args?: Record<string, unknown>;
  phase?: "call" | "result";
  principal?: string | null;
}

export interface Preset {
  id: string;
  title: string;
  description: string;
  rules: PlaygroundRuleSpec[];
  events: PlaygroundEventSpec[];
  expect: string[];
}

export interface PresetsResponse {
  presets: Preset[];
}

export async function fetchPresets(): Promise<PresetsResponse> {
  const response = await fetch("/api/presets");
  return parseJsonResponse<PresetsResponse>(response);
}

export interface EvaluateResult {
  index: number;
  verdict: string;
  verdict_code: number;
  reason: string;
  policy_id: string | null;
  attributed_to: string | null;
  modified_args: unknown;
  modified_result: unknown;
}

export interface EvaluateResponse {
  results: EvaluateResult[];
}

export async function evaluatePlayground(rules: unknown, events: unknown): Promise<EvaluateResponse> {
  const response = await fetch("/api/evaluate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ rules, events }),
  });
  return parseJsonResponse<EvaluateResponse>(response);
}

export interface ScopeExampleResponse {
  document: unknown;
  principal: string;
  event: unknown;
}

export async function fetchScopeExample(): Promise<ScopeExampleResponse> {
  const response = await fetch("/api/scopes/example");
  return parseJsonResponse<ScopeExampleResponse>(response);
}

export interface SandboxProfile {
  read_paths: string[];
  write_paths: string[];
  allow_network: boolean;
  allowed_hosts: string[];
  env_keys: string[];
  cpu_seconds: number | null;
  memory_mb: number | null;
  unshare_pid: boolean;
  workdir: string | null;
}

export interface ScopeSandbox {
  profile: SandboxProfile;
  backend: string;
  enforced: string[];
  not_enforced: string[];
  available_backends: string[];
}

export interface ScopeDecision {
  index: number;
  verdict: string;
  verdict_code: number;
  reason: string;
  policy_id: string | null;
  attributed_to: string | null;
  modified_args: unknown;
  modified_result: unknown;
}

export interface ScopeResolveResponse {
  scope: string[];
  scope_backend: string;
  resolved: Record<string, Record<string, unknown>>;
  sandbox: ScopeSandbox;
  decision: ScopeDecision | null;
}

export async function resolveScope(
  document: unknown,
  principal: string,
  event: unknown
): Promise<ScopeResolveResponse> {
  const response = await fetch("/api/scopes/resolve", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ document, principal, event }),
  });
  return parseJsonResponse<ScopeResolveResponse>(response);
}
