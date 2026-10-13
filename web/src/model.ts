/**
 * The console's state: what the person is doing (`State`) and what the
 * server last said (`Data`). Kept apart so the view-model can be a pure
 * function of both.
 */
import type {
  ActivityResponse,
  Analysis,
  DetectorDetail,
  DetectorsResponse,
  DoctorCheck,
  EvaluateResult,
  Hook,
  McpServer,
  Overlay,
  PolicyResponse,
  Preset,
  Receipt,
  ReceiptLog,
  Review,
  ScopeResolveResponse,
  Session,
  SidecarState,
  VerifyResponse,
} from "./api";
import type { ThemeName } from "./format";

export interface Route {
  path: string;
  id: string | null;
  q: Record<string, string>;
}

export function parseHash(hash: string): Route {
  const h = (hash || "#/").replace(/^#/, "") || "/";
  const [p, qs] = h.split("?");
  const parts = p.split("/").filter(Boolean);
  const q: Record<string, string> = {};
  (qs || "").split("&").forEach((kv) => {
    if (!kv) return;
    const [k, v] = kv.split("=");
    q[k] = decodeURIComponent(v || "");
  });
  return { path: parts[0] || "activity", id: parts[1] ? decodeURIComponent(parts.slice(1).join("/")) : null, q };
}

export type Win = "30m" | "24h" | "7d";
export type TailKind = "connecting" | "live" | "paused" | "disconnected" | "reset";

export interface PgRule {
  module: string;
  factory: string;
  params: Record<string, string>;
}

export interface PgEvent {
  action: string;
  phase: "call" | "result";
  principal: string;
  args: string;
}

export interface Pg {
  rules: PgRule[];
  events: PgEvent[];
}

export interface State {
  route: Route;
  now: number;
  w: number;
  themeOverride: ThemeName | null;
  // write gate
  unlockOpen: boolean;
  unlockVal: string;
  unlockErr: string;
  keysOpen: boolean;
  navOpen: boolean;
  // activity
  win: Win;
  focusV: string | null;
  selB: number | null;
  hovB: number | null;
  hovR: number | null;
  // audit
  live: boolean;
  pausedNew: number;
  tail: TailKind;
  vf: string;
  rf: string;
  q: string;
  shown: number;
  // reviews
  revTab: "pending" | "approved" | "history";
  rejectReason: string;
  busy: "approve" | "reject" | "revoke" | null;
  flash: string;
  copied: string;
  // policy
  policyText: string;
  polTab: "rules" | "edit" | "overlays" | "pack";
  check: { rules: number; locked: number; quar: number; overlays: string; epoch: string } | null;
  saveOpen: boolean;
  saving: boolean;
  /** The last save's outcome, shown under the save button. */
  policyNote: string;
  // playground
  pgPreset: string;
  pg: Pg;
  pgRan: boolean;
  // catalog
  catQ: string;
  catCat: string;
  // inspector
  insDoc: string;
  insPrincipal: string;
  insEvent: string;
  insOut: ScopeResolveResponse | null;
  insErr: string | null;
}

export interface Data {
  session: Session | null;
  connDown: boolean;
  activity: ActivityResponse | null;
  activityErr: string | null;
  focusAct: ActivityResponse | null;
  reviews: Review[];
  reviewsConfigured: boolean;
  receipts: Receipt[];
  receiptsTotal: number;
  receiptsAll: number;
  receiptRules: string[];
  receiptsErr: string | null;
  receiptsLoaded: boolean;
  selReceipt: Receipt | null;
  verify: VerifyResponse | null;
  policy: PolicyResponse | null;
  draft: Analysis | null;
  overlays: Overlay[];
  catalog: DetectorsResponse | null;
  details: Record<string, DetectorDetail>;
  presets: Preset[];
  pgResults: EvaluateResult[] | null;
  pgErrs: Record<number, { msg: string; line: number }>;
  pgApiErr: string | null;
  doctor: { level: "enforced" | "degraded" | "unprotected"; checks: DoctorCheck[] } | null;
  hooks: Hook[];
  mcp: { servers: McpServer[]; warnings: string[]; clients_seen: number; clients_known: number } | null;
  sidecar: SidecarState | null;
  receiptLog: ReceiptLog | null;
}

export const initialState = (): State => ({
  route: parseHash(window.location.hash),
  now: Date.now(),
  w: typeof window !== "undefined" ? window.innerWidth : 1280,
  themeOverride: (() => {
    try {
      const t = localStorage.getItem("interlock.theme");
      return t === "light" || t === "dark" ? t : null;
    } catch {
      return null;
    }
  })(),
  unlockOpen: false,
  unlockVal: "",
  unlockErr: "",
  keysOpen: false,
  navOpen: false,
  win: "24h",
  focusV: null,
  selB: null,
  hovB: null,
  hovR: null,
  live: true,
  pausedNew: 0,
  tail: "connecting",
  vf: "all",
  rf: "all",
  q: "",
  shown: 200,
  revTab: "pending",
  rejectReason: "",
  busy: null,
  flash: "",
  copied: "",
  policyText: "",
  polTab: "rules",
  check: null,
  saveOpen: false,
  saving: false,
  policyNote: "",
  pgPreset: "",
  pg: { rules: [], events: [] },
  pgRan: false,
  catQ: "",
  catCat: "all",
  insDoc: "",
  insPrincipal: "",
  insEvent: "",
  insOut: null,
  insErr: null,
});

export const initialData = (): Data => ({
  session: null,
  connDown: false,
  activity: null,
  activityErr: null,
  focusAct: null,
  reviews: [],
  reviewsConfigured: false,
  receipts: [],
  receiptsTotal: 0,
  receiptsAll: 0,
  receiptRules: [],
  receiptsErr: null,
  receiptsLoaded: false,
  selReceipt: null,
  verify: null,
  policy: null,
  draft: null,
  overlays: [],
  catalog: null,
  details: {},
  presets: [],
  pgResults: null,
  pgErrs: {},
  pgApiErr: null,
  doctor: null,
  hooks: [],
  mcp: null,
  sidecar: null,
  receiptLog: null,
});
