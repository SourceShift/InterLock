/**
 * The offline fallback policy a sidecar publishes for when it is unreachable.
 *
 * A port of `interlock/sidecar/fallback.py`; read that module for the design.
 * `RemoteEngine` uses this only with `unreachable: "degraded"`: when the daemon
 * cannot be reached, the call is decided by the last fallback policy the
 * sidecar signed. A missing, unsigned, tampered or stale file denies.
 *
 * The file carries the policy as a JSON *string* and the MAC covers
 * `"<written_at>\n<policy>"` exactly, so this client and the Python one verify
 * the same bytes without agreeing on a JSON canonicalization.
 */
import { createHmac, timingSafeEqual } from "node:crypto";
import { createRequire } from "node:module";

import { Decision, Verdict } from "./enforce.js";
import type { SensorEvent } from "./event.js";

export type Unreachable = "deny" | "degraded" | "allow";
export const UNREACHABLE_LEVELS: readonly Unreachable[] = ["deny", "degraded", "allow"];
export const UNREACHABLE_POLICY_ID = "sidecar_unreachable";
export const FALLBACK_SUFFIX = ".fallback.json";
export const DEFAULT_FALLBACK_MAX_AGE_SECONDS = 7 * 86400;

const OPERATORS = new Set([
  "eq", "ne", "in", "not_in", "gt", "ge", "lt", "le", "contains", "startswith",
  "endswith", "glob", "exists",
]);
const RULE_KEYS = new Set(["id", "verdict", "reason", "when", "locked", "on", "description", "phase"]);
const EVENT_FIELDS = new Set(["action", "principal", "phase", "span_id", "parent_principal", "call_id"]);
const MISSING = Symbol("missing");

const require_ = createRequire(import.meta.url);

/**
 * `fs.readFileSync`, required at call time rather than imported at link time.
 *
 * This module is reachable from `client.js`, which the ESM-hook preload imports
 * *before* it can register the loader. A static `import { readFileSync } from
 * "node:fs"` would link `node:fs` first, caching the unpatched module record
 * for the whole process - and the loader could no longer replace it. Keeping the
 * link lazy is what lets `node --import interlock-guard/esm-hook` close the
 * named-import hole instead of inheriting it.
 */
function readFileSync(path: string): Buffer;
function readFileSync(path: string, encoding: "utf8"): string;
function readFileSync(path: string, encoding?: "utf8"): Buffer | string {
  const fs = require_("node:fs") as typeof import("node:fs");
  return encoding === undefined ? fs.readFileSync(path) : fs.readFileSync(path, encoding);
}

export class FallbackError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "FallbackError";
  }
}

export function fallbackPath(socketPath: string): string {
  return String(socketPath) + FALLBACK_SUFFIX;
}

/** Read a key file the way the sidecar does: 64 hex characters, or raw bytes. */
export function readKeyFile(path: string): Uint8Array {
  let raw = readFileSync(path);
  while (raw.length > 0 && (raw[raw.length - 1] === 0x0a || raw[raw.length - 1] === 0x0d)) {
    raw = raw.subarray(0, raw.length - 1);
  }
  if (raw.length === 64 && /^[0-9a-fA-F]{64}$/.test(raw.toString("ascii"))) {
    return new Uint8Array(Buffer.from(raw.toString("ascii"), "hex"));
  }
  if (raw.length === 0) {
    throw new FallbackError(`key file ${path} is empty`);
  }
  return new Uint8Array(raw);
}

type Condition = (event: SensorEvent) => { name: string | null } | null;

export interface FallbackPolicy {
  evaluate(event: SensorEvent): Decision;
  readonly rules: number;
}

/** The verified fallback policy, compiled. Throws `FallbackError` otherwise. */
export function readFallback(
  path: string,
  key: Uint8Array,
  maxAgeSeconds = DEFAULT_FALLBACK_MAX_AGE_SECONDS,
  nowSeconds = Date.now() / 1000,
): FallbackPolicy {
  let body: unknown;
  try {
    body = JSON.parse(readFileSync(path, "utf8"));
  } catch (exc) {
    const code = (exc as NodeJS.ErrnoException).code;
    throw new FallbackError(
      code === "ENOENT" ? `no fallback policy at ${path}` : `unreadable fallback policy: ${String(exc)}`,
    );
  }
  if (body === null || typeof body !== "object" || (body as Record<string, unknown>)["version"] !== 1) {
    throw new FallbackError("not a fallback policy file");
  }
  const { written_at: writtenAt, policy, mac } = body as Record<string, unknown>;
  if (!Number.isInteger(writtenAt) || typeof policy !== "string" || typeof mac !== "string") {
    throw new FallbackError("fallback policy is unsigned or malformed");
  }
  const expected = createHmac("sha256", key).update(`${writtenAt}\n${policy}`, "utf8").digest();
  const given = Buffer.from(mac, "hex");
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) {
    throw new FallbackError("fallback policy signature does not verify");
  }
  const age = nowSeconds - (writtenAt as number);
  if (age > maxAgeSeconds) {
    throw new FallbackError(`fallback policy is stale (${Math.round(age)}s old)`);
  }
  return compileFallback(JSON.parse(policy));
}

/** Compile an offline policy document; throws `FallbackError` on anything outside the subset. */
export function compileFallback(doc: unknown): FallbackPolicy {
  if (doc === null || typeof doc !== "object" || Array.isArray(doc)) {
    throw new FallbackError("a fallback policy must be an object");
  }
  const rules = (doc as Record<string, unknown>)["rules"];
  if (!Array.isArray(rules) || rules.length === 0) {
    throw new FallbackError("a fallback policy needs at least one rule");
  }
  const compiled = rules.map((raw, index) => compileRule(raw, `rules[${index}]`));
  return {
    rules: compiled.length,
    evaluate(event: SensorEvent): Decision {
      let escalation: Decision | null = null;
      for (const rule of compiled) {
        const decision = rule(event);
        if (decision === null) {
          continue;
        }
        if (decision.verdict === Verdict.BLOCK) {
          return decision;
        }
        escalation = escalation ?? decision;
      }
      return escalation ?? Decision.allow();
    },
  };
}

function compileRule(raw: unknown, where: string): (event: SensorEvent) => Decision | null {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new FallbackError(`${where}: not an object`);
  }
  const rule = raw as Record<string, unknown>;
  for (const key of Object.keys(rule)) {
    if (!RULE_KEYS.has(key)) {
      throw new FallbackError(`${where}: offline rules cannot use ${key}`);
    }
  }
  const id = rule["id"];
  const verdict = rule["verdict"];
  if (typeof id !== "string" || (verdict !== "block" && verdict !== "escalate")) {
    throw new FallbackError(`${where}: needs an id and verdict block or escalate`);
  }
  const reason = typeof rule["reason"] === "string" ? (rule["reason"] as string) : id;
  const phase = rule["phase"] ?? "call";
  const scope = rule["on"] === undefined ? null : actionCondition(rule["on"], where);
  const when = compileCondition(rule["when"], `${where}.when`);
  return (event: SensorEvent) => {
    if ((event.phase ?? "call") !== phase) {
      return null;
    }
    if (scope !== null && scope(event) === null) {
      return null;
    }
    const hit = when(event);
    if (hit === null) {
      return null;
    }
    return verdict === "block"
      ? Decision.block(reason, id, hit.name)
      : Decision.escalate(reason, id, hit.name);
  };
}

function compileCondition(raw: unknown, where: string): Condition {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw) || Object.keys(raw).length === 0) {
    throw new FallbackError(`${where}: not a condition`);
  }
  const cond = raw as Record<string, unknown>;
  for (const key of ["all", "any"] as const) {
    if (key in cond) {
      const parts = cond[key];
      if (!Array.isArray(parts) || parts.length === 0) {
        throw new FallbackError(`${where}: ${key} needs a list`);
      }
      const subs = parts.map((p, i) => compileCondition(p, `${where}.${key}[${i}]`));
      if (key === "all") {
        return (event) => {
          let name: string | null = null;
          for (const sub of subs) {
            const hit = sub(event);
            if (hit === null) {
              return null;
            }
            name = name ?? hit.name;
          }
          return { name };
        };
      }
      return (event) => {
        for (const sub of subs) {
          const hit = sub(event);
          if (hit !== null) {
            return hit;
          }
        }
        return null;
      };
    }
  }
  if ("not" in cond) {
    const sub = compileCondition(cond["not"], `${where}.not`);
    return (event) => (sub(event) === null ? { name: null } : null);
  }
  const keys = Object.keys(cond);
  if (keys.length === 1 && keys[0] === "action") {
    return actionCondition(cond["action"], where);
  }
  const subject = "field" in cond ? "field" : "arg" in cond ? "arg" : null;
  if (subject === null) {
    throw new FallbackError(`${where}: unknown condition`);
  }
  const name = cond[subject];
  if (typeof name !== "string" || (subject === "field" && !EVENT_FIELDS.has(name))) {
    throw new FallbackError(`${where}: bad ${subject}`);
  }
  const ops = keys.filter((k) => k !== subject);
  if (ops.length !== 1 || !OPERATORS.has(ops[0]!)) {
    throw new FallbackError(`${where}: offline operators are ${[...OPERATORS].sort().join(", ")}`);
  }
  const test = operator(ops[0]!, cond[ops[0]!], where);
  return (event) => {
    const value =
      subject === "field"
        ? ((event as unknown as Record<string, unknown>)[name] ?? null)
        : lookup(event.args, name);
    return test(value) ? { name: subject === "arg" ? name : null } : null;
  };
}

function actionCondition(value: unknown, where: string): Condition {
  if (typeof value === "string") {
    return (event) => (event.action === value ? { name: null } : null);
  }
  if (Array.isArray(value) && value.length > 0 && value.every((v) => typeof v === "string")) {
    const names = new Set(value as string[]);
    return (event) => (names.has(event.action) ? { name: null } : null);
  }
  if (value !== null && typeof value === "object" && typeof (value as Record<string, unknown>)["glob"] === "string") {
    const pattern = globToRegExp((value as Record<string, string>)["glob"]!);
    return (event) => (pattern.test(event.action) ? { name: null } : null);
  }
  throw new FallbackError(`${where}: bad action`);
}

function lookup(args: Record<string, unknown>, path: string): unknown {
  let current: unknown = args;
  for (const part of path.split(".")) {
    if (Array.isArray(current) && /^\d+$/.test(part) && Number(part) < current.length) {
      current = current[Number(part)];
    } else if (current !== null && typeof current === "object" && !Array.isArray(current)
      && Object.prototype.hasOwnProperty.call(current, part)) {
      current = (current as Record<string, unknown>)[part];
    } else {
      return MISSING;
    }
  }
  return current;
}

function isNumber(v: unknown): v is number {
  return typeof v === "number";
}

function operator(op: string, operand: unknown, where: string): (value: unknown) => boolean {
  switch (op) {
    case "exists":
      return (v) => (v !== MISSING && v !== null && v !== undefined) === operand;
    case "eq":
      return (v) => v !== MISSING && v === operand;
    case "ne":
      return (v) => v === MISSING || v !== operand;
    case "in":
    case "not_in": {
      if (!Array.isArray(operand)) {
        throw new FallbackError(`${where}: ${op} takes a list`);
      }
      const values = operand as unknown[];
      return op === "in"
        ? (v) => v !== MISSING && values.includes(v)
        : (v) => v === MISSING || !values.includes(v);
    }
    case "gt":
    case "ge":
    case "lt":
    case "le": {
      if (!isNumber(operand)) {
        throw new FallbackError(`${where}: ${op} takes a number`);
      }
      const n = operand;
      const cmp = { gt: (a: number) => a > n, ge: (a: number) => a >= n, lt: (a: number) => a < n, le: (a: number) => a <= n }[op];
      return (v) => isNumber(v) && cmp(v);
    }
    case "contains":
      return (v) => (typeof v === "string" && typeof operand === "string" && v.includes(operand))
        || (Array.isArray(v) && v.includes(operand));
    case "startswith":
      return (v) => typeof v === "string" && typeof operand === "string" && v.startsWith(operand);
    case "endswith":
      return (v) => typeof v === "string" && typeof operand === "string" && v.endsWith(operand);
    case "glob": {
      if (typeof operand !== "string") {
        throw new FallbackError(`${where}: glob takes a string`);
      }
      const pattern = globToRegExp(operand);
      return (v) => typeof v === "string" && pattern.test(v);
    }
    default:
      throw new FallbackError(`${where}: unknown operator ${op}`);
  }
}

/** Python's `fnmatch.fnmatchcase`: `*`, `?`, `[seq]`, `[!seq]`, whole-string. */
export function globToRegExp(pattern: string): RegExp {
  let out = "";
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i]!;
    if (c === "*") {
      out += "[\\s\\S]*";
    } else if (c === "?") {
      out += "[\\s\\S]";
    } else if (c === "[") {
      const end = pattern.indexOf("]", i + 2);
      if (end < 0) {
        out += "\\[";
        continue;
      }
      let body = pattern.slice(i + 1, end);
      const negate = body.startsWith("!");
      if (negate) {
        body = body.slice(1);
      }
      body = body.replace(/\\/g, "\\\\").replace(/\^/g, "\\^").replace(/\]/g, "\\]");
      out += `[${negate ? "^" : ""}${body}]`;
      i = end;
    } else {
      out += c.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&");
    }
  }
  return new RegExp(`^${out}$`);
}
