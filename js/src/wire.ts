/**
 * The wire protocol between this client and the Python policy engine.
 *
 * A port of `interlock/wire.py`. Two frames cross a unix socket, both
 * newline-delimited canonical JSON:
 *
 *     request   {"v":1,"id":...,"event":{action,args,principal,span_id,
 *                                        parent_principal,phase,ts}}
 *     response  {"v":1,"id":...,"verdict":0|1|2,"reason":...,"policy_id":...,
 *                "attributed_to":...,"modified_args":...,"modified_result":...}
 *
 * The Python file is the protocol; this is a reader of it. Where the two can
 * disagree, Python wins, and the disagreement is a bug in this file.
 *
 * Two fail-closed choices are inherited deliberately:
 *
 * - **Unknown keys are refused, not ignored.** A client that misspells `args`
 *   as `arg` must not have its arguments silently dropped: an engine shown an
 *   event with no arguments finds no opinion and allows. A permissive parser
 *   turns one typo into an allow-all.
 * - **A rewrite must be transmittable.** A value the codec cannot represent
 *   raises rather than being coerced or dropped, because a sanitizer that
 *   silently declines to sanitize is worse than one that refuses.
 *
 * Two refusals are additions, because JavaScript has failure modes Python does
 * not: `undefined` (which `JSON.stringify` silently *omits* from an object,
 * emptying an argument list) and integers past `Number.MAX_SAFE_INTEGER` (which
 * JSON's doubles silently *corrupt*). Both raise rather than pass.
 */

import { Decision, Verdict } from "./enforce.js";
import type { Phase, SensorEvent } from "./event.js";

export const PROTOCOL_VERSION = 1;

/**
 * One frame per line, both directions. A framed line at or above this is
 * refused rather than read: a bound the peer cannot exceed is what keeps a
 * malformed or hostile client from allocating without limit.
 */
export const MAX_LINE = 8 * 1024 * 1024;

/**
 * The tag marking a value JSON cannot carry. Chosen to be a key no real tool
 * argument uses; decode only converts an object that is *exactly* this shape,
 * so an argument dict that merely contains the key passes through untouched.
 */
const TAG = "__interlock__";
const BYTES = "bytes";

const REQUEST_KEYS: ReadonlySet<string> = new Set(["v", "id", "event"]);
const EVENT_KEYS: ReadonlySet<string> = new Set([
  "action",
  "args",
  "principal",
  "span_id",
  "parent_principal",
  "phase",
  "ts",
]);
const RESPONSE_KEYS: ReadonlySet<string> = new Set([
  "v",
  "id",
  "verdict",
  "reason",
  "policy_id",
  "attributed_to",
  "modified_args",
  "modified_result",
]);
const PHASES: readonly Phase[] = ["call", "result"];

/**
 * A frame that cannot be honoured. `code` is one of the wire codes.
 *
 * Every code is fail-closed at the far end: a client that receives an error has
 * no verdict, so it must block. There is deliberately no code for "a rule
 * raised" - a raising rule is a *denied decision* (the daemon answers with a
 * BLOCK), not a malformed frame, and it is recorded as one.
 */
export class WireError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "WireError";
    this.code = code;
  }
}

export class Unrepresentable extends WireError {
  constructor(message: string) {
    super("unrepresentable", message);
    this.name = "Unrepresentable";
  }
}

// --- canonical JSON ---------------------------------------------------------

function numberToJson(value: number): string {
  // JSON.stringify is the spec-correct number formatter here; the check above
  // has already excluded the non-finite values it would turn into `null`.
  return JSON.stringify(value);
}

function writeCanonical(value: unknown): string {
  if (value === null) {
    return "null";
  }
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "number":
      if (!Number.isFinite(value)) {
        // JSON.stringify(NaN) is "null" - a silent coercion of a value the
        // policy never produced. Python's allow_nan=False refuses; so do we.
        throw new Unrepresentable(
          `value is not JSON-representable: ${String(value)}`,
        );
      }
      return numberToJson(value);
    case "string":
      return JSON.stringify(value);
    case "object":
      break;
    default:
      throw new Unrepresentable(`value is not JSON-representable: ${typeof value}`);
  }
  if (Array.isArray(value)) {
    return `[${value.map(writeCanonical).join(",")}]`;
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  const parts = keys.map(
    (key) => `${JSON.stringify(key)}:${writeCanonical(record[key])}`,
  );
  return `{${parts.join(",")}}`;
}

/**
 * The one serialization used on the wire: sorted keys, tight separators.
 *
 * A dictionary is re-parsed by the daemon, so the two serializers need only
 * agree *semantically*. Two cosmetic differences are known and harmless: this
 * emits non-ASCII raw where Python escapes it to `\uXXXX`, and it prints `1`
 * where Python prints `1.0` for a float (JS has one number type).
 */
export function canonical(value: unknown): string {
  return writeCanonical(value);
}

// --- the value codec --------------------------------------------------------

/** Sort order for set members: by each element's canonical form, as Python does. */
function byCanonical(a: unknown, b: unknown): number {
  const left = canonical(a);
  const right = canonical(b);
  if (left < right) {
    return -1;
  }
  return left > right ? 1 : 0;
}

/**
 * Convert a JavaScript value to JSON, escaping what JSON lacks.
 *
 * Lossy by design, and the losses are named: a `Set` becomes a sorted list (JSON
 * has no set; sorting by canonical form keeps it deterministic for mixed-type
 * members) and a byte array is escaped rather than lost, because tool arguments
 * carry binary and a silently dropped payload is the exact failure this module
 * exists to prevent.
 */
export function encodeValue(value: unknown): unknown {
  if (value === undefined) {
    throw new Unrepresentable(
      "cannot represent undefined (JSON.stringify would silently drop the key)",
    );
  }
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Unrepresentable(`cannot represent a non-finite number: ${String(value)}`);
    }
    if (Number.isInteger(value) && !Number.isSafeInteger(value)) {
      // JSON numbers are doubles: an id past 2^53 would arrive corrupted, and a
      // corrupted path is worse than a refused one.
      throw new Unrepresentable(
        `integer ${value} is outside the range JSON can carry exactly`,
      );
    }
    return value;
  }
  if (typeof value === "bigint") {
    throw new Unrepresentable("cannot represent a bigint; send a string or a safe integer");
  }
  if (value instanceof Uint8Array) {
    // Buffer is a Uint8Array subclass, so this covers both.
    return { [TAG]: BYTES, b64: Buffer.from(value).toString("base64") };
  }
  if (Array.isArray(value)) {
    return value.map(encodeValue);
  }
  if (value instanceof Set) {
    return [...value].map(encodeValue).sort(byCanonical);
  }
  if (typeof value === "function" || typeof value === "symbol") {
    throw new Unrepresentable(`cannot represent a ${typeof value}`);
  }
  const proto: unknown = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) {
    // Map, Date, a class instance: things JSON has no shape for. Refusing beats
    // a lossy repr the policy would then reason about.
    const name = value.constructor?.name ?? "object";
    throw new Unrepresentable(`cannot represent a ${name}`);
  }
  const symbols = Object.getOwnPropertySymbols(value);
  if (symbols.length > 0) {
    // Object.entries skips symbol keys, so they would vanish silently.
    throw new Unrepresentable("object has symbol keys, which JSON cannot carry");
  }
  const out: Record<string, unknown> = {};
  for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
    out[key] = encodeValue(item);
  }
  return out;
}

const B64_RE = /^[A-Za-z0-9+/]*={0,2}$/;

function decodeBase64Strict(text: string): Buffer {
  // Node's Buffer.from(s, "base64") ignores characters outside the alphabet,
  // where Python's b64decode(validate=True) rejects them. A lenient decoder
  // would accept a frame the daemon refuses, so validate here.
  if (text.length % 4 !== 0 || !B64_RE.test(text)) {
    throw new WireError("bad_request", "invalid base64 in bytes envelope");
  }
  const buffer = Buffer.from(text, "base64");
  if (buffer.toString("base64") !== text) {
    throw new WireError("bad_request", "invalid base64 in bytes envelope");
  }
  return buffer;
}

/** Invert `encodeValue` for the shapes it escapes. */
export function decodeValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(decodeValue);
  }
  if (value !== null && typeof value === "object") {
    const record = value as Record<string, unknown>;
    const keys = Object.keys(record);
    if (keys.length === 2 && record[TAG] === BYTES && "b64" in record) {
      const b64 = record["b64"];
      if (typeof b64 !== "string") {
        throw new WireError("bad_request", "bytes envelope b64 must be a string");
      }
      return decodeBase64Strict(b64);
    }
    const out: Record<string, unknown> = {};
    for (const key of keys) {
      out[key] = decodeValue(record[key]);
    }
    return out;
  }
  return value;
}

// --- frames -----------------------------------------------------------------

/** One framed line: canonical JSON plus its newline, as UTF-8 bytes. */
export function encodeFrame(frame: Record<string, unknown>): Buffer {
  return Buffer.from(`${canonical(frame)}\n`, "utf8");
}

/** Parse one line into a frame, checking the version. Takes bytes or str. */
export function decodeLine(line: string | Uint8Array): Record<string, unknown> {
  let text: string;
  if (typeof line === "string") {
    text = line;
  } else {
    try {
      // ignoreBOM: true leaves a leading BOM in place, matching Python's utf-8
      // codec (which does not strip it) rather than TextDecoder's default.
      text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(line);
    } catch (err) {
      throw new WireError(
        "bad_request",
        `frame is not valid UTF-8: ${(err as Error).message}`,
      );
    }
  }
  let frame: unknown;
  try {
    frame = JSON.parse(text);
  } catch (err) {
    throw new WireError("bad_request", `frame is not valid JSON: ${(err as Error).message}`);
  }
  if (frame === null || typeof frame !== "object" || Array.isArray(frame)) {
    throw new WireError("bad_request", "frame must be a JSON object");
  }
  const record = frame as Record<string, unknown>;
  if (record["v"] !== PROTOCOL_VERSION) {
    throw new WireError(
      "bad_version",
      `unsupported protocol version ${JSON.stringify(record["v"])} (expected ${PROTOCOL_VERSION})`,
    );
  }
  return record;
}

function checkKeys(frame: Record<string, unknown>, allowed: ReadonlySet<string>, what: string): void {
  const unknown = Object.keys(frame).filter((key) => !allowed.has(key));
  if (unknown.length > 0) {
    throw new WireError(
      "bad_request",
      `unknown ${what} key(s): ${unknown.sort().join(", ")}`,
    );
  }
}

function optStr(frame: Record<string, unknown>, key: string): string | null {
  const value = frame[key];
  if (value !== undefined && value !== null && typeof value !== "string") {
    throw new WireError("bad_request", `${key} must be a string or null`);
  }
  return value ?? null;
}

/** Build the frame that asks the engine to decide one event. */
export function requestFrame(opId: string, event: SensorEvent): Record<string, unknown> {
  const payload: Record<string, unknown> = {
    action: event.action,
    args: encodeValue(event.args),
    phase: event.phase,
  };
  for (const key of ["principal", "span_id", "parent_principal"] as const) {
    const value = event[key];
    if (value !== null && value !== undefined) {
      payload[key] = value;
    }
  }
  if (event.ts) {
    payload["ts"] = event.ts;
  }
  return { v: PROTOCOL_VERSION, id: opId, event: payload };
}

export interface ParsedRequest {
  opId: string;
  event: SensorEvent;
}

/**
 * Read a request frame into `{opId, event}`.
 *
 * `action` and `args` are required. A missing `args` is refused rather than
 * defaulted to `{}`: an engine shown an empty argument object finds no opinion
 * and allows, so defaulting here would quietly convert a client bug into a
 * bypass.
 */
export function parseRequest(frame: Record<string, unknown>): ParsedRequest {
  checkKeys(frame, REQUEST_KEYS, "request");
  const opId = frame["id"];
  if (typeof opId !== "string" || opId.length === 0) {
    throw new WireError("bad_request", "id must be a non-empty string");
  }

  const rawEvent = frame["event"];
  if (rawEvent === null || typeof rawEvent !== "object" || Array.isArray(rawEvent)) {
    throw new WireError("bad_request", "event must be a JSON object");
  }
  const event = rawEvent as Record<string, unknown>;
  checkKeys(event, EVENT_KEYS, "event");

  const action = event["action"];
  if (typeof action !== "string" || action.length === 0) {
    throw new WireError("bad_request", "event.action must be a non-empty string");
  }
  if (!("args" in event)) {
    throw new WireError("bad_request", "event.args is required");
  }
  const args = event["args"];
  if (args === null || typeof args !== "object" || Array.isArray(args)) {
    throw new WireError("bad_request", "event.args must be a JSON object");
  }

  const phase = event["phase"] ?? "call";
  if (phase !== "call" && phase !== "result") {
    throw new WireError("bad_request", `event.phase must be one of ${PHASES.join(", ")}`);
  }

  const rawTs = event["ts"];
  if (rawTs !== undefined && rawTs !== null) {
    if (typeof rawTs !== "number") {
      throw new WireError("bad_request", "event.ts must be a number");
    }
    if (!Number.isFinite(rawTs)) {
      throw new WireError("bad_request", "event.ts must be finite");
    }
  }

  return {
    opId,
    event: {
      action,
      args: decodeValue(args) as Record<string, unknown>,
      principal: optStr(event, "principal"),
      span_id: optStr(event, "span_id"),
      parent_principal: optStr(event, "parent_principal"),
      phase,
      ts: typeof rawTs === "number" ? rawTs : Date.now() / 1000,
    },
  };
}

/**
 * Build the frame carrying one decision. Raises on an unrepresentable rewrite,
 * which the caller turns into an error frame - the far end then has no verdict
 * and blocks.
 */
export function responseFrame(opId: string, decision: Decision): Record<string, unknown> {
  if (
    decision.modified_args !== null &&
    (typeof decision.modified_args !== "object" || Array.isArray(decision.modified_args))
  ) {
    throw new WireError("internal", "modified_args must be an object or null");
  }
  return {
    v: PROTOCOL_VERSION,
    id: opId,
    verdict: decision.verdict,
    reason: decision.reason,
    policy_id: decision.policy_id,
    attributed_to: decision.attributed_to,
    modified_args: encodeValue(decision.modified_args),
    modified_result: encodeValue(decision.modified_result),
  };
}

/**
 * Read a response frame into a `Decision`, or raise on an error frame.
 *
 * `modified_result` of `null` means "no replacement", matching the in-process
 * path (which applies a MODIFY result only when it is not null). The wire
 * invents no semantics Python lacks, so one conformance corpus can describe
 * both.
 */
export function parseResponse(frame: Record<string, unknown>, opId: string): Decision {
  if ("error" in frame) {
    const error = frame["error"];
    if (error === null || typeof error !== "object" || Array.isArray(error)) {
      throw new WireError("internal", "error must be an object");
    }
    const record = error as Record<string, unknown>;
    throw new WireError(
      typeof record["code"] === "string" ? record["code"] : "internal",
      typeof record["message"] === "string" ? record["message"] : "",
    );
  }
  checkKeys(frame, RESPONSE_KEYS, "response");
  if (frame["id"] !== opId) {
    throw new WireError(
      "bad_request",
      `response id ${JSON.stringify(frame["id"])} does not match request ${JSON.stringify(opId)}`,
    );
  }
  const rawVerdict = frame["verdict"];
  // A JSON `true` is not a verdict: Python's isinstance(bool) guard, restated.
  if (typeof rawVerdict !== "number" || !Number.isInteger(rawVerdict)) {
    throw new WireError("bad_request", "verdict must be an integer");
  }
  if (rawVerdict !== Verdict.ALLOW && rawVerdict !== Verdict.BLOCK && rawVerdict !== Verdict.MODIFY) {
    throw new WireError("bad_request", `unknown verdict ${JSON.stringify(rawVerdict)}`);
  }

  const reason = frame["reason"] ?? "";
  if (typeof reason !== "string") {
    throw new WireError("bad_request", "reason must be a string");
  }

  const modifiedArgs = frame["modified_args"];
  if (
    modifiedArgs !== undefined &&
    modifiedArgs !== null &&
    (typeof modifiedArgs !== "object" || Array.isArray(modifiedArgs))
  ) {
    throw new WireError("bad_request", "modified_args must be an object or null");
  }

  const rawResult = frame["modified_result"] ?? null;

  return new Decision({
    verdict: rawVerdict,
    reason,
    policy_id: optStr(frame, "policy_id"),
    modified_args:
      modifiedArgs === undefined || modifiedArgs === null
        ? null
        : (decodeValue(modifiedArgs) as Record<string, unknown>),
    attributed_to: optStr(frame, "attributed_to"),
    modified_result: decodeValue(rawResult),
  });
}

/**
 * Build the frame that answers a request with a failure instead of a verdict.
 * The far end must treat any of these as a block.
 */
export function errorFrame(opId: string, code: string, message: string): Record<string, unknown> {
  return { v: PROTOCOL_VERSION, id: opId, error: { code, message } };
}
