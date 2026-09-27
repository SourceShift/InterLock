/**
 * The wire, as a unit: canonical JSON, the value codec, and the frames.
 *
 * Three groups of claims, in the order the module makes them:
 *
 * 1. **parity** - behaviour `interlock/wire.py` also has, so a divergence is a
 *    bug in this port;
 * 2. **JS-only refusals** - `undefined`, unsafe integers, symbols, `NaN`. Things
 *    `JSON.stringify` would silently drop or corrupt, which Python's codec never
 *    meets and this one must refuse;
 * 3. **the response contract** - a verdict is an integer, `null` means "no
 *    replacement", and an error frame is not a verdict.
 */
import assert from "node:assert/strict";
import test from "node:test";

import { Decision, Verdict } from "../src/enforce.js";
import { sensorEvent } from "../src/event.js";
import {
  MAX_LINE,
  PROTOCOL_VERSION,
  Unrepresentable,
  WireError,
  canonical,
  decodeLine,
  decodeValue,
  encodeFrame,
  encodeValue,
  errorFrame,
  parseRequest,
  parseResponse,
  requestFrame,
  responseFrame,
} from "../src/wire.js";

function isWireError(code: string): (err: unknown) => boolean {
  return (err) => err instanceof WireError && err.code === code;
}

test("canonical: sorted keys, tight separators", () => {
  assert.equal(
    canonical({ b: 1, a: [2, { d: 4, c: 3 }] }),
    '{"a":[2,{"c":3,"d":4}],"b":1}',
  );
});

test("canonical: refuses the non-finite numbers JSON would turn into null", () => {
  assert.throws(() => canonical(NaN), Unrepresentable);
  assert.throws(() => canonical(Infinity), Unrepresentable);
  assert.throws(() => canonical(-Infinity), Unrepresentable);
});

test("the frozen constants match the protocol", () => {
  assert.equal(PROTOCOL_VERSION, 1);
  assert.equal(MAX_LINE, 8 * 1024 * 1024);
});

test("encodeValue: bytes become a tagged envelope, and decodeValue inverts it", () => {
  const encoded = encodeValue(Buffer.from([0x00, 0x01, 0xff]));
  assert.deepEqual(encoded, { __interlock__: "bytes", b64: "AAH/" });
  const decoded = decodeValue(encoded);
  assert.ok(Buffer.isBuffer(decoded));
  assert.ok((decoded as Buffer).equals(Buffer.from([0x00, 0x01, 0xff])));
});

test("decodeValue: strict base64 - a lenient decoder would accept what the daemon refuses", () => {
  // Node's Buffer.from(s, "base64") ignores the invalid characters below.
  assert.throws(
    () => decodeValue({ __interlock__: "bytes", b64: "AAH" }),
    isWireError("bad_request"),
  );
  assert.throws(
    () => decodeValue({ __interlock__: "bytes", b64: "AA!?" }),
    isWireError("bad_request"),
  );
});

test("decodeValue: only the exact envelope is converted", () => {
  assert.deepEqual(decodeValue({ __interlock__: "bytes" }), {
    __interlock__: "bytes",
  });
  assert.deepEqual(
    decodeValue({ __interlock__: "bytes", b64: "AAH/", extra: 1 }),
    { __interlock__: "bytes", b64: "AAH/", extra: 1 },
  );
});

test("encodeValue: a Set becomes a sorted list", () => {
  assert.deepEqual(encodeValue(new Set([3, 1, 2])), [1, 2, 3]);
});

test("encodeValue: undefined is refused, not dropped", () => {
  // JSON.stringify({a: undefined}) is "{}" - the key vanishes and the engine
  // sees an argument-less event that finds no opinion and allows.
  assert.throws(() => encodeValue(undefined), Unrepresentable);
  assert.throws(() => encodeValue({ a: undefined }), Unrepresentable);
});

test("encodeValue: an integer past the safe range is refused, not corrupted", () => {
  assert.equal(encodeValue(Number.MAX_SAFE_INTEGER), Number.MAX_SAFE_INTEGER);
  assert.throws(() => encodeValue(Number.MAX_SAFE_INTEGER + 1), Unrepresentable);
});

test("encodeValue: bigint, Map, Date and class instances have no JSON form", () => {
  class Widget {
    readonly kind = "widget";
  }
  assert.throws(() => encodeValue(10n), Unrepresentable);
  assert.throws(() => encodeValue(new Map()), Unrepresentable);
  assert.throws(() => encodeValue(new Date()), Unrepresentable);
  assert.throws(() => encodeValue(new Widget()), Unrepresentable);
});

test("encodeValue: symbol keys are refused - Object.entries would skip them", () => {
  const tagged = { a: 1 } as Record<PropertyKey, unknown>;
  tagged[Symbol("hidden")] = 2;
  assert.throws(() => encodeValue(tagged), Unrepresentable);
});

test("encodeFrame: one canonical line plus its newline", () => {
  const frame = encodeFrame({ v: 1, id: "op-1", event: { action: "ping" } });
  assert.equal(
    frame.toString("utf8"),
    '{"event":{"action":"ping"},"id":"op-1","v":1}\n',
  );
});

test("decodeLine: refuses bad JSON, non-objects, and a wrong version", () => {
  assert.throws(() => decodeLine("{"), isWireError("bad_request"));
  assert.throws(() => decodeLine("[]"), isWireError("bad_request"));
  assert.throws(
    () => decodeLine('{"v":2,"id":"x"}'),
    isWireError("bad_version"),
  );
  assert.throws(() => decodeLine(Buffer.from([0xff, 0xfe])), isWireError("bad_request"));
});

test("requestFrame / parseRequest round-trip every field a rule can read", () => {
  const event = sensorEvent({
    action: "read_file",
    args: { path: "/etc/passwd", nested: { n: 1 } },
    principal: "agent-a",
    span_id: "span-9",
    parent_principal: "root-agent",
    phase: "result",
  });
  const parsed = parseRequest(requestFrame("op-7", event));
  assert.equal(parsed.opId, "op-7");
  assert.equal(parsed.event.action, "read_file");
  assert.deepEqual(parsed.event.args, { path: "/etc/passwd", nested: { n: 1 } });
  assert.equal(parsed.event.principal, "agent-a");
  assert.equal(parsed.event.span_id, "span-9");
  assert.equal(parsed.event.parent_principal, "root-agent");
  assert.equal(parsed.event.phase, "result");
});

test("parseRequest: refuses exactly what the daemon refuses", () => {
  const bad = (frame: Record<string, unknown>): void => {
    assert.throws(() => parseRequest(frame), isWireError("bad_request"));
  };
  bad({ v: 1, id: "x", event: { action: "ping", args: {}, extra: 1 } });
  bad({ v: 1, id: "x", event: { action: "ping", arg: {} } });
  bad({ v: 1, id: "x", event: { action: "ping" } });
  bad({ v: 1, id: "x", event: { action: "ping", args: [] } });
  bad({ v: 1, id: "x", event: { action: "ping", args: {}, phase: "Result" } });
  bad({ v: 1, id: "x", event: { action: "ping", args: {} }, extra: 1 });
  bad({ v: 1, id: "", event: { action: "ping", args: {} } });
});

test("parseRequest: phase defaults to call and ts defaults to now", () => {
  const parsed = parseRequest({
    v: 1,
    id: "op-1",
    event: { action: "ping", args: {} },
  });
  assert.equal(parsed.event.phase, "call");
  assert.ok(Math.abs(parsed.event.ts - Date.now() / 1000) < 5);
});

const OK_RESPONSE: Record<string, unknown> = {
  v: 1,
  id: "op-1",
  verdict: 1,
  reason: "etc is off limits",
  policy_id: "p.no-etc",
  attributed_to: "path",
  modified_args: null,
  modified_result: null,
};

test("parseResponse: a decision survives the frame intact", () => {
  const decision = parseResponse({ ...OK_RESPONSE }, "op-1");
  assert.equal(decision.verdict, Verdict.BLOCK);
  assert.equal(decision.verdictName, "BLOCK");
  assert.equal(decision.reason, "etc is off limits");
  assert.equal(decision.policy_id, "p.no-etc");
  assert.equal(decision.attributed_to, "path");
});

test("parseResponse: a verdict must be an integer - a JSON true is not one", () => {
  assert.throws(
    () => parseResponse({ ...OK_RESPONSE, verdict: true }, "op-1"),
    isWireError("bad_request"),
  );
  assert.throws(
    () => parseResponse({ ...OK_RESPONSE, verdict: 3 }, "op-1"),
    isWireError("bad_request"),
  );
  assert.throws(
    () => parseResponse({ ...OK_RESPONSE, verdict: 1.5 }, "op-1"),
    isWireError("bad_request"),
  );
});

test("parseResponse: the id must echo the request, and unknown keys are refused", () => {
  assert.throws(
    () => parseResponse({ ...OK_RESPONSE, id: "other" }, "op-1"),
    isWireError("bad_request"),
  );
  assert.throws(
    () => parseResponse({ ...OK_RESPONSE, junk: 1 }, "op-1"),
    isWireError("bad_request"),
  );
});

test("parseResponse: null means no replacement; false, 0, '' do not", () => {
  assert.equal(parseResponse({ ...OK_RESPONSE, modified_result: null }, "op-1").modified_result, null);
  assert.equal(parseResponse({ ...OK_RESPONSE, modified_result: false }, "op-1").modified_result, false);
  assert.equal(parseResponse({ ...OK_RESPONSE, modified_result: 0 }, "op-1").modified_result, 0);
  assert.equal(parseResponse({ ...OK_RESPONSE, modified_result: "" }, "op-1").modified_result, "");
});

test("parseResponse: an error frame raises a WireError carrying its code", () => {
  assert.throws(
    () => parseResponse(errorFrame("op-1", "unrepresentable", "no JSON form"), "op-1"),
    isWireError("unrepresentable"),
  );
});

test("responseFrame: raises on a rewrite the wire cannot carry", () => {
  assert.throws(
    () => responseFrame("op-1", Decision.modify({ bad: undefined } as Record<string, unknown>)),
    Unrepresentable,
  );
});

test("responseFrame: a decision encodes to the frozen response keys", () => {
  const frame = responseFrame("op-1", Decision.block("nope", "p.x", "path"));
  assert.deepEqual(Object.keys(frame).sort(), [
    "attributed_to",
    "id",
    "modified_args",
    "modified_result",
    "policy_id",
    "reason",
    "v",
    "verdict",
  ]);
  assert.equal(frame["verdict"], Verdict.BLOCK);
});
