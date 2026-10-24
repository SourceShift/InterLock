/**
 * Intercept outbound HTTP: decide a request before it leaves the process.
 *
 * `fetch` is guarded under the action name `http.fetch` (namespaced, so a
 * policy can tell a raw egress call from an MCP tool that happens to be named
 * "fetch"). The event carries a *narrowed* view of the request - `url`,
 * `method`, `headers`, and a string/Buffer `body` - not the raw `init`. A
 * `Request` input is recognised as such and contributes its own `url`, `method`
 * and `headers`; an explicit `init` still overrides them.
 *
 * ## Why the view is narrowed
 *
 * `fetch(url, init)` is a bag, not a positional list, and the bag holds values
 * the wire codec must refuse: a streaming `body`, an `AbortSignal`, a `Headers`
 * instance. Passing them through unchanged would turn every mid-stream upload
 * into a `unrepresentable` error, which the client fails closed on - a guard
 * that blocks legitimate traffic is a denial-of-service primitive, so those
 * fields are omitted from the event rather than smuggled in. A `Headers`
 * instance is flattened to a plain object, since its contents *are* what a
 * policy wants to match; a stream body is documented as not inspected.
 *
 * ## What is not guarded, and why
 *
 * `http.request` / `https.request` / `http.get` / `https.get` are **not**
 * intercepted. Each returns a `ClientRequest` synchronously, so a guard that must
 * await a verdict cannot return one - the same constraint that excludes
 * `spawn`. `fetch` is the promise-native surface, and it is the one an HTTP egress
 * policy belongs on. `installInterceptors()` reports this in `uncovered`.
 */

import { isPlainObject } from "./enforce.js";
import type { EnforceOptions } from "./mcp.js";
import { enforceToolCall } from "./mcp.js";

/** Is `input` a `Request`? Guarded, so a runtime without one does not throw. */
function isRequest(input: unknown): input is Request {
  return typeof Request !== "undefined" && input instanceof Request;
}

/** The URL a `fetch` call is aimed at, as a string. */
function urlOf(input: unknown): string {
  if (typeof input === "string") {
    return input;
  }
  if (input instanceof URL) {
    return input.href;
  }
  if (isRequest(input)) {
    return input.url;
  }
  if (isPlainObject(input) && typeof input["url"] === "string") {
    return input["url"] as string;
  }
  return String(input);
}

/** Flatten a `Headers` instance (or accept a plain object); else `undefined`. */
function plainHeaders(value: unknown): Record<string, string> | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (isPlainObject(value)) {
    return value as Record<string, string>;
  }
  const headers = value as { entries?: () => Iterable<[string, string]> };
  if (typeof headers.entries === "function") {
    return Object.fromEntries(headers.entries());
  }
  return undefined;
}

/**
 * The policy-visible slice of a `fetch` call.
 *
 * A `Request` input contributes its `url`, `method` and flattened `headers`; an
 * explicit `init` overrides any of them, exactly as it does for the real call.
 * Its body is deliberately not read: inspecting it would consume the stream the
 * caller still means to send.
 */
function fetchArgs(input: unknown, init: unknown): Record<string, unknown> {
  const out: Record<string, unknown> = { url: urlOf(input) };
  const bag = isPlainObject(init) ? init : {};
  const request = isRequest(input) ? input : undefined;
  const method =
    typeof bag["method"] === "string" ? bag["method"] : request?.method;
  if (typeof method === "string") {
    out["method"] = method;
  }
  const headers = plainHeaders(
    bag["headers"] !== undefined ? bag["headers"] : request?.headers,
  );
  if (headers !== undefined) {
    out["headers"] = headers;
  }
  const body = bag["body"];
  if (typeof body === "string" || Buffer.isBuffer(body)) {
    out["body"] = body;
  }
  return out;
}

export interface FetchPatch {
  covered: string[];
  uninstall(): void;
}

/**
 * Guard `globalThis.fetch` for this process. Returns an uninstaller.
 *
 * A runtime with no global `fetch` (Node < 18) is not an error: nothing is
 * patched and `covered` is empty.
 */
export function patchFetch(options: EnforceOptions): FetchPatch {
  const original = globalThis.fetch as typeof fetch | undefined;
  if (typeof original !== "function") {
    return { covered: [], uninstall: () => undefined };
  }

  type FetchInput = Parameters<typeof fetch>[0];
  type FetchInit = Parameters<typeof fetch>[1];

  const wrapped = async (
    input: FetchInput,
    init?: FetchInit,
  ): Promise<Response> => {
    const url = urlOf(input);
    const projected = fetchArgs(input, init);
    const safe = await enforceToolCall("http.fetch", projected, options);

    // Copy the original init so unprojected fields (signal, credentials, ...)
    // survive, then write back only what the policy actually changed - a value
    // identical to the projected view is the caller's own, not a rewrite.
    const next: Record<string, unknown> = isPlainObject(init) ? { ...init } : {};
    for (const key of ["method", "headers", "body"]) {
      if (
        Object.prototype.hasOwnProperty.call(safe, key) &&
        !Object.is(safe[key], projected[key])
      ) {
        next[key] = safe[key];
      }
    }

    // A rewritten url changes what must be fetched. For a Request input the
    // original carries method, headers and signal, so rebuild around a *clone*:
    // passing the Request itself as `init` transfers its body, which marks the
    // caller's Request used as soon as the rebuilt request is read. The clone
    // shares the body source but leaves the original untouched, so the body is
    // forwarded rather than inspected. A body already used or locked cannot be
    // cloned (and could not have been fetched either), so that rejects rather
    // than silently sending an empty body - fail-closed, and documented.
    let target: unknown = input;
    if (safe["url"] !== url) {
      target = isRequest(input)
        ? new Request(safe["url"] as string, input.clone())
        : safe["url"];
    }
    return original(target as FetchInput, next as FetchInit);
  };

  globalThis.fetch = wrapped as typeof fetch;
  return {
    covered: ["http.fetch"],
    uninstall(): void {
      globalThis.fetch = original;
    },
  };
}
