/**
 * Intercept outbound HTTP: decide a request before it leaves the process.
 *
 * `fetch` is guarded under the action name `http.fetch` (namespaced, so a
 * policy can tell a raw egress call from an MCP tool that happens to be named
 * "fetch"). The event carries a *narrowed* view of the request - `url`,
 * `method`, `headers`, and a string/Buffer `body` - not the raw `init`.
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

/** The URL a `fetch` call is aimed at, as a string. */
function urlOf(input: unknown): string {
  if (typeof input === "string") {
    return input;
  }
  if (input instanceof URL) {
    return input.href;
  }
  if (isPlainObject(input) && typeof input["url"] === "string") {
    // A `Request` object.
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

/** The policy-visible slice of a `fetch` call. */
function fetchArgs(input: unknown, init: unknown): Record<string, unknown> {
  const out: Record<string, unknown> = { url: urlOf(input) };
  const bag = isPlainObject(init) ? init : {};
  if (typeof bag["method"] === "string") {
    out["method"] = bag["method"];
  }
  const headers = plainHeaders(bag["headers"]);
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
    const safe = await enforceToolCall("http.fetch", fetchArgs(input, init), options);

    // Copy the original init so unprojected fields (signal, credentials, ...)
    // survive, then write back only what the policy saw fit to rewrite.
    const next: Record<string, unknown> = isPlainObject(init) ? { ...init } : {};
    for (const key of ["method", "headers", "body"]) {
      if (Object.prototype.hasOwnProperty.call(safe, key)) {
        next[key] = safe[key];
      }
    }
    const target: unknown = safe["url"] !== url ? safe["url"] : input;
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
