/**
 * Talk to the daemon: a stand-in for PolicyEngine that lives in another process.
 *
 * A port of `interlock/sidecar/client.py`. `RemoteEngine` duck-types the one
 * method every call site uses, `evaluate(event) -> Decision`, so it drops in
 * wherever an engine is accepted.
 *
 * **Every transport failure rejects with `BlockedError`.** Not a warning, not an
 * allow, not a special exception a caller has to know about: a caller that
 * already handles `BlockedError` gets the fail-closed behaviour for free. A
 * caller running in `monitor` mode is not exempt: an unreachable daemon is an
 * infrastructure failure, not a policy verdict, so it must not be downgraded
 * into a silent pass-through.
 *
 * Two things differ from Python, both forced by the platform:
 *
 * - **`evaluate` is async.** Node has no synchronous unix-socket client, so a
 *   request is a promise. The honest consequence: a synchronous JS tool call
 *   cannot be guarded, because there is no synchronous transport to guard it
 *   with. MCP's `callTool` is already async, so the interceptor fits.
 * - **The lock is a promise chain.** A request/response exchange on a stream
 *   socket cannot be interleaved, so concurrent callers queue behind one
 *   another on the single connection rather than racing on it.
 */

import * as net from "node:net";

import { BlockedError, Decision, Verdict } from "./enforce.js";
import {
  DEFAULT_FALLBACK_MAX_AGE_SECONDS,
  FallbackError,
  type FallbackPolicy,
  UNREACHABLE_LEVELS,
  UNREACHABLE_POLICY_ID,
  type Unreachable,
  fallbackPath,
  readFallback,
  readKeyFile,
} from "./fallback.js";
import type { SensorEvent } from "./event.js";
import {
  MAX_LINE,
  WireError,
  decodeLine,
  encodeFrame,
  parseResponse,
  requestFrame,
} from "./wire.js";

/** The limit `readLine` reads up to: one byte past the accepted frame size. */
const READ_LIMIT = MAX_LINE + 1;

/**
 * Seconds `RemoteEngine` waits for a connect or a reply when no `timeout` is
 * given. A hung daemon then blocks the call after this long instead of hanging
 * it forever. Pass `timeout: null` to wait without limit.
 */
export const DEFAULT_TIMEOUT_SECONDS = 5;

/** An error that names its own cause, so `reasonFor` reports a real type name. */
class SocketTimeout extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SocketTimeout";
  }
}

interface PendingRead {
  limit: number;
  resolve: (line: Buffer | null) => void;
  reject: (err: Error) => void;
}

/**
 * A line-buffered reader over one socket, bounded at `limit` bytes.
 *
 * Mirrors Python's `sock.makefile("rb")` + `readline(limit)`: at most `limit`
 * bytes are returned, and a line that does not fit is truncated at the limit
 * rather than buffered without bound. `null` means clean EOF.
 */
class LineReader {
  private buffer: Buffer = Buffer.alloc(0);
  private ended = false;
  private failure: Error | null = null;
  private pending: PendingRead | null = null;

  private timer: NodeJS.Timeout | null = null;

  /**
   * `timeoutSeconds` bounds how long one `readLine` waits for its reply. It is
   * armed only while a read is pending, never while the connection sits idle
   * between calls: an idle gap is not a hung daemon, and a socket-level idle
   * timeout would turn the first call after a pause into a spurious block.
   */
  constructor(
    private readonly socket: net.Socket,
    private readonly timeoutSeconds: number | null,
  ) {
    socket.on("data", (chunk: Buffer) => {
      this.buffer =
        this.buffer.length === 0 ? chunk : Buffer.concat([this.buffer, chunk]);
      this.flush();
    });
    socket.on("end", () => {
      this.ended = true;
      this.flush();
    });
    socket.on("close", () => {
      this.ended = true;
      this.flush();
    });
    socket.on("error", (err: Error) => this.fail(err));
  }

  fail(err: Error): void {
    this.failure = err;
    this.flush();
  }

  readLine(limit: number): Promise<Buffer | null> {
    if (this.pending !== null) {
      return Promise.reject(
        new WireError("internal", "concurrent read on one connection"),
      );
    }
    return new Promise<Buffer | null>((resolve, reject) => {
      this.pending = {
        limit,
        resolve: (line) => {
          this.clearTimer();
          resolve(line);
        },
        reject: (err) => {
          this.clearTimer();
          reject(err);
        },
      };
      const seconds = this.timeoutSeconds;
      if (seconds !== null) {
        this.timer = setTimeout(() => {
          this.timer = null;
          this.fail(new SocketTimeout(`no reply within ${seconds}s`));
          this.socket.destroy();
        }, seconds * 1000);
      }
      this.flush();
    });
  }

  dispose(): void {
    this.clearTimer();
    this.socket.removeAllListeners();
    // A close can race an 'error' (ECONNRESET) the kernel already queued. Keep a
    // no-op listener so tearing down a dead connection never becomes an
    // uncaught exception in the caller's process.
    this.socket.on("error", () => undefined);
  }

  private clearTimer(): void {
    if (this.timer !== null) {
      clearTimeout(this.timer);
      this.timer = null;
    }
  }

  private flush(): void {
    const pending = this.pending;
    if (pending === null) {
      return;
    }
    const { limit } = pending;
    const newline = this.buffer.indexOf(0x0a);
    if (newline !== -1 && newline + 1 <= limit) {
      this.deliver(this.buffer.subarray(0, newline + 1), pending);
      return;
    }
    if (this.buffer.length >= limit) {
      // Longer than a line may be: hand back a full limit's worth and let the
      // caller refuse it, exactly as `readline(limit)` would.
      this.deliver(this.buffer.subarray(0, limit), pending);
      return;
    }
    if (this.failure !== null) {
      this.pending = null;
      pending.reject(this.failure);
      return;
    }
    if (this.ended) {
      // A trailing partial line is real data (JSON.parse will judge it); only a
      // truly empty buffer is a clean EOF.
      if (this.buffer.length > 0) {
        this.deliver(this.buffer, pending);
      } else {
        this.pending = null;
        pending.resolve(null);
      }
    }
  }

  private deliver(line: Buffer, pending: PendingRead): void {
    this.buffer = this.buffer.subarray(line.length);
    this.pending = null;
    pending.resolve(line);
  }
}

export interface RemoteEngineOptions {
  /**
   * Seconds to wait for the connect and for each reply. Defaults to
   * `DEFAULT_TIMEOUT_SECONDS` (5). `null` disables it. A timeout rejects with
   * `BlockedError`, like any other transport failure.
   */
  timeout?: number | null;
  /**
   * What to do when the daemon is unreachable (no socket, refused, timed out,
   * hung up): `"deny"` (default) blocks; `"degraded"` decides with the fallback
   * policy the sidecar signed (`--fallback-policy`), denying if that file is
   * missing, tampered or stale; `"allow"` lets the call through. Every
   * non-deny decision calls `onFallback` (default: `process.emitWarning`). A
   * daemon that answers with an error frame is reachable: always blocked.
   */
  unreachable?: Unreachable;
  /** Fallback file; default `<path>.fallback.json`. */
  fallbackFile?: string;
  /** The sidecar's `--key-file` key, to verify the fallback file. */
  fallbackKey?: Uint8Array;
  /** Or the key file itself (64 hex characters, or raw bytes). */
  fallbackKeyFile?: string;
  /** Oldest fallback file accepted, in seconds (default 7 days). */
  fallbackMaxAge?: number;
  /** Called once per call decided without the daemon. */
  onFallback?: (message: string) => void;
}

const UNREACHABLE_CODES = new Set([
  "ENOENT", "ECONNREFUSED", "ECONNRESET", "EPIPE", "ENOTSOCK", "EACCES", "ETIMEDOUT",
]);

/** No daemon to ask - as opposed to a live daemon refusing. */
function isUnreachable(exc: unknown): boolean {
  if (exc instanceof SocketTimeout) {
    return true;
  }
  if (exc instanceof WireError) {
    return exc.message === "daemon closed the connection";
  }
  const code = (exc as NodeJS.ErrnoException | null)?.code;
  return typeof code === "string" && UNREACHABLE_CODES.has(code);
}

export class RemoteEngine {
  readonly path: string;
  readonly timeout: number | null;

  private socket: net.Socket | null = null;
  private reader: LineReader | null = null;
  private nextId = 1;
  private tail: Promise<unknown> = Promise.resolve();

  readonly unreachable: Unreachable;
  readonly fallbackFile: string;
  /** How many calls were decided without the daemon. */
  fallbacks = 0;
  private readonly fallbackKey: Uint8Array | null;
  private readonly fallbackMaxAge: number;
  private readonly onFallback: (message: string) => void;

  constructor(path: string, options: RemoteEngineOptions = {}) {
    this.path = String(path);
    this.timeout =
      options.timeout === undefined ? DEFAULT_TIMEOUT_SECONDS : options.timeout;
    this.unreachable = options.unreachable ?? "deny";
    if (!UNREACHABLE_LEVELS.includes(this.unreachable)) {
      throw new TypeError(`unreachable must be one of ${UNREACHABLE_LEVELS.join(", ")}`);
    }
    this.fallbackFile = options.fallbackFile ?? fallbackPath(this.path);
    this.fallbackKey =
      options.fallbackKey ?? (options.fallbackKeyFile ? readKeyFile(options.fallbackKeyFile) : null);
    if (this.unreachable === "degraded" && this.fallbackKey === null) {
      throw new TypeError('unreachable: "degraded" needs fallbackKey or fallbackKeyFile');
    }
    this.fallbackMaxAge = options.fallbackMaxAge ?? DEFAULT_FALLBACK_MAX_AGE_SECONDS;
    this.onFallback =
      options.onFallback ?? ((message: string) => process.emitWarning(message, "InterlockFallback"));
  }

  /** Ask the daemon for the verdict, or reject with `BlockedError`. */
  evaluate(event: SensorEvent): Promise<Decision> {
    return this.runExclusive(async () => {
      try {
        return await this.exchange(event);
      } catch (exc) {
        this.drop();
        if (this.unreachable !== "deny" && isUnreachable(exc)) {
          return this.withoutDaemon(event, exc);
        }
        throw new BlockedError(
          Decision.block(this.reasonFor(exc)),
          event.action,
        );
      }
    });
  }

  private withoutDaemon(event: SensorEvent, exc: unknown): Decision {
    this.fallbacks += 1;
    const why = exc instanceof Error ? `${exc.name}: ${exc.message}` : String(exc);
    if (this.unreachable === "allow") {
      this.onFallback(
        `interlock: guard daemon unreachable at ${this.path} (${why}); ALLOWING ${event.action} unchecked`,
      );
      return Decision.allow(`guard daemon unreachable (${why}); allowed unchecked`, UNREACHABLE_POLICY_ID);
    }
    let policy: FallbackPolicy;
    try {
      policy = readFallback(this.fallbackFile, this.fallbackKey!, this.fallbackMaxAge);
    } catch (problem) {
      const detail = problem instanceof FallbackError ? problem.message : String(problem);
      throw new BlockedError(
        Decision.block(
          `guard daemon unreachable at ${this.path} (${why}) and the fallback policy is unusable: ${detail}; denied fail-closed`,
          UNREACHABLE_POLICY_ID,
        ),
        event.action,
      );
    }
    this.onFallback(
      `interlock: guard daemon unreachable at ${this.path} (${why}); deciding ${event.action} with the offline fallback policy`,
    );
    const decision = policy.evaluate(event);
    if (decision.verdict === Verdict.ALLOW) {
      return Decision.allow("decided by the offline fallback policy", UNREACHABLE_POLICY_ID);
    }
    return new Decision({
      verdict: decision.verdict,
      reason: `[guard daemon unreachable: fallback policy] ${decision.reason}`,
      policy_id: `fallback/${decision.policy_id}`,
      attributed_to: decision.attributed_to,
    });
  }

  /** Drop the connection once every queued call has finished. */
  close(): Promise<void> {
    return this.runExclusive(async () => {
      this.drop();
    });
  }

  // -- internals -----------------------------------------------------------

  /**
   * Serialize on the one connection. The chain continues after a rejection, so
   * a failed call does not wedge every later one.
   */
  private runExclusive<T>(fn: () => Promise<T>): Promise<T> {
    const result = this.tail.then(fn, fn);
    this.tail = result.then(
      () => undefined,
      () => undefined,
    );
    return result;
  }

  private async exchange(event: SensorEvent): Promise<Decision> {
    const opId = `op-${process.pid}-${this.nextId++}`;
    const socket = await this.connect();
    const reader = this.reader;
    if (reader === null) {
      // connect installs it; unreachable in practice.
      throw new WireError("internal", "connection has no reader");
    }
    // Ref only while a reply is outstanding. An idle guard connection must not
    // keep the process alive: a script that guards one call and is done has to
    // exit, rather than wait for a socket it will never use again.
    socket.ref();
    try {
      socket.write(encodeFrame(requestFrame(opId, event)));
      const line = await reader.readLine(READ_LIMIT);
      if (line === null || line.length === 0) {
        throw new WireError("bad_response", "daemon closed the connection");
      }
      if (line.length > MAX_LINE) {
        throw new WireError("too_large", "response exceeded the frame limit");
      }
      return parseResponse(decodeLine(line), opId);
    } finally {
      if (this.socket === socket) {
        socket.unref();
      }
    }
  }

  private connect(): Promise<net.Socket> {
    if (this.socket !== null) {
      return Promise.resolve(this.socket);
    }
    return new Promise<net.Socket>((resolve, reject) => {
      const socket = net.connect({ path: this.path });
      let settled = false;
      const fail = (err: Error) => {
        if (settled) {
          return;
        }
        settled = true;
        socket.removeAllListeners();
        socket.on("error", () => undefined);
        socket.destroy();
        reject(err);
      };
      socket.once("error", (err: Error) => fail(err));
      socket.once("connect", () => {
        if (settled) {
          return;
        }
        settled = true;
        // The reader takes over error and timeout handling from here. The
        // connect timeout is a socket idle timer; disarm it so an idle
        // connection between calls never fires it.
        socket.removeAllListeners("error");
        socket.removeAllListeners("timeout");
        socket.setTimeout(0);
        this.socket = socket;
        this.reader = new LineReader(socket, this.timeout);
        // Idle between calls: let the process exit. `exchange` refs around the
        // one reply it is waiting for.
        socket.unref();
        resolve(socket);
      });
      if (this.timeout !== null) {
        socket.setTimeout(this.timeout * 1000);
        socket.once("timeout", () => {
          fail(new SocketTimeout(`connect to ${this.path} timed out`));
        });
      }
    });
  }

  private drop(): void {
    const reader = this.reader;
    const socket = this.socket;
    this.reader = null;
    this.socket = null;
    if (reader !== null && socket !== null) {
      reader.dispose();
    }
    if (socket !== null) {
      socket.destroy();
    }
  }

  private reasonFor(exc: unknown): string {
    if (exc instanceof WireError) {
      return `guard daemon refused the request (${exc.code}) at ${this.path}: ${exc.message}`;
    }
    const err = exc as { constructor?: { name?: string }; message?: string };
    const name = err?.constructor?.name ?? "Error";
    const message = err?.message ?? String(exc);
    return `guard daemon unreachable at ${this.path}: ${name}: ${message}`;
  }
}

/**
 * True if something is accepting connections at `path`.
 *
 * Used to tell a live daemon from a socket file left behind by a crash, so the
 * second daemon refuses to start instead of unlinking a live socket. Async
 * because Node has no synchronous unix-socket connect; the Python form is not.
 */
export function probe(path: string, timeout = 0.25): Promise<boolean> {
  return new Promise<boolean>((resolve) => {
    const socket = net.connect({ path });
    let settled = false;
    const done = (value: boolean) => {
      if (settled) {
        return;
      }
      settled = true;
      socket.removeAllListeners();
      socket.on("error", () => undefined);
      socket.destroy();
      resolve(value);
    };
    socket.once("connect", () => done(true));
    socket.once("error", () => done(false));
    socket.setTimeout(timeout * 1000, () => done(false));
  });
}
