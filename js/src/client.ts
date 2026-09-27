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

import { BlockedError, Decision } from "./enforce.js";
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

  constructor(
    private readonly socket: net.Socket,
    timeoutSeconds: number | null,
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
    if (timeoutSeconds !== null) {
      socket.setTimeout(timeoutSeconds * 1000);
      socket.on("timeout", () => {
        this.fail(new SocketTimeout(`no reply within ${timeoutSeconds}s`));
        socket.destroy();
      });
    }
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
      this.pending = { limit, resolve, reject };
      this.flush();
    });
  }

  dispose(): void {
    this.socket.removeAllListeners();
    // A close can race an 'error' (ECONNRESET) the kernel already queued. Keep a
    // no-op listener so tearing down a dead connection never becomes an
    // uncaught exception in the caller's process.
    this.socket.on("error", () => undefined);
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
  /** Seconds to wait for connect and for each reply. `null` disables it. */
  timeout?: number | null;
}

export class RemoteEngine {
  readonly path: string;
  readonly timeout: number | null;

  private socket: net.Socket | null = null;
  private reader: LineReader | null = null;
  private nextId = 1;
  private tail: Promise<unknown> = Promise.resolve();

  constructor(path: string, options: RemoteEngineOptions = {}) {
    this.path = String(path);
    this.timeout = options.timeout ?? null;
  }

  /** Ask the daemon for the verdict, or reject with `BlockedError`. */
  evaluate(event: SensorEvent): Promise<Decision> {
    return this.runExclusive(async () => {
      try {
        return await this.exchange(event);
      } catch (exc) {
        this.drop();
        throw new BlockedError(
          Decision.block(this.reasonFor(exc)),
          event.action,
        );
      }
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
    socket.write(encodeFrame(requestFrame(opId, event)));
    const line = await reader.readLine(READ_LIMIT);
    if (line === null || line.length === 0) {
      throw new WireError("bad_response", "daemon closed the connection");
    }
    if (line.length > MAX_LINE) {
      throw new WireError("too_large", "response exceeded the frame limit");
    }
    return parseResponse(decodeLine(line), opId);
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
        // The reader takes over error and timeout handling from here.
        socket.removeAllListeners("error");
        socket.removeAllListeners("timeout");
        this.socket = socket;
        this.reader = new LineReader(socket, this.timeout);
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
