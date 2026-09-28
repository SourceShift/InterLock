/**
 * Run the real sidecar daemon as a child process, and speak to it raw.
 *
 * Unlike the Python suite, which hosts the daemon in-process, the JS tests
 * spawn `python -m interlock.sidecar` - the same CLI a deployment runs. That is
 * the honest boundary: the client only ever talks to a daemon over a socket, so
 * the test should exercise the thing the client actually meets.
 *
 * Two deliberate choices:
 *
 * - **A failure to start FAILS the suite, with the daemon's stderr.** A skipped
 *   conformance test is a green suite that proves nothing.
 * - **The socket lives in a short `/tmp` directory.** AF_UNIX paths are capped
 *   near 104 bytes; the pytest/macOS `tmp_path` is far longer than that.
 */
import { spawn, type ChildProcess } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import * as net from "node:net";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { RemoteEngine, probe } from "../src/client.js";
import { MAX_LINE, decodeLine } from "../src/wire.js";

const HERE = dirname(fileURLToPath(import.meta.url));

/** `js/dist-test/test/` -> the repository root (where `interlock/` is importable). */
export const REPO_ROOT = resolve(HERE, "..", "..", "..");
export const CORPUS_PATH = join(REPO_ROOT, "tests", "conformance", "events.json");
export const CONFORMANCE_RULES = "interlock.testing.fixtures:CONFORMANCE_ENGINE";
/** The rules for the native effect actions (`fs.*`, `child_process.*`, `http.fetch`). */
export const EFFECT_RULES = "interlock.testing.fixtures:EFFECT_ENGINE";

export function delay(ms: number): Promise<void> {
  return new Promise((done) => setTimeout(done, ms));
}

function socketDir(): string {
  return mkdtempSync(join("/tmp", "il-"));
}

export interface SpawnOptions {
  /** A `MODULE:ATTR` rules spec; defaults to the conformance engine. */
  rules?: string;
  /** The interpreter to run; defaults to `$PYTHON` then `python3`. */
  python?: string;
  /** A path for `--receipts`, if the test wants a receipt chain. */
  receipts?: string;
  /** How long to wait for the socket to accept connections, in ms. */
  timeout?: number;
}

/**
 * A daemon running as a child process.
 *
 * `ready()` resolves once the socket accepts a connection. After that, any
 * unexpected exit is a test failure: `assertAlive` turns a dead daemon into a
 * loud error carrying its stderr, rather than an ambiguous timeout downstream.
 */
export class Daemon {
  readonly dir: string;
  readonly path: string;

  private readonly child: ChildProcess;
  private stderrText = "";
  private exitInfo: { code: number | null; signal: NodeJS.Signals | null } | null = null;
  private stopping = false;

  constructor(dir: string, path: string, child: ChildProcess) {
    this.dir = dir;
    this.path = path;
    this.child = child;
    child.stderr?.setEncoding("utf8");
    child.stderr?.on("data", (chunk: string) => {
      this.stderrText += chunk;
    });
    child.on("exit", (code, signal) => {
      this.exitInfo = { code, signal };
    });
  }

  get stderr(): string {
    return this.stderrText;
  }

  private exitReport(): string | null {
    if (this.exitInfo === null) {
      return null;
    }
    return `daemon exited (code=${this.exitInfo.code}, signal=${this.exitInfo.signal})\n${this.stderrText}`;
  }

  /** Resolve once the socket is accepting, or throw with the daemon's stderr. */
  async ready(): Promise<void> {
    const deadline = Date.now() + 15_000;
    while (Date.now() < deadline) {
      const report = this.exitReport();
      if (report !== null) {
        throw new Error(`the guard daemon could not start: ${report}`);
      }
      if (await probe(this.path, 0.25)) {
        return;
      }
      await delay(20);
    }
    throw new Error(
      `the guard daemon did not become ready within 15s\n${this.stderrText}`,
    );
  }

  /** Throw if the daemon died while a test was driving it. */
  assertAlive(context: string): void {
    const report = this.exitReport();
    if (report !== null && !this.stopping) {
      throw new Error(`the guard daemon died during ${context}: ${report}`);
    }
  }

  /** Terminate the daemon and remove its socket directory. */
  async stop(): Promise<void> {
    this.stopping = true;
    if (this.exitInfo === null) {
      await new Promise<void>((done) => {
        const timer = setTimeout(() => this.child.kill("SIGKILL"), 5_000);
        this.child.once("exit", () => {
          clearTimeout(timer);
          done();
        });
        this.child.kill("SIGTERM");
      });
    }
    rmSync(this.dir, { recursive: true, force: true });
  }
}

export async function spawnDaemon(options: SpawnOptions = {}): Promise<Daemon> {
  const python = options.python ?? process.env["PYTHON"] ?? "python3";
  const rules = options.rules ?? CONFORMANCE_RULES;
  const dir = socketDir();
  const path = join(dir, "g.sock");
  const args = ["-m", "interlock.sidecar", "--rules", rules, "--socket", path];
  if (options.receipts !== undefined) {
    args.push("--receipts", options.receipts);
  }
  const child = spawn(python, args, {
    cwd: REPO_ROOT,
    stdio: ["ignore", "ignore", "pipe"],
  });
  const daemon = new Daemon(dir, path, child);
  await daemon.ready();
  return daemon;
}

export interface GuardedContext {
  engine: RemoteEngine;
  /** A scratch directory for the test's own files. */
  dir: string;
  daemon: Daemon;
}

/**
 * Run `body` against a live daemon and a scratch directory, tearing both down.
 *
 * The interceptors patch process-global module objects, so every test that
 * installs one must uninstall it; this gives the daemon and temp dir the same
 * guaranteed cleanup without repeating the boilerplate in five files.
 */
export async function withEngine(
  rules: string,
  body: (ctx: GuardedContext) => Promise<void>,
): Promise<void> {
  const daemon = await spawnDaemon({ rules });
  const engine = new RemoteEngine(daemon.path, { timeout: 5 });
  const dir = mkdtempSync(join("/tmp", "il-work-"));
  try {
    await body({ engine, dir, daemon });
  } finally {
    await engine.close();
    await daemon.stop();
    rmSync(dir, { recursive: true, force: true });
  }
}

/**
 * Send one line to a daemon at `path` and read one frame back; `{}` on EOF.
 *
 * Exists for the frames a client would never build: the negatives. A malformed
 * line has to reach the socket as bytes, which `RemoteEngine` deliberately will
 * not do.
 */
export function sendRaw(
  path: string,
  line: string,
  timeout = 15_000,
): Promise<Record<string, unknown>> {
  return new Promise<Record<string, unknown>>((resolve, reject) => {
    const socket = net.connect({ path });
    let buffer = Buffer.alloc(0);
    let settled = false;
    const finish = (fn: () => void): void => {
      if (settled) {
        return;
      }
      settled = true;
      socket.removeAllListeners();
      // The oversized negative writes far more than the daemon reads, so it may
      // close the connection while bytes are still buffered here. Swallow the
      // resulting EPIPE/ECONNRESET: the reply is already in hand.
      socket.on("error", () => undefined);
      socket.destroy();
      fn();
    };
    const parse = (raw: Buffer): void => {
      finish(() => {
        try {
          resolve(decodeLine(raw));
        } catch (err) {
          reject(err as Error);
        }
      });
    };
    socket.on("connect", () => {
      const framed = line.endsWith("\n") ? line : `${line}\n`;
      socket.write(Buffer.from(framed, "utf8"));
    });
    socket.on("data", (chunk: Buffer) => {
      buffer = Buffer.concat([buffer, chunk]);
      const newline = buffer.indexOf(0x0a);
      if (newline !== -1) {
        parse(buffer.subarray(0, newline + 1));
      } else if (buffer.length > MAX_LINE) {
        parse(buffer.subarray(0, MAX_LINE + 1));
      }
    });
    socket.on("end", () => {
      finish(() => {
        if (buffer.length === 0) {
          resolve({});
          return;
        }
        try {
          resolve(decodeLine(buffer));
        } catch (err) {
          reject(err as Error);
        }
      });
    });
    socket.on("error", (err: Error) => finish(() => reject(err)));
    socket.setTimeout(timeout, () =>
      finish(() => reject(new Error(`sendRaw timed out after ${timeout}ms`))),
    );
  });
}
