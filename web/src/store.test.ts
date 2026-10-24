/**
 * The chain badge is only trustworthy while it describes the bytes on disk:
 * a receipt event marks the last verify stale immediately (even while the
 * audit view is paused), and a verify that resolves before the next receipt
 * clears the mark. A verify that was already in flight when a receipt
 * arrived must not clear it.
 */
import { afterEach, expect, test, vi } from "vitest";

vi.mock("./api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./api")>();
  return { ...actual, fetchVerify: vi.fn() };
});

import * as api from "./api";
import type { VerifyResponse } from "./api";
import { ConsoleStore } from "./store";

class FakeEventSource {
  static last: FakeEventSource | null = null;
  listeners: Record<string, ((event: Event) => void)[]> = {};
  onerror: ((event: Event) => void) | null = null;

  constructor(public url: string) {
    FakeEventSource.last = this;
  }

  addEventListener(name: string, fn: (event: Event) => void) {
    (this.listeners[name] ??= []).push(fn);
  }

  close() {
    /* the test drives events itself */
  }

  emit(name: string) {
    (this.listeners[name] ?? []).forEach((fn) => fn(new Event(name)));
  }
}

const intact = {
  status: "intact",
  problem: null,
  count: 3,
  head: "a".repeat(64),
  broken_index: null,
  expected_head: null,
} as VerifyResponse;

const internals = (store: ConsoleStore) =>
  store as unknown as { connectStream(): void; loadVerify(): Promise<void> };

afterEach(() => {
  vi.useRealTimers();
  delete (globalThis as { EventSource?: unknown }).EventSource;
});

test("a receipt marks the chain stale and a successful verify clears it", async () => {
  vi.useFakeTimers();
  (globalThis as { EventSource?: unknown }).EventSource = FakeEventSource;
  vi.mocked(api.fetchVerify).mockResolvedValue(intact);

  const store = new ConsoleStore();
  internals(store).connectStream();
  expect(store.S.verifyStale).toBe(false);

  FakeEventSource.last!.emit("receipt");
  expect(store.S.verifyStale).toBe(true);

  await internals(store).loadVerify();
  expect(store.S.verifyStale).toBe(false);
  expect(store.D.verify).toEqual(intact);

  store.stop();
});

test("a receipt arriving during a verify keeps the badge stale", async () => {
  vi.useFakeTimers();
  (globalThis as { EventSource?: unknown }).EventSource = FakeEventSource;
  let resolve: (value: VerifyResponse) => void = () => {};
  vi.mocked(api.fetchVerify).mockReturnValue(new Promise((r) => { resolve = r; }));

  const store = new ConsoleStore();
  internals(store).connectStream();
  FakeEventSource.last!.emit("receipt");

  const pending = internals(store).loadVerify();
  FakeEventSource.last!.emit("receipt");
  resolve(intact);
  await pending;

  expect(store.S.verifyStale).toBe(true);

  store.stop();
});
