/**
 * Desktop alerts: a pending review is announced once per browser, never on
 * the first run (which would fire one notification for every review already
 * queued), and never while the toggle is off. Turning the toggle on
 * announces what is already waiting, once.
 */
import { afterEach, beforeEach, expect, test, vi } from "vitest";

vi.mock("./api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./api")>();
  return { ...actual, fetchReviews: vi.fn() };
});

import * as api from "./api";
import type { Review } from "./api";
import { ConsoleStore } from "./store";

class FakeNotification {
  static permission: NotificationPermission = "granted";
  static requestPermission = vi.fn(async () => FakeNotification.permission);
  static instances: FakeNotification[] = [];
  onclick: (() => void) | null = null;
  close = vi.fn();
  constructor(
    public title: string,
    public options?: NotificationOptions,
  ) {
    FakeNotification.instances.push(this);
  }
}

const rev = (id: string, status: Review["status"] = "pending"): Review => ({
  id,
  status,
  action: "Bash",
  phase: "call",
  principal: "claude-code",
  requester: "admin",
  policy_id: "privilege",
  reason: "running a command as another user",
  args_digest: null,
  preview: "{}",
  created: 1,
  pending_until: 2,
  decided: null,
  approval_until: null,
  executed: null,
  decided_by: null,
  rejection_reason: null,
  min_approvals: 1,
  approvers: [],
  next: "wait",
  self_ok: true,
});

const serve = async (store: ConsoleStore, reviews: Review[]) => {
  vi.mocked(api.fetchReviews).mockResolvedValue({ configured: true, path: "/x", reviews });
  await (store as unknown as { loadReviews(): Promise<void> }).loadReviews();
};

const toggle = (store: ConsoleStore) =>
  (store as unknown as { toggleAlerts(): Promise<void> }).toggleAlerts();

beforeEach(() => {
  localStorage.clear();
  FakeNotification.instances = [];
  FakeNotification.permission = "granted";
  FakeNotification.requestPermission.mockReset();
  FakeNotification.requestPermission.mockImplementation(async () => FakeNotification.permission);
  (globalThis as { Notification?: unknown }).Notification = FakeNotification;
});

afterEach(() => {
  delete (globalThis as { Notification?: unknown }).Notification;
  vi.mocked(api.fetchReviews).mockReset();
});

test("the first run adopts what is queued without announcing it", async () => {
  localStorage.setItem("interlock.alerts", "on");
  const store = new ConsoleStore();
  expect(store.S.alerts).toBe("on");

  await serve(store, [rev("r-a"), rev("r-b")]);

  expect(FakeNotification.instances).toEqual([]);
});

test("a newly filed review notifies exactly once", async () => {
  localStorage.setItem("interlock.alerts", "on");
  const store = new ConsoleStore();
  await serve(store, [rev("r-a")]);

  await serve(store, [rev("r-a"), rev("r-b")]);
  const [n] = FakeNotification.instances;
  expect(FakeNotification.instances).toHaveLength(1);
  expect(n.title).toContain("approval");
  expect(n.options?.body).toContain("Bash");
  expect(n.options?.body).toContain("running a command as another user");
  expect(n.options?.tag).toBe("r-b");

  await serve(store, [rev("r-a"), rev("r-b")]);
  expect(FakeNotification.instances).toHaveLength(1);
});

test("a review that is no longer pending is never announced", async () => {
  localStorage.setItem("interlock.alerts", "on");
  const store = new ConsoleStore();
  await serve(store, []);

  await serve(store, [rev("r-c", "approved"), rev("r-d", "rejected")]);

  expect(FakeNotification.instances).toEqual([]);
});

test("with alerts off nothing fires, but the ids are remembered", async () => {
  const store = new ConsoleStore();
  expect(store.S.alerts).toBe("off");
  await serve(store, [rev("r-a")]);

  await serve(store, [rev("r-a"), rev("r-b")]);

  expect(FakeNotification.instances).toEqual([]);
  expect(JSON.parse(localStorage.getItem("interlock.alerts.seen") ?? "[]")).toContain("r-b");
});

test("turning alerts on asks the browser and announces what is waiting", async () => {
  FakeNotification.permission = "default";
  FakeNotification.requestPermission.mockImplementation(async () => {
    FakeNotification.permission = "granted";
    return "granted";
  });
  const store = new ConsoleStore();
  expect(store.S.alerts).toBe("off");
  await serve(store, [rev("r-a"), rev("r-b")]);

  await toggle(store);

  expect(FakeNotification.requestPermission).toHaveBeenCalledTimes(1);
  expect(store.S.alerts).toBe("on");
  expect(localStorage.getItem("interlock.alerts")).toBe("on");
  expect(FakeNotification.instances.map((n) => n.options?.tag)).toEqual(["r-a", "r-b"]);
});

test("turning alerts off writes nothing and stops the next announcement", async () => {
  localStorage.setItem("interlock.alerts", "on");
  const store = new ConsoleStore();
  await serve(store, [rev("r-a")]);
  await toggle(store);

  expect(store.S.alerts).toBe("off");
  await serve(store, [rev("r-a"), rev("r-b")]);
  expect(FakeNotification.instances).toEqual([]);
});

test("a browser that blocked notifications says so and asks nothing", async () => {
  FakeNotification.permission = "denied";
  const store = new ConsoleStore();
  expect(store.S.alerts).toBe("denied");

  await toggle(store);

  expect(FakeNotification.requestPermission).not.toHaveBeenCalled();
  expect(store.S.alerts).toBe("denied");
});

test("a large batch is capped at three plus a count", async () => {
  localStorage.setItem("interlock.alerts", "on");
  const store = new ConsoleStore();
  await serve(store, []);

  await serve(store, ["r-1", "r-2", "r-3", "r-4", "r-5"].map((id) => rev(id)));

  expect(FakeNotification.instances.map((n) => n.options?.tag)).toEqual(["r-1", "r-2", "r-3", "interlock-more"]);
  expect(FakeNotification.instances[3].title).toContain("2 more reviews");
});
