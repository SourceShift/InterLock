import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { App } from "./App";

beforeEach(() => {
  vi.stubGlobal(
    "fetch",
    vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ status: "ok", version: "0.0.0" }),
    })
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
  window.location.hash = "";
});

describe("App", () => {
  it("renders the overview and its nav bar at the root route", async () => {
    window.location.hash = "#/";
    render(<App />);
    expect(screen.getByTestId("nav-catalog")).toBeTruthy();
    await waitFor(() => expect(screen.getByTestId("health-status")).toBeTruthy());
  });

  it("renders the catalog page at #/catalog", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          count: 1,
          categories: [{ name: "Category A", description: "d", modules: ["mod_one"] }],
          detectors: [
            {
              module: "mod_one",
              category: "Category A",
              summary: "A detector.",
              factories: [{ name: "mod_one_rule", signature: "()", params: [] }],
              verdicts: ["ALLOW"],
              scope: "any call",
              configurable: false,
            },
          ],
        }),
      })
    );

    window.location.hash = "#/catalog";
    render(<App />);
    await waitFor(() => expect(screen.getByTestId("detector-row")).toBeTruthy());
  });
});
