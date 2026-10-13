import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { Catalog } from "./Catalog";

const DETECTORS_BODY = {
  count: 3,
  categories: [
    {
      name: "Category A",
      description: "First category.",
      modules: ["mod_one", "mod_two"],
    },
    {
      name: "Category B",
      description: "Second category.",
      modules: ["mod_three"],
    },
  ],
  detectors: [
    {
      module: "mod_one",
      category: "Category A",
      summary: "First detector.",
      factories: [{ name: "mod_one_rule", signature: "()", params: [] }],
      verdicts: ["ALLOW"],
      scope: "any call",
      configurable: false,
    },
    {
      module: "mod_two",
      category: "Category A",
      summary: "Second detector mentions shell_injection in its summary.",
      factories: [{ name: "mod_two_rule", signature: "(limit=1)", params: [] }],
      verdicts: ["BLOCK"],
      scope: "any call",
      configurable: false,
    },
    {
      module: "mod_three",
      category: "Category B",
      summary: "Third detector.",
      factories: [{ name: "mod_three_rule", signature: "()", params: [] }],
      verdicts: ["MODIFY"],
      scope: "tool results",
      configurable: false,
    },
  ],
};

function stubFetch() {
  vi.stubGlobal(
    "fetch",
    vi.fn().mockImplementation((url: string) => {
      if (url === "/api/detectors") {
        return Promise.resolve({ ok: true, json: async () => DETECTORS_BODY });
      }
      if (url === "/api/detectors/mod_one") {
        return Promise.resolve({
          ok: true,
          json: async () => ({ ...DETECTORS_BODY.detectors[0], doc: "Full mod_one docstring." }),
        });
      }
      return Promise.resolve({
        ok: false,
        json: async () => ({ error: { code: "unknown_detector", message: "no such detector" } }),
      });
    })
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("Catalog", () => {
  it("renders one row per detector, grouped under one header per category", async () => {
    stubFetch();
    render(<Catalog />);

    await waitFor(() => {
      expect(screen.getAllByTestId("detector-row")).toHaveLength(3);
    });
    expect(screen.getAllByTestId("category-header")).toHaveLength(2);
  });

  it("filters rows case-insensitively and hides category headers with no match", async () => {
    stubFetch();
    render(<Catalog />);

    await waitFor(() => {
      expect(screen.getAllByTestId("detector-row")).toHaveLength(3);
    });

    fireEvent.change(screen.getByTestId("catalog-search"), {
      target: { value: "SHELL_INJECTION" },
    });

    await waitFor(() => {
      expect(screen.getAllByTestId("detector-row")).toHaveLength(1);
    });
    const headers = screen.getAllByTestId("category-header");
    expect(headers).toHaveLength(1);
    expect(headers[0].textContent).toBe("Category A");
    expect(screen.getByTestId("detector-row").textContent).toContain("shell_injection");
  });

  it("opens the detail panel with factory signatures, verdicts, scope, and the docstring", async () => {
    stubFetch();
    render(<Catalog />);

    await waitFor(() => {
      expect(screen.getAllByTestId("detector-row")).toHaveLength(3);
    });

    fireEvent.click(screen.getAllByTestId("detector-row")[0]);

    await waitFor(() => {
      expect(screen.getByTestId("detector-detail")).toBeTruthy();
    });
    const detail = screen.getByTestId("detector-detail");
    expect(detail.textContent).toContain("any call");
    expect(detail.textContent).toContain("ALLOW");
    expect(detail.textContent).toContain("Full mod_one docstring.");
    const signatures = screen.getAllByTestId("factory-signature");
    expect(signatures.length).toBeGreaterThan(0);
    expect(signatures[0].textContent).toContain("(");
    expect(screen.getByTestId("try-in-playground").getAttribute("href")).toBe(
      "#/playground?detector=mod_one"
    );
  });
});
