import { afterEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { Overview } from "./Overview";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("Overview", () => {
  it("shows ok and the version once the health check answers", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ status: "ok", version: "9.9.9" }),
      })
    );

    render(<Overview />);

    await waitFor(() => {
      const el = screen.getByTestId("health-status");
      expect(el.textContent).toContain("ok");
      expect(el.textContent).toContain("9.9.9");
    });
  });

  it("shows unreachable when the health check fails", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockRejectedValue(new Error("network down"))
    );

    render(<Overview />);

    await waitFor(() => {
      expect(screen.getByTestId("health-status").textContent).toContain("unreachable");
    });
  });
});
