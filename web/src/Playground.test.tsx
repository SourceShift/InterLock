import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { Playground } from "./Playground";

const PRESETS_BODY = {
  presets: [
    {
      id: "egress",
      title: "Data egress allowlist",
      description: "An outbound post to an unlisted host, then one to an allowlisted host.",
      rules: [
        {
          detector: "data_egress",
          factory: "network_egress_guard",
          kwargs: { allowed_hosts: ["api.acme.com"] },
        },
      ],
      events: [
        { action: "http_post", args: { url: "https://evil.example/collect" } },
        { action: "http_post", args: { url: "https://api.acme.com/notes" } },
      ],
      expect: ["BLOCK", "ALLOW"],
    },
    {
      id: "pii",
      title: "PII redaction",
      description: "A card number in an outbound payload is masked, not blocked.",
      rules: [{ detector: "data_egress", factory: "pii_redaction_guard", kwargs: {} }],
      events: [{ action: "http_post", args: { body: "Card on file: 4111 1111 1111 1111" } }],
      expect: ["MODIFY"],
    },
  ],
};

const EGRESS_RESULTS = {
  results: [
    {
      index: 0,
      verdict: "BLOCK",
      verdict_code: 1,
      reason: "evil.example is not an allowed host",
      policy_id: "data_egress",
      attributed_to: "args",
      modified_args: null,
      modified_result: null,
    },
    {
      index: 1,
      verdict: "ALLOW",
      verdict_code: 0,
      reason: "allowed host",
      policy_id: null,
      attributed_to: null,
      modified_args: null,
      modified_result: null,
    },
  ],
};

const PII_RESULTS = {
  results: [
    {
      index: 0,
      verdict: "MODIFY",
      verdict_code: 2,
      reason: "redacted a credit card number",
      policy_id: "data_egress",
      attributed_to: "args",
      modified_args: { body: "Card on file: [REDACTED CREDIT_CARD]" },
      modified_result: null,
    },
  ],
};

function stubFetch(overrides: Record<string, unknown> = {}) {
  vi.stubGlobal(
    "fetch",
    vi.fn().mockImplementation((url: string, init?: RequestInit) => {
      if (url === "/api/presets") {
        return Promise.resolve({ ok: true, json: async () => PRESETS_BODY });
      }
      if (url === "/api/evaluate") {
        const body = JSON.parse((init?.body as string) ?? "{}");
        if (overrides.evaluateError) {
          return Promise.resolve({
            ok: false,
            json: async () => ({
              error: { code: "no_rules", message: "rules must be a non-empty list" },
            }),
          });
        }
        const isPii = JSON.stringify(body.rules).includes("pii_redaction_guard");
        return Promise.resolve({ ok: true, json: async () => (isPii ? PII_RESULTS : EGRESS_RESULTS) });
      }
      if (url.startsWith("/api/detectors/")) {
        const module = url.slice("/api/detectors/".length);
        return Promise.resolve({
          ok: true,
          json: async () => ({
            module,
            category: "Category A",
            summary: "A detector.",
            factories: [{ name: `${module}_rule`, signature: "()", params: [] }],
            verdicts: ["ALLOW"],
            scope: "any call",
            configurable: false,
            doc: "doc",
          }),
        });
      }
      return Promise.resolve({
        ok: false,
        json: async () => ({ error: { code: "not_found", message: "no such route" } }),
      });
    })
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("Playground", () => {
  it("fills the rules and events editors when a preset is chosen", async () => {
    stubFetch();
    render(<Playground detectorParam={null} />);

    await waitFor(() => {
      expect(screen.getByTestId("preset-select").querySelectorAll("option").length).toBe(3);
    });
    fireEvent.change(screen.getByTestId("preset-select"), { target: { value: "egress" } });

    expect((screen.getByTestId("rules-editor") as HTMLTextAreaElement).value).toContain(
      "network_egress_guard"
    );
    expect((screen.getByTestId("events-editor") as HTMLTextAreaElement).value).toContain(
      "http_post"
    );
  });

  it("evaluates the egress preset and renders a result row per event", async () => {
    stubFetch();
    render(<Playground detectorParam={null} />);

    await waitFor(() => screen.getByTestId("preset-select").querySelectorAll("option"));
    fireEvent.change(screen.getByTestId("preset-select"), { target: { value: "egress" } });
    fireEvent.click(screen.getByTestId("evaluate-button"));

    await waitFor(() => {
      expect(screen.getAllByTestId("result-row")).toHaveLength(2);
    });
    const badges = screen.getAllByTestId("verdict-badge");
    expect(badges[0].textContent).toBe("BLOCK");
    expect(badges[1].textContent).toBe("ALLOW");
  });

  it("shows the rewritten args for a MODIFY verdict", async () => {
    stubFetch();
    render(<Playground detectorParam={null} />);

    await waitFor(() => screen.getByTestId("preset-select").querySelectorAll("option"));
    fireEvent.change(screen.getByTestId("preset-select"), { target: { value: "pii" } });
    fireEvent.click(screen.getByTestId("evaluate-button"));

    await waitFor(() => {
      expect(screen.getByTestId("modified-args").textContent).toContain(
        "[REDACTED CREDIT_CARD]"
      );
    });
  });

  it("shows editor-error for invalid JSON and sends no request", async () => {
    stubFetch();
    render(<Playground detectorParam={null} />);
    const fetchMock = vi.mocked(fetch);

    await waitFor(() => screen.getByTestId("preset-select").querySelectorAll("option"));
    fetchMock.mockClear();
    fireEvent.change(screen.getByTestId("events-editor"), { target: { value: "{not json" } });
    fireEvent.click(screen.getByTestId("evaluate-button"));

    expect(screen.getByTestId("editor-error")).toBeTruthy();
    expect(fetchMock).not.toHaveBeenCalledWith("/api/evaluate", expect.anything());
  });

  it("shows api-error with the error code and message on a failed evaluate", async () => {
    stubFetch({ evaluateError: true });
    render(<Playground detectorParam={null} />);

    await waitFor(() => screen.getByTestId("preset-select").querySelectorAll("option"));
    fireEvent.click(screen.getByTestId("evaluate-button"));

    await waitFor(() => {
      const error = screen.getByTestId("api-error");
      expect(error.textContent).toContain("no_rules");
      expect(error.textContent).toContain("rules must be a non-empty list");
    });
  });

  it("adds the detector's first factory to the rules editor from the detector param", async () => {
    stubFetch();
    render(<Playground detectorParam="shell_injection_guard" />);

    await waitFor(() => {
      expect((screen.getByTestId("rules-editor") as HTMLTextAreaElement).value).toContain(
        "shell_injection_guard"
      );
    });
  });
});
