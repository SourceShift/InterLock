import { useEffect, useState } from "react";
import { ApiError, ScopeResolveResponse, fetchScopeExample, resolveScope } from "./api";

export function Inspector() {
  const [docText, setDocText] = useState("{}");
  const [principal, setPrincipal] = useState("");
  const [eventText, setEventText] = useState("");
  const [apiError, setApiError] = useState<{ code: string; message: string } | null>(null);
  const [result, setResult] = useState<ScopeResolveResponse | null>(null);

  useEffect(() => {
    fetchScopeExample()
      .then((example) => {
        setDocText(JSON.stringify(example.document, null, 2));
        setPrincipal(example.principal);
        setEventText(example.event === null ? "" : JSON.stringify(example.event, null, 2));
      })
      .catch(() => {});
  }, []);

  function handleResolve() {
    setApiError(null);
    setResult(null);

    let document: unknown;
    try {
      document = JSON.parse(docText);
    } catch {
      setApiError({ code: "bad_document", message: "the scope document must be valid JSON" });
      return;
    }

    let event: unknown = null;
    if (eventText.trim() !== "") {
      try {
        event = JSON.parse(eventText);
      } catch {
        setApiError({ code: "bad_event", message: "the event must be valid JSON" });
        return;
      }
    }

    resolveScope(document, principal, event)
      .then((response) => setResult(response))
      .catch((error) => {
        if (error instanceof ApiError) {
          setApiError({ code: error.code, message: error.message });
        } else {
          setApiError({ code: "unknown_error", message: "the request failed" });
        }
      });
  }

  return (
    <section>
      <h1>Scopes &amp; sandbox inspector</h1>
      <div className="inspector-editors">
        <label>
          Scope document
          <textarea
            className="mono"
            data-testid="scope-doc-editor"
            rows={14}
            value={docText}
            onChange={(event) => setDocText(event.target.value)}
          />
        </label>
        <label>
          Principal
          <input
            data-testid="principal-input"
            value={principal}
            onChange={(event) => setPrincipal(event.target.value)}
          />
        </label>
        <label>
          Event (optional)
          <textarea
            className="mono"
            data-testid="scope-event-editor"
            rows={6}
            value={eventText}
            onChange={(event) => setEventText(event.target.value)}
          />
        </label>
      </div>
      <button type="button" data-testid="resolve-button" onClick={handleResolve}>
        Resolve
      </button>
      {apiError && (
        <p data-testid="scope-error">
          {apiError.code}: {apiError.message}
        </p>
      )}
      {result && (
        <>
          <div data-testid="resolved-params">
            {Object.entries(result.resolved).map(([templateId, params]) => (
              <div key={templateId} data-testid="resolved-template">
                <strong>{templateId}</strong>
                <code className="mono">{JSON.stringify(params)}</code>
              </div>
            ))}
          </div>
          <p data-testid="sandbox-profile">
            network {result.sandbox.profile.allow_network ? "on" : "off"}; allowed hosts:{" "}
            {result.sandbox.profile.allowed_hosts.join(", ")}; read paths:{" "}
            {result.sandbox.profile.read_paths.join(", ")}; write paths:{" "}
            {result.sandbox.profile.write_paths.join(", ")}; cpu seconds:{" "}
            {String(result.sandbox.profile.cpu_seconds)}; memory mb:{" "}
            {String(result.sandbox.profile.memory_mb)}
          </p>
          <p data-testid="backend-name">{result.sandbox.backend}</p>
          <p data-testid="enforced-tokens">{result.sandbox.enforced.join(", ")}</p>
          <p data-testid="not-enforced-tokens">{result.sandbox.not_enforced.join(", ")}</p>
          {result.decision && (
            <span
              className={`verdict-badge verdict-${result.decision.verdict}`}
              data-testid="scope-verdict"
            >
              {result.decision.verdict}
            </span>
          )}
        </>
      )}
    </section>
  );
}
