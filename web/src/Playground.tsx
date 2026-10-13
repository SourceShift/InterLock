import { useEffect, useState } from "react";
import {
  ApiError,
  EvaluateResult,
  Preset,
  evaluatePlayground,
  fetchDetectorDetail,
  fetchPresets,
} from "./api";

export interface PlaygroundProps {
  detectorParam: string | null;
}

function appendRule(rulesText: string, detector: string, factory: string): string {
  let rules: unknown[] = [];
  try {
    const parsed = JSON.parse(rulesText);
    if (Array.isArray(parsed)) {
      rules = parsed;
    }
  } catch {
    rules = [];
  }
  rules.push({ detector, factory, kwargs: {} });
  return JSON.stringify(rules, null, 2);
}

export function Playground({ detectorParam }: PlaygroundProps) {
  const [presets, setPresets] = useState<Preset[]>([]);
  const [selectedPreset, setSelectedPreset] = useState("");
  const [rulesText, setRulesText] = useState("[]");
  const [eventsText, setEventsText] = useState("[]");
  const [editorError, setEditorError] = useState(false);
  const [apiError, setApiError] = useState<{ code: string; message: string } | null>(null);
  const [results, setResults] = useState<EvaluateResult[] | null>(null);

  useEffect(() => {
    fetchPresets()
      .then((response) => setPresets(response.presets))
      .catch(() => setPresets([]));
  }, []);

  useEffect(() => {
    if (!detectorParam) {
      return;
    }
    let cancelled = false;
    fetchDetectorDetail(detectorParam)
      .then((detail) => {
        if (cancelled || detail.factories.length === 0) {
          return;
        }
        setRulesText((current) => appendRule(current, detail.module, detail.factories[0].name));
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [detectorParam]);

  function handlePresetChange(id: string) {
    setSelectedPreset(id);
    const preset = presets.find((candidate) => candidate.id === id);
    if (!preset) {
      return;
    }
    setRulesText(JSON.stringify(preset.rules, null, 2));
    setEventsText(JSON.stringify(preset.events, null, 2));
    setResults(null);
    setApiError(null);
    setEditorError(false);
  }

  function handleEvaluate() {
    setApiError(null);
    setResults(null);

    let rules: unknown;
    let events: unknown;
    try {
      rules = JSON.parse(rulesText);
      events = JSON.parse(eventsText);
    } catch {
      setEditorError(true);
      return;
    }
    setEditorError(false);

    evaluatePlayground(rules, events)
      .then((response) => setResults(response.results))
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
      <h1>Policy playground</h1>
      <label>
        Preset:{" "}
        <select
          data-testid="preset-select"
          value={selectedPreset}
          onChange={(event) => handlePresetChange(event.target.value)}
        >
          <option value="">Choose a preset…</option>
          {presets.map((preset) => (
            <option key={preset.id} value={preset.id}>
              {preset.title}
            </option>
          ))}
        </select>
      </label>
      <div className="playground-editors">
        <label>
          Rules
          <textarea
            className="mono"
            data-testid="rules-editor"
            rows={10}
            value={rulesText}
            onChange={(event) => setRulesText(event.target.value)}
          />
        </label>
        <label>
          Events
          <textarea
            className="mono"
            data-testid="events-editor"
            rows={10}
            value={eventsText}
            onChange={(event) => setEventsText(event.target.value)}
          />
        </label>
      </div>
      <button type="button" data-testid="evaluate-button" onClick={handleEvaluate}>
        Evaluate
      </button>
      {editorError && (
        <p data-testid="editor-error">rules and events must each be valid JSON.</p>
      )}
      {apiError && (
        <p data-testid="api-error">
          {apiError.code}: {apiError.message}
        </p>
      )}
      {results && (
        <div data-testid="results">
          {results.map((result) => (
            <div key={result.index} data-testid="result-row">
              <span className={`verdict-badge verdict-${result.verdict}`} data-testid="verdict-badge">
                {result.verdict}
              </span>
              <span data-testid="result-reason">{result.reason}</span>
              {result.verdict === "MODIFY" && (
                <code className="mono" data-testid="modified-args">
                  {JSON.stringify(result.modified_args)}
                </code>
              )}
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
