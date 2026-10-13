import { useEffect, useMemo, useState } from "react";
import {
  Detector,
  DetectorCategory,
  DetectorDetail,
  fetchDetectorDetail,
  fetchDetectors,
} from "./api";

type LoadState =
  | { kind: "loading" }
  | { kind: "ready"; categories: DetectorCategory[]; detectors: Detector[] }
  | { kind: "error" };

function matchesQuery(detector: Detector, query: string): boolean {
  if (!query) {
    return true;
  }
  const needle = query.toLowerCase();
  if (detector.module.toLowerCase().includes(needle)) {
    return true;
  }
  if (detector.summary.toLowerCase().includes(needle)) {
    return true;
  }
  return detector.factories.some((factory) => factory.name.toLowerCase().includes(needle));
}

export function Catalog() {
  const [state, setState] = useState<LoadState>({ kind: "loading" });
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<string | null>(null);
  const [detail, setDetail] = useState<DetectorDetail | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetchDetectors()
      .then((response) => {
        if (!cancelled) {
          setState({
            kind: "ready",
            categories: response.categories,
            detectors: response.detectors,
          });
        }
      })
      .catch(() => {
        if (!cancelled) {
          setState({ kind: "error" });
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (selected === null) {
      setDetail(null);
      return;
    }
    let cancelled = false;
    fetchDetectorDetail(selected)
      .then((response) => {
        if (!cancelled) {
          setDetail(response);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setDetail(null);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [selected]);

  const groups = useMemo(() => {
    if (state.kind !== "ready") {
      return [];
    }
    return state.categories
      .map((category) => ({
        category,
        detectors: state.detectors.filter(
          (detector) => detector.category === category.name && matchesQuery(detector, query)
        ),
      }))
      .filter((group) => group.detectors.length > 0);
  }, [state, query]);

  if (state.kind === "loading") {
    return (
      <section>
        <h1>Detector catalog</h1>
        <p>loading…</p>
      </section>
    );
  }

  if (state.kind === "error") {
    return (
      <section>
        <h1>Detector catalog</h1>
        <p>could not load the detector catalog.</p>
      </section>
    );
  }

  return (
    <section>
      <h1>Detector catalog</h1>
      <input
        type="text"
        placeholder="Search detectors…"
        data-testid="catalog-search"
        value={query}
        onChange={(event) => setQuery(event.target.value)}
      />
      {groups.map(({ category, detectors }) => (
        <div key={category.name}>
          <h2 data-testid="category-header">{category.name}</h2>
          <ul>
            {detectors.map((detector) => (
              <li key={detector.module}>
                <button
                  type="button"
                  data-testid="detector-row"
                  onClick={() => setSelected(detector.module)}
                >
                  <span className="mono">{detector.module}</span>
                  <span>{detector.summary}</span>
                </button>
              </li>
            ))}
          </ul>
        </div>
      ))}
      {detail && (
        <div data-testid="detector-detail">
          <h2 className="mono">{detail.module}</h2>
          <p>
            <a data-testid="try-in-playground" href={`#/playground?detector=${detail.module}`}>
              Try in playground
            </a>
          </p>
          <p>{detail.scope}</p>
          <ul>
            {detail.verdicts.map((verdict) => (
              <li key={verdict}>{verdict}</li>
            ))}
          </ul>
          {detail.factories.map((factory) => (
            <code key={factory.name} className="mono" data-testid="factory-signature">
              {factory.name}
              {factory.signature}
            </code>
          ))}
          <pre>{detail.doc}</pre>
        </div>
      )}
    </section>
  );
}
