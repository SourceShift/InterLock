import { useEffect, useState } from "react";
import { fetchHealth } from "./api";

type HealthState =
  | { kind: "checking" }
  | { kind: "ok"; status: string; version: string }
  | { kind: "unreachable" };

export function Overview() {
  const [health, setHealth] = useState<HealthState>({ kind: "checking" });

  useEffect(() => {
    let cancelled = false;
    fetchHealth()
      .then((response) => {
        if (!cancelled) {
          setHealth({ kind: "ok", status: response.status, version: response.version });
        }
      })
      .catch(() => {
        if (!cancelled) {
          setHealth({ kind: "unreachable" });
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  let statusText: string;
  let statusClass: string;
  if (health.kind === "ok") {
    statusText = `${health.status} · v${health.version}`;
    statusClass = "health-ok";
  } else if (health.kind === "unreachable") {
    statusText = "unreachable";
    statusClass = "health-unreachable";
  } else {
    statusText = "checking…";
    statusClass = "";
  }

  return (
    <section>
      <h1>Overview</h1>
      <p>
        API health:{" "}
        <span className={statusClass} data-testid="health-status">
          {statusText}
        </span>
      </p>
    </section>
  );
}
