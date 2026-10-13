import { useEffect, useState } from "react";
import { Audit } from "./Audit";
import { Catalog } from "./Catalog";
import { Inspector } from "./Inspector";
import { NavBar } from "./NavBar";
import { Overview } from "./Overview";
import { Placeholder } from "./Placeholder";
import { Playground } from "./Playground";

function currentRoute(): string {
  const hash = window.location.hash;
  if (!hash || hash === "#") {
    return "/";
  }
  return hash.slice(1);
}

function routePath(route: string): string {
  const queryIndex = route.indexOf("?");
  return queryIndex === -1 ? route : route.slice(0, queryIndex);
}

function routeQuery(route: string): URLSearchParams {
  const queryIndex = route.indexOf("?");
  return new URLSearchParams(queryIndex === -1 ? "" : route.slice(queryIndex + 1));
}

function renderRoute(route: string) {
  switch (routePath(route)) {
    case "/":
      return <Overview />;
    case "/catalog":
      return <Catalog />;
    case "/playground":
      return <Playground detectorParam={routeQuery(route).get("detector")} />;
    case "/audit":
      return <Audit />;
    case "/inspector":
      return <Inspector />;
    default:
      return <Placeholder title="Not found" note="Unknown route." />;
  }
}

export function App() {
  const [route, setRoute] = useState<string>(currentRoute());

  useEffect(() => {
    const onHashChange = () => setRoute(currentRoute());
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

  return (
    <div className="app-shell">
      <NavBar />
      <main>{renderRoute(route)}</main>
    </div>
  );
}
