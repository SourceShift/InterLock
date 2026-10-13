import React from "react";
import ReactDOM from "react-dom/client";
import "@fontsource/instrument-sans/400.css";
import "@fontsource/instrument-sans/500.css";
import "@fontsource/instrument-sans/600.css";
import "@fontsource/instrument-sans/700.css";
import "@fontsource/martian-mono/400.css";
import "@fontsource/martian-mono/500.css";
import "./base.css";
import "./design/hover.css";
import { App } from "./App";

const root = document.getElementById("root");
if (!root) {
  throw new Error("missing #root element");
}

ReactDOM.createRoot(root).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
