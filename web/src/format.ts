/**
 * The design's small vocabulary - verdict marks and colours, tones, themes,
 * time formats - plus the adapters that turn real API data into what the
 * screens draw (docstrings into blocks, parameter text into keyword arguments).
 */
import type { DetectorParam } from "./api";

export const V = {
  ALLOW: { word: "allow", mark: "✓", c: "var(--il-allow)" },
  MODIFY: { word: "rewrite", mark: "~", c: "var(--il-rewrite)" },
  BLOCK: { word: "block", mark: "✗", c: "var(--il-block)" },
  ESCALATE: { word: "escalate", mark: "‖", c: "var(--il-escalate)" },
} as const;

export type VerdictKey = keyof typeof V;

export const vk = (verdict: string | null | undefined): VerdictKey =>
  verdict && verdict in V ? (verdict as VerdictKey) : "ALLOW";

export const THEMES = {
  dark: {
    bg: "#0f1012", panel: "#151619", raised: "#1c1d21", sunken: "#0b0c0d", fg: "#ecebe6", fg2: "#b4b3ad",
    dim: "#8d8c86", rule: "rgba(255,255,255,.08)", rule2: "rgba(255,255,255,.14)", allow: "#5fd68a",
    rewrite: "#f5c04a", block: "#ff7a6b", escalate: "#8ec5ff", acc: "#f5a524", accfg: "#16120a",
    hover: "rgba(255,255,255,.04)", sel: "rgba(255,255,255,.07)",
  },
  light: {
    bg: "#f4f3ef", panel: "#ffffff", raised: "#f7f6f2", sunken: "#eceae4", fg: "#16171a", fg2: "#45464b",
    dim: "#5f6066", rule: "rgba(0,0,0,.09)", rule2: "rgba(0,0,0,.16)", allow: "#17784b", rewrite: "#8a5a00",
    block: "#c2321f", escalate: "#1d5ea6", acc: "#a86400", accfg: "#ffffff", hover: "rgba(0,0,0,.035)",
    sel: "rgba(0,0,0,.06)",
  },
} as const;

export type ThemeName = keyof typeof THEMES;

export interface Chip {
  mark: string;
  word: string;
  c: string;
  bg: string;
  bc: string;
  bs: string;
}

export function chip(verdict: string | null | undefined, observed?: boolean): Chip {
  const m = V[vk(verdict)];
  return {
    mark: observed ? "◌" : m.mark,
    word: observed ? "would " + m.word : m.word,
    c: m.c,
    bg: observed ? "transparent" : "color-mix(in oklch, " + m.c + " 14%, transparent)",
    bc: "color-mix(in oklch, " + m.c + " " + (observed ? 60 : 36) + "%, transparent)",
    bs: observed ? "dashed" : "solid",
  };
}

export const tone = (c: string) => ({
  c,
  bg: "color-mix(in oklch, " + c + " 13%, transparent)",
  bc: "color-mix(in oklch, " + c + " 36%, transparent)",
});

export const muted = { c: "var(--il-fg2)", bg: "transparent", bc: "var(--il-rule2)" };
export const faint = { c: "var(--il-dim)", bg: "transparent", bc: "var(--il-rule2)" };

const pad = (n: number) => String(n).padStart(2, "0");

/** HH:MM:SS for a time in milliseconds. */
export function fmtT(ms: number): string {
  const d = new Date(ms);
  return pad(d.getHours()) + ":" + pad(d.getMinutes()) + ":" + pad(d.getSeconds());
}

export function fmtDT(ms: number): string {
  const d = new Date(ms);
  return d.toLocaleDateString("en-GB", { day: "numeric", month: "short" }) + " " + fmtT(ms);
}

export function hm(ms: number): string {
  const d = new Date(ms);
  return pad(d.getHours()) + ":" + pad(d.getMinutes());
}

export function ago(ms: number): string {
  const s = Math.max(0, Math.round(ms / 1000));
  if (s < 60) return s + "s ago";
  const m = Math.round(s / 60);
  if (m < 60) return m + "m ago";
  const h = Math.round(m / 60);
  if (h < 48) return h + "h ago";
  return Math.round(h / 24) + "d ago";
}

/** A countdown: "11:33", or "1h 05m" past an hour. */
export function left(ms: number): string {
  if (ms <= 0) return "0:00";
  const s = Math.floor(ms / 1000);
  const m = Math.floor(s / 60);
  if (m >= 60) return Math.floor(m / 60) + "h " + String(m % 60).padStart(2, "0") + "m";
  return m + ":" + String(s % 60).padStart(2, "0");
}

export const num = (n: number) => n.toLocaleString("en-US");

export function tilde(path: string | null | undefined, home: string | undefined): string {
  if (!path) return "";
  return home && path.startsWith(home + "/") ? "~" + path.slice(home.length) : path;
}

export function duration(seconds: number): string {
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d) return d + "d " + h + "h";
  if (h) return h + "h " + m + "m";
  return m + "m";
}

// --- docstrings ------------------------------------------------------------------

export interface DocBlock {
  isP: boolean;
  isCode: boolean;
  isH: boolean;
  t: string;
}

/**
 * A detector docstring as paragraphs, headings and code blocks. Headings are
 * reST-style (a line underlined with ---/===/~~~); code is an indented block,
 * a block after a paragraph ending in "::", or a ">>>" session.
 */
export function docBlocks(doc: string): DocBlock[] {
  const lines = doc.replace(/\r/g, "").split("\n");
  const blocks: DocBlock[] = [];
  const block = (kind: "p" | "code" | "h", t: string) =>
    t.trim() && blocks.push({ isP: kind === "p", isCode: kind === "code", isH: kind === "h", t });
  let para: string[] = [];
  let code: string[] = [];
  let expectCode = false;
  const flushPara = () => {
    if (!para.length) return;
    let text = para.map((l) => l.trim()).join(" ");
    expectCode = text.endsWith("::");
    if (expectCode) text = text.replace(/::$/, text.endsWith(" ::") ? "" : ":");
    // Sphinx roles (:mod:`x`, :class:`x`) read as their target.
    block("p", text.replace(/:[a-z]+:`~?([^`]+)`/g, "$1").replace(/``/g, "").replace(/\s+/g, " ").trim());
    para = [];
  };
  const flushCode = () => {
    if (!code.length) return;
    const indent = Math.min(...code.filter((l) => l.trim()).map((l) => l.length - l.trimStart().length));
    block("code", code.map((l) => l.slice(indent)).join("\n").replace(/\n+$/, ""));
    code = [];
  };
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const next = lines[i + 1] ?? "";
    const indented = /^\s{2,}\S/.test(line) || /^\s*>>>/.test(line);
    if (!line.trim()) {
      if (code.length) code.push("");
      else flushPara();
      continue;
    }
    if (/^[-=~^]{3,}\s*$/.test(next) && !para.length && !code.length) {
      block("h", line.trim());
      i++;
      continue;
    }
    if (code.length && !indented) flushCode();
    if (code.length || (indented && (expectCode || !para.length)) || /^\s*>>>/.test(line)) {
      if (!code.length) flushPara();
      code.push(line);
      continue;
    }
    expectCode = false;
    para.push(line);
  }
  flushCode();
  flushPara();
  return blocks;
}

// --- playground parameters ---------------------------------------------------------

/** A parameter's text field, as the text a person would type for its default. */
export function paramText(value: unknown): string {
  if (value === null || value === undefined) return "";
  if (Array.isArray(value)) return value.map((v) => (typeof v === "string" ? v : JSON.stringify(v))).join(", ");
  if (typeof value === "string") return value;
  return JSON.stringify(value);
}

/**
 * The keyword argument a text field stands for, read by the parameter's
 * annotation: list-like types split on commas, numbers and booleans parse,
 * anything else is a string (or JSON when it looks like JSON). Empty means
 * "use the default", so the argument is left out.
 */
export function paramValue(text: string, param: DetectorParam | undefined): { set: boolean; value?: unknown } {
  const t = text.trim();
  if (!t) return { set: false };
  const ann = (param?.annotation ?? "").toLowerCase();
  if (/^[[{]/.test(t)) {
    try {
      return { set: true, value: JSON.parse(t) };
    } catch {
      // not JSON after all: fall through to the annotation
    }
  }
  if (/(list|sequence|iterable|set|tuple|collection)\b|\[str\]/.test(ann)) {
    return { set: true, value: t.split(",").map((s) => s.trim()).filter(Boolean) };
  }
  if (/\bbool\b/.test(ann) && /^(true|false)$/i.test(t)) return { set: true, value: /^true$/i.test(t) };
  if (/\b(int|float)\b/.test(ann) && /^-?\d+(\.\d+)?$/.test(t)) return { set: true, value: Number(t) };
  if (t === "None") return { set: true, value: null };
  return { set: true, value: t };
}

/**
 * Where JSON text first stops being JSON, as an offset - or -1 if it parses.
 * Engines disagree on whether their error message says (V8 often doesn't), so
 * the editors find the spot themselves.
 */
export function jsonErrorOffset(text: string): number {
  let i = 0;
  const ws = () => {
    while (i < text.length && " \t\n\r".includes(text[i])) i++;
  };
  const fail = (): never => {
    throw i;
  };
  const value = (): void => {
    ws();
    const c = text[i];
    if (c === "{") {
      i++;
      ws();
      if (text[i] === "}") {
        i++;
        return;
      }
      for (;;) {
        ws();
        if (text[i] !== '"') fail();
        str();
        ws();
        if (text[i] !== ":") fail();
        i++;
        value();
        ws();
        if (text[i] === ",") i++;
        else if (text[i] === "}") {
          i++;
          return;
        } else fail();
      }
    }
    if (c === "[") {
      i++;
      ws();
      if (text[i] === "]") {
        i++;
        return;
      }
      for (;;) {
        value();
        ws();
        if (text[i] === ",") i++;
        else if (text[i] === "]") {
          i++;
          return;
        } else fail();
      }
    }
    if (c === '"') return str();
    const lit = /^(true|false|null|-?(0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)?)/.exec(text.slice(i));
    if (!lit) fail();
    i += lit![0].length;
  };
  const str = () => {
    i++;
    while (i < text.length && text[i] !== '"') {
      if (text[i] === "\\") i++;
      else if (text[i] === "\n") fail();
      i++;
    }
    if (i >= text.length) fail();
    i++;
  };
  try {
    value();
    ws();
    return i < text.length ? i : -1;
  } catch (at) {
    return Math.min(Number(at), text.length);
  }
}

/** A JSON.parse error as a short message and the 1-based line it happened on. */
export function jsonErrorLine(text: string, err: unknown): { msg: string; line: number } {
  const message = err instanceof Error ? err.message : String(err);
  const offset = jsonErrorOffset(text);
  const line = offset >= 0 ? text.slice(0, offset).split("\n").length : 1;
  const msg = message
    .replace(/, ".*" is not valid JSON$/s, "")
    .replace(/^JSON\.parse: /, "")
    .replace(/ in JSON at position \d+.*$/, "")
    .replace(/ \(line \d+ column \d+\)/, "")
    .replace(/ at line \d+ column \d+ of the JSON data$/, "");
  return { msg, line };
}

// --- signatures --------------------------------------------------------------------

/**
 * A Python annotation in today's spelling, the way the design writes them:
 * `Optional[Iterable[str]]` -> `list[str] | None`, `Union[int, str]` -> `int | str`.
 */
export function prettyAnn(ann: string | null | undefined): string {
  if (!ann) return "";
  let t = ann.replace(/['"]/g, "").replace(/\btyping\./g, "").trim();
  const ARG = /(\w+)\[([^[\]]*)\]/;
  // innermost brackets first, until none change
  for (let guard = 0; guard < 20; guard++) {
    const next = t.replace(ARG, (_m, head: string, inner: string) => {
      const parts = inner.split(",").map((s) => s.trim());
      switch (head) {
        case "Optional":
          return parts[0] + " | None";
        case "Union":
          return parts.join(" | ");
        case "List": case "Iterable": case "Sequence": case "Collection": case "MutableSequence":
          return "list⟦" + parts.join(", ") + "⟧";
        case "Set": case "FrozenSet": case "AbstractSet":
          return "set⟦" + parts.join(", ") + "⟧";
        case "Dict": case "Mapping": case "MutableMapping":
          return "dict⟦" + parts.join(", ") + "⟧";
        case "Tuple":
          return "tuple⟦" + parts.join(", ") + "⟧";
        default:
          return head + "⟦" + parts.join(", ") + "⟧";
      }
    });
    if (next === t) break;
    t = next;
  }
  return t.replace(/⟦/g, "[").replace(/⟧/g, "]");
}

/** A default value short enough for one cell. */
export function shortDefault(value: unknown): string {
  const text = value === null || value === undefined ? "None" : typeof value === "string" ? value : JSON.stringify(value);
  return text.length > 28 ? text.slice(0, 26) + "…" : text;
}

/** `name(p: ann = default, ...)` from a factory's parameter list. */
export function signature(name: string, params: DetectorParam[]): string {
  return name + "(" + params.map((p) => {
    const kw = p.kind === "VAR_POSITIONAL" ? "*" : p.kind === "VAR_KEYWORD" ? "**" : "";
    return kw + p.name + (p.annotation ? ": " + prettyAnn(p.annotation) : "") + (p.required || kw ? "" : " = " + shortDefault(p.default));
  }).join(", ") + ")";
}
