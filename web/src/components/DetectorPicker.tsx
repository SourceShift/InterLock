/**
 * Detector picker: the playground's detector menu, searchable.
 *
 * It replaces a native <select>. A rule card shows one per rule, and the
 * catalog holds more detectors than a menu can be scanned through by eye, so
 * the trigger keeps the design's frame and aria-label and the popup filters as
 * you type. The filter matches the whole key, so "egress" finds
 * network_egress_guard without knowing which module it lives in.
 */
import { useEffect, useId, useLayoutEffect, useMemo, useRef, useState } from "react";
import type { CSSProperties, KeyboardEvent, ReactNode } from "react";

export type DetectorPickerProps = {
  value: string;
  options: Array<{ v: string }>;
  /** Event-shaped, so the view-model's onChange stays as it was. */
  onChange: (e: { target: { value: string } }) => void;
  "aria-label"?: string;
};

const mono = "'Martian Mono',monospace";

const trigger: CSSProperties = {
  display: "flex", alignItems: "center", gap: "8px", width: "100%",
  fontFamily: mono, fontSize: "11px", padding: "6px 8px", borderRadius: "7px",
  border: "1px solid var(--il-rule2)", background: "var(--il-sunken)", color: "var(--il-fg)",
  cursor: "pointer", textAlign: "left",
};
const valueStyle: CSSProperties = { flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" };
const caret: CSSProperties = { color: "var(--il-dim)", fontSize: "9px", marginLeft: "auto" };
const popup: CSSProperties = {
  position: "absolute", top: "calc(100% + 6px)", left: 0, right: 0, zIndex: 40, minWidth: "260px",
  background: "var(--il-raised)", border: "1px solid var(--il-rule2)", borderRadius: "10px",
  boxShadow: "0 16px 40px rgba(0,0,0,.5)", overflow: "hidden",
};
const searchRow: CSSProperties = {
  display: "flex", alignItems: "center", gap: "7px", padding: "7px 9px",
  borderBottom: "1px solid var(--il-rule)",
};
const searchInput: CSSProperties = {
  flex: 1, minWidth: 0, border: 0, background: "transparent", color: "var(--il-fg)",
  fontFamily: mono, fontSize: "11px", outline: "none", padding: 0,
};
const count: CSSProperties = { fontFamily: mono, fontSize: "9.5px", color: "var(--il-dim)", fontVariantNumeric: "tabular-nums" };
const listStyle: CSSProperties = { maxHeight: "264px", overflowY: "auto", padding: "4px" };
const empty: CSSProperties = { padding: "10px 8px", fontSize: "11.5px", color: "var(--il-dim)" };

function optionStyle(active: boolean, selected: boolean): CSSProperties {
  return {
    display: "flex", alignItems: "center", gap: "8px", width: "100%", textAlign: "left",
    fontFamily: mono, fontSize: "11px", padding: "7px 8px", borderRadius: "6px", border: 0,
    background: active ? "var(--il-sel)" : "transparent",
    color: selected ? "var(--il-fg)" : "var(--il-fg2)", cursor: "pointer",
  };
}

/** The typed run, so the eye lands on why a row matched. */
function marked(text: string, query: string): ReactNode {
  const q = query.trim().toLowerCase();
  const i = q ? text.toLowerCase().indexOf(q) : -1;
  if (i < 0) return text;
  return (
    <>
      {text.slice(0, i)}
      <span style={{ color: "var(--il-acc)" }}>{text.slice(i, i + q.length)}</span>
      {text.slice(i + q.length)}
    </>
  );
}

const SearchIcon = (
  <svg width="12" height="12" viewBox="0 0 16 16" fill="none" aria-hidden style={{ flex: "0 0 auto", color: "var(--il-dim)" }}>
    <circle cx="7" cy="7" r="4.5" stroke="currentColor" strokeWidth="1.5" />
    <path d="m10.6 10.6 3.4 3.4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
  </svg>
);

// A text glyph renders a few pixels wide in the mono face; the tick is drawn.
const CheckIcon = (
  <svg width="12" height="12" viewBox="0 0 16 16" fill="none" aria-hidden style={{ flex: "0 0 auto", color: "var(--il-acc)" }}>
    <path d="m3.5 8.5 3 3 6-7" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
);

/** `module.factory` where the two usually match: say the name once. */
function keyLabel(key: string, query: string): ReactNode {
  const i = key.indexOf(".");
  if (i < 0) return marked(key, query);
  const module = key.slice(0, i);
  const name = key.slice(i + 1);
  if (module === name) return marked(name, query);
  return (
    <>
      <span style={{ color: "var(--il-dim)" }}>{marked(module, query)}.</span>
      {marked(name, query)}
    </>
  );
}

export function DetectorPicker({ value, options, onChange, ...rest }: DetectorPickerProps) {
  const label = rest["aria-label"] ?? "Detector";
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const root = useRef<HTMLDivElement>(null);
  const search = useRef<HTMLInputElement>(null);
  const list = useRef<HTMLDivElement>(null);
  const optionsId = useId();

  const shown = useMemo(() => {
    const q = query.trim().toLowerCase();
    return q ? options.filter((o) => o.v.toLowerCase().includes(q)) : options;
  }, [options, query]);

  // `options` is rebuilt on every view-model pass, so the open effect keys on
  // `open` alone and reads the current list through a ref. Depending on the
  // array would reset the filter on each render and make typing impossible.
  const latest = useRef({ value, options });
  latest.current = { value, options };
  useEffect(() => {
    if (!open) return;
    const { value: current, options: all } = latest.current;
    setQuery("");
    const at = all.findIndex((o) => o.v === current);
    setActive(at < 0 ? 0 : at);
    const focus = window.setTimeout(() => search.current?.focus(), 0);
    const away = (e: PointerEvent) => {
      if (root.current && !root.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("pointerdown", away);
    return () => {
      window.clearTimeout(focus);
      document.removeEventListener("pointerdown", away);
    };
  }, [open]);

  useLayoutEffect(() => {
    if (!open) return;
    list.current?.querySelector<HTMLElement>('[data-active="true"]')?.scrollIntoView?.({ block: "nearest" });
  }, [open, active, query]);

  function pick(v: string) {
    onChange({ target: { value: v } });
    setOpen(false);
  }

  function onKey(e: KeyboardEvent<HTMLInputElement>) {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setActive((a) => Math.min(a + 1, shown.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActive((a) => Math.max(a - 1, 0));
    } else if (e.key === "Enter") {
      e.preventDefault();
      const o = shown[active];
      if (o) pick(o.v);
    } else if (e.key === "Escape") {
      e.preventDefault();
      setOpen(false);
    } else if (e.key === "Tab") {
      setOpen(false);
    }
  }

  return (
    <div ref={root} style={{ position: "relative", flex: "1", minWidth: 0 }}>
      <button
        type="button"
        aria-label={label}
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-controls={open ? optionsId : undefined}
        onClick={() => setOpen((o) => !o)}
        style={trigger}
      >
        <span style={valueStyle}>{keyLabel(value, "")}</span>
        <span aria-hidden style={caret}>▾</span>
      </button>
      {open ? (
        <div style={popup}>
          <div style={searchRow}>
            {SearchIcon}
            <input
              ref={search}
              value={query}
              onChange={(e) => {
                setQuery(e.target.value);
                setActive(0);
              }}
              onKeyDown={onKey}
              placeholder="filter detectors…"
              aria-label="Filter detectors"
              aria-controls={optionsId}
              style={searchInput}
            />
            <span style={count}>
              {shown.length}/{options.length}
            </span>
          </div>
          <div ref={list} role="listbox" id={optionsId} aria-label="Detectors" style={listStyle}>
            {shown.map((o, i) => (
              <button
                key={o.v}
                type="button"
                role="option"
                aria-selected={o.v === value}
                data-active={i === active ? "true" : "false"}
                onMouseEnter={() => setActive(i)}
                onClick={() => pick(o.v)}
                style={optionStyle(i === active, o.v === value)}
              >
                <span style={valueStyle}>{keyLabel(o.v, query)}</span>
                {o.v === value ? CheckIcon : null}
              </button>
            ))}
            {shown.length ? null : <div style={empty}>no detector matches “{query.trim()}”</div>}
          </div>
        </div>
      ) : null}
    </div>
  );
}
