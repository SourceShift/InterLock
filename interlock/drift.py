"""Record each covered surface's shape as a corpus, and diff a live surface
against it: additions, removals and schema-shape changes, each with a severity.

A *surface* is a tool listing - the set of tools an MCP server (or any other
capability surface) exposes. The corpus records what each covered surface
looked like when you last looked:

    {
      "corpus_version": 1,
      "surfaces": [
        {"name": "demo", "tools": ["read", "write"]}
      ]
    }

A tool entry is either a bare name (``"read"``) or an object carrying the name
plus whatever schema shape you recorded for it
(``{"name": "read", "input_schema": {...}}``). ``corpus_version`` is optional -
a corpus written by hand without it loads with the current default.

The fingerprint of a surface is
:func:`interlock.detectors.mcp_server_attestation.listing_digest`, the same
canonicalization the ``mcp_server_attestation`` detector and the
``mcp_surface_baseline`` rule use at admission time. There is exactly **one**
canonicalizer on purpose: a second, independently-written fingerprint of "the
same surface" that disagreed with the runtime guard would let this command
report "unchanged" while the guard blocked, which is the contradictory signal
this feature exists to prevent.

Nothing here is written back and nothing is filed automatically. The diff is a
report; the corpus is only ever read. See ``interlock/cli/drift.py`` for the
command, or run ``interlock drift --help``.
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

from .detectors.mcp_server_attestation import listing_digest

CORPUS_VERSION = 1

# The three ways a live surface can differ from the record.
ADDITION = "addition"
REMOVAL = "removal"
CHANGE = "change"

# Every finding is drift and every finding fails the command; the severity only
# orders the report. An addition is a tool the operator never recorded now
# reachable, and a change is the same name with a different shape underneath it
# - the silent substitution schema pinning exists to catch - so both are high.
# A removal is a recorded capability gone; the contract shrank, which matters,
# but nothing new became reachable, so it is medium.
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
_SEVERITY_OF = {
    ADDITION: SEVERITY_HIGH,
    CHANGE: SEVERITY_HIGH,
    REMOVAL: SEVERITY_MEDIUM,
}

# The report's machine/human summary keyed by finding kind, in a fixed order.
_KINDS = (ADDITION, REMOVAL, CHANGE)


class CorpusError(ValueError):
    """The corpus file is not a usable corpus."""


class LiveOutputError(ValueError):
    """The live command's output is not a usable tool listing."""


def _body(entry: Dict[str, Any]) -> str:
    """The canonical JSON body of one entry, for equality and fingerprinting.

    Sorted keys and tight separators, matching ``listing_digest``'s per-entry
    rendering, so "the same entry" means the same bytes on both sides.
    """
    return json.dumps(entry, sort_keys=True, separators=(",", ":"))


def normalize_tool(entry: Any) -> Dict[str, Any]:
    """Normalise one tool entry to a dict with at least a non-empty ``name``.

    A bare string becomes ``{"name": entry}``; a mapping is used as-is. An
    entry that is neither, or whose ``name`` is missing/blank/non-str, is not
    usable and raises :class:`CorpusError` - the caller must not guess a name
    the surface never claimed.
    """
    if isinstance(entry, str):
        return {"name": entry} if entry else _bad_tool(entry)
    if not isinstance(entry, dict):
        return _bad_tool(entry)
    name = entry.get("name")
    if not isinstance(name, str) or not name:
        return _bad_tool(entry)
    return entry


def _bad_tool(entry: Any) -> Dict[str, Any]:
    raise CorpusError(
        "unusable tool entry {!r}: expected a non-empty name or an object"
        " with a non-empty str 'name'".format(entry)
    )


def normalize_surface(surface: Any) -> Dict[str, Any]:
    """Normalise a corpus surface to ``{"name": str, "tools": [entry, ...]}``.

    Order is the record's order and is preserved; the fingerprint is
    order-independent, so a re-ordered recording is not drift.
    """
    if not isinstance(surface, dict):
        raise CorpusError("surface must be a JSON object, got {!r}".format(surface))
    name = surface.get("name")
    if not isinstance(name, str) or not name:
        raise CorpusError("surface needs a non-empty str 'name'")
    tools = surface.get("tools")
    if not isinstance(tools, list):
        raise CorpusError("surface {!r} needs a 'tools' list".format(name))
    return {"name": name, "tools": [normalize_tool(t) for t in tools]}


def build_corpus(surfaces: List[Dict[str, Any]]) -> Dict[str, Any]:
    """The corpus as a dict, ready to serialise (validation included)."""
    return {
        "corpus_version": CORPUS_VERSION,
        "surfaces": [normalize_surface(s) for s in surfaces],
    }


def dumps(corpus: Dict[str, Any]) -> str:
    """Serialise a corpus canonically (sorted keys, two-space indent)."""
    return json.dumps(corpus, indent=2, sort_keys=True)


def write_corpus(path: str, surfaces: List[Dict[str, Any]]) -> None:
    """Write a corpus canonically, with a trailing newline, making parents."""
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(dumps(build_corpus(surfaces)))
        fh.write("\n")


def validate_corpus(raw: Any) -> Dict[str, Any]:
    """Turn parsed JSON into a normalised corpus, or raise :class:`CorpusError`."""
    if not isinstance(raw, dict):
        raise CorpusError("corpus must be a JSON object")
    surfaces = raw.get("surfaces")
    if not isinstance(surfaces, list):
        raise CorpusError("corpus must have a 'surfaces' list")
    return {
        "corpus_version": raw.get("corpus_version", CORPUS_VERSION),
        "surfaces": [normalize_surface(s) for s in surfaces],
    }


def load_corpus(path: str) -> Dict[str, Any]:
    """Read and validate a corpus file.

    Raises :class:`OSError` if it cannot be read and :class:`CorpusError` (a
    ``ValueError``) if it is not a usable corpus - malformed JSON surfaces as
    ``json.JSONDecodeError``, which is also a ``ValueError``.
    """
    with open(path, "r", encoding="utf-8") as fh:
        raw = json.load(fh)
    return validate_corpus(raw)


def select_surface(corpus: Dict[str, Any], name: Optional[str] = None) -> Dict[str, Any]:
    """Pick the corpus surface the live command describes.

    With no ``name``, the only surface is chosen; an empty or multi-surface
    corpus cannot be resolved without one and raises ``ValueError`` (the CLI
    treats that as a usage error). A ``name`` the corpus does not record is
    likewise a ``ValueError``.
    """
    surfaces = corpus["surfaces"]
    if name is None:
        if len(surfaces) == 1:
            return surfaces[0]
        raise ValueError(
            "corpus records {} surfaces; choose one with --surface".format(len(surfaces))
        )
    for surface in surfaces:
        if surface["name"] == name:
            return surface
    raise ValueError("no surface named {!r} in the corpus".format(name))


def parse_live(text: str) -> List[Any]:
    """Parse a live command's stdout into a list of tool entries.

    One tool per non-blank line. A line that begins with ``{`` is read as a
    JSON object carrying the tool's name and (optionally) schema shape; any
    other line is a bare tool name. A ``{``-line that is not a JSON object
    with a usable ``name`` is malformed output, not a tool named ``{...}``, so
    it raises :class:`LiveOutputError` rather than silently becoming a name.
    """
    entries: List[Any] = []
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("{"):
            try:
                entry = json.loads(stripped)
            except ValueError as exc:
                raise LiveOutputError("live line {} is not valid JSON: {}".format(number, exc))
            try:
                entries.append(normalize_tool(entry))
            except CorpusError as exc:
                raise LiveOutputError("live line {}: {}".format(number, exc))
        else:
            entries.append(stripped)
    return entries


def _shape(entry: Dict[str, Any]) -> Dict[str, Any]:
    """An entry's schema shape: its keys other than ``name``."""
    return {key: value for key, value in entry.items() if key != "name"}


def _changed_keys(recorded: Dict[str, Any], live: Dict[str, Any]) -> List[str]:
    """Schema-shape keys that both sides state and that disagree.

    Only keys present on *both* sides are compared, and ``name`` is ignored.
    A corpus that records a schema and a live probe that reports only a bare
    name therefore agree - neither side asserts a shape the other contradicts -
    so a coarse probe cannot manufacture a false positive. Two entries that
    both state ``input_schema`` and disagree *are* a change.
    """
    rec, liv = _shape(recorded), _shape(live)
    shared = set(rec) & set(liv)
    return sorted(key for key in shared if rec[key] != liv[key])


def diff(corpus_surface: Dict[str, Any], live_tools: List[Any]) -> Dict[str, Any]:
    """Diff a live tool listing against one recorded corpus surface.

    ``corpus_surface`` is a normalised ``{"name", "tools"}`` surface (or a raw
    one, re-normalised here) and ``live_tools`` a list of str/dict entries.
    Returns a structured report: ``findings`` (each ``kind``/``tool``/
    ``severity``/``detail``), a per-kind ``counts`` block, both fingerprints,
    and ``drift`` - true when there is at least one finding. Pure: nothing is
    read or written, the corpus is not mutated.
    """
    surface = normalize_surface(corpus_surface)
    recorded = {entry["name"]: entry for entry in surface["tools"]}
    live: Dict[str, Dict[str, Any]] = {}
    for entry in live_tools:
        normalized = normalize_tool(entry)
        live[normalized["name"]] = normalized

    findings: List[Dict[str, str]] = []
    for tool in sorted(set(live) - set(recorded)):
        findings.append({
            "kind": ADDITION, "tool": tool, "severity": _SEVERITY_OF[ADDITION],
            "detail": "present live, not recorded in the corpus",
        })
    for tool in sorted(set(recorded) - set(live)):
        findings.append({
            "kind": REMOVAL, "tool": tool, "severity": _SEVERITY_OF[REMOVAL],
            "detail": "recorded in the corpus, not present live",
        })
    for tool in sorted(set(recorded) & set(live)):
        changed = _changed_keys(recorded[tool], live[tool])
        if changed:
            findings.append({
                "kind": CHANGE, "tool": tool, "severity": _SEVERITY_OF[CHANGE],
                "detail": "schema shape changed: " + ", ".join(changed),
            })
    findings.sort(key=lambda f: (f["tool"], f["kind"]))

    counts = {kind: 0 for kind in _KINDS}
    for finding in findings:
        counts[finding["kind"]] += 1
    counts["total"] = len(findings)

    return {
        "surface": surface["name"],
        "corpus_fingerprint": listing_digest(surface["tools"]),
        "live_fingerprint": listing_digest(list(live.values())),
        "tools": {"corpus": len(recorded), "live": len(live)},
        "drift": bool(findings),
        "counts": counts,
        "findings": findings,
    }


_MARKER = {ADDITION: "+", REMOVAL: "-", CHANGE: "~"}


def render(report: Dict[str, Any]) -> str:
    """Render a diff report as human-readable lines."""
    lines: List[str] = []
    surface = report["surface"]
    if not report["drift"]:
        lines.append('drift: surface "{}" matches the corpus ({} tool(s))'.format(
            surface, report["tools"]["corpus"]))
        return "\n".join(lines)
    counts = report["counts"]
    lines.append(
        'drift: surface "{}" changed ({} finding(s): {} added, {} removed, {} changed)'.format(
            surface, counts["total"], counts[ADDITION], counts[REMOVAL], counts[CHANGE])
    )
    for finding in report["findings"]:
        lines.append("  {} {:<28} {:<9} {:<7} {}".format(
            _MARKER[finding["kind"]], finding["tool"], finding["kind"],
            finding["severity"], finding["detail"]))
    return "\n".join(lines)


def to_json(report: Dict[str, Any]) -> str:
    """Render a diff report as canonical JSON."""
    return json.dumps(report, indent=2, sort_keys=True)
