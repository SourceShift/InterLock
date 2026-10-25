"""Boundary provenance: which tool a value came from, and where it may go (R9).

A flat rule sees an argument and judges it. It cannot ask the question that
matters most for an agent, because the answer is not in the argument: *where
did this value come from?* A URL typed by a user and a URL copied out of a
fetched web page are the same string to an argument matcher, and only one of
them should reach ``send_email``.

This module adds the missing edge. Values that enter through a guarded tool
result are recorded with an origin label (``tool:fetch_url``) and the boundary
remembers them for the rest of their span. When a later call carries one of
those values, the boundary puts the label on the event's per-argument
:attr:`~interlock.event.SensorEvent.origins` map, and a declarative flow rule
can constrain source → sink::

    {"flow": {"source": "tool:fetch_url", "sink": "to"}}

**What this is, and is not.** Provenance is tracked at the *boundary*, by
matching the text a tool returned against the text a later call sends. It is
not a language-level taint system: a value rewritten by a string operation
(``value[::-1]``, a paraphrase, a re-encoded blob) loses its origin, and the
guard honestly cannot see that transformation. That limit is the design, not an
oversight - claiming deeper tracking would be false assurance. The useful
property it does give is the one an attacker is most likely to violate: moving
a fetched document, a database row, or a secret into an outbound field
verbatim.

Origins are labels:

- ``tool:<canonical action>`` - a tool result entered here;
- ``principal:<id>`` - the value was produced under that principal (so a
  delegation edge is visible even when tool names are reused).

The tracker is bounded (a fixed number of fragments, a maximum fragment size,
and a maximum amount of text inspected per call). A hostile tool can flood it to
evict an older fragment; provenance is defence in depth, not the only control,
and the bound is what keeps a long-lived agent process from growing without
limit.
"""
from __future__ import annotations

import fnmatch
import itertools
import re
import threading
from collections import OrderedDict
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from .actions import canonical_action
from .event import SensorEvent

#: Label prefix for a value that entered through a tool result.
TOOL_PREFIX = "tool:"
#: Label prefix for the principal a value was produced under.
PRINCIPAL_PREFIX = "principal:"

#: Fragments kept by a tracker, newest last. Old fragments are evicted first.
MAX_FRAGMENTS = 512
#: A fragment shorter than this is not distinctive enough to track: it would
#: match ordinary prose and turn provenance into a false-positive generator.
MIN_FRAGMENT_CHARS = 16
#: The longest fragment retained; longer runs are split.
MAX_FRAGMENT_CHARS = 512
#: The most result text one record() call inspects, so a huge tool result cannot
#: stall the boundary.
MAX_RECORD_CHARS = 64 * 1024
#: The most argument text one origins_for() call inspects.
MAX_SCAN_CHARS = 64 * 1024
#: How deep the argument walk descends, and how many strings it visits.
MAX_DEPTH = 6
MAX_STRINGS = 256
#: Origins reported for one argument. A value copied from many sources is
#: already suspicious; the extra labels add no decision value.
MAX_ORIGINS_PER_ARG = 8


def origin_for_tool(action: Any) -> str:
    """The origin label for a value returned by *action*.

    Action names are canonicalised the same way detectors compare them, so
    ``fetch.URL`` and ``fetch_url`` produce one label rather than two.
    A non-string action yields ``tool:`` (the label is still a valid, if
    uninformative, source).
    """
    return TOOL_PREFIX + canonical_action(action)


def origin_for_principal(principal: Any) -> Optional[str]:
    """The origin label for a value produced under *principal*, or None."""
    if not isinstance(principal, str) or not principal.strip():
        return None
    return PRINCIPAL_PREFIX + principal.strip()


def _as_origin_tuple(value: Any) -> Tuple[str, ...]:
    """Normalise one origin entry to a tuple of non-empty strings.

    Any iterable is accepted (a generator included), bounded so a hostile or
    broken caller cannot make a boundary walk an unbounded sequence.
    """
    if isinstance(value, str):
        value = (value,)
    try:
        items = iter(value)  # type: ignore[arg-type]
    except TypeError:
        return ()
    seen: List[str] = []
    for item in items:
        if len(seen) >= MAX_ORIGINS_PER_ARG * 4:
            break
        if isinstance(item, str) and item.strip():
            label = item.strip()
            if label not in seen:
                seen.append(label)
    return tuple(seen)


def normalise_origins(origins: Optional[Mapping[str, Any]]) -> Dict[str, Tuple[str, ...]]:
    """Copy a per-argument origin map into immutable tuples.

    Accepts a label (``"tool:fetch_url"``), an iterable of labels, or None for
    an argument. Invalid shapes are dropped rather than raising: a boundary
    must not fail open because provenance was malformed, and its absence simply
    leaves a flow rule with nothing to match.
    """
    if not isinstance(origins, Mapping):
        return {}
    cleaned: Dict[str, Tuple[str, ...]] = {}
    for key, value in origins.items():
        if not isinstance(key, str) or not key:
            continue
        labels = _as_origin_tuple(value)
        if labels:
            cleaned[key] = labels
    return cleaned


def _strings(value: Any, path: str, *, depth: int = 0) -> Iterable[Tuple[str, str]]:
    """Yield ``(argument path, string)`` pairs under *value*, bounded.

    A top-level string keeps its argument name. A nested string gets a dotted
    path (``payload.body``), so a sink can name the field it means. Keys are
    never yielded: they are not payload data.
    """
    if depth > MAX_DEPTH:
        return
    if isinstance(value, str):
        yield path, value
        return
    if isinstance(value, Mapping):
        for key, item in itertools.islice(value.items(), MAX_STRINGS):
            if isinstance(key, str):
                yield from _strings(item, "{}.{}".format(path, key) if path else key,
                                    depth=depth + 1)
        return
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(itertools.islice(value, MAX_STRINGS)):
            yield from _strings(item, "{}[{}]".format(path, index), depth=depth + 1)


#: An alphanumeric run inside a line: a key, an identifier, a URL segment.
_TOKEN = re.compile(r"[0-9A-Za-z]{2,}")


def _fragments(text: str) -> Iterable[str]:
    """The distinctive fragments of *text* worth remembering.

    A short value is remembered whole. Text is also split on lines and long
    alphanumeric tokens, because a model copies a line, an identifier or a key
    into a larger template - the surrounding prose is the attacker's, not the
    tool's, so requiring the *whole* line to survive would miss the common
    case. A token is only recorded when it is at least as long as the minimum
    fragment size; ordinary words fall below it and would otherwise turn every
    result into a source of false positives. Whitespace is stripped so
    indentation cannot hide a match.
    """
    text = text[:MAX_RECORD_CHARS]
    if len(text) <= MAX_FRAGMENT_CHARS:
        stripped = text.strip()
        if len(stripped) >= MIN_FRAGMENT_CHARS:
            yield stripped
    for line in text.splitlines():
        line = line.strip()
        if len(line) < MIN_FRAGMENT_CHARS:
            continue
        for start in range(0, len(line), MAX_FRAGMENT_CHARS):
            piece = line[start:start + MAX_FRAGMENT_CHARS].strip()
            if len(piece) >= MIN_FRAGMENT_CHARS:
                yield piece
        for token in _TOKEN.findall(line):
            if len(token) >= MIN_FRAGMENT_CHARS:
                yield token


class FlowTracker:
    """A bounded, thread-safe memory of values and where they entered.

    One tracker is enough for a process: the boundary records result text under
    the span it belongs to, and a later call in that span is matched against
    it. A span id keeps two concurrent agent runs from tainting each other;
    events with no span (an ad-hoc call) share the ``None`` bucket, which is
    the only sensible scope for a caller that did not identify its run.
    """

    def __init__(
        self,
        *,
        max_fragments: int = MAX_FRAGMENTS,
        min_fragment_chars: int = MIN_FRAGMENT_CHARS,
        max_record_chars: int = MAX_RECORD_CHARS,
    ) -> None:
        self._lock = threading.RLock()
        # (span, fragment) -> origins, in insertion order for eviction. A dict
        # keeps insertion order on every supported Python, but OrderedDict also
        # gives move_to_end() when a fragment is seen again.
        self._fragments: "OrderedDict[Tuple[Optional[str], str], Tuple[str, ...]]" = OrderedDict()
        self._max_fragments = max(1, int(max_fragments))
        self._min_chars = max(1, int(min_fragment_chars))
        self._max_record_chars = max(1, int(max_record_chars))

    def reset(self) -> None:
        """Forget every recorded fragment. Intended for tests and session edges."""
        with self._lock:
            self._fragments.clear()

    def record(self, value: Any, origins: Iterable[str], *, span_id: Optional[str] = None) -> None:
        """Remember every distinctive string under *value* as coming from *origins*.

        Empty and non-string labels are ignored. A value with no usable label
        records nothing: provenance without a source is not provenance.
        """
        labels = _as_origin_tuple(origins)
        if not labels:
            return
        found = list(_strings(value, ""))
        budget = self._max_record_chars
        with self._lock:
            for _path, text in found:
                if budget <= 0:
                    break
                used = min(len(text), budget)
                budget -= used
                for fragment in _fragments(text[:used]):
                    if len(fragment) < self._min_chars:
                        continue
                    key = (span_id, fragment)
                    existing = self._fragments.get(key, ())
                    merged = tuple(dict.fromkeys(existing + labels))
                    self._fragments[key] = merged
                    self._fragments.move_to_end(key)
            while len(self._fragments) > self._max_fragments:
                self._fragments.popitem(last=False)

    def origins_for(
        self, value: Any, *, span_id: Optional[str] = None
    ) -> Dict[str, Tuple[str, ...]]:
        """The origins visible in *value*, keyed by the path that carries them.

        Scans string values under a mapping or sequence, matching a recorded
        fragment as a substring. Only fragments recorded under the same span
        (or under no span, when *span_id* is None) are considered. A non-string
        scalar carries no text and therefore no provenance.
        """
        with self._lock:
            if not self._fragments:
                return {}
            relevant = [(fragment, labels) for (span, fragment), labels
                        in self._fragments.items() if span == span_id]
        if not relevant:
            return {}
        found: Dict[str, Tuple[str, ...]] = {}
        budget = MAX_SCAN_CHARS
        for path, text in _strings(value, ""):
            if budget <= 0:
                break
            used = min(len(text), budget)
            budget -= used
            text = text[:used]
            labels: List[str] = []
            for fragment, fragment_labels in relevant:
                if fragment in text:
                    for label in fragment_labels:
                        if label not in labels:
                            labels.append(label)
            if labels:
                key = path or "result"
                found[key] = tuple(labels[:MAX_ORIGINS_PER_ARG])
        return found


#: The process tracker. ``None`` means the process has never asked for one.
_tracker: Optional[FlowTracker] = None
_tracker_lock = threading.Lock()


def get_tracker() -> FlowTracker:
    """The process-wide tracker, creating it on first use."""
    global _tracker
    if _tracker is None:
        with _tracker_lock:
            if _tracker is None:
                _tracker = FlowTracker()
    return _tracker


def set_tracker(tracker: Optional[FlowTracker]) -> Optional[FlowTracker]:
    """Install *tracker* as the process tracker; ``None`` restores a fresh one.

    Returns the previous tracker, so a test (or an embedder) can restore it.
    """
    global _tracker
    with _tracker_lock:
        previous = _tracker
        _tracker = tracker
    return previous


def record_origin(
    value: Any, origins: Any, *, span_id: Optional[str] = None
) -> None:
    """Public shorthand: remember *value* as entering from *origins*.

    An integration that knows a value's source (a retrieved document, a row
    read under a delegated principal) can record it without going through a
    tool result. ``origins`` may be one label or an iterable of labels.
    """
    labels = _as_origin_tuple(origins)
    if labels:
        get_tracker().record(value, labels, span_id=span_id)


def _matches(value: str, selector: str) -> bool:
    """A glob match that also treats a bare selector as exact.

    ``fnmatch`` already does this for a string with no metacharacters, but a
    selector such as ``tool:*`` should match, and a selector with a literal
    ``[`` must not raise. ``fnmatchcase`` is used so the match is predictable
    across platforms.
    """
    try:
        return fnmatch.fnmatchcase(value, selector)
    except (TypeError, ValueError):
        return False


def _selectors(value: Any) -> Optional[List[str]]:
    """Validate a source/sink selector into a list, or None when malformed."""
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, (list, tuple)):
        return None
    out = [item.strip() for item in value if isinstance(item, str) and item.strip()]
    return out or None


def _sink_matches(path: str, selector: str) -> bool:
    """Whether an argument path is the sink a selector names.

    A sink names a top-level argument (``body``), a nested field
    (``payload.body``), or a glob. A top-level selector also matches the same
    field anywhere it appears (``body`` matches ``payload.body``), because the
    egress fields that matter are conventionally named the same at both levels.
    An indexed path contributes its leaf too, so ``urls.0`` matches ``urls``.
    """
    candidates = {path}
    if "." in path:
        candidates.add(path.rsplit(".", 1)[-1])
    if path.endswith("]"):
        leaf = path.rsplit("[", 1)[0]
        candidates.add(leaf)
    return any(_matches(candidate, selector) for candidate in candidates)


def flow_matches(
    event: SensorEvent,
    sources: Any,
    sinks: Any,
) -> Optional[Tuple[str, str]]:
    """Return ``(argument path, origin)`` when *event* carries a forbidden flow.

    *sources* and *sinks* are a selector or a list of selectors; a malformed
    selector yields no match (a rule that cannot be understood must not block
    every event). The first matching argument in event order wins, and the
    origin reported is the first label that matched, so a verdict's
    ``attributed_to`` names the field and its reason can name the source.
    """
    source_selectors = _selectors(sources)
    sink_selectors = _selectors(sinks)
    if not source_selectors or not sink_selectors:
        return None
    origins = getattr(event, "origins", None)
    if not isinstance(origins, Mapping):
        return None
    for path, labels in origins.items():
        if not isinstance(path, str) or not any(
            _sink_matches(path, selector) for selector in sink_selectors
        ):
            continue
        for label in _as_origin_tuple(labels):
            if any(_matches(label, selector) for selector in source_selectors):
                return path, label
    return None


def describe_origins(origins: Optional[Mapping[str, Any]]) -> List[str]:
    """A stable, human-readable rendering of an origin map, for reports.

    Sorted by argument then label so a receipt or a console row is diffable.
    """
    if not isinstance(origins, Mapping):
        return []
    rows = []
    for key in sorted(origins):
        labels = _as_origin_tuple(origins[key])
        if labels:
            rows.append("{} <- {}".format(key, ", ".join(labels)))
    return rows


__all__ = [
    "FlowTracker",
    "MAX_FRAGMENTS",
    "describe_origins",
    "flow_matches",
    "get_tracker",
    "normalise_origins",
    "origin_for_principal",
    "origin_for_tool",
    "record_origin",
    "set_tracker",
]
