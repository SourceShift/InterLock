"""Allow only the shell commands a runbook names, with every parameter checked.

Deny rules chase an open set; a runbook closes it. Give the agent a list of
command templates, typed parameters included, and every shell command must be
one of them::

    runbook_guard(runbooks=[
        {"name": "restart-deployment",
         "templates": ["kubectl rollout restart deployment/{name} -n {namespace}"],
         "params": {"name": {"pattern": "^[a-z0-9-]{1,63}$"},
                    "namespace": {"options": ["staging", "prod"]}}},
        {"name": "tail-logs", "templates": ["kubectl logs {pod} --tail={lines}"],
         "params": {"lines": {"type": "integer", "max": 500}}},
    ])

A command matches when it is a **single** invocation - no pipes, chains,
redirects or substitutions (checked with :mod:`interlock.shell`) - whose words
match a template's words one for one, every ``{param}`` filled by a value that
passes its spec:

================  ===========================================================
``pattern``       a regular expression the whole value must match
``options``       the value must be one of these
``type``          ``string`` (default), ``integer`` (``min``/``max`` apply) or
                  ``path`` (no ``..``, no leading ``-``)
``allow_option``  a value beginning with ``-`` is refused unless this is true
``minlength``     / ``maxlength`` on the value's length
================  ===========================================================

An argument may be the command string or an already-split list/tuple (the
``argv`` a tool was handed). A list's words are matched against the template
words directly, with no shell parse; a non-string word, or an empty sequence,
fails as "not a single plain command".

An unspecified parameter accepts ``[A-Za-z0-9._:/@=+-]+`` only - no spaces, no
shell characters - and, like a declared one, may not begin with ``-``. Anything
that matches no runbook is blocked (or escalated,
with ``verdict="escalate"``); the reason names the closest runbook and the
parameter that failed, never the value. Templates come from your policy or
local files (:func:`load_runbooks`), never from the network.
"""
from __future__ import annotations

import glob
import json
import os
import re
import shlex
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule
from ..shell import parse

POLICY_ID = "runbook"
_SPEC_KEYS = frozenset({"pattern", "options", "type", "minlength", "maxlength", "min", "max",
                        "description", "allow_option"})
_DEFAULT_VALUE = re.compile(r"^[A-Za-z0-9._:/@=+-]+$")
_PLACEHOLDER = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")


class _Runbook:
    def __init__(self, raw: Mapping[str, Any]) -> None:
        if not isinstance(raw, Mapping):
            raise ValueError("a runbook is an object")
        self.name = str(raw.get("name") or "")
        if not self.name:
            raise ValueError("a runbook needs a name")
        templates = raw.get("templates") or ([raw["template"]] if "template" in raw else [])
        if not templates or not all(isinstance(t, str) and t.strip() for t in templates):
            raise ValueError("runbook {!r} needs templates".format(self.name))
        params = raw.get("params") or {}
        if not isinstance(params, Mapping):
            raise ValueError("runbook {!r}: params must be an object".format(self.name))
        self.params: Dict[str, Mapping[str, Any]] = {}
        for pname, spec in params.items():
            if not isinstance(spec, Mapping) or set(spec) - _SPEC_KEYS:
                raise ValueError("runbook {!r}: bad spec for {!r} (keys: {})".format(
                    self.name, pname, ", ".join(sorted(_SPEC_KEYS))))
            if spec.get("type", "string") not in ("string", "integer", "path"):
                raise ValueError("runbook {!r}: type must be string, integer or path".format(self.name))
            if "pattern" in spec:
                re.compile(spec["pattern"])
            self.params[pname] = spec
        self.templates: List[List[Tuple["re.Pattern[str]", List[str]]]] = []
        for template in templates:
            words = []
            for word in shlex.split(template):
                names = _PLACEHOLDER.findall(word)
                regex = "".join(
                    "(?P<{}_{}>.+)".format(part, i) if i % 2 else re.escape(part)
                    for i, part in enumerate(_PLACEHOLDER.split(word)))
                words.append((re.compile("^" + regex + "$", re.S), names))
            self.templates.append(words)

    def check(self, argv: Sequence[str]) -> Tuple[bool, Optional[str], int]:
        """(matches, failure, literal words matched) against the best template."""
        best: Tuple[bool, Optional[str], int] = (False, "no template has this shape", -1)
        for words in self.templates:
            if len(words) != len(argv):
                continue
            values: Dict[str, str] = {}
            literal_hits, failure = 0, None
            for (regex, names), token in zip(words, argv):
                m = regex.match(token)
                if not m:
                    failure = failure or "a fixed word differs"
                    continue
                if not names:
                    literal_hits += 1
                for group, value in m.groupdict().items():
                    pname = group.rsplit("_", 1)[0]
                    if pname in values and values[pname] != value:
                        failure = failure or "{} differs between uses".format(pname)
                    values[pname] = value
            if failure is None:
                for pname, value in values.items():
                    problem = self._check_param(pname, value)
                    if problem:
                        failure = problem
                        break
            if failure is None:
                return True, None, literal_hits
            if literal_hits > best[2]:
                best = (False, failure, literal_hits)
        return best

    def _check_param(self, pname: str, value: str) -> Optional[str]:
        spec = self.params.get(pname)
        if spec is None:
            if value.startswith("-"):
                return "{} may not start with an option".format(pname)
            return None if _DEFAULT_VALUE.match(value) else \
                "{} has characters outside [A-Za-z0-9._:/@=+-]".format(pname)
        kind = spec.get("type", "string")
        if value.startswith("-") and not spec.get("allow_option", False):
            return "{} may not start with an option".format(pname)
        if kind == "integer":
            if not re.match(r"^-?\d+$", value):
                return "{} must be an integer".format(pname)
            number = int(value)
            if "min" in spec and number < spec["min"]:
                return "{} is below {}".format(pname, spec["min"])
            if "max" in spec and number > spec["max"]:
                return "{} is above {}".format(pname, spec["max"])
        if kind == "path" and (".." in value.split("/") or value.startswith("-")):
            return "{} must be a plain path".format(pname)
        if "options" in spec and value not in [str(o) for o in spec["options"]]:
            return "{} must be one of {}".format(pname, ", ".join(str(o) for o in spec["options"]))
        if "pattern" in spec and not re.fullmatch(spec["pattern"], value):
            return "{} does not match its pattern".format(pname)
        if "minlength" in spec and len(value) < spec["minlength"]:
            return "{} is shorter than {}".format(pname, spec["minlength"])
        if "maxlength" in spec and len(value) > spec["maxlength"]:
            return "{} is longer than {}".format(pname, spec["maxlength"])
        if "pattern" not in spec and "options" not in spec and kind == "string" \
                and not _DEFAULT_VALUE.match(value):
            return "{} has characters outside [A-Za-z0-9._:/@=+-]".format(pname)
        return None


def load_runbooks(path: str) -> List[Dict[str, Any]]:
    """Runbooks from a JSON file, or from every ``*.runbook.json`` in a directory."""
    files = sorted(glob.glob(os.path.join(path, "*.runbook.json"))) if os.path.isdir(path) else [path]
    out: List[Dict[str, Any]] = []
    for file in files:
        with open(file, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        out.extend(data if isinstance(data, list) else [data])
    return out


def runbook_guard(
    runbooks: Sequence[Mapping[str, Any]],
    *,
    verdict: str = "block",
    keys: Optional[Iterable[str]] = ("command", "cmd", "argv"),
    actions: Optional[Iterable[str]] = None,
) -> Rule:
    """Build a Rule allowing only commands that match a runbook.

    runbooks: runbook objects (see the module docstring).
    verdict:  ``block`` (default) or ``escalate`` for anything else.
    keys:     argument names holding the command (a string or an already-split
              list/tuple); None reads every string or sequence argument.
    actions:  tools the rule applies to (e.g. ``["Bash"]``); default every tool.
    """
    if verdict not in ("block", "escalate"):
        raise ValueError("verdict must be block or escalate")
    compiled = [_Runbook(r) for r in runbooks]
    if not compiled:
        raise ValueError("runbook_guard needs at least one runbook")
    key_set = None if keys is None else frozenset(keys)
    action_set = None if actions is None else frozenset(actions)
    make = Decision.block if verdict == "block" else Decision.escalate

    def rule(event: SensorEvent) -> Optional[Decision]:
        if action_set is not None and event.action not in action_set:
            return None
        args = getattr(event, "args", None)
        if not isinstance(args, dict):
            return None
        for name, value in args.items():
            if key_set is not None and name not in key_set:
                continue
            if isinstance(value, (list, tuple)):
                if not value:
                    return make("runbook: {} is not a single plain command".format(name),
                                POLICY_ID, attributed_to=name)
                if not all(isinstance(word, str) for word in value):
                    return make("runbook: {} holds a non-string word".format(name),
                                POLICY_ID, attributed_to=name)
                argv = list(value)
            elif isinstance(value, str):
                parsed = parse(value)
                if parsed.partial or len(parsed.invocations) != 1 or parsed.invocations[0].redirects:
                    return make("runbook: {} is not a single plain command".format(name),
                                POLICY_ID, attributed_to=name)
                try:
                    argv = shlex.split(value)
                except ValueError:
                    return make("runbook: {} does not parse".format(name), POLICY_ID, attributed_to=name)
            else:
                continue
            closest: Tuple[int, str, Optional[str]] = (-1, "", None)
            for book in compiled:
                ok, failure, hits = book.check(argv)
                if ok:
                    break
                if hits > closest[0]:
                    closest = (hits, book.name, failure)
            else:
                detail = " (closest: {}: {})".format(closest[1], closest[2]) if closest[0] > 0 else ""
                return make("runbook: {} matches no runbook{}".format(name, detail), POLICY_ID,
                            attributed_to=name)
        return None

    return rule
