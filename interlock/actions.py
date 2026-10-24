"""One normaliser for action names, shared by every detector.

The built-in detectors are written against the snake_case action names the
Python adapters emit - ``http_post``, ``read_file``, ``child_process_exec``.
The Node client reports the same effects under namespaced, camelCased names -
``http.fetch``, ``fs.readFile``, ``child_process.execFile``. Comparing those
raw strings to a snake_case set leaves a Node caller unprotected by every
default rule, so this module is the single place that reconciles the spellings:

* :func:`canonical_action` folds case, turns the separators ``.``, ``:`` and
  ``/`` into ``_``, and splits a camelCase boundary. An existing snake_case
  name comes back unchanged.
* :func:`canonical_actions` materialises any iterable of names into a frozen,
  canonical set once, so a rule does not re-normalise its allowlist per event.
* :func:`action_matches` is the only test a detector makes: a canonical event
  action against a canonical allowed set. A non-string name matches nothing.
* :func:`joined_command` renders a split ``command`` (a single program word)
  plus an ``args`` sequence as the one shell command it would run, or None when
  the pair does not split that way. A ``command`` that already carries whitespace
  is a whole command line, so it is judged as written rather than joined with a
  second argument list.
* :func:`command_values` yields the command candidates a rule should judge,
  joining ``command`` plus an ``args`` sequence into one shell command so
  ``child_process.execFile("rm", ["-rf", "/"])`` is seen as ``rm -rf /``.

The shared Node base sets live here too. A detector that already declares its
own egress, read or execution set unions the relevant base into it rather than
repeating the Node names.
"""
from __future__ import annotations

import json
import re
import shlex
from typing import Any, Iterable, Iterator, Mapping, Optional, Tuple

#: Separators a namespaced action may use between its parts.
_SEPARATOR_TRANSLATION = str.maketrans({".": "_", ":": "_", "/": "_"})

#: A camelCase boundary: a lower/digit followed by an upper, or an acronym
#: followed by a capitalised word ("HTTPServer" -> "HTTP_Server").
_LOWER_UPPER = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_ACRONYM_WORD = re.compile(r"(?<=[A-Z])(?=[A-Z][a-z])")


class CanonicalActionSet(frozenset):
    """A frozenset of action names that are already canonical.

    Detectors build one at construction time (via :func:`canonical_actions`),
    so :func:`action_matches` can test membership without re-normalising the
    whole allowlist on every event.
    """

    __slots__ = ()


def canonical_action(name: object) -> str:
    """Return the canonical spelling of an action name.

    ``http.fetch`` -> ``http_fetch``, ``fs.readFile`` -> ``fs_read_file``,
    ``child_process.execFile`` -> ``child_process_exec_file``. The canonical
    form is lowercase, uses ``_`` between words, and leaves an existing
    snake_case name unchanged. A non-string (or empty) name returns ``""``,
    which matches nothing rather than raising.
    """
    if not isinstance(name, str) or not name:
        return ""
    text = name.translate(_SEPARATOR_TRANSLATION)
    text = _ACRONYM_WORD.sub("_", text)
    text = _LOWER_UPPER.sub("_", text)
    return text.lower()


def canonical_actions(names: object) -> CanonicalActionSet:
    """Materialise any iterable of action names into a canonical set.

    A bare string is one name, not its characters. Non-string entries, empty
    names, ``None`` and a non-iterable argument are ignored, so a malformed
    config narrows a rule instead of raising or admitting junk. A generator is
    consumed here, once, rather than on every event.
    """
    if names is None:
        return CanonicalActionSet()
    if isinstance(names, str):
        items: Iterable[Any] = (names,)
    else:
        try:
            items = iter(names)  # type: ignore[arg-type]
        except TypeError:
            return CanonicalActionSet()
    found = set()
    for item in items:
        canonical = canonical_action(item)
        if canonical:
            found.add(canonical)
    return CanonicalActionSet(found)


def action_matches(name: object, allowed: Iterable[str]) -> bool:
    """Whether *name* matches any name in *allowed*, after normalisation.

    Both sides are canonicalised, so a configured ``http_post`` also matches an
    event action spelled ``http.post`` and vice versa. Pass a set produced by
    :func:`canonical_actions` to avoid re-normalising it per event; any other
    iterable is canonicalised here. A non-string or empty *name* returns False.
    """
    canonical = canonical_action(name)
    if not canonical:
        return False
    if isinstance(allowed, CanonicalActionSet):
        return canonical in allowed
    return canonical in canonical_actions(allowed)


#: The Node client's namespaced egress names, in canonical form.
NODE_EGRESS_ACTIONS: CanonicalActionSet = canonical_actions({"http.fetch"})

#: The Node client's namespaced file-read names, in canonical form.
NODE_READ_ACTIONS: CanonicalActionSet = canonical_actions({
    "fs.readFile",
    "fs.open",
    "fs.opendir",
    "fs.createReadStream",
    "fs.readlink",
    "fs.readdir",
    "fs.access",
})

#: The Node client's namespaced execution names, in canonical form. The
#: substring-based execution guard already covers these; the set is exported
#: for policies and detectors that compare action names exactly.
NODE_EXECUTION_ACTIONS: CanonicalActionSet = canonical_actions({
    "child_process.exec",
    "child_process.execFile",
})

#: The Node client's namespaced mutating file effects, in canonical form. The
#: write budget counts these as state-changing: the raw name starts ``fs_``, so
#: the ``write``/``delete``/... prefix test alone would never see them.
NODE_WRITE_ACTIONS: CanonicalActionSet = canonical_actions({
    "fs.appendFile",
    "fs.chmod",
    "fs.chown",
    "fs.copyFile",
    "fs.cp",
    "fs.createWriteStream",
    "fs.link",
    "fs.mkdir",
    "fs.rename",
    "fs.rm",
    "fs.rmdir",
    "fs.symlink",
    "fs.truncate",
    "fs.unlink",
    "fs.utimes",
    "fs.writeFile",
})

#: Every shared Node action name, canonical. A call that differs from a
#: configured spelling only because it is one of these namespaced Node names
#: is still the action the operator listed; anything else must match exactly.
NODE_ACTION_NAMES: CanonicalActionSet = CanonicalActionSet(
    NODE_EGRESS_ACTIONS | NODE_READ_ACTIONS | NODE_EXECUTION_ACTIONS
    | NODE_WRITE_ACTIONS
)


def _scalar_text(value: Any) -> str:
    """Render one ``args`` element as a shell word.

    A string is used as-is; a bool, None or number is rendered the way a JS
    runtime stringifies it (``true``, ``false``, ``null``, ``3``); a container
    is rendered as its JSON text, so no element can hide the rest of an argv
    from a scanner. Nothing here returns None: an unjoinable element is still
    text a detector must see.
    """
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    if isinstance(value, (int, float)):
        return str(value)
    try:
        return json.dumps(value, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return str(value)


def joined_command(args: object) -> Optional[str]:
    """Join a split ``command`` plus ``args`` sequence into one shell command.

    ``{"command": "rm", "args": ["-rf", "/"]}`` is the invocation
    ``rm -rf /`` - judging the bare program name alone would let the real
    command hide behind it. Returns None when ``args`` is not a mapping, when
    ``command`` is not a string, when ``args["args"]`` is not a non-empty
    list/tuple, or when ``command`` already carries whitespace: that value is a
    whole command line, and joining a second argument list onto it would judge
    an invocation nobody wrote. Non-scalar elements are stringified (see
    :func:`_scalar_text`) rather than disabling the join. The mapping is never
    mutated.
    """
    if not isinstance(args, Mapping):
        return None
    command = args.get("command")
    tail = args.get("args")
    if not isinstance(command, str) or not isinstance(tail, (list, tuple)) or not tail:
        return None
    try:
        head = shlex.split(command)
    except ValueError:
        return None
    if len(head) != 1:
        return None
    words = [_scalar_text(item) for item in tail]
    try:
        return shlex.join([command, *words])
    except (TypeError, ValueError):
        return None


def command_values(
    args: object, keys: Optional[Iterable[str]] = None
) -> Iterator[Tuple[str, str]]:
    """Yield ``(argument name, command text)`` candidates from ``args``.

    Every configured top-level string value is yielded, and when ``command`` is
    a single program word and ``args["args"]`` is a non-empty list/tuple, one
    extra ``("command", shlex.join([command, *args]))`` is yielded *before* it.
    The joined form is the argv the process receives; the bare ``command`` is
    still yielded because a caller may also carry a whole command line there
    (``{"command": "rm -rf /", "args": ["--verbose"]}``). A rule that wants only
    the invocation, not the bare value, tells them apart by comparing against
    :func:`joined_command` (as ``runbook_guard`` and ``destructive_command_guard``
    do). The derived entry keeps the name ``command``, so attribution and a
    ``keys=["command"]`` filter keep working.

    ``keys`` filters the yielded names; ``None`` reads every top-level string.
    ``args`` is never mutated, and a non-mapping ``args`` yields nothing.
    """
    if not isinstance(args, Mapping):
        return

    key_set: Optional[frozenset] = None
    if keys is not None:
        if isinstance(keys, str):
            key_set = frozenset({keys})
        else:
            try:
                key_set = frozenset(k for k in keys if isinstance(k, str))
            except TypeError:
                key_set = frozenset()

    joined = joined_command(args)
    if joined is not None and (key_set is None or "command" in key_set):
        yield ("command", joined)

    for name, value in args.items():
        if not isinstance(value, str):
            continue
        if key_set is not None and name not in key_set:
            continue
        yield (name, value)
