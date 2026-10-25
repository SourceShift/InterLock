"""Documentation contract: the prose must state what the code actually does.

Each test is named for the drift it prevents:

- every documented detector count equals ``len(detector_names())``;
- every command in ``interlock.cli.COMMANDS`` has its own section in the
  generated CLI reference;
- every name in ``interlock.__all__`` appears in the Python API reference;
- every signature shown in a ``python`` fence matches ``inspect.signature``.

The scan is deliberately narrow. A detector count is a number immediately
followed by "detector(s)" (or "ready-made rule(s)"/"built-in rule(s)"), or the
standalone number in the landing page's ``il-card__num`` stat tile. Not any
number that happens to appear near the word. The generated detector catalog is
excluded: it is owned by ``scripts/gen_detector_catalog.py``. The landing page,
``landing/index.md``, is scanned alongside ``docs/``: its stat tile is the
headline count, and it is its own Zensical build (see zensical.landing.toml).
"""
from __future__ import annotations

import ast
import importlib
import inspect
import re
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
DOCS = ROOT / "docs"
LANDING = ROOT / "landing"
CLI_REF = DOCS / "reference" / "cli.md"
API_REF = DOCS / "reference" / "python-api.md"

#: Generated from the detector modules; its count line is checked by
#: ``scripts/gen_detector_catalog.py --check`` instead.
EXCLUDED_COUNT_FILES = {DOCS / "reference" / "detectors.md"}

COUNT_PATTERNS = (
    re.compile(r"(?i)\bdetectors?\s*:\s*(\d+)\b"),
    re.compile(r"(?i)\b(\d+)\s+(?:built-in\s+)?detectors?\b"),
    re.compile(r"(?i)\b(\d+)\s+ready-made\s+(?:rules|detectors)\b"),
    re.compile(r"(?i)\b(\d+)\s+built-in\s+rules?\b"),
    # The landing page renders its headline count as a bare stat tile, with the
    # "detectors" word on the following heading line, so the patterns above
    # never see it. This is the only ``il-card__num`` in the docs.
    re.compile(r'class="il-card__num">(\d+)<'),
)

#: Public names the reference deliberately does not cover. Empty: every name in
#: ``interlock.__all__`` has a place in the reference today. Add a name here
#: only when it is a genuinely internal detail, not to silence a real gap.
UNDOCUMENTED_ALLOWED: set[str] = set()

#: Modules whose callables are documented with a signature in the Python API
#: reference. Every signature-like line must resolve here (or be a non-callable
#: sketch in ``SKETCH_SKETCHES``); a new documented API name that is not imported
#: below fails loudly rather than being silently skipped.
SIGNATURE_MODULES = (
    "interlock",
    "interlock.brace",
    "interlock.event",
    "interlock.interceptors",
    "interlock.interceptors.mcp",
    "interlock.policy.scopes",
    "interlock.receipt",
    "interlock.sink",
    "interlock.testing.harness",
)

#: Callables whose signature ``inspect`` cannot report. ``ScopeTree`` is the
#: native Rust extension type; its Python fallback, ``PyScopeTree``, is covered.
SIGNATURE_SKIPS = {"ScopeTree"}

#: Column-zero call expressions in the examples that parse as a parameter list
#: but are not API signatures. Keep this explicit and tiny.
SKETCH_ALLOWLIST: set[str] = set()

SIGNATURE_START = re.compile(r"^([A-Za-z_]\w*)\(")


def _count_files() -> Iterator[Path]:
    yield README
    for path in sorted([*DOCS.rglob("*.md"), *LANDING.rglob("*.md")]):
        if path in EXCLUDED_COUNT_FILES:
            continue
        yield path


def test_documented_detector_counts_match_the_catalog() -> None:
    from interlock.console.catalog import detector_names

    expected = len(detector_names())
    failures: List[str] = []
    seen: set[Tuple[Path, int]] = set()
    for path in _count_files():
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            for pattern in COUNT_PATTERNS:
                match = pattern.search(line)
                if match is None:
                    continue
                if (path, lineno) in seen:
                    break
                seen.add((path, lineno))
                found = int(match.group(1))
                if found != expected:
                    failures.append(
                        "{}:{}: says {} detectors; the code has {}".format(
                            path.relative_to(ROOT), lineno, found, expected
                        )
                    )
                break
    assert not failures, "stale detector counts:\n" + "\n".join(failures)


def test_every_cli_command_has_a_reference_section() -> None:
    from interlock.cli import COMMANDS

    text = CLI_REF.read_text(encoding="utf-8")
    missing = [
        name for name, _help, _module in COMMANDS
        if "## `interlock {}`".format(name) not in text
    ]
    assert not missing, (
        "docs/reference/cli.md is missing a section for: {}. "
        "Regenerate it with `python scripts/gen_cli_reference.py`.".format(
            ", ".join(missing)
        )
    )


def test_every_public_name_is_in_the_python_api_reference() -> None:
    import interlock

    text = API_REF.read_text(encoding="utf-8")
    missing = [
        name for name in interlock.__all__
        if name not in UNDOCUMENTED_ALLOWED
        and re.search(r"\b{}\b".format(re.escape(name)), text) is None
    ]
    assert not missing, (
        "docs/reference/python-api.md does not mention: {}".format(", ".join(missing))
    )


def _signature_registry() -> Dict[str, object]:
    registry: Dict[str, object] = {}
    for module_name in SIGNATURE_MODULES:
        module = importlib.import_module(module_name)
        names = getattr(module, "__all__", None) or dir(module)
        for name in names:
            try:
                obj = getattr(module, name)
            except AttributeError:
                continue
            if callable(obj) and name not in registry:
                registry[name] = obj
    return registry


def _python_blocks(path: Path) -> Iterator[Tuple[int, List[str]]]:
    """Yield ``(first_line_number, lines)`` for each fenced python block."""
    lines = path.read_text(encoding="utf-8").splitlines()
    start: Optional[int] = None
    for index, line in enumerate(lines):
        if line.strip() == "```python":
            start = index + 1
        elif start is not None and line.startswith("```"):
            yield start + 1, lines[start:index]
            start = None


def _signature_lines(lines: List[str], first_lineno: int) -> Iterator[Tuple[int, str, str]]:
    """Yield column-zero ``name(...)`` candidates, joining wrapped signatures."""
    index = 0
    while index < len(lines):
        match = SIGNATURE_START.match(lines[index])
        if match is None:
            index += 1
            continue
        text = lines[index]
        depth = text.count("(") - text.count(")")
        end = index
        while depth > 0 and end + 1 < len(lines):
            end += 1
            text += " " + lines[end].strip()
            depth += lines[end].count("(") - lines[end].count(")")
        yield first_lineno + index, match.group(1), text
        index = end + 1


def _documented_params(text: str) -> Optional[ast.arguments]:
    """Parse a documented signature, or ``None`` when the line is a call.

    Example code at column zero (``set_sink(None)``, ``print(...)``) parses as
    invalid parameter syntax and is skipped: only a real parameter list can be
    compared with ``inspect.signature``.
    """
    without_comment = re.sub(r"#.*$", "", text).strip()
    open_paren = without_comment.find("(")
    close_paren = without_comment.rfind(")")
    if open_paren < 0 or close_paren < open_paren:
        return None
    params = without_comment[open_paren + 1:close_paren]
    try:
        module = ast.parse("def _documented({}):\n    pass".format(params))
    except SyntaxError:
        return None
    return module.body[0].args  # type: ignore[attr-defined]


def _kinds(args: ast.arguments) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    out += [(arg.arg, "positional_only") for arg in args.posonlyargs]
    out += [(arg.arg, "positional_or_keyword") for arg in args.args]
    if args.vararg is not None:
        out.append((args.vararg.arg, "var_positional"))
    out += [(arg.arg, "keyword_only") for arg in args.kwonlyargs]
    if args.kwarg is not None:
        out.append((args.kwarg.arg, "var_keyword"))
    return out


def _documented_defaults(args: ast.arguments) -> Dict[str, Optional[ast.expr]]:
    defaults: Dict[str, Optional[ast.expr]] = {}
    positional = list(args.posonlyargs) + list(args.args)
    for arg in positional:
        defaults[arg.arg] = None
    for arg, default in zip(positional[len(positional) - len(args.defaults):], args.defaults):
        defaults[arg.arg] = default
    for arg, default in zip(args.kwonlyargs, args.kw_defaults):
        defaults[arg.arg] = default
    return defaults


def _default_matches(documented: Optional[ast.expr], real: object) -> bool:
    """Compare a documented default with the real one where it is meaningful.

    Mutable literals (``{}``, dataclass ``<factory>``) and other expressions
    that ``repr`` cannot round-trip are treated as "not comparable", so the test
    does not assert on a value it cannot see. Constants and named defaults are
    compared, which is what catches a stale ``shared=False``.
    """
    if real is inspect.Parameter.empty:
        return documented is None
    if documented is None:
        return False
    if isinstance(documented, ast.Constant):
        return real == documented.value
    if isinstance(documented, ast.Name):
        return getattr(real, "__name__", None) == documented.id
    if isinstance(documented, ast.Attribute):
        return getattr(real, "__name__", None) == documented.attr
    if isinstance(documented, ast.Dict) or isinstance(documented, ast.List):
        return True
    if isinstance(documented, ast.Tuple):
        return not documented.elts and real == ()
    if (
        isinstance(documented, ast.Call)
        and isinstance(documented.func, ast.Name)
        and documented.func.id == "frozenset"
        and not documented.args
    ):
        return real == frozenset()
    return True


def test_documented_signatures_match_the_code() -> None:
    registry = _signature_registry()
    failures: List[str] = []
    for first_lineno, lines in _python_blocks(API_REF):
        for lineno, name, text in _signature_lines(lines, first_lineno):
            documented = _documented_params(text)
            if documented is None:
                continue
            if name in SKETCH_ALLOWLIST or name in SIGNATURE_SKIPS:
                continue
            obj = registry.get(name)
            if obj is None:
                failures.append(
                    "{}:{}: documented '{}' is not a public callable; add it to "
                    "SIGNATURE_MODULES or SKETCH_ALLOWLIST".format(
                        API_REF.relative_to(ROOT), lineno, name
                    )
                )
                continue
            try:
                real = inspect.signature(obj)
            except (TypeError, ValueError):
                failures.append(
                    "{}:{}: cannot inspect the documented signature of '{}'".format(
                        API_REF.relative_to(ROOT), lineno, name
                    )
                )
                continue
            documented_params = _kinds(documented)
            real_params = [
                (param.name, str(param.kind).split(".")[-1].lower())
                for param in real.parameters.values()
            ]
            if documented_params != real_params:
                failures.append(
                    "{}:{}: '{}' documents {} but the code has {} ({})".format(
                        API_REF.relative_to(ROOT), lineno, name,
                        documented_params, real_params, real,
                    )
                )
                continue
            defaults = _documented_defaults(documented)
            for param_name, default_node in defaults.items():
                real_default = real.parameters[param_name].default
                if not _default_matches(default_node, real_default):
                    failures.append(
                        "{}:{}: '{}' documents a default for '{}' that the code "
                        "does not have ({} != {!r})".format(
                            API_REF.relative_to(ROOT), lineno, name, param_name,
                            _source_default(default_node), real_default,
                        )
                    )
    assert not failures, "stale documented signatures:\n" + "\n".join(failures)


def _source_default(node: Optional[ast.expr]) -> str:
    if node is None:
        return "no default"
    try:
        return ast.unparse(node)
    except AttributeError:  # pragma: no cover - Python < 3.9 has no unparse
        return "a default"
