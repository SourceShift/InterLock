"""Best-effort shell parser: which programs would this command string run?

Detectors that match raw command text lose to respelling. ``rm -rf /`` is
caught, ``rm -fr /``, ``rm -r -f /``, ``/bin/rm -Rf /`` and
``bash -c 'rm -rf /'`` are not, because the destructive act is the same while
the text differs. This module recovers the *invocations* behind the text - the
program each segment runs and the arguments it gets - so a rule can judge the
act instead of the spelling.

It is deliberately not a POSIX shell. It handles the shapes that carry most
real commands and most evasions:

- Segments split on ``|``, ``|&``, ``||``, ``&&``, ``;``, ``&`` and newlines,
  never inside quotes, ``$(...)``, backticks or a ``( ... )`` subshell.
- Command substitutions (``$(...)``, backticks, ``<(...)``, ``>(...)``) are
  parsed as commands of their own, because they run.
- Wrappers that run another program (``sudo``, ``env``, ``xargs``,
  ``timeout``, ``nohup``, ``nice``, ``busybox`` ...) are looked through, their
  own flags skipped, and the wrapped command parsed.
- Shell interpreters given a script (``sh -c``, ``bash -lc``, ``eval``,
  ``su -c``, ``ssh host '...'``) have the script parsed recursively.
- ``find -exec`` runs a command per match; it is parsed with ``{}`` replaced by
  the paths ``find`` searches, so ``find / -exec rm -rf {} +`` reads as a
  delete of ``/``.
- Inline code for script interpreters (``python -c``, ``node -e``,
  ``perl -e``, ``osascript -e`` ...) has its string literals parsed as shell
  commands, which catches ``os.system("...")``, ``execSync("...")`` and
  ``subprocess.run(["rm", "-rf", "/"])``. This is a heuristic over string
  literals, not a parser for those languages.

The parser never raises. Input it cannot fully read (an unclosed quote, a
nesting deeper than :data:`MAX_DEPTH`, more than :data:`MAX_INVOCATIONS`
commands) yields what it could read with ``partial=True``: a lower bound on
what the string runs, never a claim that it runs nothing else. A parser is not
a boundary - obfuscation such as ``$'\\x72\\x6d'`` or base64 passes it - and
code that must be contained belongs in the BRACE sandbox.
"""
from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from typing import Dict, FrozenSet, List, Optional, Sequence, Tuple

#: How deep nested scripts (``bash -c 'bash -c "..."'``), substitutions and
#: inline code are followed. Deeper input is reported ``partial``.
MAX_DEPTH = 6

#: Longest input read. The rest is ignored and the result marked ``partial``.
MAX_INPUT = 64 * 1024

#: Most invocations recorded for one string.
MAX_INVOCATIONS = 256


@dataclass(frozen=True)
class Invocation:
    """One program the command string would run.

    binary:    the program's basename as written (``rm`` for ``/bin/rm``).
    args:      its arguments, with quotes removed and redirections taken out.
    via:       how it was reached, outermost first: ``("sudo",)``,
               ``("bash -c",)``, ``("$()",)``, ``("python -c",)``. Empty for a
               top-level command.
    redirects: files its output is redirected to (``>``, ``>>``, ``&>``).
    pipeline:  which pipeline it belongs to; invocations sharing a number are
               connected by pipes.
    stage:     its position in that pipeline, 0 for the first command.
    """

    binary: str
    args: Tuple[str, ...] = ()
    via: Tuple[str, ...] = ()
    redirects: Tuple[str, ...] = ()
    pipeline: int = 0
    stage: int = 0

    @property
    def name(self) -> str:
        """The binary lowercased, for classification.

        Lowercased because the default macOS filesystem is case-insensitive:
        ``RM -rf ~`` finds ``/bin/rm`` there.
        """
        return self.binary.lower()


@dataclass(frozen=True)
class ParsedCommand:
    """Every invocation recovered from one command string."""

    source: str
    invocations: Tuple[Invocation, ...] = ()
    partial: bool = False

    @property
    def binaries(self) -> Tuple[str, ...]:
        """Distinct lowercased binary names, in first-seen order."""
        seen: Dict[str, None] = {}
        for inv in self.invocations:
            seen.setdefault(inv.name, None)
        return tuple(seen)


def parse(cmd: str) -> ParsedCommand:
    """Recover the invocations a shell command string would run. Never raises."""
    if not isinstance(cmd, str):
        return ParsedCommand(source="", partial=True)
    parser = _Parser()
    text = cmd
    if len(text) > MAX_INPUT:
        text = text[:MAX_INPUT]
        parser.partial = True
    try:
        parser.text(text, depth=0, via=())
    except RecursionError:
        parser.partial = True
    return ParsedCommand(
        source=cmd, invocations=tuple(parser.found), partial=parser.partial,
    )


# --- tables ------------------------------------------------------------------

_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")

# Shell reserved words that can precede a command in one segment
# ("then rm -rf /") or stand alone ("fi").
_LEADING_KEYWORDS = frozenset(
    {"if", "then", "else", "elif", "do", "while", "until", "!", "{", "}", "(", ")",
     "fi", "done", "esac"}
)
# Segments starting with these are compound-command headers, not commands.
_COMPOUND_HEADERS = frozenset({"for", "case", "select", "function"})

_SHELLS = frozenset(
    {"sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "fish", "yash", "csh", "tcsh"}
)

# Wrapper -> (options that take a value, positional arguments before the
# wrapped command). Options are skipped up to the first non-option token.
_WRAPPERS: Dict[str, Tuple[FrozenSet[str], int]] = {
    "sudo": (frozenset({"-u", "-g", "-h", "-p", "-C", "-D", "-r", "-t", "-U", "-T",
                        "--user", "--group", "--host", "--prompt", "--chdir",
                        "--role", "--type", "--other-user", "--command-timeout",
                        "--close-from"}), 0),
    "doas": (frozenset({"-u", "-C"}), 0),
    "pkexec": (frozenset({"--user"}), 0),
    "env": (frozenset({"-u", "--unset", "-C", "--chdir"}), 0),
    "nice": (frozenset({"-n", "--adjustment"}), 0),
    "ionice": (frozenset({"-c", "-n", "-p", "-P", "-u", "--class",
                          "--classdata"}), 0),
    "nohup": (frozenset(), 0),
    "setsid": (frozenset(), 0),
    "timeout": (frozenset({"-s", "--signal", "-k", "--kill-after"}), 1),
    "time": (frozenset({"-f", "--format", "-o", "--output"}), 0),
    "command": (frozenset(), 0),
    "builtin": (frozenset(), 0),
    "exec": (frozenset({"-a"}), 0),
    "stdbuf": (frozenset({"-i", "-o", "-e"}), 0),
    "chroot": (frozenset({"--userspec", "--groups"}), 1),
    "flock": (frozenset({"-w", "--timeout", "-E", "--conflict-exit-code"}), 1),
    "caffeinate": (frozenset({"-w", "-t"}), 0),
    "unbuffer": (frozenset(), 0),
    "chronic": (frozenset(), 0),
    "busybox": (frozenset(), 0),
    "xargs": (frozenset({"-I", "-n", "-P", "-L", "-d", "-E", "-s", "-a",
                         "--arg-file", "--delimiter", "--max-args", "--max-procs",
                         "--max-lines", "--replace", "--eof", "--max-chars"}), 0),
}

# Wrappers that also accept NAME=value assignments before the command.
_ASSIGNING_WRAPPERS = frozenset({"env", "sudo", "doas"})

_SSH_VALUE_OPTIONS = frozenset(
    {"-b", "-c", "-D", "-E", "-e", "-F", "-I", "-i", "-J", "-L", "-l", "-m", "-O",
     "-o", "-p", "-Q", "-R", "-S", "-W", "-w"}
)

_SCRIPT_INTERPRETER = re.compile(
    r"^(python[0-9.]*|pypy[0-9.]*|node|nodejs|bun|deno|perl[0-9.]*|ruby[0-9.]*"
    r"|php[0-9.]*|lua[0-9.]*|osascript)$"
)

# Exact flags that introduce inline code, per interpreter family.
_CODE_FLAGS: Dict[str, FrozenSet[str]] = {
    "node": frozenset({"-e", "--eval", "-p", "--print"}),
    "bun": frozenset({"-e", "--eval", "-p", "--print"}),
    "php": frozenset({"-r"}),
    "lua": frozenset({"-e"}),
    "osascript": frozenset({"-e"}),
}

# A string literal in inline code: triple-quoted, single, double or backtick.
_LITERAL = re.compile(
    r'"""(.*?)"""|\'\'\'(.*?)\'\'\'|"((?:\\.|[^"\\])*)"|\'((?:\\.|[^\'\\])*)\'|`((?:\\.|[^`\\])*)`',
    re.DOTALL,
)
# A bracketed list made only of string literals: ["rm", "-rf", "/"].
_LITERAL_LIST = re.compile(
    r"\[\s*(?:(?:\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*')\s*,\s*)*"
    r"(?:\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*')\s*,?\s*\]"
)

_OUT_REDIRECT = re.compile(r"^(?:\d+|&)?(>>?|>\||&>>?)(.*)$")
_IN_REDIRECT = re.compile(r"^\d*(<<<|<<-?|<>|<)(.*)$")


# --- the parser --------------------------------------------------------------


class _Parser:
    def __init__(self) -> None:
        self.found: List[Invocation] = []
        self.partial = False
        self._pipeline = 0

    # Top level of a piece of shell text: split, then parse each segment.
    def text(self, text: str, depth: int, via: Tuple[str, ...]) -> None:
        if depth > MAX_DEPTH:
            self.partial = True
            return
        segments, substitutions, complete = _split(text)
        if not complete:
            self.partial = True
        for inner in substitutions:
            self.text(inner, depth + 1, via + ("$()",))
        stage = 0
        for segment, op in segments:
            if op in ("|", "|&"):
                stage += 1
            else:
                self._pipeline += 1
                stage = 0
            self.segment(segment, depth, via, self._pipeline, stage)

    def segment(self, segment: str, depth: int, via: Tuple[str, ...],
                pipeline: int, stage: int) -> None:
        body = segment.strip()
        if not body:
            return
        inner = _subshell_body(body)
        if inner is not None:
            self.text(inner, depth + 1, via)
            return
        tokens = self.tokens(body)
        tokens, redirects = _take_redirects(tokens)
        self.command(tokens, depth, via, redirects, pipeline, stage)

    def tokens(self, body: str) -> List[str]:
        lexer = shlex.shlex(body, posix=True)
        lexer.whitespace_split = True
        lexer.commenters = ""
        try:
            return list(lexer)
        except ValueError:  # unclosed quote or a trailing escape
            self.partial = True
            return body.split()

    def record(self, inv: Invocation) -> bool:
        if len(self.found) >= MAX_INVOCATIONS:
            self.partial = True
            return False
        self.found.append(inv)
        return True

    def command(self, tokens: Sequence[str], depth: int, via: Tuple[str, ...],
                redirects: Tuple[str, ...], pipeline: int, stage: int) -> None:
        tokens = list(tokens)
        while tokens and tokens[0] in _LEADING_KEYWORDS:
            tokens.pop(0)
        while tokens and _ASSIGNMENT.match(tokens[0]):
            tokens.pop(0)
        if not tokens or tokens[0] in _COMPOUND_HEADERS:
            return
        binary = _basename(tokens[0])
        if not binary:
            return
        args = tuple(tokens[1:])
        inv = Invocation(binary, args, via, redirects, pipeline, stage)
        if not self.record(inv):
            return
        self.unwrap(inv, depth)

    def unwrap(self, inv: Invocation, depth: int) -> None:
        """Parse whatever program ``inv`` runs on its caller's behalf."""
        name = inv.name
        args = list(inv.args)
        nested = depth + 1
        if nested > MAX_DEPTH:
            if name in _WRAPPERS or name in _SHELLS or name in ("eval", "su", "ssh",
                                                              "find", "watch"):
                self.partial = True
            return
        via = inv.via + (name,)

        if name in _WRAPPERS:
            if name == "command" and any(a in ("-v", "-V") for a in args):
                return  # a lookup, not an execution
            if name == "env":
                split = _option_value(args, ("-S", "--split-string"))
                if split is not None:
                    self.text(split, nested, via)
                    return
            rest = _skip_options(args, *_WRAPPERS[name],
                                 assignments=name in _ASSIGNING_WRAPPERS)
            if rest:
                self.command(rest, nested, via, inv.redirects, inv.pipeline, inv.stage)
            return

        if name in _SHELLS:
            script = _shell_script(args)
            if script is not None:
                self.text(script, nested, inv.via + (name + " -c",))
            return

        if name == "eval" and args:
            self.text(" ".join(args), nested, inv.via + ("eval",))
            return

        if name == "su":
            script = _option_value(args, ("-c", "--command"))
            if script is not None:
                self.text(script, nested, inv.via + ("su -c",))
            return

        if name == "watch":
            rest = _skip_options(args, frozenset({"-n", "--interval", "-d"}), 0)
            if rest:
                self.text(" ".join(rest), nested, via)
            return

        if name == "ssh":
            rest = _skip_options(args, _SSH_VALUE_OPTIONS, 1)
            if rest:
                self.text(" ".join(rest), nested, via)
            return

        if name == "find":
            self.find_exec(inv, nested)
            return

        if _SCRIPT_INTERPRETER.match(name):
            for code in _inline_code(name, args):
                for literal in _literals(code):
                    self.text(literal, nested, inv.via + (name + " -c",))

    def find_exec(self, inv: Invocation, depth: int) -> None:
        """Parse each ``-exec``/``-execdir``/``-ok`` command of a ``find``."""
        args = list(inv.args)
        roots = _find_roots(args) or ["."]
        i = 0
        while i < len(args):
            if args[i] in ("-exec", "-execdir", "-ok", "-okdir"):
                j = i + 1
                while j < len(args) and args[j] not in (";", "+"):
                    j += 1
                cmd = args[i + 1:j]
                for root in roots:
                    replaced = [root if a == "{}" else a for a in cmd]
                    self.command(replaced, depth, inv.via + ("find -exec",),
                                 inv.redirects, inv.pipeline, inv.stage)
                i = j + 1
                continue
            i += 1


# --- helpers -----------------------------------------------------------------


def _basename(token: str) -> str:
    return token.rstrip("/").rsplit("/", 1)[-1].lstrip("\\")


def _split(text: str) -> Tuple[List[Tuple[str, str]], List[str], bool]:
    """Split shell text into (segment, operator-before-it) pairs.

    Also returns the bodies of every command/process substitution found outside
    single quotes, and whether every quote and bracket was closed.
    """
    segments: List[Tuple[str, str]] = []
    substitutions: List[str] = []
    buf: List[str] = []
    op = ""
    complete = True
    quote: Optional[str] = None
    depth = 0
    i = 0
    n = len(text)

    def flush(next_op: str) -> None:
        nonlocal op
        segments.append(("".join(buf), op))
        buf.clear()
        op = next_op

    while i < n:
        c = text[i]
        if quote == "'":
            buf.append(c)
            if c == "'":
                quote = None
            i += 1
            continue
        if c == "\\" and i + 1 < n:
            buf.append(text[i:i + 2])
            i += 2
            continue
        # $( ... ) and backticks execute even inside double quotes.
        if c == "$" and text.startswith("$(", i) and not text.startswith("$((", i):
            inner, end, ok = _matching(text, i + 2, "(", ")")
            complete = complete and ok
            substitutions.append(inner)
            buf.append(text[i:end])
            i = end
            continue
        if c == "`":
            end = text.find("`", i + 1)
            if end < 0:
                complete = False
                substitutions.append(text[i + 1:])
                buf.append(text[i:])
                i = n
                continue
            substitutions.append(text[i + 1:end])
            buf.append(text[i:end + 1])
            i = end + 1
            continue
        if quote == '"':
            buf.append(c)
            if c == '"':
                quote = None
            i += 1
            continue
        if c in ("'", '"'):
            quote = c
            buf.append(c)
            i += 1
            continue
        if c in "<>" and text.startswith("(", i + 1):
            inner, end, ok = _matching(text, i + 2, "(", ")")
            complete = complete and ok
            substitutions.append(inner)
            buf.append(text[i:end])
            i = end
            continue
        if c == "#" and (not buf or buf[-1][-1:] in (" ", "\t", "\n", ";", "|", "&", "(")):
            while i < n and text[i] != "\n":
                i += 1
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth = max(0, depth - 1)
        if depth == 0:
            two = text[i:i + 2]
            if two in ("&&", "||", "|&"):
                flush(two)
                i += 2
                continue
            if c == "|" or c == ";" or c == "\n":
                flush("|" if c == "|" else ";")
                i += 1
                continue
            if c == "&":
                prev = buf[-1][-1:] if buf else ""
                if prev not in (">", "<") and not text.startswith("&>", i):
                    flush(";")
                    i += 1
                    continue
        buf.append(c)
        i += 1
    if quote is not None or depth:
        complete = False
    flush("")
    return [s for s in segments if s[0].strip()], substitutions, complete


def _matching(text: str, start: int, open_: str, close: str) -> Tuple[str, int, bool]:
    """Body of a bracketed span starting after its opener; quotes respected.

    Returns (body, index just past the closer, closed?).
    """
    depth = 1
    quote: Optional[str] = None
    i = start
    n = len(text)
    while i < n:
        c = text[i]
        if quote:
            if c == "\\" and quote == '"':
                i += 2
                continue
            if c == quote:
                quote = None
        elif c == "\\":
            i += 2
            continue
        elif c in ("'", '"'):
            quote = c
        elif c == open_:
            depth += 1
        elif c == close:
            depth -= 1
            if depth == 0:
                return text[start:i], i + 1, True
        i += 1
    return text[start:], n, False


def _subshell_body(body: str) -> Optional[str]:
    """``( ... )`` around a whole segment: return what is inside."""
    if not body.startswith("("):
        return None
    inner, end, ok = _matching(body, 1, "(", ")")
    if not ok:
        return inner
    if body[end:].strip() and not body[end:].lstrip().startswith((">", "<", "2>", "&>")):
        return None
    return inner


def _take_redirects(tokens: List[str]) -> Tuple[List[str], Tuple[str, ...]]:
    """Remove redirection operators; return the output-redirect targets."""
    kept: List[str] = []
    targets: List[str] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        out = _OUT_REDIRECT.match(tok)
        if out:
            target = out.group(2)
            if not target and i + 1 < len(tokens):
                target = tokens[i + 1]
                i += 1
            if target and not target.startswith("&"):
                targets.append(target)
            i += 1
            continue
        if tok.startswith(("<(", ">(")):
            kept.append(tok)  # process substitution, an argument (its body runs)
            i += 1
            continue
        inp = _IN_REDIRECT.match(tok)
        if inp:
            if not inp.group(2):
                i += 1  # skip the operand (a file, here-doc word or string)
            i += 1
            continue
        kept.append(tok)
        i += 1
    return kept, tuple(targets)


def _skip_options(args: Sequence[str], valued: FrozenSet[str], positional: int,
                  *, assignments: bool = False) -> List[str]:
    """Drop a wrapper's options (and N positionals); return the wrapped command."""
    i = 0
    while i < len(args):
        tok = args[i]
        if tok == "--":
            i += 1
            break
        if tok.startswith("-") and len(tok) > 1:
            i += 2 if tok in valued else 1
            continue
        if assignments and _ASSIGNMENT.match(tok):
            i += 1
            continue
        break
    i += positional
    return list(args[i:]) if i < len(args) else []


def _option_value(args: Sequence[str], names: Sequence[str]) -> Optional[str]:
    for i, tok in enumerate(args):
        if tok in names and i + 1 < len(args):
            return args[i + 1]
        for name in names:
            if name.startswith("--") and tok.startswith(name + "="):
                return tok[len(name) + 1:]
    return None


def _shell_script(args: Sequence[str]) -> Optional[str]:
    """The script a shell runs with ``-c``, or None for a file/stdin shell."""
    has_c = False
    i = 0
    while i < len(args):
        tok = args[i]
        if tok == "--":
            i += 1
            break
        if tok in ("--command",) and i + 1 < len(args):
            return args[i + 1]  # fish
        if tok.startswith("--command="):
            return tok[len("--command="):]
        if tok in ("-o", "+o", "-O", "+O", "--rcfile", "--init-file"):
            i += 2
            continue
        if tok.startswith("-") and not tok.startswith("--") and len(tok) > 1:
            if "c" in tok[1:]:
                has_c = True
            i += 1
            continue
        if tok.startswith("--") or tok.startswith("+"):
            i += 1
            continue
        break
    if has_c and i < len(args):
        return args[i]
    return None


def _inline_code(name: str, args: Sequence[str]) -> List[str]:
    """Every inline-code argument given to a script interpreter."""
    family = re.sub(r"[0-9.]+$", "", name)
    if family == "nodejs":
        family = "node"
    codes: List[str] = []
    i = 0
    while i < len(args):
        tok = args[i]
        nxt = args[i + 1] if i + 1 < len(args) else None
        if family in ("python", "pypy"):
            if tok.startswith("-") and not tok.startswith("--") and tok.endswith("c"):
                if nxt is not None:
                    codes.append(nxt)
                break  # everything after the code is argv for it
        elif family in ("perl", "ruby"):
            if tok.startswith("-") and not tok.startswith("--") and tok[-1] in "eE":
                if nxt is not None:
                    codes.append(nxt)
                    i += 2
                    continue
        elif family == "deno":
            if tok == "eval" and nxt is not None:
                codes.append(nxt)
                break
        else:
            flags = _CODE_FLAGS.get(family, frozenset())
            if tok in flags and nxt is not None:
                codes.append(nxt)
                i += 2
                continue
            for flag in flags:
                if flag.startswith("--") and tok.startswith(flag + "="):
                    codes.append(tok[len(flag) + 1:])
        i += 1
    return codes


def _literals(code: str) -> List[str]:
    """String literals in inline code, plus each list of literals joined."""
    found: List[str] = []
    for match in _LITERAL_LIST.finditer(code):
        items = [next(g for g in m.groups() if g is not None)
                 for m in _LITERAL.finditer(match.group(0))]
        if len(items) > 1:
            found.append(" ".join(shlex.quote(_unescape(s)) for s in items))
    for match in _LITERAL.finditer(code):
        value = next((g for g in match.groups() if g is not None), "")
        if value.strip():
            found.append(_unescape(value))
    return found


def _unescape(value: str) -> str:
    return value.replace('\\"', '"').replace("\\'", "'").replace("\\\\", "\\")


def _find_roots(args: Sequence[str]) -> List[str]:
    """The start paths of a ``find``: arguments before the first expression."""
    roots: List[str] = []
    for tok in args:
        if tok.startswith("-") or tok in ("(", ")", "!", ","):
            if tok in ("-H", "-L", "-P"):
                continue
            break
        roots.append(tok)
    return roots
