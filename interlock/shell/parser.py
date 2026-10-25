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
a boundary: ANSI-C quoting such as ``$'\\x72\\x6d'`` is decoded, but a base64
payload piped into a shell, or a script fetched in one command and run by a
later one, passes it - code that must be contained belongs in the BRACE
sandbox.
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
    "runuser": (frozenset({"-u", "--user", "-g", "--group", "-s", "--shell",
                           "-c", "--command", "-w", "--whitelist-environment"}),
                0),
    "nsenter": (frozenset({"-t", "--target", "-S", "--setuid", "-G", "--setgid",
                           "-w", "--wd"}), 0),
    "unshare": (frozenset({"-w", "--wd", "-S", "--setuid", "-G", "--setgid",
                           "--map-user", "--map-group", "--map-users",
                           "--map-groups", "--propagation",
                           "--kill-child-signal"}), 0),
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
    r"|php[0-9.]*|lua[0-9.]*|osascript|awk|gawk|mawk|nawk)$"
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
# Two or more string literals joined with ``+``: "rm -rf " + "/" is the one
# string the interpreter evaluates, so it is folded before it is scanned.
_LITERAL_CONCAT = re.compile(
    r'(?:"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\')'
    r'(?:\s*\+\s*(?:"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'))+'
)
# Adjacent string literals with no operator (Python implicit concatenation),
# separated only by blanks on the same line.
_LITERAL_ADJACENT = re.compile(
    r'(?:"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\')'
    r'(?:[ \t]+(?:"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'))+'
)

# An ANSI-C quoted word (``$'\\x72\\x6d'``). ``shlex`` keeps the escapes as
# text, so the word is decoded here, before it can name a program.
_ANSI_C_QUOTED = re.compile(r"\$'((?:\\.|[^'\\])*)'")
_C_ESCAPES = {
    "a": "\a", "b": "\b", "e": "\x1b", "f": "\f", "n": "\n", "r": "\r",
    "t": "\t", "v": "\v", "\\": "\\", "'": "'", '"': '"', "?": "?",
}

# Positional parameters a shell script can read: ``$1``, ``${1}``, ``$@``.
_POSITIONAL = re.compile(r"\$(?:\{([0-9]+|[@*])\}|([0-9]|[@*]))")

# A first program that reads its stdin as a script, so a here-document body is
# code rather than data (``bash <<EOF`` runs what follows).
_STDIN_CODE = re.compile(
    r"^(?:sh|bash|zsh|dash|ksh|mksh|ash|fish|python[0-9.]*|perl[0-9.]*"
    r"|ruby[0-9.]*|node|php[0-9.]*)$"
)

_OUT_REDIRECT = re.compile(r"^(?:\d+|&)?(>>?|>\||&>>?)(.*)$")
_IN_REDIRECT = re.compile(r"^\d*(<<<|<<-?|<>|<)(.*)$")


# --- the parser --------------------------------------------------------------


class _Parser:
    def __init__(self) -> None:
        self.found: List[Invocation] = []
        self.partial = False
        self._pipeline = 0
        # Shell variables bound by a literal ``NAME=value`` seen earlier in the
        # same command string. Only literal bindings are tracked: an unknown
        # variable stays as written rather than being guessed from this process.
        self.vars: Dict[str, str] = {}

    # Top level of a piece of shell text: split, then parse each segment.
    def text(self, text: str, depth: int, via: Tuple[str, ...]) -> None:
        if depth > MAX_DEPTH:
            self.partial = True
            return
        segments, substitutions, heredocs, complete = _split(text)
        if not complete:
            self.partial = True
        for inner in substitutions:
            self.text(inner, depth + 1, via + ("$()",))
        for body in heredocs:
            self.text(body, depth + 1, via + ("heredoc",))
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
        # ``$'...'`` is one word whose escapes bash decodes. shlex would keep
        # the backslashes, so decode it first and re-quote the result, keeping
        # spaces inside the word from splitting it.
        body = _ANSI_C_QUOTED.sub(
            lambda m: shlex.quote(_c_unescape(m.group(1))), body)
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
        # A literal assignment is not dropped: the shell remembers it, so a
        # later ``"$NAME"`` word must resolve to the value it binds. Dropping
        # it left the operand a bare ``$NAME`` no guard could resolve.
        while tokens and _ASSIGNMENT.match(tokens[0]):
            key, _, value = tokens.pop(0).partition("=")
            self.vars[key] = self.expand(value)
        tokens = [self.expand(tok) for tok in tokens]
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

    def expand(self, word: str) -> str:
        """``word`` with the variables bound so far substituted.

        Only ``$NAME`` and ``${NAME}`` of variables this string bound are
        replaced; an unbound reference stays as written rather than being read
        from this process's environment, so the result stays deterministic.
        """
        if "$" not in word or not self.vars:
            return word

        def replace(match: "re.Match[str]") -> str:
            name = match.group(1) or match.group(2)
            return self.vars.get(name, match.group(0))

        return re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)",
                      replace, word)

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
            if name in _ASSIGNING_WRAPPERS:
                # ``env P=/x cmd`` binds P for the wrapped command too.
                self._bind_assignments(args)
            if name == "runuser":
                # ``runuser -u root -c 'cmd'`` runs the string as a shell.
                script = _option_value(args, ("-c", "--command"))
                if script is not None:
                    self.text(script, nested, via)
                    return
            if name == "xargs":
                self._xargs(inv, args, nested, via)
                return
            options, positional = _WRAPPERS[name]
            if name == "runuser" and not any(
                    a in ("-u", "--user") or a.startswith("--user=") for a in args):
                # Without ``-u`` the user is the first positional argument.
                positional = 1
            rest = _skip_options(args, options, positional,
                                 assignments=name in _ASSIGNING_WRAPPERS)
            if rest and rest[0] == "--":
                # ``runuser root -- cmd``: the separator follows the wrapper's
                # positional argument, after ``_skip_options`` stops.
                rest = rest[1:]
            if rest:
                self.command(rest, nested, via, inv.redirects, inv.pipeline, inv.stage)
            return

        if name in _SHELLS:
            script, positionals = _shell_script(args)
            if script is not None:
                self.text(_expand_positionals(script, positionals), nested,
                          inv.via + (name + " -c",))
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

    def _bind_assignments(self, args: Sequence[str]) -> None:
        """Bind literal ``NAME=value`` words a wrapper takes before its command."""
        for tok in args:
            if _ASSIGNMENT.match(tok):
                key, _, value = tok.partition("=")
                self.vars[key] = self.expand(value)
            elif not tok.startswith("-"):
                return

    def _xargs(self, inv: Invocation, args: List[str], depth: int,
               via: Tuple[str, ...]) -> None:
        """Parse ``xargs``' command with the operands it reads on stdin.

        ``echo / | xargs rm -rf`` runs ``rm -rf /``: the path travels in the
        pipe, not in the xargs argv. The previous stage's words are the data
        xargs appends (or substitutes for ``-I``/``--replace``), so the wrapped
        command is judged with them.
        """
        rest = _skip_options(args, *_WRAPPERS["xargs"], assignments=False)
        data: List[str] = []
        for prev in reversed(self.found[:-1]):
            if prev.pipeline == inv.pipeline and prev.stage == inv.stage - 1:
                data = _xargs_input(prev)
                break
        if data:
            replace_with = _option_value(args, ("-I", "--replace"))
            if replace_with:
                expanded: List[str] = []
                for tok in rest:
                    expanded.extend(data if tok == replace_with else [tok])
                rest = expanded
            else:
                rest = rest + data
        if rest:
            self.command(rest, depth, via, inv.redirects, inv.pipeline, inv.stage)

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


#: ``find`` options whose value is a name/pattern, i.e. something that could
#: be an operand of the command it is piped into. ``find``'s roots and its
#: tests (``-xdev``, ``-maxdepth``) describe the walk, not the matched paths,
#: so they are not carried over.
_FIND_PATTERN_OPTIONS = frozenset({"-name", "-iname", "-path", "-wholename"})


def _xargs_input(prev: Invocation) -> List[str]:
    """The words ``prev`` feeds to a downstream ``xargs``.

    ``xargs`` splits its stdin on blanks, so a stage's *output* is word-shaped
    even when its argument is not: ``printf '/\\n'`` feeds ``/``. A ``find``
    feeds matched paths, modelled by its name patterns; carrying its roots
    would put ``/`` into the wrapped command's argv and block a harmless
    ``find / -name '*.pyc' | xargs rm``.
    """
    if _basename(prev.binary) == "find":
        args = list(prev.args)
        return [args[i + 1] for i, a in enumerate(args[:-1])
                if a in _FIND_PATTERN_OPTIONS]
    words: List[str] = []
    for arg in prev.args:
        text = arg.replace("\\n", "\n").replace("\\t", "\t").replace("\\r", "\r")
        words.extend(text.split())
    return words


def _split(text: str) -> Tuple[List[Tuple[str, str]], List[str], List[str], bool]:
    """Split shell text into (segment, operator-before-it) pairs.

    Also returns the bodies of every command/process substitution found outside
    single quotes, the here-document bodies that are themselves executed (a
    shell reading its stdin as a script), and whether every quote and bracket
    was closed. A here-document feeding ``cat`` is data, not a command.
    """
    segments: List[Tuple[str, str]] = []
    substitutions: List[str] = []
    heredoc_scripts: List[str] = []
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
            if c == "\n":
                # The line just read may open a here-document; its body runs
                # to the delimiter and is data unless the command reads stdin
                # as a script.
                line = "".join(buf)
                pending = _heredocs(line)
                flush(";")
                i += 1
                if pending:
                    program = _stdin_code_program(line)
                    for delimiter, strip_tabs in pending:
                        body, i, found = _consume_heredoc(
                            text, i, delimiter, strip_tabs)
                        if found and program:
                            heredoc_scripts.append(_heredoc_text(program, body))
                continue
            if c == "|" or c == ";":
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
    return ([s for s in segments if s[0].strip()], substitutions,
            heredoc_scripts, complete)


def _heredocs(line: str) -> List[Tuple[str, bool]]:
    """``(delimiter, strip_tabs)`` for each here-document opened on ``line``.

    Quote-aware, so ``echo '<<EOF'`` is not a here-document; a quoted
    delimiter (``<<'EOF'``) is unquoted to its word, as the shell does.
    """
    found: List[Tuple[str, bool]] = []
    quote: Optional[str] = None
    i = 0
    n = len(line)
    while i < n:
        c = line[i]
        if quote:
            if c == "\\" and quote == '"':
                i += 2
                continue
            if c == quote:
                quote = None
            i += 1
            continue
        if c == "\\":
            i += 2
            continue
        if c in ("'", '"'):
            quote = c
            i += 1
            continue
        if c == "`":
            # ``<<`` inside a backtick substitution is that command's own
            # text; reading it as a here-document here would swallow the
            # rest of the line's commands as data.
            close = line.find("`", i + 1)
            i = (close + 1) if close > i else i + 1
            continue
        if line.startswith("$((", i):
            # Arithmetic expansion: ``$(($n << 2))``. A ``<<`` here is a
            # shift, never a here-document.
            close = line.find("))", i + 3)
            i = (close + 2) if close > i else i + 1
            continue
        if line.startswith("<<", i) and not line.startswith("<<<", i):
            j = i + 2
            strip_tabs = False
            if j < n and line[j] == "-":
                strip_tabs = True
                j += 1
            while j < n and line[j] in " \t":
                j += 1
            if j < n and line[j] in ("'", '"'):
                closing = line.find(line[j], j + 1)
                if closing < 0:
                    break
                found.append((line[j + 1:closing], strip_tabs))
                i = closing + 1
                continue
            start = j
            while j < n and line[j] not in " \t;&|<>()":
                j += 1
            if j > start:
                found.append((line[start:j], strip_tabs))
            i = j
            continue
        i += 1
    return found


def _consume_heredoc(text: str, i: int, delimiter: str,
                     strip_tabs: bool) -> Tuple[str, int, bool]:
    """The body before ``delimiter``'s line, the index past it, and whether a
    terminator was found.

    An unterminated here-document is not consumed: the shell would only error
    on it, and treating the remaining lines as its body would hide commands
    that the caller still has to judge.
    """
    lines: List[str] = []
    n = len(text)
    while i <= n:
        end = text.find("\n", i)
        line = text[i:] if end < 0 else text[i:end]
        check = line.lstrip("\t") if strip_tabs else line
        if check == delimiter:
            return "\n".join(lines), (end + 1 if end >= 0 else n), True
        lines.append(line)
        if end < 0:
            return "", i, False
        i = end + 1
    return "", i, False


#: Programs whose first non-option word is the program actually run. A
#: here-document fed to ``env bash`` is still a script fed to a shell.
_STDIN_WRAPPERS = frozenset({
    "env", "nohup", "setsid", "command", "exec", "builtin", "unbuffer",
    "timeout", "nice", "ionice", "chrt", "taskset", "stdbuf", "time",
})


def _unwrap_wrappers(tokens: List[str]) -> List[str]:
    """Drop leading wrapper programs and their own arguments."""
    while tokens:
        name = _basename(tokens[0]).lower()
        if name == "env":
            tokens = tokens[1:]
            while tokens and (tokens[0].startswith("-") or _ASSIGNMENT.match(tokens[0])):
                tokens.pop(0)
            continue
        if name not in _STDIN_WRAPPERS:
            return tokens
        tokens = tokens[1:]
        if name == "timeout":
            while tokens and tokens[0].startswith("-"):
                tokens.pop(0)
            if tokens:  # the duration
                tokens.pop(0)
            continue
        if name in ("taskset", "chrt", "ionice"):
            while tokens and tokens[0].startswith("-"):
                tokens.pop(0)
            if tokens:  # class / priority / cpu list
                tokens.pop(0)
            continue
        while tokens and tokens[0].startswith("-"):
            flag = tokens.pop(0)
            if name == "nice" and flag in ("-n", "--adjustment") and tokens:
                tokens.pop(0)
        continue
    return tokens


def _heredoc_text(program: str, body: str) -> str:
    """The text to judge for a here-document that ``program`` reads as a script.

    A shell runs the body as shell, so it is parsed unchanged. A script
    interpreter runs it in *its own* language, so only the string literals are
    judged - that is where an embedded command lives (``os.system("rm -rf /")``).
    """
    if _SCRIPT_INTERPRETER.match(program):
        return "\n".join(_literals(body))
    return body


def _stdin_code_program(line: str) -> Optional[str]:
    """The program on ``line`` that reads its stdin as a script, if any."""
    try:
        tokens = shlex.split(line, posix=True)
    except ValueError:
        return None
    while tokens and tokens[0] in _LEADING_KEYWORDS:
        tokens.pop(0)
    while tokens and _ASSIGNMENT.match(tokens[0]):
        tokens.pop(0)
    tokens = _unwrap_wrappers(tokens)
    while tokens and tokens[0] in _LEADING_KEYWORDS:
        tokens.pop(0)
    while tokens and _ASSIGNMENT.match(tokens[0]):
        tokens.pop(0)
    if not tokens:
        return None
    name = _basename(tokens[0]).lower()
    if not _STDIN_CODE.match(name):
        return None
    # A redirection token (``<<EOF``, ``2>``, ``<file``) is not a script
    # operand: ``bash <<EOF`` still reads its script from stdin.
    operands = [a for a in tokens[1:]
                if not a.startswith("-") and not a.lstrip("0123456789").startswith(("<<", "<", ">", "&>"))]
    return name if not operands or operands[0] == "-" else None


def _reads_stdin_code(line: str) -> bool:
    """Whether the command on ``line`` reads its stdin as a script."""
    return _stdin_code_program(line) is not None


def _c_unescape(value: str) -> str:
    """Decode the C escapes in an ANSI-C quoted word (``$'...'``)."""
    out: List[str] = []
    i = 0
    n = len(value)
    while i < n:
        c = value[i]
        if c != "\\" or i + 1 >= n:
            out.append(c)
            i += 1
            continue
        escape = value[i + 1]
        if escape == "x":
            j = i + 2
            while j < n and j < i + 4 and value[j] in "0123456789abcdefABCDEF":
                j += 1
            if j > i + 2:
                out.append(chr(int(value[i + 2:j], 16)))
                i = j
                continue
            out.append("x")
            i += 2
            continue
        if escape in "01234567":
            j = i + 1
            while j < n and j < i + 4 and value[j] in "01234567":
                j += 1
            out.append(chr(int(value[i + 1:j], 8)))
            i = j
            continue
        if escape in "uU":
            width = 4 if escape == "u" else 8
            j = i + 2
            limit = min(j + width, n)
            while j < limit and value[j] in "0123456789abcdefABCDEF":
                j += 1
            if j > i + 2 and j - (i + 2) == width:
                out.append(chr(int(value[i + 2:j], 16)))
                i = j
                continue
            # Bash also accepts a short run (``$'\u72'``) when the next
            # character is not a hex digit.
            if j > i + 2 and (j >= n or value[j] not in "0123456789abcdefABCDEF"):
                out.append(chr(int(value[i + 2:j], 16)))
                i = j
                continue
            out.append(escape)
            i += 2
            continue
        out.append(_C_ESCAPES.get(escape, escape))
        i += 2
    return "".join(out)


def _expand_positionals(script: str, positionals: Sequence[str]) -> str:
    """Substitute ``$0``/``$1``/``$@`` with a shell's positional parameters."""
    if not positionals or "$" not in script:
        return script

    def replace(match: "re.Match[str]") -> str:
        token = match.group(1) or match.group(2)
        if token in ("@", "*"):
            return " ".join(shlex.quote(p) for p in positionals[1:])
        index = int(token)
        if index < len(positionals):
            return shlex.quote(positionals[index])
        return match.group(0)

    return _POSITIONAL.sub(replace, script)


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


def _shell_script(args: Sequence[str]) -> Tuple[Optional[str], List[str]]:
    """The script a shell runs with ``-c`` and its positional parameters.

    ``sh -c 'rm -rf "$1"' _ /`` sets ``$0`` to ``_`` and ``$1`` to ``/``; the
    positions after the script are returned so they can be substituted into
    the script before it is parsed.
    """
    has_c = False
    i = 0
    while i < len(args):
        tok = args[i]
        if tok == "--":
            i += 1
            break
        if tok in ("--command",) and i + 1 < len(args):
            return args[i + 1], list(args[i + 2:])  # fish
        if tok.startswith("--command="):
            return tok[len("--command="):], list(args[i + 1:])
        if tok in ("-o", "+o", "-O", "+O", "--rcfile", "--init-file"):
            i += 2
            continue
        if tok.startswith("-") and not tok.startswith("--") and len(tok) > 1:
            body = tok[1:]
            if "c" in body:
                # ``sh -c'rm -rf /'`` is one token: the script is attached to
                # the flag. Reading only a separate token left it unparsed.
                attached = body.split("c", 1)[1]
                if attached:
                    return attached, list(args[i + 1:])
                has_c = True
            i += 1
            continue
        if tok.startswith("--") or tok.startswith("+"):
            i += 1
            continue
        break
    if has_c and i < len(args):
        return args[i], list(args[i + 1:])
    return None, []


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
        elif family in ("awk", "gawk", "mawk", "nawk"):
            # awk's program is its first operand (``awk 'BEGIN{...}'``); a
            # ``-f`` file cannot be read here, and ``-v var=value`` is input.
            if tok in ("-f", "--file"):
                break
            if tok in ("-v", "--assign", "-F", "--field-separator"):
                i += 2
                continue
            if tok.startswith("-") and len(tok) > 1:
                i += 1
                continue
            if _ASSIGNMENT.match(tok):
                i += 1
                continue
            codes.append(tok)
            break
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
    """String literals in inline code, plus each list or ``+`` chain joined."""
    found: List[str] = []
    for match in _LITERAL_LIST.finditer(code):
        items = [next(g for g in m.groups() if g is not None)
                 for m in _LITERAL.finditer(match.group(0))]
        if len(items) > 1:
            found.append(" ".join(shlex.quote(_unescape(s)) for s in items))
    # Python concatenates adjacent literals without an operator
    # (``os.system("rm -rf " "/")``), on one logical line. Only same-line
    # adjacency is folded: a newline ends the expression, and folding across
    # it would invent concatenation the interpreter never performs.
    for match in _LITERAL_ADJACENT.finditer(code):
        items = [next(g for g in m.groups() if g is not None)
                 for m in _LITERAL.finditer(match.group(0))]
        if len(items) > 1:
            joined = _unescape("".join(items))
            if joined.strip():
                found.append(joined)
    # ``"rm -rf " + "/"`` evaluates to one string; folding it here means the
    # interpreter's own concatenation is judged, not its harmless pieces.
    for match in _LITERAL_CONCAT.finditer(code):
        items = [next(g for g in m.groups() if g is not None)
                 for m in _LITERAL.finditer(match.group(0))]
        if len(items) > 1:
            joined = _unescape("".join(items))
            if joined.strip():
                found.append(joined)
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
