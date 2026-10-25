"""Classify parsed shell invocations into semantic intents.

A rule that wants to stop "force-pushing to main" should not have to know that
``git push -f``, ``git push --force origin main``, ``git -C repo push origin
+main`` and ``git -c alias.p='push --force' p`` are the same act. The parser
recovers the invocations; this module names what they do.

Each :class:`Intent` has a dotted ``kind`` and, where it matters, the
``targets`` it acts on, a ``detail`` qualifier, and ``critical`` - set when the
act is unrecoverable for the host (a recursive delete of ``/`` or ``~``, a raw
disk write, fetched code piped into a shell). Rules match on ``kind`` prefixes:
``"git"`` covers every ``git.*`` intent.

Kinds:

==========================  ==================================================
``fs.delete.recursive``     ``rm -r``, ``find -delete``; targets are the paths
``fs.permissions.recursive`` ``chmod/chown/chgrp -R``; targets are the paths
``disk.overwrite``          ``dd of=/dev/...``, ``> /dev/sda``, ``shred /dev/..``
``disk.format``             ``mkfs*``, ``wipefs``, ``diskutil eraseDisk`` ...
``git.push``                any push; ``detail`` names the branch class
``git.push.force``          ``-f``, ``--force*``, ``--mirror``, ``+refspec``;
                            ``detail`` is ``default``, ``topic`` or ``implicit``
``git.push.delete``         ``--delete`` or ``:branch``
``git.discard``             ``reset --hard``, ``clean -f``, ``checkout .`` ...
``credential.read``         ``git config --get ...password``, ``git credential fill``
``net.fetch``               ``curl``, ``wget`` ...
``net.fetch_exec``          fetched content piped or substituted into a shell
``pkg.publish``             ``npm publish``, ``cargo publish``, ``twine upload`` ...
``persist.schedule``        ``crontab``, ``at``, ``launchctl load``, ``systemctl enable``
``persist.shell_init``      writes to ``~/.bashrc``, ``~/.zshrc`` ...
``priv.escalate``           ``sudo``, ``doas``, ``su``, ``pkexec``
``interlock.tamper``        ``interlock trust``/``install-hook``, any command
                            naming a path under ``~/.interlock`` (``detail``
                            ``write`` for a write, move or delete, ``path``
                            for any other program), or an HTTP client calling
                            the local console's unlock or write API
==========================  ==================================================
"""
from __future__ import annotations

import fnmatch
import os
import posixpath
import re
from dataclasses import dataclass
from typing import Dict, FrozenSet, Iterable, List, Optional, Sequence, Tuple, Union

from .parser import _SCRIPT_INTERPRETER, _WRAPPERS, Invocation, ParsedCommand, _literals, parse


@dataclass(frozen=True)
class Intent:
    """One semantic act recovered from a command string."""

    kind: str
    binary: str
    targets: Tuple[str, ...] = ()
    detail: str = ""
    critical: bool = False

    def matches(self, selector: str) -> bool:
        """Whether a selector names this intent.

        A selector is a kind or kind prefix (``"git"`` matches
        ``"git.push.force"``), optionally followed by ``":qualifier"``, where
        the qualifier is either this intent's ``detail`` or ``"critical"``:
        ``"git.push.force:default"``, ``"fs.delete.recursive:critical"``.
        """
        kind, _, qualifier = selector.partition(":")
        if not (self.kind == kind or self.kind.startswith(kind + ".")):
            return False
        if not qualifier:
            return True
        if qualifier == "critical":
            return self.critical
        return self.detail == qualifier


def analyze(command: Union[str, ParsedCommand], cwd: Optional[str] = None) -> Tuple[Intent, ...]:
    """Every intent a command string carries, duplicates removed, in order.

    ``cwd`` is the directory the command runs in (an agent hook's session
    directory); a relative path is resolved against it, or against this
    process's directory when None. A literal ``cd`` moves that base for the
    invocations after it (see :func:`_cd`).
    """
    parsed = parse(command) if isinstance(command, str) else command
    invocations = parsed.invocations
    # The base each invocation runs from, walking in order. A cd is classified
    # against the base before it, so ``cd ~/.interlock`` still names the home.
    bases: List[Optional[str]] = []
    base = cwd
    for inv in invocations:
        bases.append(base)
        base = _cd(inv, base)
    found: List[Intent] = []
    for i, inv in enumerate(invocations):
        found.extend(_classify(inv, bases[i]))
        if "$()" in inv.via:
            # A substitution is recorded before the commands of its own text,
            # so before a cd that may run ahead of it: every later base counts.
            for later in dict.fromkeys(bases[i + 1:] + [base]):
                if later != bases[i]:
                    found.extend(_tamper(inv, later))
    found.extend(_fetch_exec(invocations))
    unique: Dict[Intent, None] = {}
    for intent in found:
        unique.setdefault(intent, None)
    return tuple(unique)


def invocation_bases(parsed: ParsedCommand,
                     cwd: Optional[str] = None) -> List[Optional[str]]:
    """The directory each invocation of ``parsed`` runs from, in order.

    A literal ``cd`` earlier in the string moves the base for the invocations
    after it. Exposed so a path-based detector can resolve a relative word the
    same way :func:`analyze` resolves an intent's target.
    """
    bases: List[Optional[str]] = []
    base = cwd
    for inv in parsed.invocations:
        bases.append(base)
        base = _cd(inv, base)
    return bases


def read_command(command: Union[str, ParsedCommand],
                 cwd: Optional[str] = None) -> Tuple[Tuple[Intent, ...], bool]:
    """:func:`analyze`'s intents, and whether the command was only partly read.

    One parse serves both. A partly read command (an unclosed quote, nesting
    deeper than the parser follows) may run more than its intents show: a rule
    must not treat it as harmless. Input that is not a string is unread.
    """
    parsed = command if isinstance(command, ParsedCommand) else parse(command)
    return analyze(parsed, cwd), parsed.partial


def _cd(inv: Invocation, base: Optional[str]) -> Optional[str]:
    """The directory after ``inv``: ``base`` unless ``inv`` is a readable ``cd``.

    ``cd DIR`` with one operand expands ``~`` and ``$HOME``, joins a relative
    DIR to ``base`` and resolves ``..``; a bare ``cd`` goes home. ``cd -``, a
    DIR holding a variable, glob, brace, substitution or backtick, and more
    than one operand leave ``base`` as it was: the target is not guessed.
    """
    if inv.name != "cd":
        return base
    operands = _flags(inv.args)[1]
    if not operands:
        return os.path.expanduser("~")
    if len(operands) != 1 or operands[0] in ("", "-"):
        return base
    target = os.path.expanduser(_HOME_VAR.sub("~", operands[0]))
    if len(target) > _PATH_MAX or re.search(r"[$`]", target) or _GLOB.search(target) \
            or _BRACES.search(target) or target.startswith("~"):
        return base
    if not target.startswith("/"):
        root = base or _getcwd()
        if not root:
            return base
        target = posixpath.join(root, target)
    return posixpath.normpath(re.sub(r"/+", "/", target))


# --- critical paths ----------------------------------------------------------

#: Top-level directories whose recursive deletion or permission change breaks
#: the host. A target equal to one of these (or to its ``/*`` glob) is critical.
SYSTEM_DIRS: FrozenSet[str] = frozenset(
    {"/bin", "/boot", "/dev", "/etc", "/lib", "/lib32", "/lib64", "/opt", "/proc",
     "/root", "/sbin", "/srv", "/sys", "/usr", "/usr/bin", "/usr/lib",
     "/usr/local", "/usr/sbin", "/var", "/var/lib", "/home", "/Users", "/System",
     "/Library", "/Applications", "/private", "/private/etc", "/private/var"}
)

_HOME_VAR = re.compile(r"^\$(?:HOME\b|\{HOME\})")


def is_critical_path(target: str) -> bool:
    """Whether deleting (or re-permissioning) ``target`` recursively is fatal.

    Root-equivalent targets - ``/``, ``/*``, ``~``, ``$HOME``, ``~/*``, ``..``
    climbs above them - and the :data:`SYSTEM_DIRS` (with their ``/*``)
    count. Relative paths never do: ``./build`` and ``node_modules`` are routine.
    """
    t = target.strip()
    if not t:
        return False
    t = _HOME_VAR.sub("~", t)
    if t.startswith("~"):
        # "~" or "~user", then an optional path under it.
        _, sep, rest = t.partition("/")
        rest = _normalise("/" + rest) if sep else "/"
        return rest in ("/", "/*", "/.*")
    if not t.startswith("/"):
        return False
    norm = _normalise(t)
    if norm in ("/", "/*", "/.*"):
        return True
    if norm.endswith("/*"):
        norm = norm[:-2]
    return norm in SYSTEM_DIRS


def _normalise(path: str) -> str:
    collapsed = re.sub(r"/+", "/", path)
    glob = collapsed.endswith("/*")
    base = collapsed[:-2] if glob else collapsed
    norm = posixpath.normpath(base) if base else "/"
    if norm == ".":
        norm = "/"
    return norm.rstrip("/") + "/*" if glob else norm


# --- classification ----------------------------------------------------------

_BLOCK_DEVICE = re.compile(
    r"^/dev/(?:r?disk\d|sd[a-z]|hd[a-z]|vd[a-z]|xvd[a-z]|nvme\d|mmcblk\d|md\d|dm-\d|mapper/|loop\d)"
)
_FORMATTERS = re.compile(r"^(?:mkfs(?:\..+)?|mke2fs|mkswap|newfs(?:_.+)?|wipefs|sfdisk|sgdisk)$")
_DISKUTIL_ERASE = frozenset(
    {"erasedisk", "erasevolume", "zerodisk", "randomdisk", "secureerase",
     "partitiondisk", "reformat"}
)
_FETCHERS = frozenset({"curl", "wget", "fetch", "http", "https", "aria2c", "xh"})
_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "fish"})
_STDIN_INTERPRETER = re.compile(r"^(python[0-9.]*|perl[0-9.]*|ruby[0-9.]*|node|php[0-9.]*)$")
_SUBST_FETCH = re.compile(r"(?:\$\(|`|<\()\s*(?:curl|wget)\b")
_DEFAULT_BRANCHES = frozenset({"main", "master", "trunk", "develop", "production"})
_SHELL_INIT = frozenset(
    {".bashrc", ".bash_profile", ".bash_login", ".profile", ".zshrc", ".zshenv",
     ".zprofile", ".zlogin", ".cshrc", ".tcshrc", ".kshrc", "config.fish"}
)
_PRIVILEGE = frozenset({"sudo", "doas", "su", "pkexec", "run0"})


def _flags(args: Sequence[str]) -> Tuple[set, List[str]]:
    """Short-flag letters / long flags set, and the operands (non-options)."""
    letters: set = set()
    operands: List[str] = []
    after_dashdash = False
    for tok in args:
        if after_dashdash:
            operands.append(tok)
        elif tok == "--":
            after_dashdash = True
        elif tok.startswith("--"):
            letters.add(tok.split("=", 1)[0])
        elif tok.startswith("-") and len(tok) > 1:
            letters.update(tok[1:])
        else:
            operands.append(tok)
    return letters, operands


def _classify(inv: Invocation, cwd: Optional[str] = None) -> Iterable[Intent]:
    name = inv.name
    args = inv.args
    out: List[Intent] = []

    if name in ("rm", "srm"):
        flags, targets = _flags(args)
        if flags & {"r", "R", "--recursive"}:
            out.append(Intent("fs.delete.recursive", name, tuple(targets),
                              critical=any(is_critical_path(t) for t in targets)))

    elif name == "find":
        roots = []
        for tok in args:
            if tok in ("-H", "-L", "-P"):
                continue
            if tok.startswith("-") or tok in ("(", "!", ")"):
                break
            roots.append(tok)
        if "-delete" in args:
            roots = roots or ["."]
            out.append(Intent("fs.delete.recursive", name, tuple(roots),
                              detail="find -delete",
                              critical=any(is_critical_path(r) for r in roots)))

    elif name in ("chmod", "chown", "chgrp"):
        flags, operands = _flags(args)
        if flags & {"R", "--recursive"}:
            targets = tuple(operands[1:])  # first operand is the mode / owner
            mode = operands[0] if operands else ""
            out.append(Intent("fs.permissions.recursive", name, targets, detail=mode,
                              critical=any(is_critical_path(t) for t in targets)))

    elif name == "dd":
        for tok in args:
            if tok.startswith("of=") and _BLOCK_DEVICE.match(tok[3:]):
                out.append(Intent("disk.overwrite", name, (tok[3:],), critical=True))

    elif name == "shred":
        _, operands = _flags(args)
        devices = tuple(t for t in operands if _BLOCK_DEVICE.match(t))
        if devices:
            out.append(Intent("disk.overwrite", name, devices, critical=True))

    elif _FORMATTERS.match(name):
        _, operands = _flags(args)
        out.append(Intent("disk.format", name, tuple(operands), critical=True))

    elif name == "diskutil":
        verbs = [a.lower() for a in args if not a.startswith("-")]
        if verbs and verbs[0] in _DISKUTIL_ERASE:
            out.append(Intent("disk.format", name, tuple(args[1:]), detail=verbs[0],
                              critical=True))

    elif name == "git":
        out.extend(_git(inv))

    elif name in _FETCHERS:
        out.append(Intent("net.fetch", name, tuple(_flags(args)[1])))

    elif name in ("npm", "pnpm", "yarn", "bun"):
        verbs = list(args[1:2]) if name == "yarn" and args[:1] == ("npm",) else list(args[:1])
        if verbs and verbs[0] in ("publish", "unpublish"):
            out.append(Intent("pkg.publish", name, detail=verbs[0]))
    elif name == "cargo" and args and args[0] in ("publish", "yank"):
        out.append(Intent("pkg.publish", name, detail=args[0]))
    elif name == "twine" and args and args[0] == "upload":
        out.append(Intent("pkg.publish", name, detail="upload"))
    elif name == "gem" and args and args[0] in ("push", "yank"):
        out.append(Intent("pkg.publish", name, detail=args[0]))
    elif name in ("poetry", "uv", "flit", "hatch") and args and args[0] == "publish":
        out.append(Intent("pkg.publish", name, detail="publish"))
    elif name == "docker" and args and args[0] == "push":
        out.append(Intent("pkg.publish", name, tuple(args[1:]), detail="push"))
    elif name == "gh" and tuple(args[:2]) == ("release", "create"):
        out.append(Intent("pkg.publish", name, detail="release"))
    elif re.match(r"^python[0-9.]*$", name) and tuple(args[:3]) == ("-m", "twine", "upload"):
        out.append(Intent("pkg.publish", name, detail="upload"))

    elif name == "crontab":
        if "-l" not in args:
            out.append(Intent("persist.schedule", name, tuple(args)))
    elif name in ("at", "batch"):
        out.append(Intent("persist.schedule", name, tuple(args)))
    elif name == "launchctl" and args and args[0] in ("load", "bootstrap", "submit", "enable"):
        out.append(Intent("persist.schedule", name, tuple(args[1:]), detail=args[0]))
    elif name == "systemctl":
        verbs = [a for a in args if not a.startswith("-")]
        if verbs and verbs[0] in ("enable", "link"):
            out.append(Intent("persist.schedule", name, tuple(verbs[1:]), detail=verbs[0]))

    if name in _PRIVILEGE:
        out.append(Intent("priv.escalate", name))

    out.extend(_tamper(inv, cwd))

    for target in inv.redirects:
        if _BLOCK_DEVICE.match(target):
            out.append(Intent("disk.overwrite", name, (target,), detail="redirect",
                              critical=True))
        if _is_shell_init(target):
            out.append(Intent("persist.shell_init", name, (target,), detail="redirect"))
    if name == "tee":
        for target in _flags(args)[1]:
            if _is_shell_init(target):
                out.append(Intent("persist.shell_init", name, (target,), detail="tee"))
    if name in ("sed", "perl") and any(a.startswith("-i") or a == "--in-place" for a in args):
        for target in _flags(args)[1]:
            if _is_shell_init(target):
                out.append(Intent("persist.shell_init", name, (target,), detail="in-place"))

    if name in _SHELLS or name == "eval" or name in (".", "source"):
        joined = " ".join(args)
        if _SUBST_FETCH.search(joined):
            out.append(Intent("net.fetch_exec", name, detail="substitution", critical=True))
    return out


_INTERLOCK_CONTROL = frozenset({"trust", "install-hook", "uninstall-hook"})

#: The console's unlock and write routes, on a loopback host. An agent that
#: reaches them could approve its own reviews or rewrite its own policy, so
#: calling them is tampering whatever the HTTP client. ``/api/policy`` itself
#: (the save) is matched, not its read-only children (``check``, ``backtest``).
_CONSOLE_WRITE = re.compile(
    r"(?:^|[\s'\"(=]|https?://)(?:127\.\d+\.\d+\.\d+|localhost|\[::1\]|0\.0\.0\.0)(?::\d+)?"
    r"/api/(?:unlock|lock|policy(?=$|[?#\s'\"])|reviews/[^/?#]+/(?:approve|reject|revoke))",
    re.IGNORECASE)
_MUTATORS = frozenset({"rm", "mv", "cp", "ln", "chmod", "chown", "truncate", "tee",
                       "touch", "install", "rsync", "unlink", "shred"})

#: Programs besides the script interpreters that read a script or query from
#: an argument; a path inside it (``ATTACH '/x/reviews.db'``, ``.output /x``,
#: ``print > "/x"``, ``w /x``) is a file the program opens.
_CODE_ARGS = frozenset({"sqlite3", "sqlite", "duckdb", "litecli", "psql", "mysql", "mariadb",
                        "awk", "gawk", "mawk", "nawk", "sed", "gsed"})
_ATTACHED = re.compile(r"^-[A-Za-z0-9]+?([~/$].*)$")  # -o/path, -o~/path
_OPEN_MODE = re.compile(r"^[<>+|&]+\s*")  # perl's open(F, "</path")
_FILE_URL = re.compile(r"^file:(?://[^/]*)?", re.IGNORECASE)
_BRACES = re.compile(r"\{([^{}]*,[^{}]*)\}")
_GLOB = re.compile(r"[*?[]")
_PATH_MAX = 4096  # longer words cannot be opened as one path


def _in_interlock_home(target: str, cwd: Optional[str] = None) -> bool:
    """Whether ``target`` names ``~/.interlock`` or anything under it.

    The shell's expansions come first - ``~``, ``$HOME``, braces
    (``~/.{interlock,x}``) - then a relative path is joined to ``cwd`` and
    ``..`` resolved. A glob counts when it can match the home
    (``~/.inter*/receipts.key``), though ``*`` and ``?`` skip a leading dot, as
    in the shell. Case is ignored, as the default macOS volume ignores it.
    """
    if len(target) > _PATH_MAX:
        return False
    own = _components(os.path.join(os.path.expanduser("~"), ".interlock"))
    for word in _brace_variants(target.strip()):
        t = os.path.expanduser(_FILE_URL.sub("", _HOME_VAR.sub("~", word)))
        if not t:
            continue
        if not t.startswith("/"):
            base = cwd or _getcwd()
            if not base:
                continue
            t = posixpath.join(base, t)
        parts = _components(t)
        if len(parts) >= len(own) and all(_component_is(p, o) for p, o in zip(parts, own)):
            return True
    return False


def _components(path: str) -> List[str]:
    """An absolute path's components, ``..`` resolved, casefolded."""
    norm = posixpath.normpath(re.sub(r"/+", "/", path))
    return [p for p in norm.casefold().split("/") if p]


def _component_is(pattern: str, name: str) -> bool:
    if not _GLOB.search(pattern):
        return pattern == name
    if name.startswith(".") and pattern.startswith(("*", "?")):
        return False
    return fnmatch.fnmatchcase(name, pattern)


def _brace_variants(word: str, limit: int = 64) -> List[str]:
    """``word`` with each ``{a,b}`` expanded as the shell would, up to ``limit``."""
    done: List[str] = []
    todo = [word]
    while todo:
        w = todo.pop()
        m = _BRACES.search(w)
        if not m or len(done) + len(todo) >= limit:
            done.append(w)
            continue
        todo.extend(w[:m.start()] + alt + w[m.end():] for alt in m.group(1).split(","))
    return done


def _getcwd() -> str:
    try:
        return os.getcwd()
    except OSError:  # the directory was removed
        return ""


def _path_words(inv: Invocation) -> List[str]:
    """The words of ``inv`` that may name a file, whatever the program.

    Each operand, each output redirect, and each option's value (``--opt=V``,
    ``of=V``, ``-oV``). For a program that reads code or a query from its
    arguments, also each string literal and each word inside them.
    """
    words = list(inv.redirects)
    for arg in inv.args:
        attached = _ATTACHED.match(arg)
        if attached:
            words.append(attached.group(1))
        elif not arg.startswith("-"):
            words.append(arg)
        if "=" in arg:
            words.append(arg.split("=", 1)[1])
    if _SCRIPT_INTERPRETER.match(inv.name) or inv.name in _CODE_ARGS:
        for arg in inv.args:
            words.extend(_OPEN_MODE.sub("", w) for w in _literals(arg) + arg.split())
    return words


def _tamper(inv: Invocation, cwd: Optional[str] = None) -> List[Intent]:
    """Commands that would switch interlock off from inside the agent, or
    touch its home: the signing key, receipt log, review queue and policy."""
    out: List[Intent] = []
    name = inv.name
    args = list(inv.args)
    if re.match(r"^python[0-9.]*$", name) and args[:2] == ["-m", "interlock"]:
        name, args = "interlock", args[2:]
    if name == "interlock":
        verbs = [a for a in args if not a.startswith("-")]
        if verbs[:1] == ["reviews"] and verbs[1:2] in (["approve"], ["reject"], ["revoke"]):
            out.append(Intent("interlock.tamper", "interlock", tuple(verbs[1:]),
                              detail="review", critical=True))
        if verbs and verbs[0] in _INTERLOCK_CONTROL:
            out.append(Intent("interlock.tamper", "interlock", tuple(verbs[1:]),
                              detail="control", critical=True))
    targets = list(inv.redirects)
    if name in _MUTATORS or (name in ("sed", "perl") and any(
            a.startswith("-i") for a in inv.args)):
        targets.extend(_flags(inv.args)[1])
    if name == "dd":
        targets.extend(a[3:] for a in inv.args if a.startswith("of="))
    hit = tuple(t for t in targets if _in_interlock_home(t, cwd))
    if hit:
        out.append(Intent("interlock.tamper", name, hit, detail="write", critical=True))
    named = tuple(dict.fromkeys(w for w in _path_words(inv)
                                if w not in hit and _in_interlock_home(w, cwd)))
    if named:
        out.append(Intent("interlock.tamper", name, named, detail="path", critical=True))
    if name in _FETCHERS or re.match(r"^python[0-9.]*$", name) or name in ("node", "deno", "bun"):
        urls = tuple(a for a in inv.args if _CONSOLE_WRITE.search(a))
        if urls:
            out.append(Intent("interlock.tamper", name, urls, detail="console", critical=True))
    return out


def _is_shell_init(target: str) -> bool:
    base = target.rstrip("/").rsplit("/", 1)[-1]
    if base not in _SHELL_INIT:
        return False
    return (target.startswith(("~", "$HOME", "${HOME}", "/"))
            or "/" not in target)


def _fetch_exec(invocations: Sequence[Invocation]) -> List[Intent]:
    """A fetcher piped into a shell or stdin-reading interpreter, same pipeline."""
    out: List[Intent] = []
    for fetch in invocations:
        if fetch.name not in _FETCHERS:
            continue
        for sink in invocations:
            if sink.pipeline != fetch.pipeline or sink.stage <= fetch.stage:
                continue
            # The sink may sit behind wrappers (``curl ... | sudo bash``), but
            # not inside a script or substitution of its own.
            extra = sink.via[len(fetch.via):]
            if sink.via[:len(fetch.via)] != fetch.via or any(
                v not in _WRAPPERS for v in extra
            ):
                continue
            if _reads_stdin_as_code(sink):
                out.append(Intent("net.fetch_exec", sink.name, (fetch.name,),
                                  detail="pipe", critical=True))
    return out


def _reads_stdin_as_code(inv: Invocation) -> bool:
    name = inv.name
    if name in _SHELLS:
        operands = [a for a in inv.args if not a.startswith("-")]
        return not operands or "-s" in inv.args or operands[0] == "-"
    if _STDIN_INTERPRETER.match(name):
        operands = [a for a in inv.args if not a.startswith("-")]
        return not operands or operands[0] == "-"
    if name in ("sudo", "doas", "env", "xargs"):
        return False  # the wrapped command is recorded on its own
    return False


# --- git ---------------------------------------------------------------------

_GIT_VALUED = frozenset({"-C", "-c", "--git-dir", "--work-tree", "--namespace",
                         "--exec-path", "--config-env"})


def _git(inv: Invocation) -> List[Intent]:
    args = list(inv.args)
    aliases: Dict[str, List[str]] = {}
    i = 0
    while i < len(args):
        tok = args[i]
        if tok == "-c" and i + 1 < len(args):
            key, _, value = args[i + 1].partition("=")
            if key.startswith("alias."):
                aliases[key[len("alias."):]] = value.split()
            i += 2
            continue
        if tok in _GIT_VALUED:
            i += 2
            continue
        if tok.startswith("-"):
            i += 1
            continue
        break
    if i >= len(args):
        return []
    sub, rest = args[i], args[i + 1:]
    if sub in aliases and aliases[sub] and not aliases[sub][0].startswith("!"):
        expanded = aliases[sub]
        sub, rest = expanded[0], expanded[1:] + rest

    if sub == "push":
        return _git_push(rest)
    if sub == "reset" and "--hard" in rest:
        return [Intent("git.discard", "git", detail="reset --hard")]
    if sub == "clean":
        flags, _ = _flags(rest)
        if "f" in flags or "--force" in flags:
            return [Intent("git.discard", "git", detail="clean")]
    if sub in ("checkout", "restore"):
        _, operands = _flags(rest)
        if "--staged" not in rest and any(o in (".", ":/", "*") for o in operands):
            return [Intent("git.discard", "git", detail=sub)]
    if sub == "branch" and any(a in ("-D",) or (a.startswith("-") and "D" in a[1:]
                                                and not a.startswith("--")) for a in rest):
        return [Intent("git.discard", "git", detail="branch -D")]
    if sub == "stash" and rest[:1] in (["clear"], ["drop"]):
        return [Intent("git.discard", "git", detail="stash " + rest[0])]
    if sub == "filter-branch" or (sub == "update-ref" and "-d" in rest):
        return [Intent("git.discard", "git", detail=sub)]
    if sub == "config":
        reads = any(a.startswith("--get") or a in ("-l", "--list") for a in rest)
        keyish = " ".join(rest).lower()
        if reads and (any(k in keyish for k in ("password", "credential", "url", "token"))
                      or any(a in ("-l", "--list") for a in rest)):
            return [Intent("credential.read", "git", detail="config")]
    if sub == "credential" and rest[:1] in (["fill"], ["get"]):
        return [Intent("credential.read", "git", detail="credential " + rest[0])]
    return []


def _git_push(args: Sequence[str]) -> List[Intent]:
    flags: set = set()
    operands: List[str] = []
    skip_next = False
    for tok in args:
        if skip_next:
            skip_next = False
            continue
        if tok in ("-o", "--push-option", "--repo", "--receive-pack", "--exec"):
            skip_next = True
            continue
        if tok.startswith("--"):
            flags.add(tok.split("=", 1)[0])
        elif tok.startswith("-") and len(tok) > 1:
            flags.update("-" + c for c in tok[1:])
        else:
            operands.append(tok)
    refspecs = operands[1:]  # the first operand is the remote
    force = bool(flags & {"-f", "--force", "--force-with-lease", "--mirror"}) or any(
        r.startswith("+") for r in refspecs
    )
    delete = bool(flags & {"-d", "--delete"}) or any(
        r.startswith(":") and len(r) > 1 for r in refspecs
    )
    branches = tuple(_dest_branch(r) for r in refspecs)
    if not branches or flags & {"--all", "--mirror"}:
        detail = "implicit"
    elif any(b in _DEFAULT_BRANCHES for b in branches):
        detail = "default"
    elif any(b in ("HEAD", "@") for b in branches):
        detail = "implicit"
    else:
        detail = "topic"
    out = [Intent("git.push", "git", branches, detail=detail)]
    if force:
        out.append(Intent("git.push.force", "git", branches, detail=detail,
                          critical=detail != "topic"))
    if delete:
        out.append(Intent("git.push.delete", "git", branches, detail=detail))
    return out


def _dest_branch(refspec: str) -> str:
    ref = refspec.lstrip("+")
    if ":" in ref:
        ref = ref.split(":", 1)[1] or ref.split(":", 1)[0]
    if ref.startswith("refs/heads/"):
        ref = ref[len("refs/heads/"):]
    return ref


def intents_in(values: Iterable[str]) -> Tuple[Intent, ...]:
    """Intents across several strings (each parsed on its own)."""
    found: Dict[Intent, None] = {}
    for value in values:
        for intent in analyze(value):
            found.setdefault(intent, None)
    return tuple(found)


def first_match(intents: Iterable[Intent], selectors: Iterable[str]) -> Optional[Tuple[Intent, str]]:
    """The first (intent, selector) pair where the selector names the intent."""
    selectors = list(selectors)
    for intent in intents:
        for selector in selectors:
            if intent.matches(selector):
                return intent, selector
    return None
