"""A deterministic digest of a skill directory, and the pins that record it.

A skill is a directory of instructions an agent loads when it activates the
skill's name. The name is the thing a human reviewed; the files are what the
agent actually reads. This module binds the two: :func:`skill_digest` hashes a
skill's regular files in a stable order, and :func:`pin_skill` records that hash
under the skill's name in a small JSON pin file.

The digest covers the relative POSIX path, the byte size and the SHA-256 of
every regular file, folded in sorted path order, so it is stable across
directory-creation order and changes when any file's bytes change. Symlinks,
sockets and other non-regular entries are skipped: a link is a pointer whose
target can change without the skill directory changing, so hashing through it
would make the pin lie. Traversal is bounded (512 files, 8 MiB total) so a
pathological directory raises ``ValueError`` instead of reading forever; the
message never includes file contents.

The default roots and pin file are expanded from ``~`` at call time, never at
import time, so a caller (or a test) can point ``HOME`` elsewhere.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

#: Where Claude Code keeps skills, by default. Expanded per call.
DEFAULT_ROOTS: Sequence[str] = ("~/.claude/skills",)

#: Where the pin file lives, by default. Expanded per call.
DEFAULT_PINS_PATH = "~/.interlock/skills.json"

#: Hard bound on the work one digest may do.
MAX_FILES = 512
MAX_BYTES = 8 * 1024 * 1024

#: A single name component: no separators, no leading path, no ``..``.
_SAFE_PART = re.compile(r"^[A-Za-z0-9._-]+$")


def _safe_part(part: str) -> bool:
    """Whether ``part`` is one safe path component."""
    return bool(_SAFE_PART.match(part)) and part not in (".", "..")


def _expand_roots(roots: Optional[Iterable[str]]) -> List[str]:
    """The roots to search, with ``~`` expanded now, not at import time."""
    if roots is None:
        roots = DEFAULT_ROOTS
    elif isinstance(roots, str):
        roots = (roots,)
    return [os.path.expanduser(os.fspath(root)) for root in roots]


def _parse_name(name: object) -> Optional[tuple]:
    """Split a skill name into ``(kind, plugin, skill)``, or None if unsafe."""
    if not isinstance(name, str) or not name or os.path.isabs(name):
        return None
    if ":" in name:
        plugin, _, skill = name.partition(":")
        if not (_safe_part(plugin) and _safe_part(skill)):
            return None
        return ("plugin", plugin, skill)
    if not _safe_part(name):
        return None
    return ("plain", None, name)


def find_skill(name: object, roots: Optional[Iterable[str]] = None) -> Optional[str]:
    """Return the skill directory for ``name`` under ``roots``, or None.

    A plain name resolves to ``<root>/<name>``. A ``plugin:skill`` name first
    tries ``<root>/<plugin>/skills/<skill>``, then ``<root>/<plugin>/<skill>``,
    then ``<root>/<skill>``. A name is accepted only when every component
    matches ``^[A-Za-z0-9._-]+$``, is not ``.``/``..`` and the whole name is not
    absolute, so a name can never escape a root.
    """
    parsed = _parse_name(name)
    if parsed is None:
        return None
    kind, plugin, skill = parsed
    for root in _expand_roots(roots):
        if kind == "plugin":
            candidate = os.path.join(root, plugin, "skills", skill)
            if os.path.isdir(candidate):
                return candidate
            candidate = os.path.join(root, plugin, skill)
            if os.path.isdir(candidate):
                return candidate
            candidate = os.path.join(root, skill)
            if os.path.isdir(candidate):
                return candidate
        else:
            candidate = os.path.join(root, skill)
            if os.path.isdir(candidate):
                return candidate
    return None


def discover_skills(
    roots: Optional[Iterable[str]] = None,
) -> List[Tuple[str, str]]:
    """Return ``(name, directory)`` for every skill discoverable under ``roots``.

    A directory directly under a root is a plain skill when it contains a
    regular ``SKILL.md``; a directory ``<root>/<plugin>/skills/<skill>`` or
    ``<root>/<plugin>/<skill>`` is a ``plugin:skill`` when ``<skill>`` contains
    one. A directory that is itself a skill is never a plugin: when it holds a
    ``SKILL.md`` of its own it is reported as the plain skill and its
    subdirectories are not promoted to ``plugin:skill``. Names the component
    rule would reject are skipped, so every returned name is one
    :func:`find_skill` accepts. Symlinked directories are never followed: they
    are not part of the tree the operator reviewed.

    The result is sorted by name and deduplicated across roots (the first root
    that names a skill wins). Only directory entries and ``SKILL.md`` presence
    are read; nothing is hashed.
    """
    found: Dict[str, str] = {}

    def _entries(directory: str) -> List[os.DirEntry]:
        try:
            with os.scandir(directory) as handle:
                return list(handle)
        except OSError:
            return []

    for root in _expand_roots(roots):
        for outer in _entries(root):
            if outer.is_symlink() or not outer.is_dir(follow_symlinks=False):
                continue
            plugin = outer.name
            if not _safe_part(plugin):
                continue
            plugin_dir = outer.path
            plain = os.path.isfile(os.path.join(plugin_dir, "SKILL.md"))
            if plain:
                found.setdefault(plugin, plugin_dir)
            skills_dir = os.path.join(plugin_dir, "skills")
            if not os.path.islink(skills_dir) and os.path.isdir(skills_dir):
                for inner in _entries(skills_dir):
                    if (inner.is_symlink()
                            or not inner.is_dir(follow_symlinks=False)):
                        continue
                    skill = inner.name
                    if not _safe_part(skill):
                        continue
                    if not os.path.isfile(os.path.join(inner.path, "SKILL.md")):
                        continue
                    found.setdefault(
                        "{}:{}".format(plugin, skill), inner.path)
            # A directory that is its own skill is not a plugin: its children
            # are never promoted to ``plugin:skill``.
            if plain:
                continue
            for inner in _entries(plugin_dir):
                if inner.is_symlink() or not inner.is_dir(follow_symlinks=False):
                    continue
                skill = inner.name
                if not _safe_part(skill):
                    continue
                if not os.path.isfile(os.path.join(inner.path, "SKILL.md")):
                    continue
                found.setdefault(
                    "{}:{}".format(plugin, skill), inner.path)
    return sorted(found.items())


def skill_digest(path: str) -> str:
    """Return the lowercase hex SHA-256 of the regular files under ``path``.

    Each file contributes ``posix_relpath + "\\0" + str(size) + "\\0" +
    sha256(bytes)``, folded in sorted relative-path order. Symlinks and every
    non-regular entry are skipped. More than :data:`MAX_FILES` files or more
    than :data:`MAX_BYTES` bytes of stat size raises ``ValueError``. A
    directory that cannot be listed, or a file that cannot be read, raises
    ``OSError`` rather than producing a digest of only the readable part.
    """
    if not os.path.isdir(path):
        raise ValueError("skill path is not a directory")

    entries: List[tuple] = []
    total = 0

    def _unreadable(exc: OSError) -> None:
        # os.walk's default swallows a directory it cannot list. A skill whose
        # contents cannot all be read has an unknowable digest, so surface the
        # error: the caller treats it as "cannot be judged", never as a match.
        raise exc

    for dirpath, dirnames, filenames in os.walk(
            path, followlinks=False, onerror=_unreadable):
        # Never descend through a symlinked directory: its target is not part
        # of the skill the operator reviewed.
        dirnames[:] = sorted(
            name for name in dirnames
            if not os.path.islink(os.path.join(dirpath, name))
        )
        for filename in filenames:
            full = os.path.join(dirpath, filename)
            info = os.lstat(full)
            if not stat.S_ISREG(info.st_mode):
                continue
            rel = os.path.relpath(full, path)
            rel_posix = "/".join(rel.split(os.sep))
            entries.append((rel_posix, full, info.st_size))
            total += info.st_size
            if len(entries) > MAX_FILES:
                raise ValueError(
                    "skill exceeds {} files".format(MAX_FILES))
            if total > MAX_BYTES:
                raise ValueError(
                    "skill exceeds {} bytes".format(MAX_BYTES))

    entries.sort(key=lambda entry: entry[0])
    hasher = hashlib.sha256()
    for rel_posix, full, size in entries:
        with open(full, "rb") as handle:
            content = handle.read()
        hasher.update(rel_posix.encode("utf-8"))
        hasher.update(b"\0")
        hasher.update(str(size).encode("ascii"))
        hasher.update(b"\0")
        hasher.update(hashlib.sha256(content).hexdigest().encode("ascii"))
    return hasher.hexdigest()


def load_pins(path: Union[str, "os.PathLike[str]"]) -> Dict[str, str]:
    """Read ``{"version": 1, "skills": {name: digest}}`` from ``path``.

    A missing file is an empty mapping. A file that is not valid JSON or does
    not have that shape raises ``ValueError``; callers that must not fail on a
    bad pin file (the detector) catch it and treat the skill as unknown.
    """
    pins_path = os.path.expanduser(os.fspath(path))
    try:
        with open(pins_path, "r", encoding="utf-8") as handle:
            document = json.load(handle)
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError as exc:
        raise ValueError("malformed skill pin file") from exc
    if (not isinstance(document, dict)
            or document.get("version") != 1
            or not isinstance(document.get("skills"), dict)):
        raise ValueError("malformed skill pin file")
    pins = document["skills"]
    for name, digest in pins.items():
        if not isinstance(name, str) or not isinstance(digest, str):
            raise ValueError("malformed skill pin file")
    return dict(pins)


def save_pins(
    path: Union[str, "os.PathLike[str]"], pins: Mapping[str, str]
) -> None:
    """Write the pin document atomically, mode ``0600``.

    The temporary file is created in the destination directory so
    :func:`os.replace` is atomic on one filesystem. It is fsynced and chmodded
    before the replace, and the directory is fsynced afterwards where the
    platform allows it.
    """
    pins_path = os.path.expanduser(os.fspath(path))
    directory = os.path.dirname(os.path.abspath(pins_path))
    os.makedirs(directory, exist_ok=True)
    document = {"version": 1, "skills": dict(pins)}
    descriptor, temporary = tempfile.mkstemp(
        prefix=".skills-", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(document, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, pins_path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    try:
        directory_fd = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(directory_fd)
    except OSError:
        pass
    finally:
        os.close(directory_fd)


def pin_skill(
    name: str,
    roots: Optional[Iterable[str]] = None,
    pins_path: Optional[str] = None,
    root: Optional[str] = None,
) -> str:
    """Compute ``name``'s digest, merge it into the pins, and save.

    ``root`` names one explicit directory to search instead of ``roots``. The
    pins file is created if absent. Returns the digest that was recorded.
    """
    if root is not None:
        roots = (root,)
    directory = find_skill(name, roots)
    if directory is None:
        raise ValueError("skill not found: {}".format(name))
    digest = skill_digest(directory)
    pins_file = DEFAULT_PINS_PATH if pins_path is None else pins_path
    pins = load_pins(pins_file)
    pins[name] = digest
    save_pins(pins_file, pins)
    return digest
