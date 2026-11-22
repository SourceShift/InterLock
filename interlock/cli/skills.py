"""Pin a skill's on-disk content, and check it before activation.

  interlock skills pin NAME [--roots DIR ...] [--pins FILE] [--json]
  interlock skills list [--pins FILE] [--json]
  interlock skills check NAME [--roots DIR ...] [--pins FILE] [--json]
  interlock skills check --all [--roots DIR ...] [--pins FILE] [--json]

A skill is a directory an agent loads under a trusted name. ``pin`` records the
sha256 of the files behind that name in a pin file, ``list`` shows what is
pinned, and ``check`` recomputes a skill's digest and compares it with its pin.
With ``--all``, ``check`` walks the roots and audits every discoverable skill,
reporting each as ``ok``, ``drift``, ``unpinned`` or ``error``. The audit is
read-only: it never writes the pin file. The default pin file is
``~/.interlock/skills.json`` and the default roots are ``~/.claude/skills``.

Exit codes: 0 success / a matching digest / an audit with no drift or error,
2 a mismatch, an unknown or missing skill, or an unreadable one, 64 no or
unknown action, or a ``check`` that names neither or both of NAME and ``--all``.
"""
from __future__ import annotations

import json
import sys


def add_arguments(parser) -> None:
    sub = parser.add_subparsers(dest="skills_command", metavar="ACTION")
    pin = sub.add_parser("pin", help="record a skill's current digest")
    pin.add_argument("name")
    pin.add_argument("--roots", nargs="+", metavar="DIR", default=None,
                     help="directories holding skills (default: ~/.claude/skills)")
    pin.add_argument("--pins", metavar="FILE", default=None,
                     help="pin file (default: ~/.interlock/skills.json)")
    pin.add_argument("--json", action="store_true")
    listing = sub.add_parser("list", help="show pinned skills and their digests")
    listing.add_argument("--pins", metavar="FILE", default=None,
                         help="pin file (default: ~/.interlock/skills.json)")
    listing.add_argument("--json", action="store_true")
    check = sub.add_parser("check", help="compare a skill's digest with its pin")
    check.add_argument("name", nargs="?", default=None,
                       help="the skill to check")
    check.add_argument("--all", action="store_true",
                       help="audit every discoverable skill")
    check.add_argument("--roots", nargs="+", metavar="DIR", default=None,
                       help="directories holding skills (default: ~/.claude/skills)")
    check.add_argument("--pins", metavar="FILE", default=None,
                       help="pin file (default: ~/.interlock/skills.json)")
    check.add_argument("--json", action="store_true")


def _audit_line(name, status, digest, pinned, detail) -> str:
    """One ``check --all`` line: the name, the status, then what applies."""
    if status == "drift":
        suffix = "{} (pinned {})".format(digest, pinned)
    elif status == "error":
        suffix = detail or "digest unavailable"
    else:
        suffix = digest
    return "{:<32} {:<9} {}".format(name, status, suffix)


def run(args) -> int:
    from ..skills import (
        DEFAULT_PINS_PATH,
        discover_skills,
        find_skill,
        load_pins,
        pin_skill,
        skill_digest,
    )

    action = args.skills_command
    if action not in ("pin", "list", "check"):
        sys.stderr.write("interlock skills: choose an action: pin, list, check\n")
        return 64

    pins_file = args.pins or DEFAULT_PINS_PATH
    roots = getattr(args, "roots", None)

    if action == "pin":
        try:
            digest = pin_skill(args.name, roots=roots, pins_path=pins_file)
        except (OSError, ValueError) as exc:
            sys.stderr.write("interlock skills: {}\n".format(exc))
            return 2
        if args.json:
            print(json.dumps(
                {"name": args.name, "digest": digest, "pins": pins_file},
                indent=2))
        else:
            print("pinned {} {}".format(args.name, digest))
        return 0

    if action == "list":
        try:
            pins = load_pins(pins_file)
        except (OSError, ValueError) as exc:
            sys.stderr.write("interlock skills: {}\n".format(exc))
            return 2
        if args.json:
            print(json.dumps({"pins": pins_file, "skills": pins},
                             indent=2, sort_keys=True))
        elif not pins:
            print("no skills pinned in {}".format(pins_file))
        else:
            for name in sorted(pins):
                print("{:<32} {}".format(name, pins[name]))
        return 0

    # action == "check"
    if args.all and args.name is not None:
        sys.stderr.write(
            "interlock skills: check takes NAME or --all, not both\n")
        return 64
    if not args.all and args.name is None:
        sys.stderr.write("interlock skills: check needs NAME or --all\n")
        return 64

    try:
        pins = load_pins(pins_file)
    except (OSError, ValueError) as exc:
        sys.stderr.write("interlock skills: {}\n".format(exc))
        return 2

    if args.all:
        results = []
        failed = False
        for name, directory in discover_skills(roots):
            pinned = pins.get(name)
            try:
                digest = skill_digest(directory)
            except (OSError, ValueError) as exc:
                status, digest, detail = "error", None, str(exc)
            else:
                detail = None
                if not isinstance(pinned, str):
                    status = "unpinned"
                elif digest == pinned:
                    status = "ok"
                else:
                    status = "drift"
            if status in ("drift", "error"):
                failed = True
            results.append({"name": name, "status": status,
                            "digest": digest, "pinned": pinned})
            if not args.json:
                print(_audit_line(name, status, digest, pinned, detail))
        if args.json:
            print(json.dumps({"pins": pins_file, "skills": results},
                             indent=2, sort_keys=True))
        return 2 if failed else 0

    expected = pins.get(args.name)
    if not isinstance(expected, str):
        sys.stderr.write(
            "interlock skills: {} is not pinned\n".format(args.name))
        return 2
    directory = find_skill(args.name, roots)
    if directory is None:
        sys.stderr.write(
            "interlock skills: directory for {} not found\n".format(args.name))
        return 2
    try:
        digest = skill_digest(directory)
    except (OSError, ValueError) as exc:
        sys.stderr.write("interlock skills: {}\n".format(exc))
        return 2
    matched = digest == expected
    if args.json:
        print(json.dumps(
            {"name": args.name, "digest": digest, "pinned": expected,
             "match": matched},
            indent=2))
    elif matched:
        print("ok {} {}".format(args.name, digest))
    else:
        sys.stderr.write(
            "interlock skills: {} changed since it was pinned\n".format(args.name))
    return 0 if matched else 2
