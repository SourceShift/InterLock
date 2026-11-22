"""Pin a skill's on-disk content, and check it before activation.

  interlock skills pin NAME [--roots DIR ...] [--pins FILE] [--json]
  interlock skills list [--pins FILE] [--json]
  interlock skills check NAME [--roots DIR ...] [--pins FILE] [--json]

A skill is a directory an agent loads under a trusted name. ``pin`` records the
sha256 of the files behind that name in a pin file, ``list`` shows what is
pinned, and ``check`` recomputes a skill's digest and compares it with its pin.
The default pin file is ``~/.interlock/skills.json`` and the default roots are
``~/.claude/skills``.

Exit codes: 0 success / a matching digest, 2 a mismatch, an unknown skill or a
missing skill, 64 no or unknown action.
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
    check.add_argument("name")
    check.add_argument("--roots", nargs="+", metavar="DIR", default=None,
                       help="directories holding skills (default: ~/.claude/skills)")
    check.add_argument("--pins", metavar="FILE", default=None,
                       help="pin file (default: ~/.interlock/skills.json)")
    check.add_argument("--json", action="store_true")


def run(args) -> int:
    from ..skills import (
        DEFAULT_PINS_PATH,
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
    try:
        pins = load_pins(pins_file)
    except (OSError, ValueError) as exc:
        sys.stderr.write("interlock skills: {}\n".format(exc))
        return 2
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
