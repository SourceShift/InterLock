"""Argument guard: block sandboxed code that reaches for the network.

A code tool takes a string and runs it. When that string is supposed to run in
a sandbox, the sandbox's promise is that the code inside it cannot talk to the
outside world - no exfiltrating a secret to an attacker's host, no pulling a
second-stage payload, no calling out to a metadata service. The way code breaks
that promise is by naming a network primitive: the raw ``socket`` module, the
stdlib HTTP/URL clients (``urllib.request``, ``http.client``), the popular
``requests`` wrapper, or the transfer protocols ``smtplib`` and ``ftplib``.

The payload is the argument, and it is visible before the call runs, which is
where this rule sits: on the argument detector, ahead of any effect. Matching
the raw argument text rather than a parsed AST is deliberate - parsing submitted
source means running a parser on the attack surface, and an attacker can reach a
module through ``importlib.import_module("soc" + "ket")`` in ways no single
pattern catches. What the pattern does catch is the common case: the literal
module path as written. ``re.search`` is used rather than ``fullmatch`` because
the call is embedded in surrounding source - a multi-line script that mentions
``requests.post(`` anywhere is enough.

Only top-level string values of a dict ``args`` are scanned. An int, None, or
nested container is skipped rather than stringified, and a non-dict ``args``
yields no opinion - a detector must never raise on odd input. The first matching
value blocks the call; no match returns None (no opinion).
"""
from __future__ import annotations

import re
from typing import Optional

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

POLICY_ID = "code_network"

# A network egress primitive named as it is written in source: the raw socket
# module, the stdlib URL/HTTP clients, the ``requests`` helpers most often used
# to POST data out, and the mail/FTP transfer modules. The ``\b`` anchors keep
# the match on a module path rather than a substring of a larger identifier
# (``mysmtplib`` does not match). re.IGNORECASE is deliberately not applied:
# Python module names are case-sensitive, so folding case would only widen the
# match to spellings such as ``SOCKET.SOCKET`` that are not the module, changing
# which inputs are caught rather than merely how they are written.
PATTERN = re.compile(
    r"\b(?:socket\.socket|urllib\.request|requests\.(?:get|post)|http\.client|smtplib|ftplib)\b"
)


def code_network_guard() -> Rule:
    """Build a Rule that blocks a code argument naming a network primitive.

    Every top-level str value of a dict ``args`` is tested against
    :data:`PATTERN`. On the first match the rule returns a BLOCK naming the
    offending argument, so the caller can tell which parameter carried the
    payload. A non-dict ``args``, a dict with no str values, and a dict whose
    str values are all clean each return None (no opinion). The rule never
    raises.
    """

    def rule(event: SensorEvent) -> Optional[Decision]:
        args = getattr(event, "args", None)
        if not isinstance(args, dict):
            return None

        for name, value in args.items():
            if not isinstance(value, str):
                continue
            if PATTERN.search(value):
                return Decision.block(
                    reason="code_network: {}".format(name),
                    policy_id=POLICY_ID,
                    attributed_to=name,
                )

        return None

    return rule
