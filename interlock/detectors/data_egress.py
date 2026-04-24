"""Data-domain guards: stop the agent from moving data where it should not.

The tool and execution guards answer "may this action run?". These two answer
the question a prompt- or response-level guardrail structurally cannot: "may
this *data* leave, and may this *file* be read?" The damage in an exfiltration
incident is not in the model's text, it is in the tool call the agent makes
after the text - a ``send_email`` to an outside address, an ``http_post`` to an
attacker host. Only a guard sitting on the action sees it.

- :func:`network_egress_guard` is an *allowlist on destinations*. An outbound
  action is permitted only when every destination it names resolves to an
  allowlisted host; anything else, including an action whose destination cannot
  be determined, is denied. Fail-closed by construction, for the same reason a
  tool allowlist is: you can enumerate the few places data may go, you cannot
  enumerate every place it must not.

- :func:`sensitive_path_guard` is a *denylist on read targets*: block reads of
  the handful of paths that are secrets by definition (``/etc/passwd``, SSH and
  cloud credentials, ``.env``), and stay silent on everything else.

- :func:`pii_redaction_guard` is the *modify* case, not a block: an outbound
  action may go through, but any PII or secret in its payload (emails, API
  tokens, private keys, card numbers) is masked out first. The exfiltration is
  neutralised without failing the send, which is the allow/modify/block
  spectrum working end to end rather than only its hard edge.

All three decide on the action name plus its arguments, before the effect
happens, and all return None (no opinion) when they see nothing to object to.
"""
from __future__ import annotations

import os
import re
from typing import Any, Callable, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import urlparse

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

NETWORK_EGRESS_POLICY_ID = "network_egress"
SENSITIVE_PATH_POLICY_ID = "sensitive_path"
PII_REDACTION_POLICY_ID = "pii_redaction"

# Action names that send data off the process. Names that are unambiguously
# network egress; bare verbs like "get"/"post" are deliberately excluded so the
# guard does not shadow an unrelated in-house tool that happens to be named
# "get". Callers extend this set for their own transport names.
DEFAULT_EGRESS_ACTIONS = frozenset({
    "http_post", "http_get", "http_put", "http_delete", "http_request",
    "fetch", "upload", "download", "webhook", "curl", "wget",
    "send_email", "sendmail", "email", "smtp_send",
    "slack_post", "post_webhook", "publish_message", "notify_external",
})

# Argument keys that carry a destination (a URL, host, or recipient address).
DEFAULT_DESTINATION_KEYS = (
    "url", "endpoint", "uri", "href", "host", "hostname",
    "address", "addr", "to", "recipient", "recipients",
    "email", "dest", "destination", "target", "server", "webhook_url",
)

# Read actions the sensitive-path guard watches.
DEFAULT_READ_ACTIONS = frozenset({
    "read_file", "read", "open", "cat", "load_file", "load",
    "fs_read", "get_file", "fetch_file", "readlines", "slurp",
})

# Argument keys that carry a filesystem path.
DEFAULT_PATH_KEYS = (
    "path", "file", "filename", "filepath", "file_path",
    "src", "source", "target", "location",
)

# Argument keys that carry a message body / payload the guard scans for PII.
# Destination keys (url, to, ...) are deliberately excluded: redacting the
# recipient would break the send, and the recipient is the egress guard's job.
DEFAULT_CONTENT_KEYS = (
    "data", "body", "payload", "content", "text",
    "message", "msg", "value", "attachment", "attachments",
)

# The mask a redacted match is replaced with; ``{kind}`` names what was found.
DEFAULT_REDACTION_MARKER = "[REDACTED {kind}]"

# Paths that are secrets by definition. "~" is expanded per call.
DEFAULT_SENSITIVE_PATHS = (
    "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/ssh",
    "/proc/self/environ",
    "~/.ssh", "~/.aws/credentials", "~/.aws/config", "~/.gnupg",
    "~/.kube/config", "~/.netrc", ".env", "id_rsa",
)


def _as_name_set(names: Optional[Iterable[str]]) -> Set[str]:
    """Collect str names into a set; a bare string is one name, not its chars."""
    if names is None:
        return set()
    if isinstance(names, str):
        return {names}
    return {n for n in names if isinstance(n, str)}


def _normalize_host(value: str) -> str:
    return value.strip().lower().rstrip(".")


def _host_of(destination: str) -> Optional[str]:
    """Pull a host out of a URL, an ``user@host`` address, or a bare hostname.

    Returns None when nothing host-like can be extracted, which the caller
    treats as un-vettable and therefore denied.
    """
    text = destination.strip()
    if not text:
        return None
    if "://" in text:
        host = urlparse(text).hostname
        return _normalize_host(host) if host else None
    if "@" in text:  # an email / SMTP recipient: the domain is the destination
        return _normalize_host(text.rsplit("@", 1)[1])
    # a bare host, possibly host:port
    return _normalize_host(text.split("/", 1)[0].split(":", 1)[0])


def _host_allowed(host: str, allowed: Set[str]) -> bool:
    """True if host equals an allowed entry or is a subdomain of one."""
    return any(host == a or host.endswith("." + a) for a in allowed)


def _destinations(args: Any, keys: Iterable[str]) -> List[str]:
    """Every destination string found under the given argument keys.

    A key may hold one address or a list of them (multiple recipients); all are
    collected so a single disallowed recipient is enough to deny the send.
    """
    if not isinstance(args, dict):
        return []
    found: List[str] = []
    for key in keys:
        if key not in args:
            continue
        val = args[key]
        if isinstance(val, str):
            found.append(val)
        elif isinstance(val, (list, tuple, set)):
            found.extend(v for v in val if isinstance(v, str))
    return found


def network_egress_guard(
    allowed_hosts: Iterable[str],
    *,
    egress_actions: Iterable[str] = DEFAULT_EGRESS_ACTIONS,
    destination_keys: Iterable[str] = DEFAULT_DESTINATION_KEYS,
    reason: Optional[str] = None,
) -> Rule:
    """Rule: permit an outbound action only to allowlisted destination hosts.

    An action counts as egress when its name is in ``egress_actions``. For such
    an action every destination in its arguments must resolve to a host that is,
    or is a subdomain of, an entry in ``allowed_hosts``. Three ways to be denied,
    all fail-closed:

    - a destination whose host is not on the allowlist (the exfiltration case),
    - a destination that is not host-like and cannot be vetted,
    - an egress action that names no destination at all.

    Non-egress actions get no opinion (None), leaving them to other rules.
    """
    allowed = {_normalize_host(h) for h in allowed_hosts if isinstance(h, str)}
    actions = _as_name_set(egress_actions)

    def rule(event: SensorEvent) -> Optional[Decision]:
        if event.action not in actions:
            return None
        dests = _destinations(event.args, destination_keys)
        if not dests:
            return Decision.block(
                reason or "egress '{}' names no destination to vet; denied "
                "fail-closed".format(event.action),
                policy_id=NETWORK_EGRESS_POLICY_ID,
            )
        for dest in dests:
            host = _host_of(dest)
            if host is None or not _host_allowed(host, allowed):
                return Decision.block(
                    reason or "egress to '{}' is not on the destination "
                    "allowlist".format(host or dest),
                    policy_id=NETWORK_EGRESS_POLICY_ID,
                )
        return None

    return rule


def _path_is_sensitive(value: str, patterns: Iterable[str]) -> bool:
    expanded = os.path.expanduser(value)
    base = os.path.basename(expanded.rstrip("/"))
    for pattern in patterns:
        pat = os.path.expanduser(pattern).rstrip("/")
        if expanded == pat or expanded.startswith(pat + "/"):
            return True
        if "/" not in pattern and base == pattern:  # bare name: ".env", "id_rsa"
            return True
    return False


def sensitive_path_guard(
    sensitive_paths: Iterable[str] = DEFAULT_SENSITIVE_PATHS,
    *,
    read_actions: Iterable[str] = DEFAULT_READ_ACTIONS,
    path_keys: Iterable[str] = DEFAULT_PATH_KEYS,
    reason: Optional[str] = None,
) -> Rule:
    """Rule: deny a read action whose path argument is a known secret.

    Matches an exact path, anything under a sensitive directory, or a bare
    filename (``.env``, ``id_rsa``) wherever it sits. Read actions on any other
    path, and every non-read action, get no opinion.
    """
    patterns = tuple(p for p in sensitive_paths if isinstance(p, str))
    actions = _as_name_set(read_actions)

    def rule(event: SensorEvent) -> Optional[Decision]:
        if event.action not in actions:
            return None
        for key in path_keys:
            val = event.args.get(key) if isinstance(event.args, dict) else None
            if isinstance(val, str) and _path_is_sensitive(val, patterns):
                return Decision.block(
                    reason or "read of sensitive path '{}' is denied".format(val),
                    policy_id=SENSITIVE_PATH_POLICY_ID,
                )
        return None

    return rule


# A PII pattern: a label, the regex that finds it, and an optional validator that
# confirms a raw match before it is masked (used to Luhn-check card numbers so
# the pattern does not clobber every long digit string).
PiiPattern = Tuple[str, "re.Pattern[str]", Optional[Callable[[str], bool]]]


def _luhn_ok(candidate: str) -> bool:
    """True if the digits in ``candidate`` pass the Luhn checksum.

    Card numbers pass; arbitrary 13-to-19-digit identifiers almost never do, so
    this keeps the card pattern from redacting ordinary long numbers.
    """
    digits = [int(c) for c in candidate if c.isdigit()]
    if len(digits) < 13:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, digit in enumerate(digits):
        if i % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


# High-precision defaults: each is either structurally unambiguous (a vendor key
# prefix, a PEM header) or validated (the card number). Callers pass their own
# tuple to add house-specific secret formats.
DEFAULT_PII_PATTERNS: Tuple[PiiPattern, ...] = (
    ("PRIVATE_KEY", re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
        re.DOTALL), None),
    ("AWS_KEY", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), None),
    ("OPENAI_KEY", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"), None),
    ("GITHUB_TOKEN", re.compile(r"\bghp_[A-Za-z0-9]{36}\b"), None),
    ("SLACK_TOKEN", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), None),
    ("BEARER_TOKEN", re.compile(r"\bBearer\s+[A-Za-z0-9._\-]{20,}"), None),
    ("SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), None),
    ("EMAIL", re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"), None),
    ("CREDIT_CARD", re.compile(r"\b\d(?:[ -]?\d){12,18}\b"), _luhn_ok),
)


def _redact_text(
    text: str, patterns: Sequence[PiiPattern], marker: str
) -> Tuple[str, bool]:
    """Mask every PII match in ``text``; return the new text and whether any hit.

    A pattern with a validator only masks matches the validator accepts, so an
    invalid candidate is left untouched rather than falsely redacted.
    """
    hit = False

    for kind, regex, validator in patterns:
        replacement = marker.format(kind=kind)

        def _sub(match: "re.Match[str]") -> str:
            nonlocal hit
            if validator is not None and not validator(match.group(0)):
                return match.group(0)
            hit = True
            return replacement

        text = regex.sub(_sub, text)

    return text, hit


def pii_redaction_guard(
    *,
    actions: Iterable[str] = DEFAULT_EGRESS_ACTIONS,
    content_keys: Iterable[str] = DEFAULT_CONTENT_KEYS,
    patterns: Sequence[PiiPattern] = DEFAULT_PII_PATTERNS,
    marker: str = DEFAULT_REDACTION_MARKER,
    reason: Optional[str] = None,
) -> Rule:
    """Rule: mask PII/secrets out of an outbound action's payload, don't block it.

    For an action in ``actions`` (network egress by default), every payload field
    in ``content_keys`` is scanned; any match of ``patterns`` (emails, vendor API
    keys, private-key blocks, Luhn-valid card numbers) is replaced with
    ``marker``. When something was masked the rule returns a MODIFY carrying only
    the rewritten fields, so the send proceeds with the secret stripped. When the
    payload is clean, or the action is not an egress action, it returns None.

    This is deliberately the softer sibling of :func:`network_egress_guard`: the
    allowlist decides *whether* data may leave, this decides *what* may be in it.
    It masks structured secrets inside an otherwise legitimate message; it is not
    a substitute for the allowlist against a raw file dump to an attacker host.
    """
    act = _as_name_set(actions)
    keys = tuple(content_keys)

    def _redact_value(value: Any) -> Tuple[Any, bool]:
        if isinstance(value, str):
            return _redact_text(value, patterns, marker)
        if isinstance(value, (list, tuple)):
            out: List[Any] = []
            hit = False
            for item in value:
                new_item, item_hit = _redact_value(item)
                hit = hit or item_hit
                out.append(new_item)
            return (out, hit) if hit else (value, False)
        return value, False

    def rule(event: SensorEvent) -> Optional[Decision]:
        if event.action not in act or not isinstance(event.args, dict):
            return None
        changed: dict = {}
        for key in keys:
            if key not in event.args:
                continue
            new_value, hit = _redact_value(event.args[key])
            if hit:
                changed[key] = new_value
        if not changed:
            return None
        return Decision.modify(
            changed,
            reason or "masked PII/secret from outbound '{}'".format(event.action),
            policy_id=PII_REDACTION_POLICY_ID,
        )

    return rule
