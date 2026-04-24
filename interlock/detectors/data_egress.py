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

Both decide on the action name plus its arguments, before the effect happens,
and both return None (no opinion) when they see nothing to object to.
"""
from __future__ import annotations

import os
from typing import Any, Iterable, List, Optional, Set
from urllib.parse import urlparse

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

NETWORK_EGRESS_POLICY_ID = "network_egress"
SENSITIVE_PATH_POLICY_ID = "sensitive_path"

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
