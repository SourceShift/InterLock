"""Ops & integrations: is protection on, which agents are hooked, which MCP
servers are configured, is the guard daemon healthy, is the receipt log sound.

Each answer comes from the same code as the matching command - ``interlock
doctor``, ``install-hook``, ``mcp scan``, the sidecar's admin endpoint - run
from the console's process. The console only *reads*: installing a hook or
trusting an overlay stays a command the user runs themselves, outside any
agent, and the page offers that exact command to copy.

``/api/doctor`` is cached for a few seconds: every page's posture pill asks.
"""
from __future__ import annotations

import json
import os
import threading
import time
import urllib.request
from argparse import Namespace
from typing import Any, Dict, List, Optional, Tuple

from .server import ROUTES
from .session import ApiError, handles_errors, setting

DOCTOR_TTL = 10.0
_doctor_cache: Dict[Any, Tuple[float, Dict[str, Any]]] = {}
_doctor_lock = threading.Lock()

AGENT_LABELS = {"claude-code": "Claude Code", "codex": "Codex", "cursor": "Cursor"}
CLIENT_LABELS = {"claude-desktop": "Claude Desktop", "claude-code": "Claude Code", "cursor": "Cursor",
                 "vscode": "VS Code", "windsurf": "Windsurf", "gemini": "Gemini CLI", "codex": "Codex"}
RISK_LABELS = {"unpinned-package": "unpinned package", "unpinned-image": "unpinned image",
               "plain-http": "plain HTTP", "inline-credential": "inline credential"}


def _doctor_args(handler: Any) -> Namespace:
    policy = setting(handler, "policy_path")
    return Namespace(rules=None, policy=policy if policy and os.path.exists(policy) else None,
                     sidecar=setting(handler, "sidecar"),
                     receipts=getattr(handler.server, "receipts_path", None),
                     key_file=setting(handler, "key_file"), json=True, no_color=True)


def doctor(handler: Any) -> Dict[str, Any]:
    from ..cli import doctor as d
    from ..posture import INFO, Check, Posture

    args = _doctor_args(handler)
    key = (args.policy, args.sidecar, args.receipts, args.key_file)
    with _doctor_lock:
        hit = _doctor_cache.get(key)
        if hit and time.monotonic() - hit[0] < DOCTOR_TTL:
            return hit[1]
    checks: List[Any] = []
    if args.policy is None:
        checks.append(Check("engine.installed", INFO,
                            "no policy file at {}: hooks run the built-in coding-agent pack".format(
                                setting(handler, "policy_path"))))
    else:
        checks.extend(d._policy_checks(args))
    for provider in (d._sidecar_checks, d._receipt_checks):
        checks.extend(provider(args))
    checks.extend(d._sandbox_checks())
    checks.extend(d._hook_checks())
    for provider in d.EXTRA_CHECKS:
        try:
            checks.extend(provider(args))
        except Exception as exc:
            checks.append(Check("doctor.provider", "warn", "a check failed to run: {}".format(
                type(exc).__name__)))
    posture = Posture(tuple(checks))
    result = posture.to_dict()
    with _doctor_lock:
        _doctor_cache[key] = (time.monotonic(), result)
    return result


@handles_errors
def _handle_doctor(handler: Any) -> Tuple[int, dict]:
    return 200, doctor(handler)


@handles_errors
def _handle_hooks(handler: Any) -> Tuple[int, dict]:
    from ..adapters import ADAPTERS, get_adapter

    hooks = []
    for name in sorted(ADAPTERS):
        adapter = get_adapter(name)
        path = adapter.settings_path()
        label = AGENT_LABELS.get(name, name)
        try:
            command = adapter.installed_command()
        except Exception:
            command = None
        if command:
            state = "monitor mode" if "--monitor" in command else "installed"
            where, cmd = path, ("interlock install-hook --for {}".format(name)
                                if state == "monitor mode" else "")
        elif os.path.isdir(os.path.dirname(path)):
            state, where = "not installed", "{} has no interlock hook".format(_tilde(path))
            cmd = "interlock install-hook --for {}".format(name)
        else:
            state, where, cmd = "not on this machine", "no {} settings found".format(label), ""
        hooks.append({"agent": name, "name": label, "state": state, "where": _tilde(where),
                      "path": path, "command": command, "cmd": cmd})
    return 200, {"hooks": hooks}


def _tilde(path: str) -> str:
    home = os.path.expanduser("~")
    return "~" + path[len(home):] if path.startswith(home + os.sep) else path


@handles_errors
def _handle_mcp(handler: Any) -> Tuple[int, dict]:
    from ..mcp_inventory import config_locations, scan

    cwd = setting(handler, "project_cwd") or os.getcwd()
    servers, warnings = scan(cwd)
    clients = {c for c, _, p, _ in config_locations(cwd) if os.path.exists(p)}
    out = []
    for s in servers:
        risks = []
        for text in s.risks:
            tag, _, why = text.partition(": ")
            risks.append({"tag": RISK_LABELS.get(tag, tag), "why": why})
        target = s.url or " ".join([s.command or ""] + list(s.args)).strip()
        out.append({"name": s.name, "client": CLIENT_LABELS.get(s.client, s.client),
                    "scope": s.scope + (" · " + _tilde(s.project) if s.project else ""),
                    "transport": s.transport, "cmd": target, "config": _tilde(s.config),
                    "env": "env: " + (", ".join(s.env_keys) if s.env_keys else "none"),
                    "risks": risks})
    return 200, {"servers": out, "warnings": warnings, "clients_seen": len(clients),
                 "clients_known": len(CLIENT_LABELS)}


@handles_errors
def _handle_mcp_starter(handler: Any) -> Tuple[int, dict]:
    """The rule ``interlock mcp scan --starter`` would print: block MCP tools
    from any server not in today's inventory. Offered for review, never saved."""
    from ..mcp_inventory import scan, starter_policy

    servers, _ = scan(setting(handler, "project_cwd") or os.getcwd())
    doc = starter_policy(servers)
    rules = doc.get("rules") or []
    return 200, {"rule": rules[0] if rules else None, "servers": len(servers)}


def _admin_get(address: str, path: str) -> Optional[Dict[str, Any]]:
    host, _, port = address.rpartition(":")
    host = host.strip("[]") or "127.0.0.1"
    if host not in ("127.0.0.1", "localhost", "::1"):
        raise ApiError(400, "bad_sidecar_admin", "the sidecar admin address must be loopback")
    url = "http://{}:{}{}".format("[::1]" if host == "::1" else host, port, path)
    try:
        with urllib.request.urlopen(url, timeout=2) as resp:  # noqa: S310 - loopback only
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None


@handles_errors
def _handle_sidecar(handler: Any) -> Tuple[int, dict]:
    from ..posture import OK, probe_sidecar
    from ..sidecar.__main__ import default_socket_path

    socket_path = setting(handler, "sidecar") or default_socket_path()
    admin = setting(handler, "sidecar_admin")
    configured = bool(setting(handler, "sidecar")) or bool(admin) or os.path.exists(socket_path)
    if not configured:
        return 200, {"state": "not configured", "socket": socket_path, "admin": None}
    check = probe_sidecar(socket_path)
    state = "healthy" if check.status == OK else "unreachable"
    stats = _admin_get(admin, "/stats") if admin else None
    config = _admin_get(admin, "/config") if admin else None
    return 200, {"state": state, "socket": _tilde(socket_path), "detail": check.summary,
                 "admin": admin, "stats": stats, "config": config}


@handles_errors
def _handle_receipt_log(handler: Any) -> Tuple[int, dict]:
    from .audit import _read_receipts

    path = getattr(handler.server, "receipts_path", None)
    if path is None:
        return 200, {"configured": False}
    exists = os.path.exists(path)
    target = path if exists else os.path.dirname(path) or "."
    dropped = 0
    if exists:
        dropped = sum(1 for r in _read_receipts(path) if r.get("action") == "receipts.dropped")
    return 200, {"configured": True, "path": _tilde(path), "exists": exists,
                 "writable": os.access(target, os.W_OK),
                 "key": getattr(handler.server, "receipts_key", None) is not None,
                 "dropped": dropped}


ROUTES["/api/doctor"] = {"GET": _handle_doctor}
ROUTES["/api/hooks"] = {"GET": _handle_hooks}
ROUTES["/api/mcp"] = {"GET": _handle_mcp}
ROUTES["/api/mcp/starter"] = {"GET": _handle_mcp_starter}
ROUTES["/api/sidecar"] = {"GET": _handle_sidecar}
ROUTES["/api/receipt-log"] = {"GET": _handle_receipt_log}
