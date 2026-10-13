"""Built-in policy packs, extended with ``"extends": "builtin:<name>"``.

``coding-agent`` is the default for the Claude Code, Codex and Cursor hook
adapters (``interlock install-hook``). It is built in code rather than shipped
as a file so it can name the user's real home directory; adapters hand it
absolute, normalized paths, so a prefix test cannot be walked around with
``..`` segments.

Locked rules - which no extending file and no overlay can disable - protect
interlock itself and stop irreversible host damage:

- ``self-protect-files``: no agent writes under ``~/.interlock`` (the policy,
  the trust list, the receipt log and its key).
- ``self-protect-commands``: no ``interlock trust`` / ``install-hook`` /
  ``uninstall-hook`` from inside the agent, and no shell writes, moves or
  deletes under ``~/.interlock``.
- ``destructive-commands``: recursive delete or re-permission of ``/``, ``~``
  or a system directory, raw disk writes and formats - however spelled.

Everything else is tunable: ``"disable": ["rule-id"]`` in your own policy file
that extends this pack.
"""
from __future__ import annotations

import os
from typing import Any, Callable, Dict, List

from .declarative import register_tool_schema

#: Argument names of the tools the hook adapters produce, for load-time checks.
CODING_AGENT_TOOLS: Dict[str, List[str]] = {
    "Bash": ["command", "description", "timeout", "run_in_background"],
    "Read": ["file_path", "offset", "limit", "pages"],
    "Write": ["file_path", "content"],
    "Edit": ["file_path", "old_string", "new_string", "replace_all"],
    "MultiEdit": ["file_path", "edits"],
    "NotebookEdit": ["notebook_path", "new_source", "cell_id", "cell_type", "edit_mode"],
    "apply_patch": ["command", "file_path"],
    "WebFetch": ["url", "prompt"],
    "WebSearch": ["query", "allowed_domains", "blocked_domains"],
    "Glob": ["pattern", "path"],
    "Grep": ["pattern", "path", "glob", "type", "output_mode", "multiline", "head_limit",
             "-i", "-n", "-A", "-B", "-C"],
}

WRITE_TOOLS = ["Write", "Edit", "MultiEdit", "NotebookEdit", "apply_patch"]
FILE_TOOLS = ["Read"] + WRITE_TOOLS


def _register() -> None:
    for action, names in CODING_AGENT_TOOLS.items():
        register_tool_schema(action, names)


def _path_under(prefixes: List[str], exact: List[str] = ()) -> Dict[str, Any]:  # type: ignore[assignment]
    tests: List[Dict[str, Any]] = []
    for arg in ("file_path", "notebook_path"):
        for prefix in prefixes:
            tests.append({"arg": arg, "startswith": prefix})
        for path in exact:
            tests.append({"arg": arg, "eq": path})
    return {"any": tests}


def coding_agent() -> Dict[str, Any]:
    home = os.path.expanduser("~")
    own = os.path.join(home, ".interlock")
    secret_dirs = [os.path.join(home, d) + "/" for d in (
        ".ssh", ".aws", ".gnupg", ".config/gcloud", ".kube", ".azure", ".password-store",
        ".config/op", ".docker")]
    secret_files = [os.path.join(home, f) for f in (
        ".netrc", ".git-credentials", ".npmrc", ".pypirc", ".docker/config.json",
        ".config/gh/hosts.yml")]
    hook_settings = [os.path.join(home, f) for f in (
        ".claude/settings.json", ".claude/settings.local.json", ".codex/hooks.json",
        ".codex/config.toml", ".cursor/hooks.json")]
    return {
        "version": 1,
        "name": "coding-agent",
        "description": "Default guard for coding agents (Claude Code, Codex, Cursor).",
        "rules": [
            # --- locked: interlock's own integrity, irreversible host damage ---
            {"id": "self-protect-files", "locked": True, "verdict": "block",
             "on": WRITE_TOOLS,
             "reason": "interlock's own configuration is not writable by the agent",
             "when": _path_under([own + "/"], [own])},
            {"id": "self-protect-commands", "locked": True, "verdict": "block",
             "on": "Bash",
             "reason": "the agent may not change interlock's trust, hooks or files",
             "when": {"intent": "interlock.tamper", "arg": "command"}},
            {"id": "destructive-commands", "locked": True, "on": "Bash",
             "detector": "destructive_command_guard"},
            # --- tunable defaults ---
            {"id": "fetch-and-execute", "verdict": "block", "on": "Bash",
             "reason": "running code fetched from the network (curl | sh) is refused",
             "when": {"intent": "net.fetch_exec", "arg": "command"}},
            {"id": "force-push", "verdict": "escalate", "on": "Bash",
             "reason": "force-push to a default branch, or with no branch named, "
                       "can destroy shared history",
             "when": {"intent": ["git.push.force:default", "git.push.force:implicit"],
                      "arg": "command"}},
            {"id": "push-delete", "verdict": "escalate", "on": "Bash",
             "reason": "deleting a remote branch", "when": {"intent": "git.push.delete",
                                                           "arg": "command"}},
            {"id": "discard-work", "verdict": "escalate", "on": "Bash",
             "reason": "this git command discards uncommitted or unpushed work",
             "when": {"intent": "git.discard", "arg": "command"}},
            {"id": "publish", "verdict": "escalate", "on": "Bash",
             "reason": "publishing a package or release cannot be undone",
             "when": {"intent": "pkg.publish", "arg": "command"}},
            {"id": "shell-init-write", "verdict": "escalate", "on": "Bash",
             "reason": "writing a shell start-up file runs code in every future shell",
             "when": {"intent": "persist.shell_init", "arg": "command"}},
            {"id": "scheduled-jobs", "verdict": "escalate", "on": "Bash",
             "reason": "installing a scheduled job runs code after the session ends",
             "when": {"intent": "persist.schedule", "arg": "command"}},
            {"id": "privilege", "verdict": "escalate", "on": "Bash",
             "reason": "running a command as another user (sudo, doas, su)",
             "when": {"intent": "priv.escalate", "arg": "command"}},
            {"id": "git-credentials", "on": "Bash", "detector": "git_credential_guard"},
            {"id": "secret-files", "verdict": "block", "on": FILE_TOOLS,
             "reason": "credential stores (ssh, cloud, gpg, registry tokens) are off limits",
             "when": _path_under(secret_dirs, secret_files)},
            {"id": "env-files", "verdict": "escalate", "on": "Read",
             "reason": "reading a .env file puts its secrets in the agent's context",
             "when": {"all": [
                 {"arg": "file_path", "matches": r"(^|/)\.env(\.[^/]*)?$"},
                 {"not": {"arg": "file_path",
                          "matches": r"\.env\.(example|sample|template|dist)$"}}]}},
            {"id": "agent-hook-settings", "verdict": "escalate", "on": WRITE_TOOLS,
             "reason": "this file controls the agent's hooks; changing it can remove the guard",
             "when": {"any": [_path_under([], hook_settings),
                              {"arg": "file_path", "endswith": "/.claude/settings.json"},
                              {"arg": "file_path", "endswith": "/.claude/settings.local.json"}]}},
            {"id": "result-injection", "detector": "tool_result_injection_guard"},
            {"id": "result-secrets", "detector": "tool_output_secret_redactor"},
        ],
    }


_PACKS: Dict[str, Callable[[], Dict[str, Any]]] = {"coding-agent": coding_agent}


def builtin_pack(name: str) -> Dict[str, Any]:
    """The named pack's document. Raises KeyError for an unknown name."""
    _register()
    if name not in _PACKS:
        raise KeyError("no built-in policy {!r}; available: {}".format(
            name, ", ".join(sorted(_PACKS))))
    return _PACKS[name]()


def pack_names() -> List[str]:
    return sorted(_PACKS)
