"""Find every MCP server configured on this machine, and what to worry about (R21).

interlock can pin an MCP server's tools, attest it, and allowlist it - once you
know it exists. MCP servers accumulate in half a dozen client configs, per user
and per project, and an agent can use any of them. :func:`scan` reads those
configs (never launching a server, never touching the network) and returns one
:class:`McpServer` per entry, with risk notes:

- ``unpinned-package``: ``npx``/``uvx``/``pipx run``/``bunx`` without a version,
  or ``@latest`` - whatever is published next runs with the agent's rights
- ``unpinned-image``: ``docker run`` of an image without an ``@sha256:`` digest
- ``plain-http``: a remote server over ``http://`` to anything but loopback
- ``inline-credential``: an env var or header whose *name* says secret, set
  inline in the config (the value is never read into the report)

Clients read: Claude Desktop, Claude Code (``~/.claude.json`` user and
per-project scopes, and a project ``.mcp.json``), Cursor (user and project),
VS Code (user ``settings.json``/``mcp.json`` and project ``.vscode/mcp.json``),
Windsurf, Gemini CLI, and Codex (``[mcp_servers.*]`` in ``config.toml``).

:func:`starter_policy` turns an inventory into a declarative rule that blocks
MCP tools (``mcp__<server>__*``, the coding-agent naming) from any server not
in it - review the list before you adopt it.
"""
from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

_SECRET_NAME = re.compile(r"(?i)(token|secret|password|passwd|api[_-]?key|private[_-]?key|credential|auth)")
_LOOPBACK = ("localhost", "127.0.0.1", "::1", "[::1]")


@dataclass
class McpServer:
    name: str
    client: str
    config: str
    scope: str  # user | project
    transport: str  # stdio | http | sse
    command: Optional[str] = None
    args: List[str] = field(default_factory=list)
    url: Optional[str] = None
    env_keys: List[str] = field(default_factory=list)
    project: Optional[str] = None
    risks: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _home() -> str:
    return os.path.expanduser("~")


def config_locations(cwd: Optional[str] = None) -> List[Tuple[str, str, str, str]]:
    """``(client, scope, path, format)`` for every config file to read."""
    home = _home()
    mac = sys.platform == "darwin"
    app = os.path.join(home, "Library", "Application Support") if mac else os.path.join(home, ".config")
    paths = [
        ("claude-desktop", "user", os.path.join(app, "Claude", "claude_desktop_config.json"), "mcpServers"),
        ("claude-code", "user", os.path.join(home, ".claude.json"), "claude.json"),
        ("cursor", "user", os.path.join(home, ".cursor", "mcp.json"), "mcpServers"),
        ("vscode", "user", os.path.join(app, "Code", "User", "settings.json"), "vscode-settings"),
        ("vscode", "user", os.path.join(app, "Code", "User", "mcp.json"), "servers"),
        ("windsurf", "user", os.path.join(home, ".codeium", "windsurf", "mcp_config.json"), "mcpServers"),
        ("gemini", "user", os.path.join(home, ".gemini", "settings.json"), "mcpServers"),
        ("codex", "user", os.path.join(home, ".codex", "config.toml"), "codex-toml"),
    ]
    if cwd:
        root = _project_root(cwd)
        paths += [
            ("claude-code", "project", os.path.join(root, ".mcp.json"), "mcpServers"),
            ("cursor", "project", os.path.join(root, ".cursor", "mcp.json"), "mcpServers"),
            ("vscode", "project", os.path.join(root, ".vscode", "mcp.json"), "servers"),
        ]
    return paths


def _project_root(cwd: str) -> str:
    current = os.path.abspath(cwd)
    while True:
        if os.path.exists(os.path.join(current, ".git")):
            return current
        parent = os.path.dirname(current)
        if parent == current:
            return os.path.abspath(cwd)
        current = parent


def scan(cwd: Optional[str] = None) -> Tuple[List[McpServer], List[str]]:
    """Every configured MCP server, and any config file that could not be read."""
    servers: List[McpServer] = []
    problems: List[str] = []
    for client, scope, path, fmt in config_locations(cwd):
        if not os.path.isfile(path):
            continue
        try:
            entries = list(_read(path, fmt))
        except (OSError, ValueError) as exc:
            problems.append("{}: {}".format(path, exc))
            continue
        for name, spec, project in entries:
            if not isinstance(spec, dict):
                continue
            server = _server(name, spec, client, path, "project" if project else scope, project)
            servers.append(server)
    return servers, problems


def _read(path: str, fmt: str) -> Iterable[Tuple[str, Any, Optional[str]]]:
    if fmt == "codex-toml":
        for name, spec in _codex_servers(path).items():
            yield name, spec, None
        return
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    data = json.loads(_strip_jsonc(text)) if text.strip() else {}
    if not isinstance(data, dict):
        raise ValueError("not a JSON object")
    if fmt == "mcpServers":
        yield from ((n, s, None) for n, s in (data.get("mcpServers") or {}).items())
    elif fmt == "servers":
        yield from ((n, s, None) for n, s in (data.get("servers") or {}).items())
    elif fmt == "vscode-settings":
        mcp = data.get("mcp") or {}
        yield from ((n, s, None) for n, s in (mcp.get("servers") or {}).items())
    elif fmt == "claude.json":
        yield from ((n, s, None) for n, s in (data.get("mcpServers") or {}).items())
        for project, settings in (data.get("projects") or {}).items():
            if isinstance(settings, dict):
                for n, s in (settings.get("mcpServers") or {}).items():
                    yield n, s, project


def _strip_jsonc(text: str) -> str:
    """VS Code settings allow // and /* */ comments and trailing commas."""
    out, i, n, quote = [], 0, len(text), False
    while i < n:
        c = text[i]
        if quote:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                quote = False
            i += 1
            continue
        if c == '"':
            quote = True
            out.append(c)
        elif text.startswith("//", i):
            while i < n and text[i] != "\n":
                i += 1
            continue
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end < 0 else end + 2
            continue
        else:
            out.append(c)
        i += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


def _codex_servers(path: str) -> Dict[str, Dict[str, Any]]:
    with open(path, "rb") as fh:
        raw = fh.read()
    try:
        import tomllib  # type: ignore[import-not-found]
        data = tomllib.loads(raw.decode("utf-8"))
        servers = data.get("mcp_servers") or {}
        return {k: v for k, v in servers.items() if isinstance(v, dict)}
    except ImportError:
        pass
    # Python < 3.11: read only [mcp_servers.NAME] tables of simple key = value lines.
    servers: Dict[str, Dict[str, Any]] = {}
    current: Optional[Dict[str, Any]] = None
    for line in raw.decode("utf-8").splitlines():
        stripped = line.strip()
        header = re.match(r"^\[\s*mcp_servers\.([A-Za-z0-9_\"'.-]+?)(\.env)?\s*\]$", stripped)
        if header:
            name = header.group(1).strip("\"'")
            entry = servers.setdefault(name, {})
            current = entry.setdefault("env", {}) if header.group(2) else entry
            continue
        if stripped.startswith("["):
            current = None
            continue
        if current is None or "=" not in stripped or stripped.startswith("#"):
            continue
        key, _, value = stripped.partition("=")
        current[key.strip().strip("\"'")] = _toml_value(value.strip())
    return servers


def _toml_value(text: str) -> Any:
    if text.startswith("[") and text.endswith("]"):
        return [v.strip().strip("\"'") for v in re.findall(r'"[^"]*"|\'[^\']*\'', text)]
    if text.startswith("{"):
        return {k: v for k, v in re.findall(r'([A-Za-z0-9_]+)\s*=\s*"([^"]*)"', text)}
    return text.strip("\"'")


def _server(name: str, spec: Dict[str, Any], client: str, path: str, scope: str,
            project: Optional[str]) -> McpServer:
    url = spec.get("url") or spec.get("serverUrl") or spec.get("httpUrl")
    command = spec.get("command")
    args = [str(a) for a in spec.get("args", []) if isinstance(a, (str, int, float))]
    transport = str(spec.get("type") or spec.get("transport") or ("http" if url else "stdio"))
    raw_env, raw_headers = spec.get("env"), spec.get("headers")
    env: Dict[str, Any] = raw_env if isinstance(raw_env, dict) else {}
    headers: Dict[str, Any] = raw_headers if isinstance(raw_headers, dict) else {}
    server = McpServer(name=str(name), client=client, config=path, scope=scope,
                       transport=transport, command=str(command) if command else None,
                       args=args, url=str(url) if url else None,
                       env_keys=sorted(str(k) for k in env), project=project)
    server.risks = _risks(server, env, headers)
    return server


def _risks(server: McpServer, env: Dict[str, Any], headers: Dict[str, Any]) -> List[str]:
    risks: List[str] = []
    command = os.path.basename(server.command or "")
    argv = server.args
    runs_package = (command in ("npx", "bunx", "uvx")
                    or (command == "pnpm" and argv[:1] == ["dlx"])
                    or (command == "pipx" and argv[:1] == ["run"]))
    if runs_package:
        packages = [a for a in argv if not a.startswith("-") and a not in ("run", "dlx")]
        if packages:
            package = packages[0]
            unpinned = package.endswith("@latest") or not _has_version(package, command)
            if unpinned:
                risks.append("unpinned-package: {} runs whatever {!r} publishes next".format(
                    command, package))
    if command in ("docker", "podman") and "run" in argv:
        images = [a for a in argv[argv.index("run") + 1:] if not a.startswith("-") and "=" not in a]
        if images and "@sha256:" not in images[0]:
            risks.append("unpinned-image: {!r} has no @sha256 digest".format(images[0]))
    if server.url and server.url.startswith("http://"):
        host = re.sub(r"^http://([^/:]+).*$", r"\1", server.url)
        if host not in _LOOPBACK:
            risks.append("plain-http: {} is reached without TLS".format(host))
    secretish = sorted({k for k in list(env) + list(headers) if _SECRET_NAME.search(str(k))
                        and isinstance((env.get(k) if k in env else headers.get(k)), str)
                        and not str(env.get(k) if k in env else headers.get(k)).startswith("${")})
    if secretish:
        risks.append("inline-credential: {} set inline in {}".format(", ".join(secretish), server.config))
    return risks


def _has_version(package: str, command: str) -> bool:
    if command in ("uvx", "pipx"):
        return bool(re.search(r"(==|@)\d", package))
    bare = package[1:] if package.startswith("@") else package
    return "@" in bare


def where(servers: List[McpServer], name: str) -> List[McpServer]:
    """Every entry configuring the server ``name``."""
    return [s for s in servers if s.name == name]


def starter_policy(servers: List[McpServer]) -> Dict[str, Any]:
    """A policy that blocks MCP tools from servers outside this inventory."""
    names = sorted({s.name for s in servers})
    known = [{"action": {"glob": "mcp__{}__*".format(_component(n))}} for n in names]
    rule: Dict[str, Any] = {
        "id": "mcp-known-servers",
        "verdict": "block",
        "reason": "MCP server not in the reviewed inventory",
        "description": "generated by `interlock mcp scan --emit-policy`; review before use",
        "when": {"all": [{"action": {"glob": "mcp__*"}}]
                 + ([{"not": {"any": known}}] if known else [])},
    }
    return {"version": 1, "name": "mcp-inventory", "rules": [rule]}


def _component(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", name).replace("__", "_")
