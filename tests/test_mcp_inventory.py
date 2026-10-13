"""MCP inventory scan (R21): every client config, risk notes, and the starter policy."""
import json

import pytest

from interlock import SensorEvent, Verdict
from interlock.cli import main
from interlock.mcp_inventory import scan, starter_policy, where
from interlock.policy.declarative import load_policy


@pytest.fixture
def machine(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr("sys.platform", "darwin")
    app = home / "Library" / "Application Support"

    def write(path, data):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(data if isinstance(data, str) else json.dumps(data))

    write(app / "Claude" / "claude_desktop_config.json", {"mcpServers": {
        "filesystem": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]},
        "pinned": {"command": "npx", "args": ["-y", "@scope/server@1.2.3"]}}})
    write(home / ".claude.json", {"mcpServers": {"github": {
        "command": "docker", "args": ["run", "-i", "--rm", "ghcr.io/github/github-mcp-server"],
        "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_" + "x" * 36}}},
        "projects": {"/work/app": {"mcpServers": {"db": {"type": "http", "url": "http://db.internal:8080/mcp"}}}}})
    write(home / ".cursor" / "mcp.json", {"mcpServers": {"local": {"url": "http://localhost:3000/sse"}}})
    write(app / "Code" / "User" / "settings.json",
          '{\n  // comment\n  "mcp": {"servers": {"vs": {"command": "uvx", "args": ["mcp-server-git"]},}},\n}')
    write(home / ".codex" / "config.toml",
          '[mcp_servers.docs]\ncommand = "npx"\nargs = ["-y", "docs-mcp@2.0.0"]\n'
          '[mcp_servers.docs.env]\nAPI_KEY = "${DOCS_KEY}"\n')
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    write(repo / ".mcp.json", {"mcpServers": {"team": {"command": "node", "args": ["server.js"]}}})
    write(home / ".gemini" / "settings.json", "{broken")
    return repo


def by_name(servers):
    return {s.name: s for s in servers}


def test_scan_reads_every_client(machine):
    servers, problems = scan(str(machine))
    found = by_name(servers)
    assert set(found) == {"filesystem", "pinned", "github", "db", "local", "vs", "docs", "team"}
    assert found["db"].scope == "project" and found["db"].project == "/work/app"
    assert found["team"].client == "claude-code" and found["team"].scope == "project"
    assert found["docs"].client == "codex" and found["docs"].args == ["-y", "docs-mcp@2.0.0"]
    assert found["vs"].client == "vscode"
    assert len(problems) == 1 and "settings.json" in problems[0]


def test_risk_notes(machine):
    found = by_name(scan(str(machine))[0])
    assert any(r.startswith("unpinned-package") for r in found["filesystem"].risks)
    assert found["pinned"].risks == []
    assert any(r.startswith("unpinned-image") for r in found["github"].risks)
    assert any(r.startswith("inline-credential: GITHUB_PERSONAL_ACCESS_TOKEN") for r in found["github"].risks)
    assert any(r.startswith("plain-http: db.internal") for r in found["db"].risks)
    assert found["local"].risks == []  # loopback over http is fine
    assert any(r.startswith("unpinned-package") for r in found["vs"].risks)
    assert found["docs"].risks == []  # pinned, and the env value is a ${reference}


def test_values_never_reach_the_report(machine, capsys):
    assert main(["mcp", "scan", "--json", "--cwd", str(machine)]) == 1
    out = capsys.readouterr().out
    assert "ghp_" not in out
    assert "GITHUB_PERSONAL_ACCESS_TOKEN" in out


def test_where(machine, capsys):
    servers, _ = scan(str(machine))
    assert [s.client for s in where(servers, "github")] == ["claude-code"]
    assert main(["mcp", "where", "github", "--cwd", str(machine)]) == 0
    assert main(["mcp", "where", "nope", "--cwd", str(machine)]) == 2


def test_starter_policy_blocks_unlisted_servers(machine, tmp_path):
    out = tmp_path / "mcp.json"
    main(["mcp", "scan", "--emit-policy", str(out), "--cwd", str(machine)])
    engine = load_policy(json.loads(out.read_text()))
    assert engine.evaluate(SensorEvent("mcp__github__create_issue")).verdict is Verdict.ALLOW
    assert engine.evaluate(SensorEvent("mcp__evil__exfiltrate")).verdict is Verdict.BLOCK
    assert engine.evaluate(SensorEvent("Bash", {"command": "ls"})).verdict is Verdict.ALLOW


def test_empty_inventory_blocks_every_mcp_tool():
    engine = load_policy(starter_policy([]))
    assert engine.evaluate(SensorEvent("mcp__a__b")).verdict is Verdict.BLOCK
