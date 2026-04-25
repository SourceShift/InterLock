"""Host-granular egress via nftables (Linux, privileged, opt-in).

bubblewrap can give a sandbox network or take it away, but it cannot say "network,
but only to api.internal". That host-granular egress restriction is what this
module adds, the way a production environment does it: an nftables ruleset that
drops all outbound traffic except to an allowlist of resolved IPs (plus DNS and
loopback, without which nothing resolves).

Two things are kept strictly apart on purpose:

- ``build_ruleset`` is pure. It resolves nothing and runs nothing; it just turns
  a list of IPs into the nft script text, so the exact rules are unit tested.
- ``apply_ruleset`` is the only function that touches the system, and it refuses
  to do so unless the caller opted in *and* the process has the privilege
  (root / CAP_NET_ADMIN) plus an ``nft`` binary. It is never called
  automatically by the sandbox; a caller has to ask for it. This keeps a
  high-consequence, root-level side effect from happening as a surprise.
"""
from __future__ import annotations

import os
import shutil
import socket
from typing import List, Sequence


def resolve_hosts(hosts: Sequence[str]) -> List[str]:
    """Resolve hostnames to a de-duplicated list of IP strings.

    A host that does not resolve is skipped rather than fatal, because the
    ruleset fails closed anyway: an unresolved host simply gets no allow rule,
    so traffic to it is dropped.
    """
    ips: List[str] = []
    seen = set()
    for host in hosts:
        try:
            infos = socket.getaddrinfo(host, None)
        except socket.gaierror:
            continue
        for info in infos:
            ip = str(info[4][0])
            if ip not in seen:
                seen.add(ip)
                ips.append(ip)
    return ips


def build_ruleset(allowed_ips: Sequence[str], *, allow_dns: bool = True) -> str:
    """Return an nft script: drop all output except loopback, DNS, and allowed IPs."""
    lines = [
        "table inet interlock_brace {",
        "  chain output {",
        "    type filter hook output priority 0; policy drop;",
        "    oifname lo accept",
        "    ct state established,related accept",
    ]
    if allow_dns:
        lines.append("    udp dport 53 accept")
        lines.append("    tcp dport 53 accept")
    for ip in allowed_ips:
        family = "ip6" if ":" in ip else "ip"
        lines.append("    {} daddr {} accept".format(family, ip))
    lines += ["  }", "}"]
    return "\n".join(lines)


def can_apply() -> bool:
    """True only when applying a ruleset could actually work: root + nft present."""
    return (
        hasattr(os, "geteuid")
        and os.geteuid() == 0
        and shutil.which("nft") is not None
    )


def apply_ruleset(ruleset: str, *, confirm: bool = False) -> None:
    """Install a ruleset. Refuses unless ``confirm=True`` and the host permits it.

    This is the one privileged side effect in BRACE and it is deliberately hard
    to trigger by accident. Raises ``PermissionError`` when the process cannot
    load nftables rules, and ``ValueError`` when the caller did not explicitly
    confirm.
    """
    if not confirm:
        raise ValueError(
            "apply_ruleset refuses to modify the host firewall without confirm=True"
        )
    if not can_apply():
        raise PermissionError(
            "loading nftables rules needs root/CAP_NET_ADMIN and the nft binary"
        )
    import subprocess

    subprocess.run(["nft", "-f", "-"], input=ruleset, text=True, check=True)
