"""The confinement profile: a backend-agnostic description of what a sandboxed
process may touch, and the compiler that derives one from interlock policy.

The profile is the intermediate representation every backend consumes. bubblewrap
turns it into ``--ro-bind`` / ``--unshare-net`` flags, the macOS backend turns it
into a Seatbelt s-expression, the soft backend turns it into rlimits and a
scrubbed environment. Keeping one IR means the *policy* is written once and the
per-OS translation is the only thing that varies.

``compile_profile`` is the bridge from interlock's policy plane to that IR. It
reads a resolved policy (the ``{template_id: params}`` dict that
``ScopeRegistry.resolve`` already produces for a subject) and picks up the
bindings that describe containment. Its defaults are closed: a profile with no
network binding gets no network, a profile with no filesystem binding gets no
writable paths. You have to grant reach explicitly, the same fail-closed stance
the detectors take.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Optional, Sequence, Tuple

# Template ids the compiler understands. They are plain policy bindings, not new
# code: any scope can carry them, and a scope that carries none is fully locked.
EGRESS_TEMPLATE = "egress_allowlist"
FS_TEMPLATE = "sandbox_fs"
LIMITS_TEMPLATE = "sandbox_limits"


@dataclass(frozen=True)
class SandboxProfile:
    """An immutable description of a process's allowed reach.

    read_paths / write_paths: host paths bind-mounted read-only / read-write.
    allow_network:  whether the process gets any network namespace at all.
    allowed_hosts:  when network is allowed, the hostnames egress is confined to
                    (enforced host-granular by the nftables backend, and by the
                    in-process ``egress_allowlist`` detector on captured calls).
    env:            the exact environment handed to the child. Empty means the
                    child starts with nothing but what the backend must inject.
    cpu_seconds / memory_mb: soft resource ceilings (RLIMIT_CPU / RLIMIT_AS).
    unshare_pid:    give the child its own PID namespace where the backend can.
    workdir:        the child's working directory inside the sandbox.
    """

    read_paths: Tuple[str, ...] = ()
    write_paths: Tuple[str, ...] = ()
    allow_network: bool = False
    allowed_hosts: Tuple[str, ...] = ()
    env: Mapping[str, str] = field(default_factory=dict)
    cpu_seconds: Optional[int] = None
    memory_mb: Optional[int] = None
    unshare_pid: bool = True
    workdir: Optional[str] = None

    @staticmethod
    def locked() -> "SandboxProfile":
        """The maximally-closed profile: no fs writes, no network, no env.

        This is the default a subject with no containment bindings resolves to.
        """
        return SandboxProfile()

    def with_paths(
        self,
        *,
        read: Sequence[str] = (),
        write: Sequence[str] = (),
    ) -> "SandboxProfile":
        return SandboxProfile(
            read_paths=tuple(self.read_paths) + tuple(read),
            write_paths=tuple(self.write_paths) + tuple(write),
            allow_network=self.allow_network,
            allowed_hosts=self.allowed_hosts,
            env=dict(self.env),
            cpu_seconds=self.cpu_seconds,
            memory_mb=self.memory_mb,
            unshare_pid=self.unshare_pid,
            workdir=self.workdir,
        )


def _as_str_tuple(value: Any) -> Tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, (list, tuple, set, frozenset)):
        return tuple(str(v) for v in value)
    return (str(value),)


def compile_profile(
    resolved: Optional[Mapping[str, Mapping[str, Any]]],
    *,
    workdir: Optional[str] = None,
    base_env: Optional[Mapping[str, str]] = None,
) -> SandboxProfile:
    """Turn a resolved policy into a confinement profile, defaulting closed.

    ``resolved`` is the ``{template_id: params}`` mapping a ``ScopeRegistry``
    hands back for a subject. Recognised bindings:

    - ``egress_allowlist.allowed_hosts`` grants network and confines egress to
      those hosts. Absent, or present but empty, means no network at all.
    - ``sandbox_fs.read_paths`` / ``sandbox_fs.write_paths`` grant filesystem
      reach. Absent means no writable host path.
    - ``sandbox_limits.cpu_seconds`` / ``sandbox_limits.memory_mb`` set ceilings.

    Anything the policy does not mention stays denied. ``base_env`` is an
    optional allowlisted environment; nothing from the parent process leaks in
    unless it is passed here.
    """
    if not resolved:
        return SandboxProfile(env=dict(base_env or {}), workdir=workdir)

    egress = resolved.get(EGRESS_TEMPLATE) or {}
    hosts = _as_str_tuple(egress.get("allowed_hosts"))
    allow_network = bool(hosts)

    fs = resolved.get(FS_TEMPLATE) or {}
    read_paths = _as_str_tuple(fs.get("read_paths"))
    write_paths = _as_str_tuple(fs.get("write_paths"))

    limits = resolved.get(LIMITS_TEMPLATE) or {}
    cpu = limits.get("cpu_seconds")
    mem = limits.get("memory_mb")

    return SandboxProfile(
        read_paths=read_paths,
        write_paths=write_paths,
        allow_network=allow_network,
        allowed_hosts=hosts,
        env=dict(base_env or {}),
        cpu_seconds=int(cpu) if cpu is not None else None,
        memory_mb=int(mem) if mem is not None else None,
        workdir=workdir,
    )
