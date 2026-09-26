"""BRACE: the interlock Agent Control Environment.

A confinement layer that runs an agent's shell-outs and tool subprocesses under
kernel-enforced isolation whose rules are compiled from the same interlock policy
that governs the agent's in-process actions. One policy, two enforcement points:
the detectors intercept the calls interlock can see, and BRACE confines the
processes it cannot.

The backend is chosen for the host at runtime: bubblewrap on Linux, Seatbelt on
macOS, and a soft rlimits-and-scrubbed-env fallback everywhere else. The soft
fallback is honest about not being a security boundary, and the result object
reports which guarantees actually held so a caller can fail closed.

Guarantee table
---------------

This is the tested meaning of every ``enforced`` token, not a wish: each row
below is an escape test (the attack the token exists to stop, run for real and
asserted stopped) plus a control (the identical attack with only that
confinement relaxed, asserted to succeed, so the block is the sandbox's doing
and not the kernel refusing the syscall). The suite that proves it lives in
``tests/integration/test_brace_token_matrix.py``; a backend absent on the host
skips its rows with a reason under ``pytest -rs`` rather than silently.

============= ======== ========================================= =====================
backend       token    attack (escape / relaxed control)          tested outcome
============= ======== ========================================= =====================
soft          env      child reads a sentinel set in the         sentinel never
                       parent's environment / the same           reaches the child
                       sentinel granted via the profile          unless granted
soft          rlimit   runaway ``while True: pass`` CPU burn /   child dies with
                       the same loop under a profile with no     SIGXCPU; control
                       ceiling                                  survives to the
                                                                harness timeout
bubblewrap    env      same sentinel attack / control as soft    same as soft
bubblewrap    fs-ro    read of /etc/passwd, never granted /      read denied
                       the same read granted via read_paths      (path absent in
                                                                the mount ns)
bubblewrap    fs-rw    write outside write_paths / the same      out-of-grant write
                       write to a granted directory              fails, bytes
                                                                unchanged; in-grant
                                                                write lands
bubblewrap    pid      signal the host test process by pid /     host pids are
                       the same probe with unshare_pid off       invisible and
                                                                unsignalable in
                                                                the namespace
bubblewrap    net      POST a credentials file to a loopback     the send dies at
                       outsider / the same send with an egress   the socket,
                                                                nothing arrives;
                                                                granted egress
                                                                delivers
sandbox-exec  env      same sentinel attack / control as soft    same as soft
sandbox-exec  fs-rw    same write attack / control as bubblewrap same as bubblewrap
sandbox-exec  net      same exfil attack / control as bubblewrap same as bubblewrap
============= ======== ========================================= =====================

Tokens no backend may claim on these hosts: ``fs-ro`` and ``pid`` are never
reported by sandbox-exec (macOS cannot confine reads, and has no PID
namespaces), and ``soft`` reports only ``env`` and ``rlimit`` — it is not a
security boundary and does not pretend to be one. The drift test in the matrix
pins each backend's reported set to exactly the rows above, in both
directions, so the table and the code cannot drift apart unnoticed.

The missing rung: unprivileged host-granular egress
---------------------------------------------------

Between bubblewrap's ``--unshare-net`` (all network or none, unprivileged) and
nftables (host-granular, but root/CAP_NET_ADMIN, Linux-only, opt-in via
``backends/nftables.py``) there is no middle rung on this host, and none is
implementable unprivileged: Seatbelt's network filters accept only ``*`` or
``localhost`` as the remote host — ``sandbox-exec -p '(allow network-outbound
(remote ip "127.0.0.1:443"))'`` is rejected outright with "host must be * or
localhost in network address" — so an allowlist of specific remote hosts
cannot be expressed. When a profile grants network (``allow_network`` with
``allowed_hosts``), sandbox-exec and bubblewrap therefore open egress entirely
and report no ``net`` token, honestly; confining that grant to the listed
hosts is done in-process by the ``egress_allowlist`` detector on captured
calls, and at the host level only by the privileged nftables path. That rung
is absent, by measurement, and this table says so rather than wishing it
existed.
"""
from __future__ import annotations

from .backends import available_backends, select_backend
from .profile import SandboxProfile, compile_profile
from .result import SandboxResult
from .sandbox import Sandbox

__all__ = [
    "Sandbox",
    "SandboxProfile",
    "SandboxResult",
    "compile_profile",
    "available_backends",
    "select_backend",
]
