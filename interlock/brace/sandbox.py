"""BRACE: the Agent Control Environment facade.

This is the one class a caller touches. Give it a confinement profile (write one
directly, or compile one from a subject's policy with
:func:`~interlock.brace.profile.compile_profile`) and it will:

1. pick the strongest containment backend the host offers, unless you pin one;
2. put the launch through the policy engine as a ``process_spawn`` event, so a
   rule can block or rewrite it before any process starts;
3. run the command under the backend's confinement;
4. hand back a :class:`~interlock.brace.result.SandboxResult` that reports which
   containment guarantees actually held.

A caller that needs real isolation should say so up front with ``require=``:
``run()`` then refuses, before any process starts, when the chosen backend
cannot deliver every required token (a silent downgrade to the soft backend is
the case this exists for). Checking ``result.enforced`` after ``run()`` reports
the same thing, but only once the untrusted code has already run.

Example::

    from interlock.brace import Sandbox, compile_profile

    profile = compile_profile(registry.resolve(("root", "acme", "agent42")))
    result = Sandbox(profile, require=("net", "fs-rw")).run(["python", "worker.py"])
    # raises IsolationUnavailable, without starting worker.py, on a host that
    # can only offer the soft backend
"""
from __future__ import annotations

import dataclasses
import os
import shutil
import signal
import subprocess
import sys
import tempfile
from typing import FrozenSet, Iterable, List, Optional, Tuple

from ..policy.engine import PolicyEngine
from .backends import WrapPlan, select_backend
from .limits import check_limits
from .profile import SandboxProfile
from .result import SandboxResult
from .trace import check_spawn, record_exit

# Every token a backend can report in ``enforced``. ``require=`` is checked
# against this set so a typo ("netw") fails when the Sandbox is built instead of
# refusing every run with a token no backend could ever claim.
KNOWN_TOKENS: FrozenSet[str] = frozenset({"env", "rlimit", "fs-ro", "fs-rw", "pid", "net"})


class IsolationUnavailable(RuntimeError):
    """The backend cannot enforce a token the caller required; nothing was run."""

    def __init__(self, backend: str, missing: List[str], enforced: List[str]):
        self.backend = backend
        self.missing = missing
        self.enforced = enforced
        super().__init__(
            "refusing to run: the {} backend cannot enforce {} for this profile "
            "(it enforces {})".format(backend, missing, sorted(enforced))
        )


class Sandbox:
    def __init__(
        self,
        profile: Optional[SandboxProfile] = None,
        *,
        backend: Optional[str] = None,
        engine: Optional[PolicyEngine] = None,
        enforcement: str = "blocking",
        principal: Optional[str] = None,
        require: Iterable[str] = (),
    ):
        """Build a sandbox for ``profile`` on ``backend`` (the strongest available by default).

        ``require`` lists ``enforced`` tokens that must hold (for example
        ``("net", "fs-rw")``). ``run()`` raises :class:`IsolationUnavailable`
        before spawning anything when the backend can't deliver one of them.

        Raises ``ValueError`` for an unknown ``require`` token, and
        :class:`~interlock.brace.limits.LimitUnsupported` when the profile asks
        for a resource limit this host cannot enforce (``memory_mb`` on macOS,
        any limit on Windows), instead of failing on every launch later.
        """
        self.profile = profile or SandboxProfile.locked()
        self._backend = select_backend(backend)
        self._engine = engine
        self._enforcement = enforcement
        self._principal = principal
        if isinstance(require, str):
            require = (require,)  # a bare token, not its characters
        self.require: Tuple[str, ...] = tuple(require)
        unknown = sorted(set(self.require) - KNOWN_TOKENS)
        if unknown:
            raise ValueError(
                "unknown required token(s) {}; known tokens are {}".format(
                    unknown, sorted(KNOWN_TOKENS)
                )
            )
        check_limits(self.profile)

    @property
    def backend_name(self) -> str:
        return self._backend.name

    def plan(self, argv: List[str]):
        """Return the backend's :class:`WrapPlan` without running anything.

        Useful for inspection and for the tests: you can see the exact wrapped
        argv a run would execute without spawning a process.
        """
        return self._backend.wrap(self.profile, argv)

    def run(
        self,
        argv: List[str],
        *,
        capture_output: bool = True,
        timeout: Optional[float] = None,
    ) -> SandboxResult:
        """Check, confine, and run ``argv``.

        Raises ``Blocked`` if policy denies the launch, and
        :class:`IsolationUnavailable` if a ``require``d token can't be enforced.
        Either way no process is started.
        """
        if not argv:
            raise ValueError("argv must be non-empty")
        check_limits(self.profile)  # the profile may have been swapped since __init__

        checked = check_spawn(
            argv,
            self.profile,
            engine=self._engine,
            enforcement=self._enforcement,
            principal=self._principal,
        )

        # Probe the guarantees on the original profile before creating any
        # scratch: a ``require=`` refusal must leave no directory behind and
        # must not run anything. ``wrap()`` is pure, so this allocates nothing;
        # release its cleanup anyway if a future backend ever does.
        probe = self._backend.wrap(self.profile, checked)
        try:
            missing = [t for t in self.require if t not in probe.enforced]
        finally:
            if probe.cleanup is not None:
                probe.cleanup()
        if missing:
            raise IsolationUnavailable(self._backend.name, missing, list(probe.enforced))

        # One private, 0700 scratch directory per run. The child gets it as a
        # write grant and as TMPDIR/TMP/TEMP; the shared temp roots are never
        # granted on macOS. tempfile.mkdtemp already creates it 0700.
        scratch = tempfile.mkdtemp(prefix="interlock-brace-")
        # An escaped descendant can keep a pipe open past the drain deadline;
        # _spawn flags the TimeoutExpired when that happens. Removing the tree
        # then would yank the directory out from under a process still using it
        # as TMPDIR/cwd, so leave it in place instead.
        scratch_in_use = False
        try:
            effective = dataclasses.replace(
                self.profile,
                write_paths=tuple(self.profile.write_paths) + (scratch,),
                env={
                    **dict(self.profile.env),
                    "TMPDIR": scratch,
                    "TMP": scratch,
                    "TEMP": scratch,
                },
            )
            # The policy check saw the original profile and checked argv; the
            # scratch is an implementation detail of the run, not part of the
            # launch the caller's rules approved.
            plan = self._backend.wrap(effective, checked)
            try:
                returncode, stdout, stderr = self._spawn(
                    plan, capture_output=capture_output, timeout=timeout
                )
            except subprocess.TimeoutExpired as exc:
                scratch_in_use = getattr(exc, "scratch_in_use", False)
                raise
            finally:
                if plan.cleanup is not None:
                    plan.cleanup()
        finally:
            if not scratch_in_use:
                shutil.rmtree(scratch, ignore_errors=True)

        record_exit(self._backend.name, checked, returncode)
        return SandboxResult(
            backend=self._backend.name,
            argv=checked,
            returncode=returncode,
            stdout=stdout or "",
            stderr=stderr or "",
            enforced=plan.enforced,
        )

    def _spawn(
        self,
        plan: WrapPlan,
        *,
        capture_output: bool,
        timeout: Optional[float],
    ) -> Tuple[Optional[int], Optional[str], Optional[str]]:
        """Run a :class:`WrapPlan`, reaping the whole process group on failure.

        On POSIX the child is made a process-group leader so a failure can kill
        it and its descendants, not just the direct child. A backend whose
        wrapper already calls ``setsid()`` itself (bwrap's ``--new-session``)
        is left alone: the wrapper is the group leader and a second
        ``setsid()`` would fail with ``EPERM``. A descendant that calls
        ``setsid()`` itself leaves the group and is not killed; confinement and
        per-process rlimits still apply to it, and the bounded drain below
        keeps a pipe-holding escapee from hanging the caller.

        The group is killed on *any* exception, not only on timeout: a
        ``KeyboardInterrupt`` or a decode error in ``communicate`` must not
        leave a live sandboxed process behind. If a descendant escaped the
        group and still holds a pipe, the drain deadline can expire with the
        pipes open. The direct child is still reaped here, and the raised
        ``TimeoutExpired`` is marked ``scratch_in_use`` so ``run`` leaves the
        scratch tree in place rather than deleting a directory the escapee may
        still be using as ``TMPDIR``/cwd.

        On Windows ``start_new_session`` is unavailable and ``os.killpg`` does
        not exist, so only the direct child is killed.
        """
        popen_kwargs = dict(plan.popen_kwargs)
        if sys.platform != "win32" and not plan.creates_session:
            # Combine with any backend preexec_fn already in the plan: CPython
            # runs setsid() before the hook, so both take effect.
            popen_kwargs.setdefault("start_new_session", True)

        target = subprocess.PIPE if capture_output else None
        proc = subprocess.Popen(
            plan.exec_argv,
            stdout=target,
            stderr=target,
            text=True,
            **popen_kwargs,
        )
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            self._kill_process_group(proc)
            try:
                # Bounded drain so a descendant that escaped the group but
                # still holds a pipe cannot hang shutdown.
                proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                # The whole group got SIGKILL, so the direct child is dead;
                # reap it so no zombie remains. An escapee outside the group
                # still holds the pipe, so the scratch is not safe to remove.
                proc.wait()
                exc.scratch_in_use = True
            raise  # the original TimeoutExpired, as run(timeout=) always raised
        except BaseException:
            # subprocess.run() killed the child on any exception; kill the
            # whole group here so an interrupted run cannot leak a live
            # sandboxed process.
            self._kill_process_group(proc)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
            raise
        return proc.returncode, stdout, stderr

    @staticmethod
    def _kill_process_group(proc: subprocess.Popen) -> None:
        if sys.platform == "win32":
            # Windows has no process-group kill here; the direct child only.
            # A job object (or taskkill /T) would be needed for descendants.
            proc.kill()
            return
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            # Either the child exited between the timeout and the kill, or a
            # wrapper that calls setsid() itself (bwrap) has not reached that
            # call yet and still belongs to our group. Kill the direct child;
            # if it is already gone this raises ProcessLookupError too.
            try:
                proc.kill()
            except ProcessLookupError:
                pass
