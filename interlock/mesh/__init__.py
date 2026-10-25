"""interlock mesh: a shared, open policy network built on interlock.

Every interlock deployment runs its own policy. The mesh lets a deployment
*subscribe* to policy packs the community maintains (the commons), verified
end to end and applied in monitor mode first, and *report* what its guard
stopped in a form that never carries a prompt or an argument. The design and
the research behind it are in ``internal-docs/research/mesh-shared-policy-network.md``.

The package is organised by the phase of that design it implements:

Phase 0, the commons (no telemetry)
    :mod:`.ed25519` (signatures, pure Python), :mod:`.metadata` (TUF-shaped
    root / targets / snapshot / timestamp with thresholds, expiry and rollback
    checks), :mod:`.repository` (the maintainer side: build and sign a static
    site), :mod:`.subscriber` (the node side: fetch, verify, cache, and resolve
    ``"extends": "mesh:<pack>@<ring>"`` with status ceilings and a monitor-first
    window), :mod:`.catalog` (the installed detector set as one hash).

Phase 1, counting
    :mod:`.report` (project receipts into shareable reports), :mod:`.aggregate`
    (additive secret sharing so no single collector sees a deployment's
    counts), :mod:`.consensus` (distinct-organisation thresholds, reporter
    reputation, negative sightings, expiry), :mod:`.server` (the collector
    roles as plain HTTP).

Phase 2, similarity and the forge
    :mod:`.fingerprint` (redact, embed, quantise, randomised response),
    :mod:`.harness` (false-positive and cost gates over a benign corpus),
    :mod:`.forge` (cluster reports, draft candidate rules, run the gates, write
    a reviewable proposal).

Phase 3, decentralise
    :mod:`.log` (an append-only Merkle log with inclusion and consistency
    proofs, signed checkpoints, monitors and gossip), :mod:`.credential`
    (issuer-signed pseudonyms with per-epoch caps and revocation), and the
    ``serve`` command that seeds a node's verified cache to its peers.

Nothing here imports outside the standard library, like the rest of interlock.
"""
from __future__ import annotations

__all__ = ["MESH_DIR_ENV", "NO_REPORT_ENV", "default_mesh_dir", "reporting_killed"]

import os

#: Environment variable that relocates the mesh state directory (tests, CI).
MESH_DIR_ENV = "INTERLOCK_MESH_DIR"

#: Environment variable that refuses every upload at the send site
#: (:func:`interlock.mesh.report.submit`), whatever the node has enabled.
NO_REPORT_ENV = "INTERLOCK_MESH_NO_REPORT"


def default_mesh_dir() -> str:
    """Where a node keeps its mesh configuration, verified cache and state.

    ``$INTERLOCK_MESH_DIR`` when set, else ``~/.interlock/mesh``. The directory
    sits under ``~/.interlock`` on purpose: the coding-agent pack's locked
    self-protection rules already keep an agent's file and shell tools away
    from everything under it, so an agent cannot edit its own subscription.
    """
    override = os.environ.get(MESH_DIR_ENV)
    if override:
        return os.path.abspath(os.path.expanduser(override))
    return os.path.join(os.path.expanduser("~"), ".interlock", "mesh")


def reporting_killed() -> bool:
    """True when ``$INTERLOCK_MESH_NO_REPORT`` is set to anything but empty or ``0``.

    Read at call time, so setting it in a running process takes effect at the
    next upload.
    """
    return os.environ.get(NO_REPORT_ENV, "").strip() not in ("", "0")
