"""Receipt-chain verification for the control plane (C4).

The host owns the chain; the plane never mutates it. This package answers the
one question ingest needs - does this batch continue the chain we already
hold, and at what verification level? - and the one an auditor needs: is the
selected export intact?

The two public shapes are :func:`verify_batch` (one incoming batch) and
:func:`verify_checkpoint` (the Ed25519 attestation an HMAC host signs so its
linkage-only chain has some non-repudiation). Verification levels are the
strings FR-035 names: ``verified``, ``linkage_only`` and
``receipts_unverified`` - never a boolean.
"""
from __future__ import annotations

from .verify import (
    CHECKPOINT_MAX_AGE,
    VERIFICATION_LEVELS,
    BatchResult,
    canonical_checkpoint,
    receipt_public_key,
    sign_checkpoint,
    verify_batch,
    verify_checkpoint,
    verify_export,
)

__all__ = [
    "CHECKPOINT_MAX_AGE",
    "VERIFICATION_LEVELS",
    "BatchResult",
    "canonical_checkpoint",
    "receipt_public_key",
    "sign_checkpoint",
    "verify_batch",
    "verify_checkpoint",
    "verify_export",
]
