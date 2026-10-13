"""Append-only receipt sinks: in-memory capture and newline-delimited JSON.

"Append-only" here means tamper-evident, not a comment about the file mode.
Every receipt written through a sink carries the previous receipt's mac, and
its own mac covers that linkage, so deleting, reordering, splicing, or
editing a line breaks the chain - and ``verify()`` walks the chain and names
the first bad index. A file opened in append mode alone proves nothing: the
OS does not stop anyone rewriting a line in place.

Concurrency: the read-prev / sign / append / remember step runs under a lock,
so concurrent threads share one unbroken chain. Writers in *other* processes
are not serialized - two processes appending to one file at the same time
fork the chain, and verify() reports the junction as a break. One file, one
writer at a time.

Restarts: a ``FileSink`` opened on an existing log continues its chain from
the last receipt in the file, so one log can span process restarts. A file
whose last line is not a readable receipt is refused rather than silently
restarted at GENESIS.

Truncation: deleting receipts from the *end* leaves a valid, shorter chain.
``head`` is the latest mac; record it somewhere the log's writer can't reach
and pass it back as ``verify(head=...)`` to detect a cut tail.
"""
from __future__ import annotations

import os
import threading
from typing import Any, List, Optional

from .receipt import (
    GENESIS,
    Receipt,
    Signer,
    Verifier,
    compute_mac,
    hmac_sha256,
    process_secret,
    verify_chain,
)


class ChainedSink:
    """Sink template: chain and sign every receipt, then append it.

    Subclasses implement ``_append`` (where the receipt goes) and ``_read_back``
    (what ``verify`` walks). Anything with a ``write(receipt)`` method can be
    installed as a sink; subclassing this one is what makes the writes
    tamper-evident.
    """

    def __init__(
        self,
        *,
        signer: Signer = hmac_sha256,
        key: Optional[bytes] = None,
    ) -> None:
        self._signer = signer
        self._key = key if key is not None else process_secret()
        # True when no key was given: the per-process secret dies with the
        # process, so nobody can verify these receipts after a restart.
        self.ephemeral_key = key is None
        self._lock = threading.Lock()
        self._last_mac = GENESIS

    def write(self, receipt: Receipt) -> None:
        with self._lock:
            receipt.prev = self._last_mac
            receipt.mac = compute_mac(receipt, self._signer, self._key)
            self._append(receipt)
            self._last_mac = receipt.mac

    @property
    def head(self) -> str:
        """The mac of the latest receipt (GENESIS before the first). Record it
        outside the log and pass it to ``verify(head=...)`` to catch a cut tail."""
        with self._lock:
            return self._last_mac

    def verify(
        self,
        key: Optional[bytes] = None,
        *,
        head: Optional[str] = None,
        verifier: Optional[Verifier] = None,
    ) -> Optional[str]:
        """Walk the chain; None if intact, else a message naming the first
        bad index. Pass ``key`` to verify under a different key (every mac
        then mismatches - the wrong-key failure mode), ``head`` to also check
        the chain ends where you recorded, or ``verifier`` to check signatures
        without the signing key (a public-key scheme)."""
        with self._lock:
            return verify_chain(
                self._read_back(),
                self._signer,
                self._key if key is None else key,
                verifier=verifier,
                head=head,
            )

    def _append(self, receipt: Receipt) -> None:
        raise NotImplementedError

    def _read_back(self) -> List[Receipt]:
        raise NotImplementedError


class InMemorySink(ChainedSink):
    """Capture sink: the receipt list is the audit trail. What tests use."""

    def __init__(
        self,
        *,
        signer: Signer = hmac_sha256,
        key: Optional[bytes] = None,
    ) -> None:
        super().__init__(signer=signer, key=key)
        self.receipts: List[Receipt] = []

    def _append(self, receipt: Receipt) -> None:
        self.receipts.append(receipt)

    def _read_back(self) -> List[Receipt]:
        return list(self.receipts)


class FileSink(ChainedSink):
    """Newline-delimited-JSON file sink, opened in append mode per write.

    One canonical JSON line per receipt. The in-file chain is what makes the
    file tamper-evident; the append-mode open is what keeps concurrent writers
    from overwriting each other's bytes within one process.
    """

    def __init__(
        self,
        path: str,
        *,
        signer: Signer = hmac_sha256,
        key: Optional[bytes] = None,
        shared: bool = False,
    ) -> None:
        super().__init__(signer=signer, key=key)
        self.path = str(path)
        # shared=True: several processes may append (each coding-agent hook
        # call is its own process). Every write then takes an exclusive file
        # lock and re-reads the chain head from the file, so the writers
        # extend one chain instead of forking it. Needs fcntl (POSIX).
        self.shared = shared
        last = _last_receipt(self.path)
        if last is not None:
            self._last_mac = last.mac

    def write(self, receipt: Receipt) -> None:
        if not self.shared:
            super().write(receipt)
            return
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as fh:
                _lock_file(fh)
                try:
                    last = _last_receipt(self.path)
                    self._last_mac = last.mac if last is not None else GENESIS
                    receipt.prev = self._last_mac
                    receipt.mac = compute_mac(receipt, self._signer, self._key)
                    fh.write(receipt.to_json() + "\n")
                    fh.flush()
                    self._last_mac = receipt.mac
                finally:
                    _unlock_file(fh)

    def _append(self, receipt: Receipt) -> None:
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(receipt.to_json() + "\n")

    def _read_back(self) -> List[Receipt]:
        if not os.path.exists(self.path):
            return []
        receipts: List[Receipt] = []
        with open(self.path, "r", encoding="utf-8") as fh:
            for line in fh:
                stripped = line.strip()
                if stripped:
                    receipts.append(Receipt.from_json(stripped))
        return receipts


def _last_receipt(path: str) -> Optional[Receipt]:
    """The last receipt in an existing log, None for a missing or empty file.

    Reads backwards from the end, so reopening a large log stays cheap. A last
    line that is not a receipt (a crash mid-write, or a foreign file) raises
    ValueError: continuing would chain new receipts onto damage nobody saw.
    """
    if not os.path.exists(path):
        return None
    with open(path, "rb") as fh:
        fh.seek(0, os.SEEK_END)
        end = fh.tell()
        chunk = b""
        position = end
        while position > 0:
            step = min(65536, position)
            position -= step
            fh.seek(position)
            chunk = fh.read(step) + chunk
            stripped = chunk.rstrip(b"\r\n \t")
            if b"\n" in stripped or position == 0:
                break
    line = chunk.rstrip(b"\r\n \t").rsplit(b"\n", 1)[-1].strip()
    if not line:
        return None
    try:
        receipt = Receipt.from_json(line.decode("utf-8"))
    except Exception as exc:
        raise ValueError(
            "{}: the last line is not a readable receipt ({}); move the file "
            "aside or repair it before appending".format(path, exc)
        ) from None
    if not _is_hex_tag(receipt.mac):
        raise ValueError(
            "{}: the last receipt has no usable mac; move the file aside or "
            "repair it before appending".format(path)
        )
    return receipt


def _is_hex_tag(value: object) -> bool:
    """A usable mac: non-empty, even-length hex. The length depends on the
    signer (64 hex chars for HMAC-SHA256, 128 for an Ed25519 signature)."""
    if not isinstance(value, str) or not value or len(value) % 2:
        return False
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True


def verify_file(
    path: str,
    *,
    key: Optional[bytes] = None,
    signer: Signer = hmac_sha256,
    verifier: Optional[Verifier] = None,
    head: Optional[str] = None,
) -> Optional[str]:
    """Verify a receipt log on disk without opening a sink for writing.

    The auditor's entry point: pass the shared ``key`` for the default HMAC
    signer, or a ``verifier`` to check a public-key chain with no signing key
    at all. ``head`` additionally checks the chain ends at the mac you
    recorded. Returns None if intact, else a message naming the first problem.
    """
    if key is None and verifier is None:
        raise ValueError("verify_file needs the key the log was signed with, or a verifier")
    receipts: List[Receipt] = []
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    receipts.append(Receipt.from_json(stripped))
                except Exception:
                    return "receipt {}: not a readable receipt".format(len(receipts))
    return verify_chain(receipts, signer, key or b"", verifier=verifier, head=head)


def _lock_file(fh: Any) -> None:
    try:
        import fcntl
    except ImportError:  # not POSIX: no cross-process lock available
        return
    fcntl.flock(fh.fileno(), fcntl.LOCK_EX)


def _unlock_file(fh: Any) -> None:
    try:
        import fcntl
    except ImportError:
        return
    fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
