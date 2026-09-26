"""Append-only receipt sinks: in-memory capture and newline-delimited JSON.

"Append-only" here means tamper-evident, not a comment about the file mode.
Every receipt written through a sink carries the previous receipt's mac, and
its own mac covers that linkage, so deleting, reordering, splicing, or
editing a line breaks the chain - and ``verify()`` walks the chain and names
the first bad index. A file opened in append mode alone proves nothing: the
OS does not stop anyone rewriting a line in place.

Concurrency: the read-prev / sign / append / remember step runs under a lock,
so concurrent threads share one unbroken chain. Writers in *other* processes
are not serialized - two processes writing one file each start their own
chain at GENESIS, and verify() reports the junction as a break. One sink
instance, one process, one chain.
"""
from __future__ import annotations

import os
import threading
from typing import List, Optional

from .receipt import (
    GENESIS,
    Receipt,
    Signer,
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
        self._lock = threading.Lock()
        self._last_mac = GENESIS

    def write(self, receipt: Receipt) -> None:
        with self._lock:
            receipt.prev = self._last_mac
            receipt.mac = compute_mac(receipt, self._signer, self._key)
            self._append(receipt)
            self._last_mac = receipt.mac

    def verify(self, key: Optional[bytes] = None) -> Optional[str]:
        """Walk the chain; None if intact, else a message naming the first
        bad index. Pass ``key`` to verify under a different key (every mac
        then mismatches - the wrong-key failure mode)."""
        with self._lock:
            return verify_chain(
                self._read_back(),
                self._signer,
                self._key if key is None else key,
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
    ) -> None:
        super().__init__(signer=signer, key=key)
        self.path = str(path)

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
