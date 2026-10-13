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

``OtlpSink`` keeps the chaining above and adds an export side-effect: it stores
each receipt locally exactly as ``InMemorySink`` does, then hands a mapped
OTLP/HTTP JSON log record to a background worker that POSTs it to a collector.
The export is best-effort and off the guarded call's path - it never blocks the
call, never raises into it, and never carries an argument value.
"""
from __future__ import annotations

import collections
import json
import os
import secrets
import threading
from typing import Any, Dict, List, Optional, Tuple

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


# Verdict name (``Receipt.verdict`` is the string name, not the enum) to the
# OTLP severity it exports as. BLOCK and ESCALATE are both ERROR: an escalated
# call that no approver clears is a block, and the collector groups by severity.
_SEVERITY_BY_VERDICT: Dict[str, Tuple[int, str]] = {
    "ALLOW": (9, "INFO"),
    "MODIFY": (13, "WARN"),
    "BLOCK": (17, "ERROR"),
    "ESCALATE": (17, "ERROR"),
}
# An unrecognized verdict still gets a defined severity - WARN, never 0
# (unspecified) and never a raise - so no record reaches the collector without
# one and an unfamiliar verdict is not hidden among the ALLOWs.
_SEVERITY_DEFAULT: Tuple[int, str] = (13, "WARN")

# The export-only stand-in for a receipt that names no policy: OTLP wants the
# attribute present, and "unattributed" reads as "a default decision, no rule".
_UNATTRIBUTED = "unattributed"


def _severity(verdict: str) -> Tuple[int, str]:
    """The (severityNumber, severityText) OTLP exports a verdict as."""
    return _SEVERITY_BY_VERDICT.get(verdict, _SEVERITY_DEFAULT)


def _span_id(receipt: Receipt) -> str:
    """The id an exported record correlates to its local receipt by.

    The receipt's own ``span_id`` when the call ran inside a ``span()``. OTLP
    needs the attribute present even for a bare call, so with no open span it
    falls back to the receipt's ``call_id`` (shared by the call's own receipts,
    so it still ties the record to the local chain) and then to a fresh token.
    Read from the signed receipt only, and the receipt itself is not touched.
    """
    return receipt.span_id or receipt.call_id or secrets.token_hex(8)


def _string_attribute(key: str, value: str) -> Dict[str, Any]:
    """One OTLP KeyValue, always a string value (the receipt's fields are text
    or absent - never a structure - so no other value kind is ever needed)."""
    return {"key": key, "value": {"stringValue": str(value)}}


class OtlpSink(ChainedSink):
    """Chained receipt sink that also exports each receipt over OTLP/HTTP.

    Local behaviour is exactly ``InMemorySink``: every receipt is chained and
    signed into ``self.receipts``, so ``verify()`` and the tamper-evidence are
    unchanged. On top of that, each receipt is mapped to an OTLP/HTTP JSON log
    record and handed to a background worker that POSTs it to ``endpoint``.

    Three properties hold by construction, because a receipt is written on the
    guarded call's critical path (``receipt._write`` turns *any* exception from
    ``sink.write`` into a fail-closed ``Blocked``):

    - **Never blocks the call.** ``write`` only appends to an in-memory buffer
      and wakes a daemon worker; the POST happens off-thread, with an explicit
      timeout, and the guarded call never waits on the collector.
    - **Never raises into the call.** Every failure in the export path -
      mapping, buffering, serializing, the POST - is swallowed and counted
      (see :meth:`stats`), never raised.
    - **Never carries argument values.** The record is built from an explicit
      allow-list of receipt fields (``action``, ``principal``, ``policy_id``,
      ``reason``, ``span_id``); the arguments exist only as the receipt's
      ``args_digest``, which is not exported.

    A collector that is down does not lose records: a record that fails to POST
    stays at the front of the buffer and is retried until accepted, so the
    buffer drains in order once the collector returns. ``max_buffer`` bounds
    the queue; a record enqueued while it is full is dropped and counted, but a
    record already retained for retry is never dropped.

    ``endpoint`` is the full logs URL (e.g. ``http://collector:4318/v1/logs``)
    and is POSTed to as given - no path is appended. ``headers`` adds HTTP
    headers (an auth token, say). ``service_name`` becomes the ``service.name``
    resource attribute. Call :meth:`close` to stop the worker; the thread is a
    daemon, so a process that never closes a sink still exits.
    """

    def __init__(
        self,
        endpoint: str,
        headers: Optional[Dict[str, str]] = None,
        service_name: str = "interlock",
        *,
        signer: Signer = hmac_sha256,
        key: Optional[bytes] = None,
        timeout: float = 5.0,
        retry_interval: float = 0.5,
        max_buffer: int = 4096,
    ) -> None:
        super().__init__(signer=signer, key=key)
        self.endpoint = str(endpoint)
        self._headers = dict(headers) if headers else {}
        self.service_name = service_name
        self._timeout = float(timeout)
        self._retry_interval = float(retry_interval)
        self._max_buffer = int(max_buffer)
        self.receipts: List[Receipt] = []
        self._buffer: "collections.deque[dict]" = collections.deque()
        self._cv = threading.Condition()
        self._closed = False
        self._shutdown = threading.Event()
        self._sent = 0
        self._failed = 0
        self._dropped = 0
        self._build_failures = 0
        self._worker = threading.Thread(
            target=self._run, name="interlock-otlp-export", daemon=True
        )
        self._worker.start()

    # -- local chained storage ------------------------------------------------

    def _append(self, receipt: Receipt) -> None:
        """Store the signed receipt locally and enqueue its OTLP record.

        Called by ``ChainedSink.write`` under the chain lock, after ``prev``
        and ``mac`` are set: the receipt read here is already signed, and it is
        only read, never mutated, so the local chain stays byte-identical to a
        plain ``InMemorySink``. A failure anywhere in the export path must not
        escape - ``receipt._write`` would turn it into a fail-closed ``Blocked``
        - so the whole export is wrapped and its errors are counted instead.
        """
        self.receipts.append(receipt)
        try:
            self._enqueue(self._envelope(receipt))
        except Exception:
            self._build_failures += 1

    def _read_back(self) -> List[Receipt]:
        return list(self.receipts)

    # -- mapping --------------------------------------------------------------

    def _envelope(self, receipt: Receipt) -> dict:
        """Map one signed receipt to an OTLP/HTTP JSON log-record envelope.

        Built entirely from the allow-listed receipt fields. The argument
        values the receipt digested are not among them, and no ``event`` data
        or ``Receipt.fields()`` is read, so no argument value - and none of the
        receipt's other metadata (``args_digest``, ``masked``, ...) - can reach
        an attribute, a resource attribute or the body.
        """
        number, text = _severity(receipt.verdict)
        attributes = [
            _string_attribute("action", receipt.action),
            _string_attribute("policy_id", receipt.policy_id or _UNATTRIBUTED),
            _string_attribute("span_id", _span_id(receipt)),
        ]
        # principal and reason are omitted while empty (as Receipt.fields()
        # drops them), so an unset field is an absent attribute, not an empty
        # one; the three above are always present.
        if receipt.principal:
            attributes.append(_string_attribute("principal", receipt.principal))
        if receipt.reason:
            attributes.append(_string_attribute("reason", receipt.reason))
        return {
            "resourceLogs": [
                {
                    "resource": {
                        "attributes": [
                            _string_attribute("service.name", self.service_name),
                        ]
                    },
                    "scopeLogs": [
                        {
                            "scope": {"name": "interlock.receipt"},
                            "logRecords": [
                                {
                                    "timeUnixNano": str(int(receipt.ts * 1_000_000_000)),
                                    "severityNumber": number,
                                    "severityText": text,
                                    "body": {
                                        "stringValue": "{} {}".format(
                                            receipt.verdict, receipt.action
                                        )
                                    },
                                    "attributes": attributes,
                                }
                            ],
                        }
                    ],
                }
            ]
        }

    # -- the export worker ----------------------------------------------------

    def _enqueue(self, record: dict) -> None:
        with self._cv:
            if self._closed or len(self._buffer) >= self._max_buffer:
                self._dropped += 1
                return
            self._buffer.append(record)
            self._cv.notify()

    def _peek(self) -> Optional[dict]:
        """The record at the front of the buffer, blocking until one exists;
        None once the sink is closed and the buffer is drained."""
        with self._cv:
            while not self._buffer and not self._closed:
                self._cv.wait()
            return self._buffer[0] if self._buffer else None

    def _remove(self, record: dict) -> None:
        with self._cv:
            if self._buffer and self._buffer[0] is record:
                self._buffer.popleft()

    def _run(self) -> None:
        while True:
            record = self._peek()
            if record is None:  # closed and drained
                return
            if self._post(record):
                self._remove(record)
                self._sent += 1
                continue
            # Retained: the record stays at the front of the buffer, so the
            # buffer replays in order once the collector returns. Back off
            # before the next attempt, and stop if the sink is closing.
            self._failed += 1
            if self._shutdown.wait(self._retry_interval):
                return

    def _post(self, record: dict) -> bool:
        """POST one record to the collector: True when it is accepted, False on
        any failure. Never raises - the guarded call must not see export
        trouble, so the whole attempt, transport included, is caught here."""
        try:
            # Imported lazily so a process that never exports a record does not
            # pay urllib's import cost when it imports interlock.
            import urllib.request

            body = json.dumps(record, separators=(",", ":")).encode("utf-8")
            headers = {"Content-Type": "application/json"}
            headers.update(self._headers)
            request = urllib.request.Request(
                self.endpoint, data=body, headers=headers, method="POST"
            )
            with urllib.request.urlopen(request, timeout=self._timeout) as response:
                response.read()
            return True
        except Exception:
            return False

    # -- lifecycle / observability -------------------------------------------

    def close(self, timeout: float = 2.0) -> None:
        """Stop the export worker. Idempotent. A POST already in flight is not
        interrupted; records still buffered when the worker exits are left
        undelivered and reported by :meth:`stats`."""
        with self._cv:
            self._closed = True
            self._cv.notify_all()
        self._shutdown.set()
        worker = getattr(self, "_worker", None)
        if worker is not None and worker is not threading.current_thread():
            worker.join(timeout)

    @property
    def pending(self) -> int:
        """Records buffered but not yet accepted by the collector."""
        with self._cv:
            return len(self._buffer)

    @property
    def sent(self) -> int:
        """Records the collector has accepted."""
        return self._sent

    @property
    def failed(self) -> int:
        """Export attempts that failed (each is retried, not lost)."""
        return self._failed

    def stats(self) -> Dict[str, int]:
        """Export counters: ``sent`` accepted, ``failed`` attempts that failed,
        ``pending`` still buffered, ``dropped`` never buffered because the
        buffer was full or the sink closed, and ``build_failures`` receipts that
        could not be mapped. None of these ever raises into the guarded call."""
        return {
            "sent": self._sent,
            "failed": self._failed,
            "pending": self.pending,
            "dropped": self._dropped,
            "build_failures": self._build_failures,
        }


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
