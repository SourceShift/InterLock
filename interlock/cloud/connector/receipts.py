"""Tail the host's receipt log from a durable byte offset (FR-032).

The host's sink writes canonical, newline-terminated receipt JSON. This module
turns that file into batches the connector can spool and upload:

* only **complete** lines are batched - a trailing partial write stays unread,
  so a crash mid-``write`` never ships half a receipt;
* a malformed line stops the batch *before* it and is remembered with its line
  number; it is never skipped silently, and the offset does not move past it;
* the offset is persisted atomically (temp file + fsync + rename) and advances
  only when the caller calls :meth:`ReceiptTailer.commit` - which the
  connector does only after the plane acknowledged the batch (FR-032).

``rewind_to(line_no)`` is operator recovery only and is exposed through
``interlock cloud status --reset-offset LINE --yes``.
"""
from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from ...receipt import Receipt

#: Per-batch bounds from the kickoff.
DEFAULT_MAX_BATCH = 2_000
DEFAULT_MAX_BYTES = 4 * 1024 * 1024

#: A single line larger than this is treated as unreadable rather than letting
#: one bad write stall the tailer forever.
HARD_LINE_BYTES = 16 * 1024 * 1024

_TMP_SUFFIX = ".tmp"


class TailerError(ValueError):
    """A receipt log or offset file could not be read safely."""


@dataclass
class ReceiptBatch:
    """One framed batch of complete receipt lines.

    ``start_offset``/``end_offset`` are byte positions in the log;
    ``start_line``/``end_line`` are 1-based physical line numbers at those
    positions. ``end_line`` is the next line to read, so a committed batch
    leaves the tailer exactly at ``end_offset``.
    """

    receipts: List[Receipt]
    start_offset: int
    end_offset: int
    start_line: int
    end_line: int

    @property
    def count(self) -> int:
        return len(self.receipts)

    @property
    def bytes(self) -> int:
        return max(0, self.end_offset - self.start_offset)

    def __bool__(self) -> bool:
        return bool(self.receipts)

    def as_payload(self, host_id: Optional[str]) -> Dict[str, Any]:
        """The exact wire body: receipt fields plus the host id."""
        return {
            "receipts": [receipt.fields() for receipt in self.receipts],
            "host_id": host_id,
        }

    def body(self, host_id: Optional[str]) -> bytes:
        """The JSON payload, before the spool gzips it."""
        return json.dumps(
            self.as_payload(host_id), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")


class ReceiptTailer:
    """A complete-line reader over the host receipt log."""

    def __init__(
        self,
        path: Union[str, Path],
        offset_path: Union[str, Path],
        *,
        max_batch: int = DEFAULT_MAX_BATCH,
        max_bytes: int = DEFAULT_MAX_BYTES,
        host_id: Optional[str] = None,
    ) -> None:
        self.path = Path(path)
        self.offset_path = Path(offset_path)
        if int(max_batch) <= 0:
            raise TailerError("max_batch must be positive")
        if int(max_bytes) <= 0:
            raise TailerError("max_bytes must be positive")
        self.max_batch = int(max_batch)
        self.max_bytes = int(max_bytes)
        self.host_id = host_id
        self._offset = 0
        self._line = 1
        #: The last framing/parse problem, with a 1-based line number.
        self.last_error: Optional[str] = None
        self.last_error_line: Optional[int] = None
        self._load_offset()

    # -- offset persistence --------------------------------------------
    def _load_offset(self) -> None:
        if not self.offset_path.is_file():
            return
        try:
            raw = self.offset_path.read_text(encoding="utf-8").strip()
        except (OSError, UnicodeDecodeError) as exc:
            raise TailerError("receipt offset is unreadable: {}".format(exc)) from None
        if not raw:
            return
        offset: Optional[int] = None
        line: Optional[int] = None
        if raw.startswith("{"):
            try:
                doc = json.loads(raw)
                offset = int(doc.get("offset", 0))
                line = int(doc.get("line", 1))
            except (TypeError, ValueError):
                raise TailerError("receipt offset is malformed") from None
        else:
            try:
                offset = int(raw)
            except ValueError:
                raise TailerError("receipt offset is malformed") from None
        if offset < 0:
            raise TailerError("receipt offset must not be negative")
        self._offset = offset
        if line is not None and line >= 1:
            self._line = line
        else:
            self._line = self._line_at(offset)

    def _atomic_offset(self, offset: int, line: int) -> None:
        self.offset_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        payload = json.dumps(
            {"offset": int(offset), "line": int(line)}, sort_keys=True
        ).encode("utf-8")
        fd, tmp_name = tempfile.mkstemp(
            dir=str(self.offset_path.parent),
            prefix="." + self.offset_path.name + ".",
            suffix=_TMP_SUFFIX,
        )
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, str(self.offset_path))
            try:
                dir_fd = os.open(str(self.offset_path.parent), os.O_RDONLY)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
            except OSError:
                pass
        except BaseException:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise

    def _line_at(self, offset: int) -> int:
        """Count newlines before ``offset`` (1-based line number)."""
        if offset <= 0 or not self.path.is_file():
            return 1
        count = 1
        remaining = int(offset)
        with self.path.open("rb") as handle:
            while remaining > 0:
                chunk = handle.read(min(1 << 20, remaining))
                if not chunk:
                    break
                count += chunk.count(b"\n")
                remaining -= len(chunk)
        return count

    # -- reading --------------------------------------------------------
    @property
    def offset(self) -> int:
        return self._offset

    @property
    def line(self) -> int:
        return self._line

    def next_batch(self) -> ReceiptBatch:
        """Frame the next batch of complete lines; never advances the offset."""
        empty = ReceiptBatch([], self._offset, self._offset, self._line, self._line)
        self.last_error = None
        self.last_error_line = None
        if not self.path.is_file():
            return empty
        try:
            size = self.path.stat().st_size
        except OSError:
            return empty
        offset = self._offset
        if offset > size:
            # The log was truncated or rotated under us. Start over; the plane
            # will report a fork rather than silently accepting a splice.
            offset = 0
            self._offset = 0
            self._line = 1

        try:
            with self.path.open("rb") as handle:
                handle.seek(offset)
                chunk = handle.read(self.max_bytes)
                if not chunk:
                    return empty
                if b"\n" not in chunk:
                    # A line longer than the cap: read one bounded extension so
                    # a realistic large receipt still makes progress, but never
                    # grow without a bound.
                    extra = handle.read(HARD_LINE_BYTES - len(chunk))
                    chunk += extra
                    if b"\n" not in chunk:
                        self.last_error = "line {}: exceeds {} bytes".format(
                            self._line, HARD_LINE_BYTES)
                        self.last_error_line = self._line
                        return empty
        except OSError as exc:
            self.last_error = "read failed: {}".format(type(exc).__name__)
            return empty

        complete_end = chunk.rfind(b"\n") + 1
        if complete_end <= 0:
            return empty
        data = chunk[:complete_end]

        receipts: List[Receipt] = []
        line_start = offset
        line_no = self._line
        stopped = False
        for segment in data.split(b"\n")[:-1]:
            try:
                receipt = Receipt.from_json(segment.decode("utf-8"))
            except Exception as exc:  # malformed is never skipped silently
                self.last_error = "line {}: {}".format(line_no, type(exc).__name__)
                self.last_error_line = line_no
                stopped = True
                break
            receipts.append(receipt)
            line_start += len(segment) + 1
            line_no += 1
            if len(receipts) >= self.max_batch:
                stopped = True
                break

        if not stopped:
            # Every complete line in the read window was parsed.
            line_start = offset + complete_end
            line_no = self._line + len(receipts)
        return ReceiptBatch(
            receipts=receipts,
            start_offset=offset,
            end_offset=line_start,
            start_line=self._line,
            end_line=line_no,
        )

    # -- acknowledgement and recovery ----------------------------------
    def commit(self, batch: ReceiptBatch) -> None:
        """Persist the batch's end offset; call this only after a 2xx (FR-032)."""
        if not isinstance(batch, ReceiptBatch):
            raise TailerError("commit() needs a ReceiptBatch")
        self._atomic_offset(batch.end_offset, batch.end_line)
        self._offset = int(batch.end_offset)
        self._line = int(batch.end_line)

    def rewind_to(self, line_no: int) -> int:
        """Move the offset to the start of 1-based ``line_no`` (operator only).

        Returns the new byte offset. A line number past the end of the log
        moves to EOF; a number below 1 is refused rather than silently
        rewritten, because this is a recovery tool.
        """
        if isinstance(line_no, bool) or not isinstance(line_no, int) or line_no < 1:
            raise TailerError("line numbers start at 1")
        if not self.path.is_file():
            raise TailerError("receipt log does not exist")
        target = 1
        offset = 0
        with self.path.open("rb") as handle:
            while target < line_no:
                line_bytes = handle.readline()
                if not line_bytes:
                    break
                offset += len(line_bytes)
                target += 1
        self._atomic_offset(offset, target)
        self._offset = offset
        self._line = target
        self.last_error = None
        self.last_error_line = None
        return offset

    # -- status ---------------------------------------------------------
    def pending_bytes(self) -> int:
        try:
            size = self.path.stat().st_size
        except OSError:
            return 0
        return max(0, size - self._offset)

    def status(self) -> Dict[str, Any]:
        """The receipt fields ``interlock cloud status`` reports."""
        return {
            "receipts_offset": self._offset,
            "receipts_line": self._line,
            "receipts_pending_bytes": self.pending_bytes(),
            "last_receipt_error": self.last_error,
        }


__all__ = [
    "DEFAULT_MAX_BATCH",
    "DEFAULT_MAX_BYTES",
    "HARD_LINE_BYTES",
    "ReceiptBatch",
    "ReceiptTailer",
    "TailerError",
]
