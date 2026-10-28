"""The outbound-only connector loop (FR-008 .. FR-014).

``run_once`` is one cycle: reconcile pending reviews from the local queue,
upload queued batches, long-poll grants, then heartbeat. A status is persisted
only after the plane acknowledged it - ``cursor`` after a 2xx grants response
and ``last_sync`` after a 2xx heartbeat - so a reconnect resumes exactly where
the last acknowledgement left it.

Retries live here, not in the transport: a 5xx or 429 is retried with capped
exponential backoff and full jitter (1 s .. 5 min), honouring ``Retry-After``;
every other 4xx is returned at once. ``410 revoked`` stops the connector and
sets ``revoked`` in status; the connector never falls back to an
unauthenticated mode.

The class prints nothing. The CLI owns user output, and every value it prints
goes through :func:`interlock.cloud.connector.config.redact` so the agent key
cannot escape through an error path.
"""
from __future__ import annotations

import email.utils
import gzip
import json
import math
import os
import random
import signal
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from ... import __version__ as CONNECTOR_VERSION
from ...sensor import DEFAULT_RING_BYTES, Ring
from ..identity import generate_host_seed, key_id, public_key_hex
from .config import CloudHome, redact
from .grants import (
    GrantProcessor,
    initial_state as grant_initial_state,
    load_state as load_grant_state,
    public_key_from_config,
)
from .receipts import ReceiptBatch, ReceiptTailer, TailerError
from .reviews import build_record
from .spool import KIND_PRIORITY, Spool
from .transport import Transport, TransportError

DEFAULT_POLL_AFTER = 300

#: A host whose last successful sync is older than this is "not connected".
CONNECTED_WINDOW = 300

#: Backoff bounds from FR-009.
MIN_BACKOFF = 1.0
MAX_BACKOFF = 300.0

#: How many times one request is tried inside a single cycle.
DEFAULT_MAX_ATTEMPTS = 4


def _retry_after(headers: Mapping[str, str]) -> Optional[float]:
    """Parse ``Retry-After`` (delta seconds or an HTTP date).

    A header the plane sent but that cannot be parsed is treated as absent:
    a hostile or broken value must never crash a cycle.
    """
    value = None
    for name, item in (headers or {}).items():
        if str(name).lower() == "retry-after":
            value = item
            break
    if value is None:
        return None
    try:
        seconds = float(str(value).strip())
    except (TypeError, ValueError):
        try:
            parsed = email.utils.parsedate_to_datetime(str(value))
        except (TypeError, ValueError, OverflowError):
            return None
        if parsed is None:
            return None
        try:
            seconds = parsed.timestamp() - time.time()
        except (OverflowError, OSError, ValueError):
            return None
    if not math.isfinite(seconds):
        return None
    return max(0.0, seconds)


def _review_id(review: Any) -> Optional[str]:
    if isinstance(review, Mapping):
        return review.get("id")
    return getattr(review, "id", None)


def _review_field(review: Any, name: str, default: Any = None) -> Any:
    if isinstance(review, Mapping):
        return review.get(name, default)
    return getattr(review, name, default)


class Connector:
    """Enroll a host, then poll the plane for work."""

    def __init__(self, home: Any, transport: Transport, queue: Any = None, *,
                 clock: Any = time.time, sleep: Any = time.sleep,
                 random_fn: Any = random.uniform,
                 timeout: float = 30,
                 max_attempts: int = DEFAULT_MAX_ATTEMPTS,
                 poll_policy: bool = False) -> None:
        self.home = home if isinstance(home, CloudHome) else CloudHome(home)
        self.transport = transport
        self.queue = queue
        self.clock = clock
        self.sleep = sleep
        self.random_fn = random_fn
        self.timeout = timeout
        self.max_attempts = max(1, int(max_attempts))
        #: C5 policy distribution is opt-in for the same connector loop. The
        #: existing review/receipt/grants cycle keeps its exact request order
        #: unless an operator (or a test) asks it to also pull policy.
        self.poll_policy = bool(poll_policy)
        self._policy: Any = None
        self._config: Optional[Dict[str, Any]] = None
        self._state: Optional[Dict[str, Any]] = None
        self._spool: Optional[Spool] = None
        self._ring: Optional[Ring] = None

    @property
    def policy_distributor(self) -> Any:
        """The C5 distributor sharing this connector's home, transport, clock."""
        if self._policy is None:
            from .policy import PolicyDistributor

            self._policy = PolicyDistributor(
                self.home, self.transport, self.clock,
                timeout=self.timeout)
        return self._policy

    # -- paths and persistence -----------------------------------------
    @property
    def config(self) -> Optional[Dict[str, Any]]:
        if self._config is None:
            try:
                self._config = self.home.document
            except (FileNotFoundError, ValueError):
                return None
        return self._config

    def _resolve(self, value: str) -> Path:
        path = Path(value).expanduser()
        return path if path.is_absolute() else self.home.root / path

    @property
    def spool(self) -> Spool:
        if self._spool is None:
            config = self.config or {}
            directory = self._resolve(str(config.get("spool_dir") or "spool"))
            self._spool = Spool(directory, clock=self.clock)
        return self._spool

    @property
    def ring(self) -> Ring:
        """The bounded sensor hand-off buffer feeding :attr:`spool`.

        The ring borrows the spool's durable sequence counter, so a sequence
        reserved here is the same one the framed batch carries and a restart
        cannot regress or reuse it.
        """
        if self._ring is None:
            self._ring = Ring(
                self._resolve("sensor-ring"),
                capacity_bytes=DEFAULT_RING_BYTES,
                clock=self.clock,
                sequence_source=self.spool.next_sequence,
                sequence_release=self.spool.release_sequence,
            )
        return self._ring

    @property
    def state_path(self) -> Path:
        config = self.config or {}
        directory = self._resolve(str(config.get("state_dir") or "state"))
        return directory / "connector.json"

    def receipt_tailer(self) -> Optional[ReceiptTailer]:
        """The tailer for the configured receipt log, or ``None``.

        The offset lives beside the connector state unless ``receipt_offset``
        names another path. ``enroll`` writes ``receipt_log`` as
        ``receipts.jsonl`` beside the connector home, the file the hook writes
        when its key exists; removing the field disables receipt upload -
        whatever the config names is what is tailed, and the connector never
        guesses a host log path.
        """
        config = self.config or {}
        log = config.get("receipt_log")
        if not log:
            return None
        offset = config.get("receipt_offset")
        if not offset:
            offset = str(self.state_path.parent / "receipt-offset.json")
        return ReceiptTailer(
            self._resolve(str(log)), self._resolve(str(offset)),
            host_id=str(config.get("host_id") or "") or None)

    def _load_state(self) -> Dict[str, Any]:
        if self._state is not None:
            return dict(self._state)
        state: Dict[str, Any] = {
            "cursor": 0,
            "last_sync": None,
            "revoked": False,
            "last_error": None,
            "poll_after": DEFAULT_POLL_AFTER,
            "last_ack_seq": 0,
            # C4 receipts: spool batches awaiting a 2xx, so an offset advances
            # only after the plane acknowledged the exact bytes it carried.
            "pending_receipt_batches": {},
            "receipts_offset": 0,
            "receipts_line": 1,
            "last_receipt_ack": None,
            "verification_level": None,
            "last_receipt_error": None,
        }
        state.update(grant_initial_state())
        try:
            doc = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            doc = None
        if isinstance(doc, dict):
            for key in state:
                if key in doc and key not in grant_initial_state():
                    state[key] = doc[key]
            state.update(load_grant_state(doc))
        self._state = state
        return dict(state)

    def _save_state(self, state: Mapping[str, Any]) -> None:
        self._state = dict(state)
        path = self.state_path
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        payload = json.dumps(self._state, sort_keys=True).encode("utf-8")
        fd, tmp_name = tempfile.mkstemp(dir=str(path.parent),
                                        prefix=".connector.", suffix=".tmp")
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, str(path))
        except BaseException:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise

    # -- headers --------------------------------------------------------
    def headers(self, *, auth: bool = True) -> Dict[str, str]:
        headers = {
            "accept": "application/json",
            "content-type": "application/json",
            "x-interlock-version": str(CONNECTOR_VERSION),
        }
        config = self.config
        if auth and config:
            headers["authorization"] = "Bearer " + str(config["agent_key"])
            headers["x-interlock-host"] = str(config["host_id"])
            # Non-secret RLS hint; the server still verifies the hash.
            headers["x-interlock-org"] = str(config["org_id"])
        return headers

    # -- requests and retry --------------------------------------------
    def _backoff(self, attempt: int) -> float:
        ceiling = min(MAX_BACKOFF, MIN_BACKOFF * (2 ** attempt))
        return float(self.random_fn(0.0, ceiling))

    def _request(self, method: str, path: str, body: Optional[bytes] = None, *,
                 auth: bool = True, attempts: Optional[int] = None):
        """Return ``(status, headers, body)``; retry 5xx/429 with jitter."""
        tries = self.max_attempts if attempts is None else max(1, int(attempts))
        last_response = None
        last_error: Optional[BaseException] = None
        for attempt in range(tries):
            try:
                status, headers, data = self.transport.request(
                    method, path, body, headers=self.headers(auth=auth),
                    timeout=self.timeout,
                )
            except TransportError as exc:
                last_error = exc
                status = None
            else:
                last_response = (status, headers, data)
                if not (status >= 500 or status == 429):
                    return status, headers, data
            if attempt == tries - 1:
                break
            retry_after = None
            if last_response is not None:
                retry_after = _retry_after(last_response[1])
            wait = retry_after if retry_after is not None \
                else self._backoff(attempt)
            self.sleep(wait)
        if last_response is not None:
            return last_response
        raise TransportError(str(last_error or "request failed"))

    @staticmethod
    def _json_body(payload: Any) -> bytes:
        return json.dumps(payload, separators=(",", ":")).encode("utf-8")

    @staticmethod
    def _error_code(data: bytes) -> str:
        try:
            payload = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return "request failed"
        error = payload.get("error") if isinstance(payload, dict) else None
        if isinstance(error, dict) and error.get("code"):
            return str(error["code"])
        return "request failed"

    # -- enrollment -----------------------------------------------------
    def enroll(self, url: str, token: str, host_name: Optional[str] = None, *,
               seed: Optional[bytes] = None) -> Dict[str, Any]:
        """Generate the host seed, enroll once and write ``cloud.json``."""
        CloudHome._validate_url(url)
        if not isinstance(token, str) or not token:
            return {"ok": False, "error": "an enrollment token is required"}
        seed = generate_host_seed() if seed is None else bytes(seed)
        self.home.save_seed(seed)
        public_hex = public_key_hex(seed)
        host_key_id = key_id(public_hex)
        if host_name is None:
            import socket

            host_name = socket.gethostname() or "unnamed-host"
        body = self._json_body({
            "token": token,
            "host_name": host_name,
            "host_public_key": public_hex,
            "host_key_id": host_key_id,
            "connector_version": str(CONNECTOR_VERSION),
        })
        # A single-use token is deliberately not retried: a retry after a
        # timeout could consume a second token or double-enroll.
        base_url = getattr(self.transport, "base_url", None)
        if not base_url:
            try:
                self.transport.base_url = url.rstrip("/")
            except Exception:
                pass
        try:
            status, _headers, data = self._request(
                "POST", "/v1/enroll", body, auth=False, attempts=1)
        except TransportError as exc:
            return {"ok": False, "error": redact(str(exc))}
        if status not in (200, 201):
            return {"ok": False, "status": status,
                    "error": self._error_code(data)}
        try:
            payload = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return {"ok": False, "status": status,
                    "error": "malformed enrollment response"}
        if not isinstance(payload, dict) or not payload.get("agent_key") \
                or not payload.get("host_id") or not payload.get("org_id"):
            return {"ok": False, "status": status,
                    "error": "incomplete enrollment response"}
        document = {
            "url": str(url).rstrip("/"),
            "org_id": str(payload["org_id"]),
            "host_id": str(payload["host_id"]),
            "agent_key_id": str(payload.get("agent_key_id") or ""),
            "agent_key": str(payload["agent_key"]),
            "host_key_id": host_key_id,
            "host_public_key": public_hex,
            "plane_public_keys": dict(payload.get("plane_public_keys") or {}),
            "spool_dir": "spool",
            "state_dir": "state",
            # FR-032: a cloud-enrolled host streams its receipt log by
            # default. Writing the field here - rather than defaulting it in
            # the connector - keeps ``receipt_tailer`` honest: whatever the
            # config names is what is tailed, and deleting the field is how an
            # operator opts out of receipt upload.
            "receipt_log": str(self.home.root / "receipts.jsonl"),
        }
        try:
            self.home.save(document)
        except (ValueError, OSError) as exc:
            return {"ok": False, "error": redact(str(exc))}
        self._config = document
        return {
            "ok": True,
            "host_id": document["host_id"],
            "agent_key_id": document["agent_key_id"],
            "org_id": document["org_id"],
        }

    # -- queue reconciliation ------------------------------------------
    def on_file(self, review: Any) -> bool:
        """Spool one masked record; never raises into the review queue.

        The body is built by :func:`build_record`, which masks the preview and
        asserts the exact wire allow-list. Without a local queue there is no
        binding to prove, so the record is not uploaded at all rather than
        sent without the hash the grant will later be checked against.
        """
        try:
            review_id = _review_id(review)
            if not review_id or self.queue is None:
                return False
            binding = self.queue.binding_of(review_id)
            config = self.config or {}
            record = build_record(
                review, binding=binding,
                agent_key=config.get("agent_key"),
                share_usernames=bool(config.get("share_usernames")),
            )
            self.ring.put(
                "security", self._json_body(record),
                host=str(config.get("host_id") or "unassigned"),
                sensor="reviews",
            )
            # Hand off to the disk spool on the same call, so the existing
            # queue contract (a batch is visible once on_file returns) is
            # unchanged. A failed drain leaves the bounded ring entry for the
            # connector loop; it never reaches the queue's writer.
            self.ring.drain_into(self.spool)
            return True
        except Exception:
            # A full disk or a bad review must not break the queue's write.
            return False

    def _pending_reviews(self) -> list:
        if self.queue is None:
            return []
        try:
            pending = self.queue.list(status="pending")
        except Exception:
            return []
        return list(pending or [])

    def queue_lag(self) -> int:
        if self.queue is None:
            return 0
        try:
            return len(self.queue.list(status="pending"))
        except Exception:
            return 0

    # -- one cycle ------------------------------------------------------
    @staticmethod
    def _upload_path(kind: str) -> str:
        # C2 moves review metadata and receipts only; policy bodies are C5.
        return "/v1/receipts" if kind == "observability" else "/v1/reviews"

    # -- receipt tailing (FR-032) ---------------------------------------
    def _spool_receipts(self, state: Dict[str, Any]) -> int:
        """Frame at most one batch of complete receipt lines into the spool.

        The offset does **not** move here: it moves in
        :meth:`_ack_receipt_batch` after the plane answers 2xx. While a
        spooled receipt batch is unacknowledged, no new batch is framed, so a
        retry re-sends the same bytes instead of splitting them.
        """
        config = self.config or {}
        try:
            tailer = self.receipt_tailer()
        except TailerError as exc:
            state["last_receipt_error"] = redact(str(exc))
            return 0
        if tailer is None:
            return 0
        if state.get("pending_receipt_batches"):
            return 0
        try:
            batch = tailer.next_batch()
        except (TailerError, OSError) as exc:
            state["last_receipt_error"] = redact(str(exc))
            return 0
        state["last_receipt_error"] = tailer.last_error
        state["receipts_offset"] = int(tailer.offset)
        state["receipts_line"] = int(tailer.line)
        if not batch:
            return 0
        entry = self.ring.put(
            "observability", batch.body(tailer.host_id),
            host=str(config.get("host_id") or "unassigned"),
            sensor="receipts",
        )
        drained = self.ring.drain_into(self.spool)
        spooled = None
        if entry is not None:
            spooled = next(
                (candidate for candidate in drained
                 if candidate.sensor == "receipts"
                 and candidate.seq == entry.sequence),
                None,
            )
        if spooled is None or not spooled.path.is_file():
            state["last_receipt_error"] = (
                "receipt batch dropped: sensor ring or spool is full")
            return 0
        pending = dict(state.get("pending_receipt_batches") or {})
        pending[spooled.name] = {
            "end_offset": int(batch.end_offset),
            "end_line": int(batch.end_line),
            "count": int(batch.count),
        }
        state["pending_receipt_batches"] = pending
        return batch.count

    def _ack_receipt_batch(self, state: Dict[str, Any], batch: Any,
                           data: bytes) -> None:
        """Advance the durable offset after a 2xx and record the plane's ack."""
        pending = dict(state.get("pending_receipt_batches") or {})
        entry = pending.pop(batch.name, None)
        if entry is not None:
            state["pending_receipt_batches"] = pending
            end_offset = int(entry.get("end_offset") or 0)
            end_line = int(entry.get("end_line") or 1)
            try:
                tailer = self.receipt_tailer()
                if tailer is not None:
                    tailer.commit(ReceiptBatch(
                        [], end_offset, end_offset, end_line, end_line))
            except (TailerError, OSError) as exc:
                state["last_receipt_error"] = redact(str(exc))
            state["receipts_offset"] = end_offset
            state["receipts_line"] = end_line
        try:
            payload = json.loads(data.decode("utf-8")) if data else {}
        except (UnicodeDecodeError, ValueError):
            payload = {}
        if isinstance(payload, dict):
            accepted = payload.get("accepted")
            if isinstance(accepted, int) and not isinstance(accepted, bool):
                state["last_receipt_ack"] = accepted
            level = payload.get("verification")
            if isinstance(level, str):
                state["verification_level"] = level
            status = payload.get("status")
            if status == "fork":
                state["last_receipt_error"] = "chain_fork"

    def run_once(self) -> Dict[str, Any]:
        """One reconcile/upload/poll/heartbeat cycle; never raises for a 4xx."""
        config = self.config
        if config is None:
            return {"ok": False, "reviews": 0, "revoked": False,
                    "error": "not enrolled"}
        state = self._load_state()
        if state.get("revoked"):
            return {"ok": False, "reviews": 0, "revoked": True,
                    "error": "revoked"}

        errors = []
        reviews = 0
        uploaded = 0
        receipts_spooled = 0
        revoked = False
        policy = None
        poll_after = int(state.get("poll_after") or DEFAULT_POLL_AFTER)

        # 0. Pull policy first when enabled: a new manifest must be active
        #    before this cycle uploads receipts produced under it.
        if self.poll_policy:
            try:
                policy = self.policy_distributor.poll_once()
                if not policy.get("ok") and policy.get("last_error"):
                    errors.append(str(policy["last_error"]))
            except Exception as exc:  # a distribution bug must not stall upload
                errors.append(redact(str(exc)))

        # 1. Reconcile reviews filed while the connector was down.
        for review in self._pending_reviews():
            if self.on_file(review):
                reviews += 1

        # 1a. Retry ring entries a previous drain could not spool. Entries
        #     stay bounded and in sequence order while the disk recovers.
        try:
            self.ring.drain_into(self.spool)
        except Exception as exc:
            errors.append(redact(str(exc)))

        # 1b. Tail the host's receipt log into the spool from the durable
        #     offset. The offset moves only after step 2 acknowledges it.
        receipts_spooled = self._spool_receipts(state)

        # 2. Upload queued batches, removing each only after a 2xx. Reviews
        #    (security) go first so a decision is never starved by a receipt
        #    backlog: at most three review batches and one receipt batch per
        #    cycle.
        try:
            queued = self.spool.peek(limit=200)
        except Exception as exc:
            queued = []
            errors.append(redact(str(exc)))
        security = [batch for batch in queued if batch.kind == "security"][:3]
        observability = [batch for batch in queued
                         if batch.kind == "observability"][:1]
        for batch in security + observability:
            try:
                body = gzip.decompress(batch.path.read_bytes())
            except (OSError, EOFError, ValueError) as exc:
                errors.append(redact(str(exc)))
                continue
            try:
                status, _headers, data = self._request(
                    "POST", self._upload_path(batch.kind), body)
            except TransportError as exc:
                errors.append(redact(str(exc)))
                continue
            if status == 410:
                revoked = True
                break
            if 200 <= status < 300:
                if batch.sensor == "receipts":
                    self._ack_receipt_batch(state, batch, data)
                self.spool.remove(batch)
                uploaded += 1
            else:
                errors.append(self._error_code(data))
        if revoked:
            return self._revoked(state, reviews, uploaded, errors)

        # 3. Poll grants after the persisted cursor. Empty is normal.
        cursor = int(state.get("cursor") or 0)
        path = "/v1/grants?cursor={}&wait=25".format(cursor)
        payload: Dict[str, Any] = {}
        try:
            status, _headers, data = self._request("GET", path)
        except TransportError as exc:
            errors.append(redact(str(exc)))
        else:
            if status == 410:
                return self._revoked(state, reviews, uploaded, errors)
            if 200 <= status < 300:
                try:
                    decoded = json.loads(data.decode("utf-8")) if data else {}
                except (UnicodeDecodeError, ValueError):
                    decoded = {}
                payload = decoded if isinstance(decoded, dict) else {}
            else:
                errors.append(self._error_code(data))

        ack_ok = True
        grants = payload.get("grants")
        if isinstance(grants, list) and grants:
            if self.queue is None:
                # No local queue: applying is impossible, so do not consume
                # the cursor and lose the grants.
                ack_ok = False
            else:
                processor = GrantProcessor(
                    self.queue,
                    public_key=public_key_from_config(config),
                    org_id=str(config["org_id"]),
                    host_id=str(config["host_id"]),
                    clock=self.clock,
                )
                outcome = processor.process(grants, state)
                if outcome["acked"] or outcome["refusals"]:
                    ack_body: Dict[str, Any] = {"grant_ids": outcome["acked"]}
                    if outcome["refusals"]:
                        ack_body["refusals"] = outcome["refusals"]
                    try:
                        ack_status, _ack_headers, ack_data = self._request(
                            "POST", "/v1/grants/ack", self._json_body(ack_body))
                    except TransportError as exc:
                        ack_ok = False
                        errors.append(redact(str(exc)))
                    else:
                        if ack_status == 410:
                            return self._revoked(state, reviews, uploaded, errors)
                        if 200 <= ack_status < 300:
                            try:
                                ack_payload = json.loads(
                                    ack_data.decode("utf-8")) if ack_data else {}
                            except (UnicodeDecodeError, ValueError):
                                ack_payload = {}
                            if isinstance(ack_payload, dict):
                                last_ack = ack_payload.get("last_ack_seq")
                                if isinstance(last_ack, int) \
                                        and not isinstance(last_ack, bool):
                                    state["last_ack_seq"] = last_ack
                        else:
                            ack_ok = False
                            errors.append(self._error_code(ack_data))

        if payload and ack_ok:
            # Persist the cursor only after the batch was applied and acked.
            new_cursor = payload.get("next_cursor", payload.get("cursor"))
            if isinstance(new_cursor, int) and not isinstance(new_cursor, bool):
                state["cursor"] = new_cursor
            else:
                state["cursor"] = cursor
            try:
                poll_after = int(payload.get("poll_after") or poll_after)
            except (TypeError, ValueError):
                pass
            state["poll_after"] = poll_after

        # 4. Heartbeat; last_sync advances only on a 2xx.
        heartbeat = self._json_body({
            "connector_version": str(CONNECTOR_VERSION),
            "last_seen": self.clock(),
            "spool_depth": self.spool.count,
            "spool_bytes": self.spool.bytes,
            "queue_lag": self.queue_lag(),
            "cursor": state.get("cursor", 0),
        })
        try:
            status, _headers, data = self._request(
                "POST", "/v1/hosts/self", heartbeat)
        except TransportError as exc:
            errors.append(redact(str(exc)))
        else:
            if status == 410:
                return self._revoked(state, reviews, uploaded, errors)
            if 200 <= status < 300:
                state["last_sync"] = self.clock()
                try:
                    payload = json.loads(data.decode("utf-8")) if data else {}
                except (UnicodeDecodeError, ValueError):
                    payload = {}
                if isinstance(payload, dict) and payload.get("poll_after"):
                    try:
                        poll_after = int(payload["poll_after"])
                        state["poll_after"] = poll_after
                    except (TypeError, ValueError):
                        pass
            else:
                errors.append(self._error_code(data))

        state["last_error"] = errors[0] if errors else None
        self._save_state(state)
        result = {
            "ok": not errors,
            "reviews": reviews,
            "uploaded": uploaded,
            "receipts_spooled": receipts_spooled,
            "poll_after": poll_after,
            "revoked": False,
            "error": errors[0] if errors else None,
        }
        if self.poll_policy:
            # Only a policy-polling cycle has a policy outcome; a local-only
            # connector keeps its original result shape exactly.
            result["policy"] = policy
        return result

    def _revoked(self, state: Dict[str, Any], reviews: int, uploaded: int,
                 errors: list) -> Dict[str, Any]:
        state["revoked"] = True
        state["last_error"] = "revoked"
        self._save_state(state)
        return {"ok": False, "reviews": reviews, "uploaded": uploaded,
                "revoked": True, "error": "revoked"}

    # -- long-running loop ---------------------------------------------
    def run_forever(self, stop_event: Any = None) -> int:
        """Alternate ``run_once`` and ``sleep(poll_after)`` until signalled."""
        stop = stop_event if stop_event is not None else threading.Event()
        previous = {}
        for signum in (signal.SIGTERM, signal.SIGINT):
            try:
                previous[signum] = signal.signal(
                    signum, lambda *_: stop.set())
            except (ValueError, OSError, AttributeError):
                # Not the main thread: a caller-supplied event is the stop.
                pass
        try:
            while not stop.is_set():
                result = self.run_once()
                if result.get("revoked"):
                    return 1
                wait = float(result.get("poll_after")
                             or self._load_state().get("poll_after")
                             or DEFAULT_POLL_AFTER)
                if hasattr(stop, "wait"):
                    stop.wait(max(0.0, wait))
                else:
                    self.sleep(max(0.0, wait))
        finally:
            for signum, handler in previous.items():
                try:
                    signal.signal(signum, handler)
                except (ValueError, OSError):
                    pass
        return 0

    # -- status / leave -------------------------------------------------
    def status(self) -> Dict[str, Any]:
        """The keys FR-014 names; never the agent key."""
        config = self.config or {}
        state = self._load_state()
        ring = {
            "capacity_bytes": DEFAULT_RING_BYTES,
            "bytes": 0,
            "dropped_entries": 0,
            "dropped_by_kind": {kind: 0 for kind in KIND_PRIORITY},
            "gaps": [],
        }
        if config:
            try:
                spool = self.spool
                spool_batches = spool.count
                spool_bytes = spool.bytes
                dropped_batches = spool.dropped_batches
                ring = self.ring.status()
            except Exception:
                spool_batches = 0
                spool_bytes = 0
                dropped_batches = 0
        else:
            spool_batches = 0
            spool_bytes = 0
            dropped_batches = 0
        last_sync = state.get("last_sync")
        now = float(self.clock())
        connected = bool(
            last_sync is not None
            and not state.get("revoked")
            and now - float(last_sync) <= CONNECTED_WINDOW
        )
        receipts = {
            "receipts_offset": state.get("receipts_offset", 0),
            "receipts_line": state.get("receipts_line", 1),
            "receipts_pending_bytes": 0,
            "last_receipt_error": state.get("last_receipt_error"),
            "last_receipt_ack": state.get("last_receipt_ack"),
            "verification_level": state.get("verification_level"),
        }
        try:
            tailer = self.receipt_tailer()
        except TailerError as exc:
            tailer = None
            receipts["last_receipt_error"] = redact(str(exc))
        if tailer is not None:
            live = tailer.status()
            live["last_receipt_error"] = (
                live.get("last_receipt_error")
                or state.get("last_receipt_error"))
            receipts.update(live)
        return redact({
            "connected": connected,
            "last_sync": last_sync,
            "url": config.get("url"),
            "org_id": config.get("org_id"),
            "host_id": config.get("host_id"),
            "spool_batches": spool_batches,
            "spool_bytes": spool_bytes,
            "dropped_batches": dropped_batches,
            "ring": ring,
            "queue_lag": self.queue_lag(),
            "cursor": state.get("cursor", 0),
            "grant_seq": state.get("grant_last_seq", 0),
            "last_ack_seq": state.get("last_ack_seq", 0),
            "grants_applied": state.get("grants_applied", 0),
            "grants_refused": state.get("grants_refused", 0),
            "grants_acked": state.get("grants_acked", 0),
            "last_grant_applied": state.get("last_grant_applied"),
            "last_grant_refusal": state.get("last_grant_refusal"),
            "revoked": bool(state.get("revoked")),
            "last_error": state.get("last_error"),
            **receipts,
        })

    def reset_receipt_offset(self, line_no: int) -> int:
        """Move the receipt offset to 1-based ``line_no`` (operator recovery).

        Any spooled receipt batch still awaiting an acknowledgement is
        forgotten: the operator has decided to re-read the log from an earlier
        line, so that batch must not later pull the offset forward again.
        """
        tailer = self.receipt_tailer()
        if tailer is None:
            raise TailerError("no receipt_log is configured")
        offset = tailer.rewind_to(int(line_no))
        state = self._load_state()
        # Queued receipt batches carry the bytes the operator is asking to
        # re-read. Leave one of them in the spool and the next cycle would
        # upload it ahead of the re-read batch and re-advance the offset past
        # the recovery point.
        for batch in self.spool.batches():
            if batch.sensor == "receipts":
                self.spool.remove(batch)
        state["pending_receipt_batches"] = {}
        state["receipts_offset"] = int(offset)
        state["receipts_line"] = int(tailer.line)
        state["last_receipt_error"] = None
        self._save_state(state)
        return int(offset)

    def leave(self, *, confirmed: bool = True) -> Dict[str, Any]:
        """Forget the enrollment; the spool and state stay for the operator."""
        config = self.config or {}
        spool_dir = self._resolve(str(config.get("spool_dir") or "spool"))
        state_dir = self._resolve(str(config.get("state_dir") or "state"))
        removed = False
        if confirmed:
            removed = self.home.remove_config()
            self._config = None
            self._state = None
            self._spool = None
            self._ring = None
        return {
            "removed": removed,
            "config": str(self.home.config_path),
            "seed": str(self.home.seed_path),
            "spool": str(spool_dir),
            "state": str(state_dir),
            "spool_remains": spool_dir.exists(),
        }


__all__ = [
    "CONNECTED_WINDOW",
    "CONNECTOR_VERSION",
    "Connector",
    "DEFAULT_POLL_AFTER",
    "MAX_BACKOFF",
    "MIN_BACKOFF",
]
