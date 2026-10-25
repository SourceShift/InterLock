"""The collector roles as plain HTTP, standard library only.

Two roles, one server class:

``consensus``
    ``POST /v1/reports`` takes a signed report envelope (which carries no
    counts) and feeds the :class:`~interlock.mesh.consensus.ConsensusEngine`.
    ``GET /v1/stats`` is the public dashboard: organisations per rule, the
    indicator funnel, demotions; no per-reporter data and no fire counts.
    ``GET /v1/indicators`` is the indicator pack the commons publishes.

``aggregator``
    ``POST /v1/shares`` takes one report's share of its counts
    (``{"report_id", "shares": {key: int}}``). ``GET /v1/manifest`` lists the
    report ids held and the batch floor (``min_batch``) so two aggregators can
    reconcile; ``POST /v1/totals`` with ``{"ids": [...]}`` returns this side's
    partial sums for exactly those ids, or 422 with a ``reason`` when fewer
    than ``min_batch`` of them are held (see :mod:`.aggregate` for why).

Run two aggregators under different organisations and point reporters at
both. The server binds loopback unless told otherwise, caps request bodies,
answers JSON only, and can require a bearer token on every ``POST``. State is
written through an atomic rename after each accepted change.

Everything here is a reference implementation meant to be fronted by a real
web server in production. It exists so that the whole pipeline can be run,
tested and reasoned about with nothing but Python.
"""
from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional, Tuple

from ._util import atomic_write, read_bounded
from .aggregate import MIN_BATCH, Aggregator
from .consensus import ConsensusEngine

__all__ = ["MeshServer", "make_server", "MAX_BODY", "MAX_MIRROR_FILE"]

MAX_BODY = 2 * 1024 * 1024
MAX_MIRROR_FILE = 16 * 1024 * 1024


class MeshServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: Tuple[str, int], role: str, *, state_path: Optional[str] = None,
                 token: Optional[str] = None, engine: Optional[ConsensusEngine] = None,
                 aggregator: Optional[Aggregator] = None, directory: Optional[str] = None) -> None:
        if role not in ("consensus", "aggregator", "mirror"):
            raise ValueError("role must be consensus, aggregator or mirror")
        super().__init__(address, _Handler)
        self.role = role
        self.state_path = state_path
        self.token = token
        self.lock = threading.Lock()
        self.engine = engine
        self.aggregator = aggregator
        # mirror: the directory whose metadata/, targets/ and log/ are served read-only
        # (a node's verified mesh cache, or a published site).
        self.directory = os.path.abspath(directory) if directory else None
        if role == "mirror" and not self.directory:
            raise ValueError("a mirror needs a directory to serve")
        if role == "consensus" and self.engine is None:
            self.engine = ConsensusEngine()
        if role == "aggregator" and self.aggregator is None:
            self.aggregator = Aggregator()

    def persist(self) -> None:
        if not self.state_path:
            return
        if self.role == "consensus" and self.engine is not None:
            self.engine.save(self.state_path)
        elif self.role == "aggregator" and self.aggregator is not None:
            atomic_write(self.state_path, json.dumps({"version": 1, "reports": self.aggregator.to_dict()},
                                                     sort_keys=True).encode("utf-8"), mode=0o600)

    @property
    def url(self) -> str:
        host, port = self.server_address[0], self.server_address[1]
        return "http://{}:{}".format(host, port)


class _Handler(BaseHTTPRequestHandler):
    server: MeshServer  # type: ignore[assignment]
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: Any) -> None:  # quiet by default
        return

    # helpers ------------------------------------------------------------------------

    def _reply(self, status: int, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> Optional[Any]:
        length = self.headers.get("Content-Length")
        try:
            size = int(length or "0")
        except ValueError:
            self._reply(400, {"error": "bad content length"})
            return None
        if size <= 0 or size > MAX_BODY:
            if MAX_BODY < size <= 4 * MAX_BODY:
                self.rfile.read(size)  # drain a modestly oversized body so the client sees the 413
            self._reply(413 if size > MAX_BODY else 400, {"error": "body must be 1..{} bytes".format(MAX_BODY)})
            if size > 4 * MAX_BODY:
                self.close_connection = True
            return None
        raw = self.rfile.read(size)
        try:
            return json.loads(raw.decode("utf-8"))
        except ValueError:
            self._reply(400, {"error": "body is not JSON"})
            return None

    def _authorized(self) -> bool:
        if not self.server.token:
            return True
        header = self.headers.get("Authorization", "")
        if header == "Bearer " + self.server.token:
            return True
        self._reply(401, {"error": "a bearer token is required"})
        return False

    # routes -------------------------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path == "/healthz":
            self._reply(200, {"ok": True, "role": self.server.role})
            return
        if self.server.role == "mirror":
            self._serve_file(path)
            return
        if self.server.role == "consensus" and self.server.engine is not None:
            if path == "/v1/stats":
                self._reply(200, self.server.engine.export_stats())
                return
            if path == "/v1/indicators":
                self._reply(200, self.server.engine.export_indicators())
                return
        if self.server.role == "aggregator" and self.server.aggregator is not None:
            if path == "/v1/manifest":
                agg = self.server.aggregator
                self._reply(200, {"ids": agg.report_ids(), "digest": agg.manifest(), "min_batch": agg.min_batch})
                return
        self._reply(404, {"error": "no such route"})

    def _serve_file(self, path: str) -> None:
        """Serve one file from the mirrored directory, read-only, no traversal."""
        parts = [p for p in path.split("/") if p]
        if (not parts or parts[0] not in ("metadata", "targets", "log") or any(p in ("..", "") for p in parts)
                or any(p.startswith(".") for p in parts)):
            self._reply(404, {"error": "no such route"})
            return
        full = os.path.join(self.server.directory or "", *parts)
        if not os.path.isfile(full):
            self._reply(404, {"error": "not found"})
            return
        try:
            data = read_bounded(full, MAX_MIRROR_FILE)
        except (OSError, ValueError):
            self._reply(404, {"error": "not found"})
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json" if full.endswith(".json") else "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _gossip(self, payload: Any) -> None:
        """Record the peer's checkpoint and answer with ours, for split-view detection."""
        if not isinstance(payload, dict) or not isinstance(payload.get("checkpoint"), dict):
            self._reply(400, {"error": "expected {checkpoint}"})
            return
        directory = self.server.directory or ""
        try:
            os.makedirs(os.path.join(directory, "log"), exist_ok=True)
            with self.server.lock:
                with open(os.path.join(directory, "log", "gossip.jsonl"), "a", encoding="utf-8") as fh:
                    fh.write(json.dumps({"from": self.client_address[0], "checkpoint": payload["checkpoint"]},
                                        sort_keys=True) + "\n")
        except OSError:
            pass
        ours = None
        path = os.path.join(directory, "log", "checkpoint.json")
        if os.path.isfile(path):
            try:
                ours = json.loads(read_bounded(path, 16 * 1024).decode("utf-8"))
            except (OSError, ValueError):
                ours = None
        self._reply(200, {"checkpoint": ours})

    def do_POST(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        if not self._authorized():
            return
        payload = self._body()
        if payload is None:
            return
        if self.server.role == "mirror":
            if path == "/v1/gossip":
                self._gossip(payload)
            else:
                self._reply(404, {"error": "no such route"})
            return
        if self.server.role == "consensus" and self.server.engine is not None and path == "/v1/reports":
            result = self.server.engine.ingest(payload)
            if result.get("accepted"):
                with self.server.lock:
                    self.server.persist()
            self._reply(200 if result.get("accepted") else 422, result)
            return
        if self.server.role == "aggregator" and self.server.aggregator is not None:
            if path == "/v1/shares":
                if not isinstance(payload, dict) or not isinstance(payload.get("shares"), dict):
                    self._reply(400, {"error": "expected {report_id, shares}"})
                    return
                try:
                    with self.server.lock:
                        self.server.aggregator.add(str(payload.get("report_id", "")), payload["shares"])
                        self.server.persist()
                except ValueError as exc:
                    self._reply(422, {"accepted": False, "reason": str(exc)})
                    return
                self._reply(200, {"accepted": True})
                return
            if path == "/v1/totals":
                ids = payload.get("ids") if isinstance(payload, dict) else None
                if not isinstance(ids, list) or not all(isinstance(i, str) for i in ids):
                    self._reply(400, {"error": "expected {ids: [...]}"})
                    return
                try:
                    with self.server.lock:
                        totals = self.server.aggregator.totals(ids)
                except ValueError as exc:
                    self._reply(422, {"reason": str(exc), "min_batch": self.server.aggregator.min_batch})
                    return
                self._reply(200, {"totals": totals})
                return
        self._reply(404, {"error": "no such route"})


def make_server(role: str, bind: str = "127.0.0.1:0", *, state_path: Optional[str] = None,
                token: Optional[str] = None, known_catalogs: Tuple[str, ...] = (),
                config: Optional[Dict[str, Any]] = None, directory: Optional[str] = None) -> MeshServer:
    """Build a server for ``role`` on ``bind`` (``host:port``; port 0 picks one),
    restoring state from ``state_path`` when it exists. A ``mirror`` serves
    ``directory`` read-only and answers gossip. ``config`` is the consensus
    engine's; for an aggregator it may set ``min_batch`` (default
    :data:`~interlock.mesh.aggregate.MIN_BATCH`, at least 2)."""
    host, _, port_text = bind.rpartition(":")
    host = host or "127.0.0.1"
    port = int(port_text or "0")
    engine = None
    aggregator = None
    if role == "mirror":
        return MeshServer((host, port), role, token=token, directory=directory)
    if role == "consensus":
        if state_path and _exists(state_path):
            engine = ConsensusEngine.load(state_path)
        else:
            engine = ConsensusEngine(config)
        for cid in known_catalogs:
            engine.register_catalog(cid)
    elif role == "aggregator":
        min_batch = (config or {}).get("min_batch", MIN_BATCH)
        if state_path and _exists(state_path):
            data = json.loads(read_bounded(state_path, 64 * 1024 * 1024).decode("utf-8"))
            aggregator = Aggregator.from_dict(data.get("reports", {}), min_batch)
        else:
            aggregator = Aggregator(min_batch)
    return MeshServer((host, port), role, state_path=state_path, token=token, engine=engine,
                      aggregator=aggregator)


def _exists(path: str) -> bool:
    import os
    return os.path.exists(path)
