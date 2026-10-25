"""The stdlib HTTP server for the DAP leader and helper roles.

Only the routes this profile uses exist. The leader publishes its HPKE config,
accepts uploads and answers collection jobs; the helper takes aggregation jobs
and aggregate-share requests. Both speak the binary media types from
draft-ietf-ppm-dap-20 and answer errors as RFC 9457 problem documents whose
``type`` is ``urn:ietf:params:ppm:dap:error:<token>``.

TLS is terminated by a reverse proxy in front of this process; the console's
existing model is the same. The server binds loopback unless told otherwise.
"""

from __future__ import annotations

import hmac
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from . import messages as m
from .aggregator import MAX_BODY, Helper, Leader
from .task import RoleKeys, Task, b64url, from_b64url

__all__ = ["make_dap_server", "DapHttpServer"]


def _media_type(header: Optional[str]) -> str:
    """The media type without parameters other than ``message=…``.

    ``message`` is part of the type DAP names, so it must be kept; charset or
    other parameters are stripped and compared separately.
    """
    if not header:
        return ""
    parts = [part.strip() for part in header.split(";")]
    kind = parts[0].lower()
    params = [p for p in parts[1:] if p.lower().startswith("message=")]
    return ";".join([kind] + params)


class DapHttpServer(ThreadingHTTPServer):
    """A ``ThreadingHTTPServer`` that carries the task and one aggregator."""

    daemon_threads = True

    def __init__(self, address: Tuple[str, int], aggregator, *, role: str,
                 leader_token: Optional[str] = None,
                 collector_token: Optional[str] = None):
        self.aggregator = aggregator
        self.role = role
        self.leader_token = leader_token
        self.collector_token = collector_token
        handler = _LeaderHandler if role == "leader" else _HelperHandler
        super().__init__(address, handler)

    @property
    def url(self) -> str:
        host, port = self.server_address[:2]
        return "http://{}:{}".format(host, port)


class _Handler(BaseHTTPRequestHandler):
    server_version = "interlock-dap"
    sys_version = ""

    @property
    def dap(self) -> DapHttpServer:
        return self.server  # type: ignore[return-value]

    # --- plumbing ----------------------------------------------------------

    def log_message(self, format: str, *args) -> None:  # noqa: A002 - stdlib name
        if os.environ.get("INTERLOCK_MESH_DEBUG"):
            super().log_message(format, *args)

    def _body(self) -> bytes:
        length = self.headers.get("Content-Length")
        if length is None:
            raise m.DapProblem("invalidMessage", "Content-Length is required", 411)
        try:
            size = int(length)
        except ValueError:
            raise m.DapProblem("invalidMessage", "bad Content-Length")
        if size < 0 or size > MAX_BODY:
            raise m.DapProblem("invalidMessage", "body over {} bytes".format(MAX_BODY), 413)
        return self.rfile.read(size)

    def _send(self, status: int, body: bytes = b"", content_type: str = "",
              headers: Optional[Dict[str, str]] = None) -> None:
        self.send_response(status)
        if content_type:
            self.send_header("Content-Type", content_type)
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _problem(self, error: m.DapProblem) -> None:
        import json

        self._send(error.status, json.dumps(error.to_json()).encode("utf-8"),
                   m.MEDIA_PROBLEM_JSON)

    def _authorized(self, expected: Optional[str]) -> bool:
        if expected is None:
            return True
        header = self.headers.get("Authorization", "")
        prefix = "Bearer "
        return header.startswith(prefix) and hmac.compare_digest(
            header[len(prefix):], expected)

    def _require(self, expected: Optional[str]) -> None:
        if not self._authorized(expected):
            raise m.DapProblem("invalidMessage", "missing or wrong bearer token", 401)

    def _task_path(self, parts) -> Optional[str]:
        """``tasks/<id>/...`` → the task id, or ``None`` when the id is wrong."""
        if len(parts) < 2 or parts[0] != "tasks":
            return None
        try:
            task_id = from_b64url(parts[1])
        except ValueError:
            return None
        if not hmac.compare_digest(task_id, self.dap.aggregator.task.task_id):
            return None
        return parts[1]

    def _dispatch(self, method: str) -> None:
        try:
            parsed = urlparse(self.path)
            parts = [part for part in parsed.path.split("/") if part]
            handler = self.do_get if method == "GET" else self.do_post
            handler(parts, parsed.query)
        except m.DapProblem as error:
            self._problem(error)
        except m.WireError as exc:
            self._problem(m.DapProblem("invalidMessage", str(exc)))
        except Exception as exc:  # noqa: BLE001 - never leak a stack trace to a peer
            print("interlock dap: internal error: {}".format(exc), file=sys.stderr)
            self._send(500, b"internal error", "text/plain; charset=utf-8")

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._dispatch("GET")

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._dispatch("POST")

    def _unknown(self) -> m.DapProblem:
        return m.DapProblem("unrecognizedTask", "no such task or route", 404)

    def do_get(self, parts, query) -> None:  # overridden per role
        raise self._unknown()

    def do_post(self, parts, query) -> None:  # overridden per role
        raise self._unknown()


class _LeaderHandler(_Handler):
    def do_get(self, parts, query) -> None:
        if parts == ["hpke_config"]:
            values = parse_qs(query).get("task_id", [])
            task = self.dap.aggregator.task
            if not values or values[0] != b64url(task.task_id):
                raise m.DapProblem("unrecognizedTask", "unknown task_id", 404,
                                   task.task_id)
            if self.dap.aggregator.task.leader_hpke is None:
                raise m.DapProblem("invalidMessage", "no leader HPKE config", 500)
            configs = m.HpkeConfigList((self.dap.aggregator.task.leader_hpke,))
            self._send(200, configs.encode(), m.MEDIA_HPKE_CONFIG_LIST)
            return
        raise self._unknown()

    def do_post(self, parts, query) -> None:
        task_part = self._task_path(parts)
        if task_part is None:
            raise m.DapProblem("unrecognizedTask", "no such task", 404)
        aggregator = self.dap.aggregator
        if parts[2:] == ["upload"]:
            if _media_type(self.headers.get("Content-Type")) != m.MEDIA_UPLOAD_REQ:
                raise m.DapProblem("invalidMessage", "expected " + m.MEDIA_UPLOAD_REQ,
                                   415)
            status, content_type, body = aggregator.upload(self._body())
            self._send(status, body, content_type)
            return
        if parts[2:] == ["collection_jobs"]:
            self._require(self.dap.collector_token)
            if _media_type(self.headers.get("Content-Type")) != m.MEDIA_COLLECTION_JOB_REQ:
                raise m.DapProblem("invalidMessage",
                                   "expected " + m.MEDIA_COLLECTION_JOB_REQ, 415)
            response = aggregator.collection_job(self._body())
            self._send(200, response.encode(), m.MEDIA_COLLECTION_JOB_RESP)
            return
        raise self._unknown()


class _HelperHandler(_Handler):
    def do_get(self, parts, query) -> None:
        task_part = self._task_path(parts)
        if task_part is None:
            raise m.DapProblem("unrecognizedTask", "no such task", 404)
        if len(parts) >= 4 and parts[2] == "aggregation_jobs":
            # Multi-round jobs only; Prio3 finishes during initialization.
            raise m.DapProblem(
                "stepMismatch",
                "this task's VDAF finishes during initialization; there is no "
                "continuation step to poll", 409)
        raise self._unknown()

    def do_post(self, parts, query) -> None:
        task_part = self._task_path(parts)
        if task_part is None:
            raise m.DapProblem("unrecognizedTask", "no such task", 404)
        aggregator = self.dap.aggregator
        self._require(self.dap.leader_token)
        if parts[2:] == ["aggregation_jobs"]:
            if _media_type(self.headers.get("Content-Type")) != (
                    m.MEDIA_AGGREGATION_JOB_INIT_REQ):
                raise m.DapProblem("invalidMessage",
                                   "expected " + m.MEDIA_AGGREGATION_JOB_INIT_REQ,
                                   415)
            job_id, payload = aggregator.aggregation_jobs(self._body())
            self._send(200, payload, m.MEDIA_AGGREGATION_JOB_RESP,
                       {"Location": "/tasks/{}/aggregation_jobs/{}".format(
                           task_part, job_id)})
            return
        if len(parts) >= 4 and parts[2] == "aggregation_jobs":
            raise m.DapProblem(
                "stepMismatch",
                "this task's VDAF finishes during initialization; a continuation "
                "request has no job state", 409)
        if parts[2:] == ["aggregate_shares"]:
            if _media_type(self.headers.get("Content-Type")) != m.MEDIA_AGGREGATE_SHARE_REQ:
                raise m.DapProblem("invalidMessage",
                                   "expected " + m.MEDIA_AGGREGATE_SHARE_REQ, 415)
            share = aggregator.aggregate_shares(self._body())
            self._send(200, share.encode(), m.MEDIA_AGGREGATE_SHARE)
            return
        raise self._unknown()


def make_dap_server(bind: str, *, role: str, task: Task, keys: RoleKeys,
                    state_path: str, peer_token: Optional[str] = None,
                    collector_token: Optional[str] = None,
                    timeout: float = 30.0) -> DapHttpServer:
    """Build (but do not start) the leader or helper server for one task.

    ``peer_token`` is the bearer token the two aggregators share: the leader
    presents it to the helper, and the helper requires it. Left out, both take
    it from the role key files, where ``dap task`` generated it.
    """
    if role == "leader":
        aggregator = Leader(task, keys, state_path, helper_token=peer_token,
                            timeout=timeout)
        collector_token = collector_token if collector_token is not None \
            else keys.token("collector")
        server = DapHttpServer(_split(bind), aggregator, role="leader",
                               collector_token=collector_token)
    elif role == "helper":
        aggregator = Helper(task, keys, state_path)
        peer_token = peer_token if peer_token is not None else keys.token("leader")
        server = DapHttpServer(_split(bind), aggregator, role="helper",
                               leader_token=peer_token)
    else:
        raise ValueError("role must be 'leader' or 'helper', not {!r}".format(role))
    server.daemon_threads = True
    return server


def _split(bind: str) -> Tuple[str, int]:
    host, _, port = bind.rpartition(":")
    if not host or not port.isdigit():
        raise ValueError("bind must be HOST:PORT, not {!r}".format(bind))
    return host, int(port)
