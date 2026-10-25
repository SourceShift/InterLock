"""The DAP client: turn one batch of counts into one Prio3 report.

The shape of the privacy guarantee is visible in this file. The client never
sends counts. It maps them to a dense vector, calls the VDAF's ``shard`` to
split that vector into two additive shares with a proof that each element is in
range, encrypts one share to the leader and one to the helper, and uploads the
ciphertexts. Neither aggregator can read a measurement from its own share; the
proof is what stops a client from claiming an out-of-range value and skewing
the totals.

Every upload goes through :func:`interlock.mesh.report.submit_bytes`, so
``INTERLOCK_MESH_NO_REPORT=1`` refuses before a socket is opened.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .. import hpke
from ..report import ReportError, reporting_killed, submit_bytes
from . import messages as m
from .aggregator import input_share_info
from .task import Task, b64url

__all__ = [
    "ClientError", "ReportPlan", "SUPPORTED_SUITE", "fetch_hpke_config",
    "build_report", "upload_report", "submit_counts",
]

#: The HPKE suite DAP requires absent a deployment profile (§7): DHKEM(X25519,
#: HKDF-SHA256), HKDF-SHA256, AES-128-GCM.
SUPPORTED_SUITE = (hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256,
                   hpke.AEAD_AES_128_GCM)

MAX_CONFIG_REPLY = 64 * 1024


class ClientError(ValueError):
    """The client cannot build or upload the report as configured."""


@dataclass(frozen=True)
class ReportPlan:
    """A built report plus the measurement it commits to (for local output)."""

    report: m.Report
    measurement: Tuple[int, ...]
    batch_index: int


def fetch_hpke_config(task: Task, *, timeout: float = 10.0) -> m.HpkeConfig:
    """``GET {leader}/hpke_config?task_id=…`` and select the DAP suite.

    When ``task.json`` pins the leader's key, the fetched config must match it:
    a leader that presents a different key is either misconfigured or is not
    the aggregator this task named.

    The kill switch is checked first: with ``INTERLOCK_MESH_NO_REPORT=1`` the
    client refuses before it opens a socket, even to read a public key.
    """
    if reporting_killed():
        raise ReportError(
            "INTERLOCK_MESH_NO_REPORT is set: every mesh upload is refused on this node")
    url = "{}/hpke_config?task_id={}".format(task.leader, b64url(task.task_id))
    request = urllib.request.Request(url, headers={"User-Agent": "interlock-mesh"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            body = response.read(MAX_CONFIG_REPLY)
    except urllib.error.HTTPError as exc:
        raise ClientError("{}: HTTP {}".format(url, exc.code))
    except OSError as exc:
        raise ClientError("{}: {}".format(url, exc))
    try:
        configs = m.HpkeConfigList.from_bytes(body).configs
    except m.WireError as exc:
        raise ClientError("{}: bad HpkeConfigList: {}".format(url, exc))
    for config in configs:
        if (config.kem_id, config.kdf_id, config.aead_id) != SUPPORTED_SUITE:
            continue
        if len(config.public_key) != 32:
            continue
        if task.leader_hpke is not None and config != task.leader_hpke:
            raise ClientError(
                "the leader presented HPKE config {}/{} but task.json pins {}/{}"
                .format(config.config_id, config.public_key.hex()[:16],
                        task.leader_hpke.config_id,
                        task.leader_hpke.public_key.hex()[:16]))
        return config
    raise ClientError("{}: no X25519 / HKDF-SHA256 / AES-128-GCM config".format(url))


def build_report(task: Task, counts: Dict[str, int], *,
                 leader_config: m.HpkeConfig,
                 batch_index: Optional[int] = None,
                 now: Optional[float] = None,
                 report_id: Optional[bytes] = None) -> ReportPlan:
    """Map counts to a measurement and shard it into one uploadable report.

    The batch is chosen from ``now`` by default. Counts outside that batch, a
    count that matches no bucket, a bucket over ``max_measurement``, or a
    missing aggregator key all raise :class:`ClientError` before anything is
    encrypted.
    """
    if batch_index is None:
        now = time.time() if now is None else now
        batch_index = int(now // task.time_precision)
    try:
        measurement = task.measurement(counts, batch_index)
    except ValueError as exc:
        raise ClientError(str(exc))
    helper_config = task.helper_hpke
    if helper_config is None:
        raise ClientError("task.json carries no helper HPKE config to encrypt to")
    if report_id is None:
        report_id = os.urandom(16)
    if len(report_id) != 16:
        raise ClientError("a report id is 16 bytes")

    vdaf = task.vdaf()
    public_share, input_shares = vdaf.shard(
        task.context(), measurement, report_id, os.urandom(vdaf.RAND_SIZE))
    encoded_public = vdaf.encode_public_share(public_share)
    metadata = m.ReportMetadata(report_id, batch_index)
    aad = m.InputShareAad(task.task_id, task.task_configuration, metadata,
                          encoded_public).encode()

    ciphertexts: List[m.HpkeCiphertext] = []
    for config, role, share in zip((leader_config, helper_config),
                                   (m.Role.LEADER, m.Role.HELPER), input_shares):
        plaintext = m.PlaintextInputShare((), vdaf.encode_input_share(share)).encode()
        enc, payload = hpke.seal_base(config.public_key, input_share_info(role),
                                      plaintext, aad)
        ciphertexts.append(m.HpkeCiphertext(config.config_id, enc, payload))
    report = m.Report(metadata, encoded_public, ciphertexts[0], ciphertexts[1])
    return ReportPlan(report, tuple(int(x) for x in measurement), batch_index)


@dataclass(frozen=True)
class UploadResult:
    accepted: int
    errors: Tuple[m.ReportUploadStatus, ...] = ()


def upload_report(task: Task, report: m.Report, *, token: Optional[str] = None,
                  timeout: float = 30.0) -> UploadResult:
    """POST one ``UploadRequest`` through the node's kill switch."""
    request = m.UploadRequest((report,))
    url = "{}/tasks/{}/upload".format(task.leader, task.task_id_b64)
    status, content_type, body = submit_bytes(
        url, request.encode(), m.MEDIA_UPLOAD_REQ, token=token, timeout=timeout)
    if status != 200:
        raise ClientError(_problem_text(status, body))
    if not body:
        return UploadResult(accepted=1)
    if content_type != m.MEDIA_UPLOAD_ERRORS:
        raise ClientError("upload reply has unexpected type {}".format(content_type))
    try:
        errors = m.UploadErrors.from_bytes(body).statuses
    except m.WireError as exc:
        raise ClientError("bad UploadErrors: {}".format(exc))
    accepted = 0 if errors else 1
    return UploadResult(accepted=accepted, errors=errors)


def submit_counts(task: Task, counts: Dict[str, int], *, token: Optional[str] = None,
                  batch_index: Optional[int] = None, now: Optional[float] = None,
                  report_id: Optional[bytes] = None) -> Tuple[ReportPlan, UploadResult]:
    """Fetch the leader's key, build the report, upload it, return both."""
    plan = build_report(task, counts, leader_config=fetch_hpke_config(task),
                        batch_index=batch_index, now=now, report_id=report_id)
    return plan, upload_report(task, plan.report, token=token)


def _problem_text(status: int, body: bytes) -> str:
    try:
        document = json.loads(body.decode("utf-8"))
        return "leader refused the upload: HTTP {} {}: {}".format(
            status, document.get("type", ""), document.get("detail", ""))
    except (ValueError, TypeError):
        return "leader refused the upload: HTTP {}".format(status)
