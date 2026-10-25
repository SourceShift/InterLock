"""The DAP collector: ask the leader for a batch, then open both shares.

The collector is the only party that can read a result. It holds the HPKE
secret matching the public config in ``task.json``; the leader and helper each
encrypt their aggregate share to that key. Neither aggregator ever sees the
other's share in the clear, and neither can decrypt the one it holds.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from .. import hpke
from ..report import post_bytes
from . import messages as m
from .aggregator import aggregate_share_info
from .task import RoleKeys, Task

__all__ = ["CollectorError", "CollectionResult", "collection_request", "collect"]


class CollectorError(ValueError):
    """The collection job failed or its response cannot be opened."""


@dataclass(frozen=True)
class CollectionResult:
    """One opened batch: the raw measurement vector and the labelled counts."""

    report_count: int
    interval: m.Interval
    measurement: Tuple[int, ...]
    counts: Dict[str, int]

    def to_json(self) -> Dict[str, object]:
        return {
            "report_count": self.report_count,
            "interval": {"start": self.interval.start,
                         "duration": self.interval.duration},
            "measurement": list(self.measurement),
            "counts": self.counts,
        }


def collection_request(task: Task, batch_index: int) -> Tuple[bytes, m.Interval]:
    """The ``CollectionJobReq`` body for one fixed batch and its interval."""
    interval = m.Interval(batch_index, 1)
    query = m.Query(m.BatchMode.TIME_INTERVAL,
                    m.TimeIntervalQueryConfig(interval).encode())
    return m.CollectionJobReq(query, b"", ()).encode(), interval


def collect(task: Task, keys: RoleKeys, batch_index: int, *,
            token: Optional[str] = None, timeout: float = 30.0) -> CollectionResult:
    """Run one collection job and open both aggregate shares."""
    if keys.role != "collector":
        raise CollectorError("collection needs the collector key file, not {!r}"
                             .format(keys.role))
    body, interval = collection_request(task, batch_index)
    url = "{}/tasks/{}/collection_jobs".format(task.leader, task.task_id_b64)
    status, content_type, payload = post_bytes(
        url, body, m.MEDIA_COLLECTION_JOB_REQ,
        token=token if token is not None else keys.token("leader"), timeout=timeout)
    if status != 200:
        raise CollectorError(_problem_text(status, payload))
    try:
        response = m.CollectionJobResp.from_bytes(payload)
    except m.WireError as exc:
        raise CollectorError("bad CollectionJobResp: {}".format(exc))

    aad = m.AggregateShareAad(task.task_id, task.task_configuration, body).encode()
    shares = []
    for ciphertext, role in ((response.leader_encrypted_agg_share, m.Role.LEADER),
                             (response.helper_encrypted_agg_share, m.Role.HELPER)):
        if ciphertext.config_id != keys.hpke_config_id:
            raise CollectorError(
                "aggregate share for config {}, but the collector key is {}"
                .format(ciphertext.config_id, keys.hpke_config_id))
        try:
            plaintext = hpke.open_base(ciphertext.enc, keys.hpke_secret,
                                       aggregate_share_info(role),
                                       ciphertext.payload, aad)
        except Exception:
            raise CollectorError(
                "cannot open the {} aggregate share".format(
                    "leader" if role is m.Role.LEADER else "helper"))
        shares.append(plaintext)

    vdaf = task.vdaf()
    try:
        decoded = [vdaf.decode_agg_share(None, share) for share in shares]
        vector = vdaf.unshard(None, decoded, response.report_count)
    except Exception as exc:
        raise CollectorError("the aggregate shares do not unshard: {}".format(exc))
    measurement = tuple(int(value) for value in vector)
    return CollectionResult(response.report_count, response.interval,
                            measurement, task.counts(measurement, batch_index))


def _problem_text(status: int, body: bytes) -> str:
    try:
        document = json.loads(body.decode("utf-8"))
        return "collection failed: HTTP {} {}: {}".format(
            status, document.get("type", ""), document.get("detail", ""))
    except (ValueError, TypeError):
        return "collection failed: HTTP {}".format(status)
