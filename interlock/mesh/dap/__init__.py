"""DAP (draft-ietf-ppm-dap-20) over Prio3, for the interlock mesh.

The package is split the way the protocol is:

* :mod:`~interlock.mesh.dap.wire` — TLS presentation language reader/writer.
* :mod:`~interlock.mesh.dap.messages` — every DAP structure and media type.
* :mod:`~interlock.mesh.dap.task` — the task file, the bucket manifest and the
  counts <-> measurement mapping.
* :mod:`~interlock.mesh.dap.client` — build and upload a report.
* :mod:`~interlock.mesh.dap.aggregator` — leader and helper state machines.
* :mod:`~interlock.mesh.dap.collector` — open the aggregate shares.
* :mod:`~interlock.mesh.dap.server` — the stdlib HTTP server for both roles.

The VDAF itself lives in :mod:`interlock.mesh.vdaf` and HPKE in
:mod:`interlock.mesh.hpke`; both are tested against their own published
vectors, so this package only has to get the DAP framing and state machines
right.
"""

DAP_DRAFT = "dap-20"
DAP_CONTEXT = DAP_DRAFT.encode("ascii")

__all__ = ["DAP_DRAFT", "DAP_CONTEXT"]
