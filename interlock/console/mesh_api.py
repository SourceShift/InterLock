"""Mesh status: this node's commons subscription, verified packs and reporting consent.

Read-only on purpose. Syncing, granting and reporting stay commands the user
runs outside any agent; the page shows what the node currently trusts and the
command to change it. The data comes from the same :class:`Subscriber` the
loader reads, so an unconfigured node answers ``configured: false`` rather
than inventing a commons.
"""
from __future__ import annotations

from typing import Tuple

from .server import ROUTES
from .session import ApiError, handles_errors, setting


@handles_errors
def _mesh(handler) -> Tuple[int, dict]:
    from ..mesh import default_mesh_dir
    from ..mesh.subscriber import Subscriber, SubscriberError

    directory = setting(handler, "mesh_dir") or default_mesh_dir()
    try:
        status = Subscriber(str(directory)).status()
    except (OSError, ValueError, SubscriberError) as exc:
        raise ApiError(500, "mesh_unreadable", "the mesh state could not be read: {}".format(exc))
    return 200, status


ROUTES["/api/mesh"] = {"GET": _mesh}
