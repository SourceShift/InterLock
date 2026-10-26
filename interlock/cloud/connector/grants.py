"""Verify, apply and acknowledge a plane grant on the host (FR-025 .. FR-027).

Nothing here trusts the plane. A grant is checked in this order before the
local queue moves: its Ed25519 signature, the org and host it names, its
expiry (60 s clock skew), its position in the per-host chain, the review's
local binding hash, and finally whether this exact grant was already applied.
A failure applies nothing, leaves the review pending, is recorded in
``last_grant_refusal`` and is reported on the next acknowledgement so an
operator can see a host refusing work.

The ack is deliberately separate from the apply: the plane redelivers until
it sees an ack, so an apply that commits and then crashes is a redelivery -
the persisted ``seen_grants`` set makes it an acknowledged no-op rather than a
second decision.

A grant for a review a local reviewer already settled is acked and applied
nothing; the local decision wins. That is the race the kickoff calls out.
"""
from __future__ import annotations

import hmac
import time
from typing import Any, Dict, Iterable, List, Mapping

from ..grants import GENESIS, DEFAULT_MAX_SKEW, verify_grant
from ...reviews import GrantRefused

#: The persisted dedupe set is capped; oldest ids are dropped first. A grant
#: older than the cap that is redelivered still fails the chain check.
DEDUPE_CAP = 10_000

#: State keys this module owns in ``connector.json``.
STATE_KEYS = (
    "grant_last_seq", "grant_last_sig", "seen_grants", "grants_applied",
    "grants_refused", "grants_acked", "last_grant_refusal", "last_grant_applied",
)


def _clock(clock: Any) -> float:
    import time as _time

    return float(clock()) if callable(clock) else _time.time()


def initial_state() -> Dict[str, Any]:
    """The grant-related defaults merged into a fresh connector state."""
    return {
        "grant_last_seq": 0,
        "grant_last_sig": GENESIS,
        "seen_grants": [],
        "grants_applied": 0,
        "grants_refused": 0,
        "grants_acked": 0,
        "last_grant_refusal": None,
        "last_grant_applied": None,
    }


def load_state(raw: Mapping[str, Any]) -> Dict[str, Any]:
    """Normalise the persisted grant state; unknown values fall back safely."""
    state = initial_state()
    for key in STATE_KEYS:
        if key not in raw:
            continue
        value = raw[key]
        if key in ("grant_last_seq", "grants_applied", "grants_refused",
                   "grants_acked"):
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                state[key] = value
        elif key == "grant_last_sig":
            if isinstance(value, str) and value:
                state[key] = value
        elif key == "seen_grants":
            if isinstance(value, list):
                state[key] = [item for item in value if isinstance(item, str)]
        elif value is None or isinstance(value, dict):
            state[key] = value
    return state


class GrantProcessor:
    """One host's chain of verified grants."""

    def __init__(self, queue: Any, *, public_key: Any, org_id: str,
                 host_id: str, clock: Any = time.time,
                 dedupe_cap: int = DEDUPE_CAP) -> None:
        self.queue = queue
        self.public_key = self._public_bytes(public_key)
        self.org_id = org_id
        self.host_id = host_id
        self.clock = clock
        self.dedupe_cap = max(1, int(dedupe_cap))

    @staticmethod
    def _public_bytes(value: Any) -> bytes:
        if isinstance(value, (bytes, bytearray)):
            return bytes(value)
        if isinstance(value, str) and value:
            try:
                return bytes.fromhex(value)
            except ValueError:
                return b""
        return b""

    # -- state ----------------------------------------------------------
    def _seen(self, state: Dict[str, Any]) -> List[str]:
        seen = state.get("seen_grants")
        if not isinstance(seen, list):
            seen = []
            state["seen_grants"] = seen
        return seen

    def _record_seen(self, state: Dict[str, Any], grant_id: str) -> None:
        seen = self._seen(state)
        if grant_id not in seen:
            seen.append(grant_id)
        if len(seen) > self.dedupe_cap:
            del seen[:len(seen) - self.dedupe_cap]

    def _advance(self, state: Dict[str, Any], grant: Mapping[str, Any]) -> None:
        seq = int(grant.get("seq") or 0)
        if seq > int(state.get("grant_last_seq") or 0):
            state["grant_last_seq"] = seq
            state["grant_last_sig"] = str(grant.get("sig") or GENESIS)

    def _refuse(self, state: Dict[str, Any], refusals: List[Dict[str, str]],
                grant_id: str, code: str) -> None:
        state["grants_refused"] = int(state.get("grants_refused") or 0) + 1
        state["last_grant_refusal"] = {
            "grant_id": grant_id, "code": code, "at": _clock(self.clock),
        }
        refusals.append({"grant_id": grant_id, "code": code})

    # -- one batch ------------------------------------------------------
    def process(self, grants: Iterable[Any], state: Dict[str, Any]) -> Dict[str, Any]:
        """Verify and apply one poll's grants; mutate ``state`` in place.

        Returns the ids to acknowledge, the refusals to report, and the
        locally-settled reviews that were acked without a second decision.
        """
        applied: List[str] = []
        acked: List[str] = []
        refusals: List[Dict[str, str]] = []
        local: List[Dict[str, str]] = []
        seen = self._seen(state)

        for grant in grants:
            if not isinstance(grant, Mapping):
                self._refuse(state, refusals, "", "version")
                continue
            grant_id = grant.get("grant_id")
            if not isinstance(grant_id, str) or not grant_id:
                self._refuse(state, refusals, "", "version")
                continue

            # A redelivery of something already acked is acked again and
            # never re-applied, even if the plane lost our previous ack.
            if grant_id in seen:
                acked.append(grant_id)
                continue

            failure = verify_grant(
                grant, self.public_key, org_id=self.org_id,
                host_id=self.host_id, now=_clock(self.clock),
                max_skew=DEFAULT_MAX_SKEW)
            if failure is not None:
                self._refuse(state, refusals, grant_id, failure)
                continue

            seq = int(grant["seq"])
            last_seq = int(state.get("grant_last_seq") or 0)
            last_sig = str(state.get("grant_last_sig") or GENESIS)
            if seq <= last_seq:
                self._refuse(state, refusals, grant_id, "seq")
                continue
            if last_seq == 0:
                if grant.get("prev") != GENESIS:
                    self._refuse(state, refusals, grant_id, "prev")
                    continue
            elif grant.get("prev") != last_sig:
                self._refuse(state, refusals, grant_id, "prev")
                continue

            review_id = grant.get("review_id")
            if not isinstance(review_id, str) or not review_id:
                self._refuse(state, refusals, grant_id, "binding")
                continue
            try:
                binding = self.queue.binding_of(review_id)
            except KeyError:
                self._refuse(state, refusals, grant_id, "binding")
                continue
            except Exception:
                self._refuse(state, refusals, grant_id, "binding")
                continue
            if not hmac.compare_digest(str(binding), str(grant.get("binding") or "")):
                self._refuse(state, refusals, grant_id, "binding")
                continue

            try:
                review = self.queue.get(review_id)
            except KeyError:
                self._refuse(state, refusals, grant_id, "binding")
                continue
            except Exception:
                self._refuse(state, refusals, grant_id, "status")
                continue

            if review.status != "pending":
                # Consume the chain position and ack; the local status is the
                # report the kickoff asks for. Nothing is applied.
                self._advance(state, grant)
                self._record_seen(state, grant_id)
                acked.append(grant_id)
                local.append({"grant_id": grant_id, "status": review.status})
                continue

            try:
                self.queue.apply_grant(grant, binding=binding)
            except GrantRefused as exc:
                if exc.check == "status":
                    try:
                        current = self.queue.get(review_id).status
                    except Exception:
                        current = "unknown"
                    self._advance(state, grant)
                    self._record_seen(state, grant_id)
                    acked.append(grant_id)
                    local.append({"grant_id": grant_id, "status": current})
                else:
                    self._refuse(state, refusals, grant_id, exc.check)
                continue
            except Exception:
                self._refuse(state, refusals, grant_id, "apply")
                continue

            self._advance(state, grant)
            self._record_seen(state, grant_id)
            acked.append(grant_id)
            applied.append(grant_id)
            state["grants_applied"] = int(state.get("grants_applied") or 0) + 1
            state["last_grant_applied"] = {
                "grant_id": grant_id, "review_id": grant["review_id"],
                "decision": grant.get("decision"), "seq": seq,
                "at": _clock(self.clock),
            }

        state["grants_acked"] = int(state.get("grants_acked") or 0) + len(acked)
        return {"applied": applied, "acked": acked,
                "refusals": refusals, "local": local}


def public_key_from_config(config: Mapping[str, Any]) -> bytes:
    """The pinned ``plane_public_keys.approval`` (hex) from ``cloud.json``."""
    keys = config.get("plane_public_keys") or {}
    if not isinstance(keys, Mapping):
        return b""
    value = keys.get("approval")
    return GrantProcessor._public_bytes(value)


__all__ = [
    "DEDUPE_CAP",
    "GrantProcessor",
    "STATE_KEYS",
    "initial_state",
    "load_state",
    "public_key_from_config",
]
