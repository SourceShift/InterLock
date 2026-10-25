"""The ping-pong VDAF topology, as DAP uses it.

Adapted from ``cfrg/draft-irtf-cfrg-vdaf`` at tag
``draft-irtf-cfrg-vdaf-22`` (``vdaf_poc/vdaf_ping_pong.py``, BSD-3-Clause; see
``LICENSE.md`` beside this package). The state machine, the ``encode`` /
``decode`` framing and the transition rules are upstream's; only the typing was
reduced to what Python 3.9 needs.

A VDAF mixed with ``PingPong`` gets the six methods DAP calls by name. The
states are opaque to DAP: it only asks which of ``Continued``,
``FinishedWithOutbound``, ``Finished`` or ``Rejected`` came back and reads
``outbound`` / ``out_share``.
"""

from __future__ import annotations

from typing import Any, List, Tuple

from ._common import byte, from_be_bytes, front, to_be_bytes


class State:
    """Terminal or non-terminal outcome of one ping-pong transition."""


class Rejected(State):
    """The report was invalid; it is removed from the candidate set."""


class Continued(State):
    """Verification is unfinished; ``outbound`` must reach the peer."""

    def __init__(self, verify_state: Any, verify_round: int, outbound: bytes):
        self.verify_state = verify_state
        self.verify_round = verify_round
        self.outbound = outbound

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, Continued)
            and self.verify_state == other.verify_state
            and self.verify_round == other.verify_round
            and self.outbound == other.outbound
        )


class Finished(State):
    """Verification is complete and ``out_share`` may be committed."""

    def __init__(self, out_share: Any):
        self.out_share = out_share

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Finished) and self.out_share == other.out_share


class FinishedWithOutbound(State):
    """The sender finished, but the peer still needs ``outbound``."""

    def __init__(self, out_share: Any, outbound: bytes):
        self.out_share = out_share
        self.outbound = outbound

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, FinishedWithOutbound)
            and self.out_share == other.out_share
            and self.outbound == other.outbound
        )


class PingPong:
    """Mixin: the DAP ping-pong methods for a two- or n-round VDAF."""

    ROUNDS: int

    # The methods below are provided by the VDAF this is mixed into. Declared
    # here only to make the dependency visible to a reader.
    def verify_init(self, verify_key, ctx, agg_id, agg_param, nonce,
                    public_share, input_share):  # pragma: no cover - abstract
        raise NotImplementedError

    def verify_next(self, ctx, verify_state, verifier_message):  # pragma: no cover
        raise NotImplementedError

    def verifier_shares_to_message(self, ctx, agg_param, verifier_shares):  # pragma: no cover
        raise NotImplementedError

    def encode_verifier_share(self, verifier_share) -> bytes:  # pragma: no cover
        raise NotImplementedError

    def decode_verifier_share(self, verify_state, encoded: bytes):  # pragma: no cover
        raise NotImplementedError

    def encode_verifier_message(self, verifier_message) -> bytes:  # pragma: no cover
        raise NotImplementedError

    def decode_verifier_message(self, verify_state, encoded: bytes):  # pragma: no cover
        raise NotImplementedError

    def encode_agg_param(self, agg_param) -> bytes:  # pragma: no cover
        raise NotImplementedError

    def decode_agg_param(self, encoded: bytes):  # pragma: no cover
        raise NotImplementedError

    def encode_input_share(self, input_share) -> bytes:  # pragma: no cover
        raise NotImplementedError

    def decode_input_share(self, agg_id: int, encoded: bytes):  # pragma: no cover
        raise NotImplementedError

    def encode_public_share(self, public_share) -> bytes:  # pragma: no cover
        raise NotImplementedError

    def decode_public_share(self, encoded: bytes):  # pragma: no cover
        raise NotImplementedError

    # --- Leader -----------------------------------------------------------

    def ping_pong_leader_init(self, vdaf_verify_key: bytes, ctx: bytes,
                              agg_param: bytes, nonce: bytes,
                              public_share: bytes, input_share: bytes) -> State:
        """Leader: prepare its own input share and produce the first message."""
        try:
            verify_state, verifier_share = self.verify_init(
                vdaf_verify_key,
                ctx,
                0,
                self.decode_agg_param(agg_param),
                nonce,
                self.decode_public_share(public_share),
                self.decode_input_share(0, input_share),
            )
            encoded_verifier_share = self.encode_verifier_share(verifier_share)
            return Continued(verify_state, 0,
                             encode(0, encoded_verifier_share))  # initialize
        except Exception:
            return Rejected()

    def ping_pong_leader_continued(self, ctx: bytes, agg_param: bytes,
                                   state: Continued, inbound: bytes) -> State:
        """Leader: consume the Helper's ``continue`` and finish."""
        return self.ping_pong_continued(True, ctx, agg_param, state, inbound)

    # --- Helper -----------------------------------------------------------

    def ping_pong_helper_init(self, vdaf_verify_key: bytes, ctx: bytes,
                              agg_param: bytes, nonce: bytes,
                              public_share: bytes, input_share: bytes,
                              inbound: bytes) -> State:
        """Helper: consume the Leader's ``initialize`` and respond."""
        try:
            verify_state, verifier_share = self.verify_init(
                vdaf_verify_key,
                ctx,
                1,
                self.decode_agg_param(agg_param),
                nonce,
                self.decode_public_share(public_share),
                self.decode_input_share(1, input_share),
            )

            inbound_type, inbound_items = decode(inbound)
            if inbound_type != 0:  # initialize
                return Rejected()

            verifier_shares = [
                self.decode_verifier_share(verify_state, inbound_items[0]),
                verifier_share,
            ]
            return self.ping_pong_transition(
                ctx, self.decode_agg_param(agg_param),
                verifier_shares, verify_state, 0)
        except Exception:
            return Rejected()

    def ping_pong_helper_continued(self, ctx: bytes, agg_param: bytes,
                                   state: Continued, inbound: bytes) -> State:
        """Helper: continue a multi-round VDAF (unreachable for Prio3)."""
        return self.ping_pong_continued(False, ctx, agg_param, state, inbound)

    # --- Shared transitions -------------------------------------------------

    def ping_pong_transition(self, ctx: bytes, agg_param, verifier_shares: List[Any],
                             verify_state, verify_round: int) -> State:
        """Combine both verifier shares and step the local state."""
        verifier_message = self.verifier_shares_to_message(
            ctx, agg_param, verifier_shares)
        encoded_verifier_message = self.encode_verifier_message(verifier_message)
        out = self.verify_next(ctx, verify_state, verifier_message)
        if verify_round + 1 == self.ROUNDS:
            return FinishedWithOutbound(
                out, encode(2, encoded_verifier_message))  # finalize
        verify_state, verifier_share = out
        encoded_verifier_share = self.encode_verifier_share(verifier_share)
        return Continued(
            verify_state, verify_round + 1,
            encode(1, encoded_verifier_message, encoded_verifier_share))

    def ping_pong_continued(self, is_leader: bool, ctx: bytes,
                            agg_param: bytes, state: Continued,
                            inbound: bytes) -> State:
        try:
            verify_round = state.verify_round
            inbound_type, inbound_items = decode(inbound)
            if inbound_type == 0:  # initialize
                return Rejected()

            verifier_message = self.decode_verifier_message(
                state.verify_state, inbound_items[0])
            out = self.verify_next(ctx, state.verify_state, verifier_message)
            if verify_round + 1 < self.ROUNDS and inbound_type == 1:  # continue
                verify_state, verifier_share = out
                verifier_shares = [
                    self.decode_verifier_share(verify_state, inbound_items[1]),
                    verifier_share,
                ]
                if is_leader:
                    verifier_shares.reverse()
                return self.ping_pong_transition(
                    ctx, self.decode_agg_param(agg_param),
                    verifier_shares, verify_state, verify_round + 1)
            elif verify_round + 1 == self.ROUNDS and inbound_type == 2:  # finish
                return Finished(out)
            return Rejected()
        except Exception:
            return Rejected()


def encode(message_type: int, *items: bytes) -> bytes:
    """``message_type`` then one ``u32be``-length-prefixed item per argument."""
    encoded = byte(message_type)
    for item in items:
        encoded += to_be_bytes(len(item), 4)
        encoded += item
    return encoded


def decode(encoded: bytes) -> Tuple[int, List[bytes]]:
    """Inverse of :func:`encode`; rejects unknown types and trailing bytes."""
    (message_type_byte, encoded) = front(1, encoded)
    message_type = message_type_byte[0]
    if message_type == 0:    # initialize
        num_counts = 1   # verifier share
    elif message_type == 1:  # continue
        num_counts = 2   # verifier message, verifier share
    elif message_type == 2:  # finish
        num_counts = 1   # verifier message
    else:
        raise ValueError('unexpected message type: {}'.format(message_type))
    items = []
    for _ in range(num_counts):
        (encoded_item_len, encoded) = front(4, encoded)
        item_len = from_be_bytes(encoded_item_len)
        (item, encoded) = front(item_len, encoded)
        items.append(item)
    if len(encoded) > 0:
        raise ValueError('unexpected message length')
    return (message_type, items)
