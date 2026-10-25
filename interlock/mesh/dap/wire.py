"""TLS presentation language, as DAP (draft-ietf-ppm-dap-20) uses it.

Only what DAP needs: fixed-width integers, fixed and variable opaque byte
strings, and vectors of structures. Every read is bounds checked, and every
decoder in :mod:`interlock.mesh.dap.messages` consumes its buffer exactly, so
a truncated or extended message is an error rather than something to guess at.

Length prefixes are big-endian, and a vector's prefix counts *bytes*, not
elements — that is the TLS convention DAP inherits.
"""

from __future__ import annotations

from typing import Callable, Iterable, List, Sequence, TypeVar

T = TypeVar("T")


class WireError(ValueError):
    """A byte string is not a valid encoding of the requested structure."""


_HEADER_SIZE = {1: 1, 2: 2, 4: 4}
_MAX_LENGTH = {1: 0xFF, 2: 0xFFFF, 4: 0xFFFFFFFF}


def _check_length(value: int, size: int, what: str) -> int:
    if value < 0:
        raise WireError("{} cannot be negative".format(what))
    limit = _MAX_LENGTH[size]
    if value > limit:
        raise WireError("{} is {} bytes, over the {}-byte maximum".format(
            what, value, limit))
    return value


class Reader:
    """A cursor over one encoded message."""

    __slots__ = ("_data", "_offset")

    def __init__(self, data: bytes):
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise WireError("expected bytes")
        self._data = bytes(data)
        self._offset = 0

    def __len__(self) -> int:
        return len(self._data)

    @property
    def offset(self) -> int:
        return self._offset

    def remaining(self) -> int:
        return len(self._data) - self._offset

    def since(self, start: int) -> bytes:
        """The bytes consumed between ``start`` and the current offset.

        Needed for nested structures whose exact encoding is itself an input to
        a key schedule (DAP's HPKE AAD), where re-encoding a decoded copy is not
        good enough.
        """
        if not 0 <= start <= self._offset:
            raise WireError("invalid slice start {}".format(start))
        return self._data[start:self._offset]

    def take(self, length: int) -> bytes:
        length = _check_length(length, 4, "field length")
        end = self._offset + length
        if end > len(self._data):
            raise WireError(
                "truncated message: wanted {} bytes at offset {}, {} remain"
                .format(length, self._offset, self.remaining()))
        chunk = self._data[self._offset:end]
        self._offset = end
        return chunk

    def uint8(self) -> int:
        return self.take(1)[0]

    def uint16(self) -> int:
        return int.from_bytes(self.take(2), "big")

    def uint32(self) -> int:
        return int.from_bytes(self.take(4), "big")

    def uint64(self) -> int:
        return int.from_bytes(self.take(8), "big")

    def opaque(self, length: int) -> bytes:
        """``opaque x[N]`` — no length prefix."""
        return self.take(length)

    def var_opaque(self, size: int = 2) -> bytes:
        """``opaque x<0..2^(8*size)-1>``."""
        length = int.from_bytes(self.take(_HEADER_SIZE[size]), "big")
        return self.take(length)

    def vector(self, decode_item: Callable[["Reader"], T], size: int = 2) -> List[T]:
        """``T x<0..2^(8*size)-1>`` — a byte-length-prefixed run of items."""
        length = int.from_bytes(self.take(_HEADER_SIZE[size]), "big")
        end = self._offset + length
        if end > len(self._data):
            raise WireError("vector length {} exceeds the message".format(length))
        items: List[T] = []
        while self._offset < end:
            before = self._offset
            items.append(decode_item(self))
            if self._offset <= before:
                raise WireError("vector decoder made no progress")
            if self._offset > end:
                raise WireError("vector item overran its declared length")
        return items

    def rest(self, decode_item: Callable[["Reader"], T]) -> List[T]:
        """``T x[message_length]`` — items until the buffer is exhausted."""
        items: List[T] = []
        while self._offset < len(self._data):
            before = self._offset
            items.append(decode_item(self))
            if self._offset <= before:
                raise WireError("sequence decoder made no progress")
        return items

    def finish(self) -> None:
        """Reject trailing bytes, which usually mean a misread field."""
        if self._offset != len(self._data):
            raise WireError(
                "{} trailing byte(s) after the message".format(self.remaining()))


class Writer:
    """An encoder for one message."""

    __slots__ = ("_parts", "_size")

    def __init__(self):
        self._parts: List[bytes] = []
        self._size = 0

    def __len__(self) -> int:
        return self._size

    def raw(self, data: bytes) -> "Writer":
        part = bytes(data)
        self._parts.append(part)
        self._size += len(part)
        return self

    def uint8(self, value: int) -> "Writer":
        return self._uint(value, 1)

    def uint16(self, value: int) -> "Writer":
        return self._uint(value, 2)

    def uint32(self, value: int) -> "Writer":
        return self._uint(value, 4)

    def uint64(self, value: int) -> "Writer":
        return self._uint(value, 8)

    def _uint(self, value: int, width: int) -> "Writer":
        if not isinstance(value, int) or isinstance(value, bool):
            raise WireError("integer field got {!r}".format(value))
        if not 0 <= value < 1 << (8 * width):
            raise WireError("{} does not fit in {} byte(s)".format(value, width))
        return self.raw(value.to_bytes(width, "big"))

    def var_opaque(self, data: bytes, size: int = 2) -> "Writer":
        part = bytes(data)
        _check_length(len(part), size, "opaque field")
        return self.raw(len(part).to_bytes(_HEADER_SIZE[size], "big")).raw(part)

    def vector(self, encoded_items: Iterable[bytes], size: int = 2) -> "Writer":
        body = b"".join(bytes(item) for item in encoded_items)
        _check_length(len(body), size, "vector")
        return self.raw(len(body).to_bytes(_HEADER_SIZE[size], "big")).raw(body)

    def bytes(self) -> bytes:
        return b"".join(self._parts)


def encode(fields: Sequence[object]) -> bytes:
    """Encode a list of already-built fields; a thin convenience wrapper."""
    writer = Writer()
    for item in fields:
        writer.raw(bytes(item))  # type: ignore[arg-type]
    return writer.bytes()


def decode(data: bytes, decode_fn: Callable[["Reader"], T]) -> T:
    """Decode one structure and insist that it consumed all of ``data``."""
    reader = Reader(data)
    value = decode_fn(reader)
    reader.finish()
    return value


def uint16_vector(items: Iterable[bytes]) -> bytes:
    """Encode a byte-length-prefixed list of encoded structures."""
    return Writer().vector(items, 2).bytes()
