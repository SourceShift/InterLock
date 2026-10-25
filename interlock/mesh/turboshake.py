"""TurboSHAKE128, the XOF both Prio3 and DAP depend on (RFC 9861).

A small, self-contained Keccak-p[1600, 12] sponge. Like the rest of
``interlock.mesh`` it is standard library only and, like the pure-Python
Ed25519, it is written for correctness rather than constant-time operation:
do not use it to guard a secret whose timing an attacker can observe.
"""

_RATE = 168          # TurboSHAKE128: 1344-bit rate, 256-bit capacity

# The last twelve of the twenty-four Keccak-f[1600] round constants.
_RC = (
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)

_ROT = (
    0, 1, 62, 28, 27,
    36, 44, 6, 55, 20,
    3, 10, 43, 25, 39,
    41, 45, 15, 21, 8,
    18, 2, 61, 56, 14,
)

_MASK = (1 << 64) - 1


def _rol(value: int, shift: int) -> int:
    shift %= 64
    return ((value << shift) | (value >> (64 - shift))) & _MASK if shift else value


def _keccak_p(state: list) -> None:
    """Keccak-p[1600, 12] over 25 little-endian 64-bit lanes."""
    for rc in _RC:
        # theta
        c = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
             for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] ^= d[x]
        # rho and pi
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rol(state[x + 5 * y], _ROT[x + 5 * y])
        # chi
        for x in range(5):
            for y in range(5):
                i = x + 5 * y
                state[i] = b[i] ^ ((~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y])
        # iota
        state[0] ^= rc


class TurboSHAKE128:
    """Streaming ``TurboSHAKE128(M, D, L)`` with ``M`` appended via ``update``.

    ``domain`` must be in ``0x01..0x7f`` (RFC 9861, Section 2.1). The first
    call to :meth:`read` finalises the sponge; later calls continue the same
    output stream.
    """

    def __init__(self, domain: int = 0x01):
        if not 0x01 <= domain <= 0x7F:
            raise ValueError("TurboSHAKE domain must be in 0x01..0x7f")
        self._domain = domain
        self._state = [0] * 25
        self._absorbed = bytearray()
        self._pos = _RATE
        self._final = False

    def update(self, data: bytes) -> "TurboSHAKE128":
        if self._final:
            raise RuntimeError("cannot update a finalised TurboSHAKE128")
        self._absorbed.extend(data)
        return self

    def _finalise(self) -> None:
        padded = bytearray(self._absorbed)
        padded.append(self._domain)
        padded.extend(b"\x00" * ((_RATE - len(padded) % _RATE) % _RATE or _RATE))
        # The last byte of the final block carries the pad10*1 final bit; if the
        # domain byte landed there, xor composes it as D | 0x80.
        padded[-1] ^= 0x80
        for off in range(0, len(padded), _RATE):
            block = padded[off:off + _RATE]
            for i in range(_RATE // 8):
                self._state[i] ^= int.from_bytes(block[8 * i:8 * i + 8], "little")
            if off + _RATE < len(padded):
                _keccak_p(self._state)
        self._pos = _RATE
        self._final = True

    def read(self, length: int) -> bytes:
        if length < 0:
            raise ValueError("length must be non-negative")
        if not self._final:
            self._finalise()
        out = bytearray()
        while len(out) < length:
            if self._pos >= _RATE:
                _keccak_p(self._state)
                self._pos = 0
            take = min(_RATE - self._pos, length - len(out))
            out.extend(b"".join(
                self._state[i].to_bytes(8, "little")
                for i in range(self._pos // 8, (self._pos + take + 7) // 8)
            )[self._pos % 8:self._pos % 8 + take])
            self._pos += take
        return bytes(out)


def turboshake128(message: bytes, domain: int = 0x01, length: int = 32) -> bytes:
    """One-shot ``TurboSHAKE128(M, D, L)``."""
    shake = TurboSHAKE128(domain)
    shake.update(message)
    return shake.read(length)
