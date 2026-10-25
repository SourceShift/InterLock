"""AES-128 and GCM, standard library only.

HPKE's mandatory suite in DAP uses AES-128-GCM. This module implements the
block cipher and the authenticated mode directly; it is not constant-time and
is intended for the same posture as the rest of ``interlock.mesh``'s pure-Python
crypto (correctness first, secrets kept out of adversary-observable timing).
"""

_SBOX = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)
_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


def _xtime(value: int) -> int:
    return ((value << 1) ^ (0x1B if value & 0x80 else 0)) & 0xFF


class AES128:
    """AES-128 block encryption (FIPS 197). Decryption is not needed for GCM."""

    block_size = 16

    def __init__(self, key: bytes):
        if len(key) != 16:
            raise ValueError("AES-128 needs a 16-byte key")
        words = [int.from_bytes(key[i:i + 4], "big") for i in range(0, 16, 4)]
        for i in range(4, 44):
            temp = words[i - 1]
            if i % 4 == 0:
                temp = ((temp << 8) & 0xFFFFFFFF) | (temp >> 24)
                temp = (int.from_bytes(bytes(_SBOX[b] for b in temp.to_bytes(4, "big")), "big")
                        ^ (_RCON[i // 4 - 1] << 24))
            words.append(words[i - 4] ^ temp)
        self._round_keys = words

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != 16:
            raise ValueError("AES block must be 16 bytes")
        state = list(block)
        self._add_round_key(state, 0)
        for rnd in range(1, 10):
            self._sub_bytes(state)
            self._shift_rows(state)
            self._mix_columns(state)
            self._add_round_key(state, rnd)
        self._sub_bytes(state)
        self._shift_rows(state)
        self._add_round_key(state, 10)
        return bytes(state)

    def _add_round_key(self, state: list, rnd: int) -> None:
        for col in range(4):
            word = self._round_keys[4 * rnd + col]
            for row in range(4):
                state[4 * col + row] ^= (word >> (24 - 8 * row)) & 0xFF

    @staticmethod
    def _sub_bytes(state: list) -> None:
        for i in range(16):
            state[i] = _SBOX[state[i]]

    @staticmethod
    def _shift_rows(state: list) -> None:
        for row in range(1, 4):
            values = [state[4 * col + row] for col in range(4)]
            for col in range(4):
                state[4 * col + row] = values[(col + row) % 4]

    @staticmethod
    def _mix_columns(state: list) -> None:
        for col in range(4):
            a = state[4 * col:4 * col + 4]
            total = a[0] ^ a[1] ^ a[2] ^ a[3]
            state[4 * col + 0] ^= total ^ _xtime(a[0] ^ a[1])
            state[4 * col + 1] ^= total ^ _xtime(a[1] ^ a[2])
            state[4 * col + 2] ^= total ^ _xtime(a[2] ^ a[3])
            state[4 * col + 3] ^= total ^ _xtime(a[3] ^ a[0])


def _ghash_mul(x: int, y: int) -> int:
    """Multiply in GF(2^128) with GCM's bit-reflected convention."""
    z = 0
    v = y
    for i in range(127, -1, -1):
        if (x >> i) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ 0xE1000000000000000000000000000000
        else:
            v >>= 1
    return z


def _ghash(h: bytes, aad: bytes, ciphertext: bytes) -> bytes:
    hv = int.from_bytes(h, "big")
    y = 0
    for data in (aad, ciphertext):
        for off in range(0, len(data), 16):
            block = data[off:off + 16].ljust(16, b"\x00")
            y = _ghash_mul(y ^ int.from_bytes(block, "big"), hv)
    lengths = (len(aad) * 8).to_bytes(8, "big") + (len(ciphertext) * 8).to_bytes(8, "big")
    y = _ghash_mul(y ^ int.from_bytes(lengths, "big"), hv)
    return y.to_bytes(16, "big")


def _inc32(block: bytes) -> bytes:
    counter = (int.from_bytes(block[12:], "big") + 1) & 0xFFFFFFFF
    return block[:12] + counter.to_bytes(4, "big")


def _ctr(cipher: AES128, nonce: bytes, data: bytes) -> bytes:
    out = bytearray()
    counter = nonce + b"\x00\x00\x00\x02"
    for off in range(0, len(data), 16):
        stream = cipher.encrypt_block(counter)
        chunk = data[off:off + 16]
        out.extend(a ^ b for a, b in zip(chunk, stream))
        counter = _inc32(counter)
    return bytes(out)


def _gcm_tag(cipher: AES128, nonce: bytes, aad: bytes, ciphertext: bytes) -> bytes:
    h = cipher.encrypt_block(b"\x00" * 16)
    s = _ghash(h, aad, ciphertext)
    j0 = nonce + b"\x00\x00\x00\x01"
    mask = cipher.encrypt_block(j0)
    return bytes(a ^ b for a, b in zip(s, mask))


def seal(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """AES-128-GCM encrypt: returns ``ciphertext || tag``."""
    if len(nonce) != 12:
        raise ValueError("GCM nonce must be 12 bytes")
    cipher = AES128(key)
    ciphertext = _ctr(cipher, nonce, plaintext)
    return ciphertext + _gcm_tag(cipher, nonce, aad, ciphertext)


def open_sealed(key: bytes, nonce: bytes, sealed: bytes, aad: bytes = b"") -> bytes:
    """AES-128-GCM decrypt; raises :class:`ValueError` on a bad tag."""
    if len(nonce) != 12:
        raise ValueError("GCM nonce must be 12 bytes")
    if len(sealed) < 16:
        raise ValueError("GCM ciphertext is shorter than its tag")
    cipher = AES128(key)
    ciphertext, tag = sealed[:-16], sealed[-16:]
    if not _constant_time_equal(_gcm_tag(cipher, nonce, aad, ciphertext), tag):
        raise ValueError("GCM authentication failed")
    return _ctr(cipher, nonce, ciphertext)


def _constant_time_equal(left: bytes, right: bytes) -> bool:
    if len(left) != len(right):
        return False
    diff = 0
    for a, b in zip(left, right):
        diff |= a ^ b
    return diff == 0
