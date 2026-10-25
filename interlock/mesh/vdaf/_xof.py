"""Extendable output functions (XOFs)."""

from abc import ABCMeta, abstractmethod
from typing import TypeVar

from ..turboshake import TurboSHAKE128

from ._common import from_le_bytes, next_power_of_2, to_le_bytes
from ._field import Field

F = TypeVar("F", bound=Field)


class Xof(metaclass=ABCMeta):
    """The base class for XOFs."""

    # Size of the seed.
    SEED_SIZE: int

    # Name of the XOF, for use in test vector filenames.
    test_vec_name: str

    @abstractmethod
    def __init__(self, seed: bytes, dst: bytes, binder: bytes):
        """
        Construct a new instance of this XOF from the given seed, domain
        separation tag, and binder string.

        Pre-conditions:

            - `len(seed) == self.SEED_SIZE`
        """
        pass

    @abstractmethod
    def next(self, length: int) -> bytes:
        """
        Output the next `length` bytes of the XOF stream.

        Pre-conditions:

            - `length > 0`
        """
        pass

    # NOTE: The methods derive_seed(), next_vec(), and expand_into_vec()
    # are excerpted in the document, de-indented, as the figure
    # {{xof-derived-methods}}. Their width should be limited to 69
    # columns after de-indenting, or 73 columns before de-indenting, to
    # avoid warnings from xml2rfc.
    # ===================================================================
    @classmethod
    def derive_seed(cls,
                    seed: bytes,
                    dst: bytes,
                    binder: bytes) -> bytes:
        """
        Derive a new seed.

        Pre-conditions:

            - `len(seed) == cls.SEED_SIZE`
        """
        xof = cls(seed, dst, binder)
        return xof.next(cls.SEED_SIZE)

    def next_vec(self, field: type[F], length: int) -> list[F]:
        """
        Output the next `length` field elements.

        Pre-conditions:

            - `field` is sub-class of `Field`
            - `length > 0`
        """
        m = next_power_of_2(field.MODULUS) - 1
        vec: list[F] = []
        while len(vec) < length:
            x = from_le_bytes(self.next(field.ENCODED_SIZE))
            x &= m
            if x < field.MODULUS:
                vec.append(field(x))
        return vec

    @classmethod
    def expand_into_vec(cls,
                        field: type[F],
                        seed: bytes,
                        dst: bytes,
                        binder: bytes,
                        length: int) -> list[F]:
        """
        Expand the input `seed` into a vector of `length` field elements.

        Pre-conditions:

            - `field` is sub-class of `Field`
            - `len(seed) == cls.SEED_SIZE`
            - `length > 0`
        """
        xof = cls(seed, dst, binder)
        return xof.next_vec(field, length)


# NOTE: A simplified implementation of this class is excerpted in the
# document. The contents of the docstrings of methods are used in
# lieu of their actual bodies, because they provide a simpler (though
# inefficient) implementation defined in terms of the
# `TurboSHAKE128(M, D, L)` function, and not a sponge/XOF API. The
# width of the relevant portions of the class should be limited to 69
# columns, to avoid warnings from xml2rfc.
# ===================================================================
class XofTurboShake128(Xof):
    """XOF wrapper for TurboSHAKE128."""

    # Associated parameters
    SEED_SIZE = 32

    # Name of the XOF, for use in test vector filenames.
    test_vec_name = 'XofTurboShake128'

    def __init__(self, seed: bytes, dst: bytes, binder: bytes):
        '''
        self.l = 0
        self.m = \
            to_le_bytes(len(dst), 2) + dst \
            to_le_bytes(len(seed), 1) + seed + \
            binder
        '''
        self.length_consumed = 0
        self.h = TurboSHAKE128(domain=1)
        self.h.update(to_le_bytes(len(dst), 2))
        self.h.update(dst)
        self.h.update(to_le_bytes(len(seed), 1))
        self.h.update(seed)
        self.h.update(binder)

    def next(self, length: int) -> bytes:
        '''
        self.l += length

        # Function `TurboSHAKE128(M, D, L)` is as defined in
        # Section 2.1 of [RFC9861].
        #
        # Implementation note: rather than re-generate the output
        # stream each time `next()` is invoked, most implementations
        # of TurboSHAKE128 will expose an "absorb-then-squeeze" API
        # that allows stateful handling of the stream.
        stream = TurboSHAKE128(self.m, 1, self.l)
        return stream[-length:]
        '''
        return self.h.read(length)
