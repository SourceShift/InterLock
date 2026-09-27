"""Shipped test material: fixtures and a language-neutral conformance corpus.

This lives in the package rather than under ``tests/`` so another-language
sensor can be pointed at the same rules. The Node.js client's job is to encode
the corpus's events and honour the corpus's verdicts; it needs the fixture
engine to be importable, not to read this repo's test directory.
"""
from __future__ import annotations

__all__: list = []
