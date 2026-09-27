"""Regenerate events.json, the checked-in conformance corpus.

    python tests/conformance/generate.py

The corpus is generated from interlock.testing.conformance so the Python side and
the stored file cannot drift; a test asserts the file matches the generator, so
editing this file by hand fails the suite rather than silently diverging.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from interlock.testing.conformance import build, write_corpus  # noqa: E402

CORPUS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "events.json")


def main() -> int:
    write_corpus(CORPUS)
    corpus = build()
    print(
        "wrote {}: {} cases, {} negatives".format(
            CORPUS, len(corpus["cases"]), len(corpus["negatives"])
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
