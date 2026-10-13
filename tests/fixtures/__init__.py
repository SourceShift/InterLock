"""Importable rule modules for the sidecar's ``--rules module:attr`` spec.

The smoke test starts a real daemon from the command line, which imports its
rules by dotted path (``tests.fixtures.rules:rules``). That path has to resolve
in the *daemon's* interpreter, run from the repository root, so the fixtures
live in this importable package rather than in an ad-hoc temporary file.
"""
