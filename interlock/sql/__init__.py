"""Analyse SQL strings: operations, tables read and written, and risk flags.

``analyze_sql(text)`` lexes the text (comments and literals out, dialect rules
for quoting and escapes) and classifies every statement by its effects - a
``WITH ... AS (DELETE ...) SELECT`` deletes, ``SELECT 'DROP TABLE x'`` only
selects. See :mod:`interlock.sql.analyze` for the selectors policies use
(``"delete"``, ``"ddl"``, ``"write:customers"``, ``"unbounded"`` ...).
"""
from .analyze import (
    FLAGS,
    GROUPS,
    OPERATIONS,
    SEVERITY,
    Relation,
    SqlAnalysis,
    Statement,
    analyze_sql,
)
from .lexer import DIALECTS, tokenize

__all__ = [
    "analyze_sql",
    "SqlAnalysis",
    "Statement",
    "Relation",
    "OPERATIONS",
    "SEVERITY",
    "GROUPS",
    "FLAGS",
    "DIALECTS",
    "tokenize",
]
