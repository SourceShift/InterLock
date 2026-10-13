"""SQL tokenizer: words, identifiers and punctuation, with literals and comments out.

Classification is only as good as the tokens under it. ``SELECT 'DROP TABLE x'``
must not read as a drop, ``/* DELETE */`` must not read as a delete, and a
PostgreSQL function body in ``$$ ... $$`` must stay one literal. This module
turns SQL text into a flat token list that the analyzer can walk.

Dialects disagree on exactly the details that decide what is code: whether a
backslash escapes a quote (MySQL yes, PostgreSQL no), whether ``/* */`` nests
(PostgreSQL yes, MySQL no), whether ``#`` starts a comment (MySQL only),
whether ``--2`` is a comment (PostgreSQL yes, MySQL needs a space), whether
``$tag$`` quotes (PostgreSQL only) and whether ``[x]`` is an identifier
(SQL Server only). :data:`DIALECTS` encodes each one; the analyzer's
``generic`` mode runs every dialect and unions the results, so text that is
ambiguous between dialects can only add findings, never hide one.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Tuple

#: Longest input tokenized; the rest is ignored and the result marked partial.
MAX_SQL = 256 * 1024


@dataclass(frozen=True)
class Dialect:
    name: str
    backslash_escapes: bool  # '\'' escapes a quote inside '...'
    nested_comments: bool  # /* /* */ */
    hash_comments: bool  # # to end of line
    dash_needs_space: bool  # '-- ' (MySQL) vs '--' (standard)
    dollar_quotes: bool  # $tag$ ... $tag$
    bracket_identifiers: bool  # [name]
    double_quote_strings: bool  # "..." is a string, not an identifier


DIALECTS = {
    "postgres": Dialect("postgres", False, True, False, False, True, False, False),
    "mysql": Dialect("mysql", True, False, True, True, False, False, True),
    "mssql": Dialect("mssql", False, False, False, False, False, True, False),
    "sqlite": Dialect("sqlite", False, False, False, False, False, True, False),
}


@dataclass(frozen=True)
class Token:
    kind: str  # word | ident | string | number | punct | param | executable
    value: str  # words lowercased; identifiers as written (unquoted)


_WORD = re.compile(r"[^\W\d][\w$]*")
_NUMBER = re.compile(r"\d+(?:\.\d*)?(?:[eE][+-]?\d+)?|\.\d+(?:[eE][+-]?\d+)?")
_DOLLAR = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)?\$")
_PARAM = re.compile(r"\$\d+|\?|:[A-Za-z_][A-Za-z0-9_]*|@@?[A-Za-z_][A-Za-z0-9_.$]*")


def tokenize(sql: str, dialect: Dialect) -> Tuple[List[Token], bool]:
    """Tokens of ``sql`` under ``dialect``, and whether every literal closed.

    String literals become ``string`` tokens carrying their content (callers
    decide whether content matters - ``EXEC('...')`` bodies do).
    """
    tokens: List[Token] = []
    complete = True
    text = sql[:MAX_SQL]
    if len(sql) > MAX_SQL:
        complete = False
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c.isspace():
            i += 1
            continue
        # --- comments -----------------------------------------------------
        if text.startswith("--", i):
            if dialect.dash_needs_space and not (i + 2 >= n or text[i + 2] in " \t\r\n"):
                tokens.append(Token("punct", "-"))
                i += 1
                continue
            end = text.find("\n", i)
            i = n if end < 0 else end + 1
            continue
        if c == "#" and dialect.hash_comments:
            end = text.find("\n", i)
            i = n if end < 0 else end + 1
            continue
        if text.startswith("/*", i):
            if text.startswith("/*!", i) and dialect.name == "mysql":
                # MySQL executable comment: the body runs. Drop only the marker.
                j = i + 3
                while j < n and text[j].isdigit():
                    j += 1
                end = text.find("*/", j)
                body = text[j:] if end < 0 else text[j:end]
                inner, ok = tokenize(body, dialect)
                tokens.extend(inner)
                complete = complete and ok and end >= 0
                i = n if end < 0 else end + 2
                continue
            i, closed = _skip_block_comment(text, i, dialect.nested_comments)
            complete = complete and closed
            continue
        # --- literals -------------------------------------------------------
        if c in ("E", "e") and i + 1 < n and text[i + 1] == "'" and dialect.name == "postgres":
            value, i, closed = _read_quoted(text, i + 1, "'", backslash=True)
            tokens.append(Token("string", value))
            complete = complete and closed
            continue
        if c in ("N", "n") and i + 1 < n and text[i + 1] == "'":
            i += 1  # N'...' national string
            c = "'"
        if c == "'":
            value, i, closed = _read_quoted(text, i, "'", backslash=dialect.backslash_escapes)
            tokens.append(Token("string", value))
            complete = complete and closed
            continue
        if c == '"':
            value, i, closed = _read_quoted(text, i, '"', backslash=dialect.backslash_escapes
                                            and dialect.double_quote_strings)
            tokens.append(Token("string" if dialect.double_quote_strings else "ident", value))
            complete = complete and closed
            continue
        if c == "`":
            value, i, closed = _read_quoted(text, i, "`", backslash=False)
            tokens.append(Token("ident", value))
            complete = complete and closed
            continue
        if c == "[" and dialect.bracket_identifiers:
            end = text.find("]", i + 1)
            if end < 0:
                tokens.append(Token("ident", text[i + 1:]))
                complete = False
                i = n
            else:
                tokens.append(Token("ident", text[i + 1:end]))
                i = end + 1
            continue
        if c == "$" and dialect.dollar_quotes:
            m = _DOLLAR.match(text, i)
            if m:
                tag = m.group(0)
                end = text.find(tag, m.end())
                if end < 0:
                    tokens.append(Token("string", text[m.end():]))
                    complete = False
                    i = n
                else:
                    tokens.append(Token("string", text[m.end():end]))
                    i = end + len(tag)
                continue
        # --- everything else -------------------------------------------------
        m = _PARAM.match(text, i)
        if m and (c != ":" or not text.startswith("::", i)):
            tokens.append(Token("param", m.group(0)))
            i = m.end()
            continue
        if text.startswith("::", i):
            tokens.append(Token("punct", "::"))
            i += 2
            continue
        m = _WORD.match(text, i)
        if m:
            tokens.append(Token("word", m.group(0).lower()))
            i = m.end()
            continue
        m = _NUMBER.match(text, i)
        if m:
            tokens.append(Token("number", m.group(0)))
            i = m.end()
            continue
        tokens.append(Token("punct", c))
        i += 1
    return tokens, complete


def _skip_block_comment(text: str, i: int, nested: bool) -> Tuple[int, bool]:
    depth = 0
    n = len(text)
    while i < n:
        if text.startswith("/*", i):
            depth = depth + 1 if (nested or depth == 0) else depth
            i += 2
            continue
        if text.startswith("*/", i):
            depth -= 1
            i += 2
            if depth <= 0:
                return i, True
            continue
        i += 1
    return n, False


def _read_quoted(text: str, i: int, quote: str, *, backslash: bool) -> Tuple[str, int, bool]:
    """Read a quoted span starting at ``text[i] == quote``; doubled quotes escape."""
    out: List[str] = []
    j = i + 1
    n = len(text)
    while j < n:
        ch = text[j]
        if backslash and ch == "\\" and j + 1 < n:
            out.append(text[j + 1])
            j += 2
            continue
        if ch == quote:
            if j + 1 < n and text[j + 1] == quote:
                out.append(quote)
                j += 2
                continue
            return "".join(out), j + 1, True
        out.append(ch)
        j += 1
    return "".join(out), n, False
