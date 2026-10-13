"""What a SQL string does: its operations, the tables it reads and writes, its flags.

The analyzer classifies by **effect**, not by leading verb:

- ``WITH gone AS (DELETE FROM t RETURNING *) SELECT * FROM gone`` deletes.
- ``SELECT 'DROP TABLE x'`` and ``SELECT 1 /* ; DROP TABLE x */`` only select.
- ``EXPLAIN ANALYZE DELETE FROM t`` deletes (PostgreSQL runs it); a plain
  ``EXPLAIN`` only plans.
- ``COPY t FROM ...`` writes ``t``; ``COPY t TO ...`` reads it.

Each statement reports ``operation`` (its most severe effect), every
``effect``, its ``relations`` (table name and ``read``/``write`` access; write
dominates), and flags:

=============  ==============================================================
``unbounded``  an ``UPDATE`` or ``DELETE`` with no ``WHERE`` - every row
``opaque``     the effect is decided elsewhere: ``DO``, ``CALL``, ``EXEC``,
               ``EXECUTE``, a PL block, or an unrecognised statement. Effects
               found inside a literal body are still reported
``external``   reaches outside the database: ``COPY ... PROGRAM``, server-side
               file ``COPY``, ``INTO OUTFILE``, ``LOAD DATA INFILE``,
               ``BULK INSERT``, ``pg_read_file``, ``xp_cmdshell``, ``dblink`` ...
``multi``      more than one statement
=============  ==============================================================

``dialect="generic"`` (the default) analyses the text under the PostgreSQL,
MySQL and SQL Server lexing rules and unions the results, so a statement whose
meaning depends on the dialect is judged by its most dangerous reading. Pass a
specific dialect when you know it.

This is a lexer and a shallow parser, not a database: it never raises, it marks
what it cannot read ``partial``, and functions called from a ``SELECT`` list
(``SELECT purge_everything()``) are invisible to it, as they are to any SQL
reader without the catalog. It is a policy aid, not a boundary - database
permissions are the boundary.
"""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .lexer import DIALECTS, Dialect, Token, tokenize

#: How severe each operation is; a statement's ``operation`` is its worst effect.
SEVERITY: Dict[str, int] = {
    "other": 0, "show": 0, "set": 0, "begin": 0, "commit": 0, "rollback": 0,
    "select": 1, "create": 2, "insert": 3, "update": 4, "grant": 5, "revoke": 5,
    "unknown": 5, "delete": 6, "alter": 6, "truncate": 7, "drop": 8,
}
OPERATIONS = frozenset(SEVERITY)
GROUPS: Dict[str, frozenset] = {
    "ddl": frozenset({"create", "drop", "alter", "truncate"}),
    "dml": frozenset({"insert", "update", "delete"}),
    "write": frozenset({"create", "drop", "alter", "truncate", "insert", "update",
                        "delete", "grant", "revoke"}),
    "control": frozenset({"show", "set", "begin", "commit", "rollback"}),
}
FLAGS = frozenset({"unbounded", "opaque", "external", "multi", "partial"})

_MAX_NEST = 12
_STARTERS = frozenset({"select", "with", "insert", "update", "delete", "merge", "values",
                       "table", "replace"})
_CLAUSE_END = frozenset({
    "where", "group", "order", "limit", "having", "window", "union", "intersect",
    "except", "on", "returning", "set", "values", "select", "offset", "fetch", "for",
    "into", "when", "then", "using", "output", "option", "qualify",
})
_TABLE_OBJECTS = frozenset({"table", "view", "materialized", "schema", "database",
                            "sequence", "index", "foreign"})
_EXTERNAL_FUNCTIONS = frozenset({
    "pg_read_file", "pg_read_binary_file", "pg_ls_dir", "pg_stat_file", "lo_import",
    "lo_export", "dblink", "dblink_exec", "xp_cmdshell", "sp_oacreate", "openrowset",
    "opendatasource", "openquery", "load_file", "sys_exec", "sys_eval", "utl_http",
    "utl_file", "pg_file_write",
})
_PL_EFFECT_WORDS = {"insert": "insert", "update": "update", "delete": "delete",
                    "drop": "drop", "truncate": "truncate", "alter": "alter",
                    "create": "create", "grant": "grant", "revoke": "revoke",
                    "merge": "update"}


@dataclass(frozen=True)
class Relation:
    name: str
    access: str  # read | write


@dataclass(frozen=True)
class Statement:
    """One statement's analysis."""

    text: str
    operation: str
    effects: Tuple[str, ...]
    relations: Tuple[Relation, ...]
    unbounded: bool = False
    opaque: bool = False
    external: bool = False

    @property
    def tables(self) -> Tuple[str, ...]:
        return tuple(r.name for r in self.relations)


@dataclass(frozen=True)
class SqlAnalysis:
    """Everything a SQL string does, across its statements (and dialects)."""

    source: str
    statements: Tuple[Statement, ...] = ()
    operation: str = "other"
    effects: Tuple[str, ...] = ()
    relations: Tuple[Relation, ...] = ()
    unbounded: bool = False
    opaque: bool = False
    external: bool = False
    multi: bool = False
    partial: bool = False
    dialect: str = "generic"

    @property
    def tables(self) -> Tuple[str, ...]:
        return tuple(r.name for r in self.relations)

    def matches(self, selector: str) -> bool:
        """Whether a selector describes this SQL.

        Selectors: an operation (``"delete"``), a group (``"ddl"``, ``"dml"``,
        ``"write"``, ``"control"``), a flag (``"unbounded"``, ``"opaque"``,
        ``"external"``, ``"multi"``, ``"partial"``), or a table:
        ``"write:customers"``, ``"read:payments*"``, ``"table:audit.*"`` (globs,
        case-insensitive, matched against the full name and its last part).
        """
        selector = selector.strip().lower()
        if selector in FLAGS:
            return bool(getattr(self, selector))
        if selector in GROUPS:
            if selector == "write" and any(r.access == "write" for r in self.relations):
                return True
            return bool(GROUPS[selector] & set(self.effects))
        if selector in OPERATIONS:
            return selector in self.effects or (selector == "unknown" and self.opaque)
        kind, sep, pattern = selector.partition(":")
        if sep and kind in ("read", "write", "table"):
            for rel in self.relations:
                if kind != "table" and rel.access != kind:
                    continue
                if _glob(rel.name, pattern):
                    return True
            return False
        return False


def _glob(name: str, pattern: str) -> bool:
    name = name.lower()
    last = name.rsplit(".", 1)[-1]
    return fnmatch.fnmatchcase(name, pattern) or fnmatch.fnmatchcase(last, pattern)


def analyze_sql(sql: str, dialect: str = "generic") -> SqlAnalysis:
    """Analyse ``sql``. Never raises; unreadable input comes back ``partial``."""
    if not isinstance(sql, str):
        return SqlAnalysis(source="", partial=True, dialect=dialect)
    if dialect == "generic":
        runs = [_analyze(sql, DIALECTS[d]) for d in ("postgres", "mysql", "mssql")]
        return _merge(sql, runs)
    if dialect not in DIALECTS:
        raise ValueError("dialect must be generic or one of {}".format(", ".join(sorted(DIALECTS))))
    return _analyze(sql, DIALECTS[dialect])


def _merge(sql: str, runs: Sequence[SqlAnalysis]) -> SqlAnalysis:
    effects: Set[str] = set()
    relations: Dict[str, str] = {}
    for run in runs:
        effects.update(run.effects)
        for rel in run.relations:
            if relations.get(rel.name) != "write":
                relations[rel.name] = rel.access
    worst = max(runs, key=lambda r: SEVERITY.get(r.operation, 0))
    return SqlAnalysis(
        source=sql, statements=worst.statements,
        operation=_worst(effects), effects=tuple(sorted(effects, key=_order)),
        relations=tuple(Relation(n, a) for n, a in relations.items()),
        unbounded=any(r.unbounded for r in runs), opaque=any(r.opaque for r in runs),
        external=any(r.external for r in runs), multi=any(r.multi for r in runs),
        partial=any(r.partial for r in runs), dialect="generic",
    )


def _order(op: str) -> Tuple[int, str]:
    return (-SEVERITY.get(op, 0), op)


def _worst(effects: Iterable[str]) -> str:
    effects = list(effects)
    return max(effects, key=lambda e: (SEVERITY.get(e, 0), e)) if effects else "other"


# --- one dialect --------------------------------------------------------------


class _Acc:
    def __init__(self) -> None:
        self.effects: Set[str] = set()
        self.relations: Dict[str, str] = {}
        self.bound: Set[str] = set()  # CTE names: not tables
        self.unbounded = False
        self.opaque = False
        self.external = False

    def rel(self, name: Optional[str], access: str) -> None:
        if not name:
            return
        name = name.lower()
        if name in self.bound:
            return
        if self.relations.get(name) != "write":
            self.relations[name] = access


def _analyze(sql: str, dialect: Dialect) -> SqlAnalysis:
    tokens, complete = tokenize(sql, dialect)
    pieces = _split(tokens)
    statements: List[Statement] = []
    effects: Set[str] = set()
    relations: Dict[str, str] = {}
    for piece in pieces:
        acc = _Acc()
        _walk(piece, acc, dialect, 0)
        if not acc.effects:
            continue
        rels = tuple(Relation(n, a) for n, a in acc.relations.items())
        statements.append(Statement(
            text=" ".join(t.value for t in piece)[:2000], operation=_worst(acc.effects),
            effects=tuple(sorted(acc.effects, key=_order)), relations=rels,
            unbounded=acc.unbounded, opaque=acc.opaque, external=acc.external,
        ))
        effects.update(acc.effects)
        for rel in rels:
            if relations.get(rel.name) != "write":
                relations[rel.name] = rel.access
    return SqlAnalysis(
        source=sql, statements=tuple(statements), operation=_worst(effects),
        effects=tuple(sorted(effects, key=_order)),
        relations=tuple(Relation(n, a) for n, a in relations.items()),
        unbounded=any(s.unbounded for s in statements),
        opaque=any(s.opaque for s in statements),
        external=any(s.external for s in statements),
        multi=len(statements) > 1, partial=not complete, dialect=dialect.name,
    )


def _split(tokens: List[Token]) -> List[List[Token]]:
    pieces: List[List[Token]] = [[]]
    depth = 0
    for tok in tokens:
        if tok.kind == "punct" and tok.value == "(":
            depth += 1
        elif tok.kind == "punct" and tok.value == ")":
            depth = max(0, depth - 1)
        if tok.kind == "punct" and tok.value == ";" and depth == 0:
            pieces.append([])
            continue
        pieces[-1].append(tok)
    return [p for p in pieces if p]


def _flatten(tokens: List[Token]) -> Tuple[List[Token], List[List[Token]]]:
    """Top-level tokens, each parenthesised group replaced by a ``group``
    token whose value indexes into the returned group list."""
    top: List[Token] = []
    groups: List[List[Token]] = []
    depth = 0
    current: List[Token] = []
    for tok in tokens:
        if tok.kind == "punct" and tok.value == "(":
            if depth == 0:
                current = []
            else:
                current.append(tok)
            depth += 1
            continue
        if tok.kind == "punct" and tok.value == ")" and depth > 0:
            depth -= 1
            if depth == 0:
                groups.append(current)
                top.append(Token("group", str(len(groups) - 1)))
            else:
                current.append(tok)
            continue
        if depth > 0:
            current.append(tok)
        else:
            top.append(tok)
    if depth > 0:  # unclosed group: keep what was read
        groups.append(current)
        top.append(Token("group", str(len(groups) - 1)))
    return top, groups


def _is(tok: Optional[Token], *words: str) -> bool:
    return tok is not None and tok.kind == "word" and tok.value in words


def _walk(tokens: List[Token], acc: _Acc, dialect: Dialect, depth: int) -> None:
    if depth > _MAX_NEST:
        acc.opaque = True
        acc.effects.add("unknown")
        return
    top, groups = _flatten(tokens)
    if not top:
        return
    # Subqueries and CTE bodies anywhere in the statement run too.
    for index, tok in enumerate(top):
        if tok.kind == "group":
            _group(groups[int(tok.value)], acc, dialect, depth)
        elif tok.kind == "word" and tok.value in _EXTERNAL_FUNCTIONS:
            nxt = top[index + 1] if index + 1 < len(top) else None
            if nxt is not None and nxt.kind == "group":
                acc.external = True
    _head(top, groups, acc, dialect, depth)


def _head(top: List[Token], groups: List[List[Token]], acc: _Acc, dialect: Dialect,
          depth: int) -> None:
    """Classify a flattened statement: skip a WITH clause, then dispatch on
    the verb. A statement opening with a parenthesised query (``(SELECT ...)
    UNION ...``) has nothing left to classify: its groups were walked."""
    i = 0
    if _is(top[0], "with"):
        i = _skip_with(top, acc)
    if i >= len(top) or top[i].kind == "group":
        return
    _verb(top, groups, i, acc, dialect, depth)


def _group(inner: List[Token], acc: _Acc, dialect: Dialect, depth: int) -> None:
    """A parenthesised group: a subquery is walked; anything else is searched
    for nested subqueries."""
    first = next((t for t in inner if t.kind != "punct" or t.value not in ("(",)), None)
    if first is not None and first.kind == "word" and first.value in _STARTERS:
        _walk(inner, acc, dialect, depth + 1)
        return
    top, groups = _flatten(inner)
    for index, tok in enumerate(top):
        if tok.kind == "group":
            _group(groups[int(tok.value)], acc, dialect, depth + 1)
        elif tok.kind == "word" and tok.value in _EXTERNAL_FUNCTIONS:
            nxt = top[index + 1] if index + 1 < len(top) else None
            if nxt is not None and nxt.kind == "group":
                acc.external = True


def _skip_with(top: List[Token], acc: _Acc) -> int:
    """Past ``WITH [RECURSIVE] a [(cols)] AS [NOT] [MATERIALIZED] (...), ...``."""
    i = 1
    if _is(top[i] if i < len(top) else None, "recursive"):
        i += 1
    while i < len(top):
        tok = top[i]
        if tok.kind in ("word", "ident"):
            acc.bound.add(tok.value.lower())
            i += 1
        if i < len(top) and top[i].kind == "group":  # column list
            i += 1
        if _is(top[i] if i < len(top) else None, "as"):
            i += 1
        while _is(top[i] if i < len(top) else None, "not", "materialized"):
            i += 1
        if i < len(top) and top[i].kind == "group":  # the body, already walked
            i += 1
        if i < len(top) and top[i].kind == "punct" and top[i].value == ",":
            i += 1
            continue
        break
    return i


def _name(top: List[Token], i: int, skip: Iterable[str] = ()) -> Tuple[Optional[str], int]:
    """A (possibly qualified) object name at ``top[i]``; returns (name, next)."""
    skip = set(skip)
    while i < len(top) and _is(top[i], *skip):
        i += 1
    parts: List[str] = []
    while i < len(top):
        tok = top[i]
        # After a dot, a "string" is a double-quoted identifier read under
        # MySQL's rules (public."Orders"); it is still part of the name.
        if tok.kind in ("word", "ident") or (tok.kind == "string" and parts):
            parts.append(tok.value.lower())
            i += 1
            if i < len(top) and top[i].kind == "punct" and top[i].value == ".":
                i += 1
                continue
        break
    if not parts:
        return None, i
    return ".".join(parts), i


def _from_relations(top: List[Token], start: int, acc: _Acc, access: str = "read") -> None:
    """Every table named by FROM / JOIN / USING lists from ``start`` on."""
    i = start
    in_list = False
    while i < len(top):
        tok = top[i]
        if _is(tok, "from", "join", "using", "straight_join") or (
                _is(tok, "apply") and i > 0 and _is(top[i - 1], "cross", "outer")):
            in_list = True
            i += 1
            while i < len(top) and _is(top[i], "only", "lateral"):
                i += 1
            if i < len(top) and top[i].kind == "group":
                i += 1
                continue
            name, j = _name(top, i)
            if name and not (j < len(top) and top[j].kind == "group"):  # not a function
                acc.rel(name, access)
            i = j if j > i else i + 1
            continue
        if in_list and tok.kind == "punct" and tok.value == ",":
            i += 1
            if i < len(top) and top[i].kind == "group":
                i += 1
                continue
            name, j = _name(top, i)
            if name and not _is(top[i], *_CLAUSE_END) and not (
                    j < len(top) and top[j].kind == "group"):
                acc.rel(name, access)
            i = j if j > i else i + 1
            continue
        if _is(tok, *_CLAUSE_END) and not _is(tok, "on", "using"):
            in_list = False
        i += 1


def _has_top(top: List[Token], start: int, *words: str) -> bool:
    return any(_is(t, *words) for t in top[start:])


def _verb(top: List[Token], groups: List[List[Token]], i: int, acc: _Acc,
          dialect: Dialect, depth: int) -> None:
    verb = top[i].value if top[i].kind == "word" else ""
    nxt = i + 1

    if verb in ("select", "values"):
        acc.effects.add("select")
        _from_relations(top, nxt, acc)
        _select_into(top, nxt, acc)
        return
    if verb == "table":  # PostgreSQL: TABLE t == SELECT * FROM t
        acc.effects.add("select")
        name, _ = _name(top, nxt)
        acc.rel(name, "read")
        return
    if verb in ("insert", "replace"):
        acc.effects.add("insert")
        if verb == "replace" or _has_top(top, nxt, "conflict") and _has_top(top, nxt, "update") \
                or _has_top(top, nxt, "duplicate"):
            acc.effects.add("update")
        name, j = _name(top, nxt, ("low_priority", "delayed", "high_priority", "ignore", "into",
                                   "overwrite", "table", "or", "replace", "rollback", "abort",
                                   "fail"))
        acc.rel(name, "write")
        _from_relations(top, j, acc)
        return
    if verb == "update":
        acc.effects.add("update")
        j = nxt
        while j < len(top) and (_is(top[j], "low_priority", "ignore", "only", "top")
                                or (top[j].kind == "group" and j > nxt and _is(top[j - 1], "top"))):
            j += 1
        name, j = _name(top, j)
        acc.rel(name, "write")
        _from_relations(top, j, acc)
        if not _has_top(top, j, "where"):
            acc.unbounded = True
        return
    if verb == "delete":
        acc.effects.add("delete")
        j = nxt
        while j < len(top) and (_is(top[j], "low_priority", "quick", "ignore", "top")
                                or (top[j].kind == "group" and j > nxt and _is(top[j - 1], "top"))):
            j += 1
        name, j2 = _name(top, j, ("from", "only"))
        acc.rel(name, "write")
        if _is(top[j2] if j2 < len(top) else None, "from"):  # DELETE t FROM t JOIN ...
            other, _ = _name(top, j2 + 1, ("only",))
            acc.rel(other, "write")
        _from_relations(top, j2, acc)
        if not _has_top(top, j2, "where"):
            acc.unbounded = True
        return
    if verb == "merge":
        acc.effects.add("update")
        name, j = _name(top, nxt, ("into", "top"))
        acc.rel(name, "write")
        for k in range(j, len(top) - 1):
            if _is(top[k], "then"):
                if _is(top[k + 1], "insert"):
                    acc.effects.add("insert")
                if _is(top[k + 1], "delete"):
                    acc.effects.add("delete")
        _from_relations(top, j, acc)
        return
    if verb == "truncate":
        acc.effects.add("truncate")
        j = nxt
        while True:
            name, j = _name(top, j, ("table", "only"))
            acc.rel(name, "write")
            if j < len(top) and top[j].kind == "punct" and top[j].value == ",":
                j += 1
                continue
            break
        return
    if verb == "drop":
        acc.effects.add("drop")
        _object_names(top, nxt, acc, list_ok=True)
        return
    if verb == "create":
        acc.effects.add("create")
        j = nxt
        while _is(top[j] if j < len(top) else None, "or", "replace", "temp", "temporary",
                  "unlogged", "global", "local", "unique", "recursive", "definer", "algorithm",
                  "sql", "security"):
            j += 1
        kind = top[j].value if j < len(top) and top[j].kind == "word" else ""
        if kind == "index":
            # CREATE INDEX [name] ON table
            for k in range(j, len(top) - 1):
                if _is(top[k], "on"):
                    name, _ = _name(top, k + 1, ("only",))
                    acc.rel(name, "write")
                    break
            return
        if kind in _TABLE_OBJECTS:
            _object_names(top, j, acc, list_ok=False)
            _from_relations(top, j, acc)
        return
    if verb == "alter":
        acc.effects.add("alter")
        _object_names(top, nxt, acc, list_ok=False)
        return
    if verb in ("grant", "revoke"):
        acc.effects.add(verb)
        for k in range(nxt, len(top)):
            if _is(top[k], "on"):
                j = k + 1
                while _is(top[j] if j < len(top) else None, "table", "all", "tables",
                          "in", "schema", "sequence", "database", "function"):
                    j += 1
                name, _ = _name(top, j)
                acc.rel(name, "write")
                break
        return
    if verb == "copy":
        j = nxt
        name = None
        if j < len(top) and top[j].kind != "group":
            name, j = _name(top, j)
        direction = next((t.value for t in top[j:] if _is(t, "from", "to")), "")
        if direction == "from":
            acc.effects.add("insert")
            acc.rel(name, "write")
        else:
            acc.effects.add("select")
            acc.rel(name, "read")
        for k, tok in enumerate(top):
            if _is(tok, "from", "to") and k + 1 < len(top):
                target = top[k + 1]
                if _is(target, "program") or target.kind == "string":
                    acc.external = True
        return
    if verb == "load":  # LOAD DATA [LOCAL] INFILE 'f' INTO TABLE t
        acc.effects.add("insert")
        acc.external = True
        for k in range(nxt, len(top) - 1):
            if _is(top[k], "into"):
                name, _ = _name(top, k + 1, ("table",))
                acc.rel(name, "write")
                break
        return
    if verb == "bulk":  # BULK INSERT t FROM 'file'
        acc.effects.add("insert")
        acc.external = True
        name, _ = _name(top, nxt, ("insert",))
        acc.rel(name, "write")
        return
    if verb == "explain":
        j = nxt
        runs = False
        while j < len(top) and (_is(top[j], "analyze", "analyse", "verbose", "costs",
                                     "buffers", "format", "plan", "query", "extended",
                                     "partitions", "json", "text", "tree", "true", "false")
                                or top[j].kind == "group"):
            if _is(top[j], "analyze", "analyse"):
                runs = True
            if top[j].kind == "group" and any(t.value in ("analyze", "analyse")
                                              for t in groups[int(top[j].value)]):
                runs = True
            j += 1
        inner = _Acc()
        inner.bound = set(acc.bound)
        rest = _unflatten(top[j:], groups)
        if rest:
            sub_top, sub_groups = _flatten(rest)
            if sub_top:
                _head(sub_top, sub_groups, inner, dialect, depth + 1)
        if runs:
            acc.effects.update(inner.effects)
            for name, access in inner.relations.items():
                acc.rel(name, access)
            acc.unbounded = acc.unbounded or inner.unbounded
            acc.external = acc.external or inner.external
            acc.opaque = acc.opaque or inner.opaque
        else:
            acc.effects.add("select")
            for name in inner.relations:
                acc.rel(name, "read")
        return
    if verb == "prepare":
        # PREPARE name [(types)] AS statement: it runs later, through EXECUTE.
        for k in range(nxt, len(top)):
            if _is(top[k], "as", "from"):
                rest = _unflatten(top[k + 1:], groups)
                if rest and rest[0].kind == "string":
                    _literal_body(rest[0].value, acc, dialect, depth)
                elif rest:
                    _walk(rest, acc, dialect, depth + 1)
                break
        acc.effects.add("other")
        return
    if verb in ("call", "exec", "execute", "do", "declare"):
        acc.opaque = True
        acc.effects.add("unknown")
        for tok in _unflatten(top[nxt:], groups):
            if tok.kind == "string":
                _literal_body(tok.value, acc, dialect, depth)
        if verb == "exec" or verb == "execute":
            name, _ = _name(top, nxt, ("immediate",))
            if name and name.rsplit(".", 1)[-1] in _EXTERNAL_FUNCTIONS:
                acc.external = True
        return
    if verb == "begin":
        following = top[nxt] if nxt < len(top) else None
        if following is None or _is(following, "transaction", "tran", "work", "isolation",
                                    "read", "deferrable", "not", "distributed"):
            acc.effects.add("begin")
            return
        acc.opaque = True  # a PL/T-SQL block: BEGIN ... END
        acc.effects.add("unknown")
        _pl_effects(_unflatten(top[nxt:], groups), acc, dialect, depth)
        return
    if verb in ("start",):
        acc.effects.add("begin")
        return
    if verb in ("commit", "end"):
        acc.effects.add("commit")
        return
    if verb in ("rollback", "abort"):
        acc.effects.add("rollback")
        return
    if verb in ("set", "reset", "use", "savepoint", "release", "pragma"):
        acc.effects.add("set")
        return
    if verb in ("show", "describe", "desc", "help"):
        acc.effects.add("show")
        return
    if verb in ("vacuum", "analyze", "analyse", "reindex", "cluster", "checkpoint", "lock",
                "listen", "notify", "unlisten", "discard", "comment", "refresh", "optimize",
                "flush", "kill", "deallocate", "close", "fetch", "move", "load_extension"):
        acc.effects.add("other")
        return
    acc.opaque = True
    acc.effects.add("unknown")


def _select_into(top: List[Token], start: int, acc: _Acc) -> None:
    for k in range(start, len(top) - 1):
        if not _is(top[k], "into"):
            continue
        target = top[k + 1]
        if _is(target, "outfile", "dumpfile"):
            acc.external = True
        elif target.kind == "param":
            pass  # INTO @variable
        else:
            name, _ = _name(top, k + 1, ("temp", "temporary", "unlogged", "table"))
            if name:
                acc.effects.add("create")
                acc.rel(name, "write")
        return


def _object_names(top: List[Token], i: int, acc: _Acc, *, list_ok: bool) -> None:
    j = i
    kind_words: List[str] = []
    while j < len(top) and _is(top[j], "table", "view", "materialized", "schema", "database",
                               "sequence", "index", "function", "procedure", "trigger", "type",
                               "role", "user", "extension", "foreign", "temporary", "temp",
                               "concurrently", "domain", "policy", "rule", "server", "event",
                               "unique", "if", "not", "exists", "only", "external", "or",
                               "replace", "global", "local", "unlogged"):
        if top[j].value not in ("if", "not", "exists", "only", "concurrently"):
            kind_words.append(top[j].value)
        j += 1
    table_like = bool(set(kind_words) & _TABLE_OBJECTS) and not set(kind_words) & {
        "function", "procedure", "trigger", "type", "role", "user", "extension",
        "domain", "policy", "rule", "server", "event"}
    while True:
        name, j = _name(top, j)
        if table_like:
            acc.rel(name, "write")
        if list_ok and j < len(top) and top[j].kind == "punct" and top[j].value == ",":
            j += 1
            continue
        break


def _unflatten(top: List[Token], groups: List[List[Token]]) -> List[Token]:
    out: List[Token] = []
    for tok in top:
        if tok.kind == "group":
            out.append(Token("punct", "("))
            out.extend(groups[int(tok.value)])
            out.append(Token("punct", ")"))
        else:
            out.append(tok)
    return out


def _literal_body(body: str, acc: _Acc, dialect: Dialect, depth: int) -> None:
    """Effects of SQL held in a literal (EXEC('...'), DO $$...$$, PREPARE)."""
    if depth >= _MAX_NEST:
        acc.opaque = True
        return
    tokens, _ = tokenize(body, dialect)
    _pl_effects(tokens, acc, dialect, depth)


def _pl_effects(tokens: List[Token], acc: _Acc, dialect: Dialect, depth: int) -> None:
    """Statements inside a procedural body: each SQL statement is analysed; PL
    keywords that open a statement (BEGIN, THEN, LOOP ...) are stepped over."""
    for piece in _split(tokens):
        j = 0
        while j < len(piece) and _is(piece[j], "begin", "then", "else", "elsif", "loop",
                                     "declare", "end", "if", "do", "as", "is", "returns"):
            j += 1
        rest = piece[j:]
        if not rest:
            continue
        first = rest[0]
        if first.kind == "word" and (first.value in _STARTERS or first.value in _PL_EFFECT_WORDS
                                     or first.value in ("truncate", "drop", "alter", "create",
                                                        "grant", "revoke", "copy", "execute",
                                                        "exec", "call", "perform")):
            if first.value == "perform":  # PL/pgSQL: PERFORM is SELECT discarding rows
                rest = [Token("word", "select")] + rest[1:]
            _walk(rest, acc, dialect, depth + 1)
        else:
            for tok in rest:
                if tok.kind == "word" and tok.value in _PL_EFFECT_WORDS:
                    acc.effects.add(_PL_EFFECT_WORDS[tok.value])
                elif tok.kind == "string" and depth + 1 < _MAX_NEST:
                    _literal_body(tok.value, acc, dialect, depth + 1)
