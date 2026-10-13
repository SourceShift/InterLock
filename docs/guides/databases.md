# Guard database and API tools

Agents are most useful, and most dangerous, when they can query data. This
guide covers the rules that understand **what a query does** and **what comes
back**: SQL analysis, data masking, personal data in arguments, and HTTP
response status and size.

## Judge SQL by what it does

`sql_statement_guard` parses each query argument and classifies it by its
**effects**, not its first word:

| The agent sends | interlock sees |
|---|---|
| `WITH gone AS (DELETE FROM t RETURNING *) SELECT * FROM gone` | a delete, unbounded |
| `SELECT 'DROP TABLE x'` | a select (the drop is inside a string) |
| `SELECT 1 /* ; DROP TABLE x */` | a select (inside a comment) |
| `EXPLAIN ANALYZE DELETE FROM t` | a delete (PostgreSQL runs it) |
| `COPY customers TO PROGRAM 'curl …'` | a read of `customers`, external |
| `UPDATE accounts SET balance = 0` | an update with no `WHERE`: unbounded |
| `DO $$ BEGIN DELETE FROM t; END $$` | opaque, and a delete inside it |

```python
from interlock.detectors.sql_statement_guard import sql_statement_guard

interlock.install(rules=[
    sql_statement_guard(
        block=["ddl", "unbounded", "external", "write:payments*"],
        escalate=["delete", "grant"],
    ),
])
```

Or keep an agent read-only:

```python
sql_statement_guard(read_only=True)   # only SELECT/SHOW/SET/transactions pass
```

Selectors:

| Selector | Matches |
|---|---|
| `select`, `insert`, `update`, `delete`, `create`, `drop`, `alter`, `truncate`, `grant`, `revoke`, `unknown` | that operation anywhere in the text |
| `ddl`, `dml`, `write`, `control` | a group (`write` also matches any table written) |
| `read:customers`, `write:pay*`, `table:audit.*` | a table read, written, or either (globs; the full name or its last part) |
| `unbounded` | `UPDATE`/`DELETE` with no `WHERE` |
| `opaque` | `DO`, `CALL`, `EXEC`, `EXECUTE`, a PL block, or an unrecognised statement |
| `external` | `COPY … PROGRAM`, server-side file I/O, `INTO OUTFILE`, `LOAD DATA INFILE`, `xp_cmdshell`, `pg_read_file`, `dblink` … |
| `multi` | more than one statement |

By default the guard reads arguments named like SQL (`sql`, `query`,
`statement`, …); pass `keys=` for others. The same selectors work in
[declarative policies](policies.md): `{"sql": "unbounded"}`.

**Dialects.** The default, `dialect="generic"`, lexes the text under
PostgreSQL, MySQL and SQL Server rules and unions the results. Where dialects
disagree (does `\'` escape a quote? do comments nest? is `--2` a comment?), a
statement hidden by one reading is still found by another. If you know your
database, pass `dialect="postgres"` (or `mysql`, `mssql`, `sqlite`).

**Limits.** This is a lexer, not a database. A function called from a `SELECT`
list (`SELECT purge_everything()`) is invisible to it, as it is to anything
without the catalog. It never raises, and text it can't fully read is reported
`partial`. Database permissions are the boundary; this is the policy aid in
front of them.

## Mask what comes back

`data_masking_guard` masks sensitive values in tool results before the agent
reads them:

```python
from interlock.detectors.data_masking_guard import data_masking_guard

interlock.install(rules=[
    data_masking_guard(rules=[
        {"columns": ["password", "customer.ssn"], "strategy": "mask"},
        {"entities": ["CREDIT_CARD"], "strategy": "partial", "keep_last": 4},
        {"entities": ["EMAIL_ADDRESS"], "strategy": "hash"},
        {},                                  # every other entity: redact
    ], hash_key=os.environ["MASKING_KEY"]),
])
```

```text
{"name": "Ada", "email": "ada@example.com", "card": "4111 1111 1111 1111"}
→ {"name": "Ada", "email": "hash:12016e848bcbd707", "card": "**** **** **** 1111"}
```

**Rules** are checked in order:

- A **column rule** (`columns`) masks a value outright by its key, without
  running detection. A dotted pattern (`customer.ssn`) matches that run of keys
  anywhere in the path; the most specific match wins.
- An **entity rule** (`entities`, empty for all) detects values in text.

**Strategies:**

| Strategy | Writes |
|---|---|
| `redact` (default) | `[REDACTED:EMAIL_ADDRESS]` |
| `mask` | `*` for every character (`mask_char` changes it), length kept |
| `partial` | keeps the last `keep_last` characters and the punctuation: `**** **** **** 1111` |
| `hash` | `hash:` + 16 hex of an HMAC under `hash_key`. Equal values stay equal (joins and grouping still work), but without the key nobody can test guesses against it |

**Entities.** Detection is local: patterns, checksums, and context words near
a match. No model, no network.

| Entity | Validated by |
|---|---|
| `CREDIT_CARD` | Luhn |
| `IBAN_CODE` | mod-97 and the country's length |
| `US_SSN`, `US_ITIN` | area/group/serial rules |
| `ABA_ROUTING` | the routing checksum (noisy: needs a word like "routing" nearby) |
| `BR_CPF`, `BR_CNPJ` | mod-11 check digits |
| `IN_AADHAAR` | Verhoeff |
| `DE_TAX_ID` | ISO 7064 MOD 11,10 and the digit-frequency rule (noisy: needs "Steuer-ID" or similar nearby) |
| `UK_NINO`, `EMAIL_ADDRESS`, `PHONE_NUMBER`, `IP_ADDRESS` | format (phone and IP addresses are noisy) |
| `AWS_ACCESS_KEY`, `GITHUB_TOKEN`, `SLACK_TOKEN`, `GOOGLE_API_KEY`, `STRIPE_KEY`, `API_KEY`, `PRIVATE_KEY`, `URL_PASSWORD` | vendor format |
| `JWT` | the header decodes and names an `alg` |

Matches below `threshold` (default 0.5) are left alone; noisy entities reach it
only with a context word nearby. `allow_list=` exempts exact values. Names and
places aren't detected: that needs a language model.

**Structure.** Results are walked through dicts and lists. A
`{"columns": [...], "rows": [[...], ...]}` table applies column names to each
cell, and every other key of that object is still masked.

**Receipts** record what was masked (`"masked": {"EMAIL_ADDRESS": 2}`), never
the values, and `interlock report` totals it.

## Stop personal data going out

`pii_argument_guard` looks for entities in a call's arguments:

```python
from interlock.detectors.pii_argument_guard import pii_argument_guard

pii_argument_guard(entities=["BR_CPF", "US_SSN"], keys=["query"])              # block
pii_argument_guard(entities=["EMAIL_ADDRESS"], verdict="escalate")             # ask
pii_argument_guard(entities=["EMAIL_ADDRESS"], verdict="mask", strategy="hash")  # rewrite
```

`verdict="mask"` rewrites the argument and lets the call proceed. A wire proxy
can't do that, because it must not change the statement a database runs.
interlock rewrites the tool call before any statement exists.

## Withhold bad responses

```python
from interlock.detectors.http_status_guard import http_status_guard
from interlock.detectors.result_size_guard import result_size_guard

http_status_guard(["5xx", 403])        # error pages often carry traces and internals
result_size_guard(max_bytes=256_000)   # a giant result floods the context window
```

Both are result rules: the tool has run, and the agent doesn't get the output.
