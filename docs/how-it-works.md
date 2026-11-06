# How it works

sigma2sql turns a rule into a dialect-independent match tree, then renders that tree as SQL for
one database. Everything specific to a database is in the rendering step.

```mermaid
flowchart LR
    Y[rule files] --> L[loader<br/>rules, correlations,<br/>count aggregations]
    L --> C[condition parser]
    L --> D[search compiler<br/>modifiers, wildcards,<br/>base64, windash]
    C --> E[match tree]
    D --> E
    P[profile<br/>fields, logsources,<br/>timestamp] --> R
    E --> R[renderer<br/>SQLite · PostgreSQL · DuckDB · ClickHouse]
    R --> Q[SQL]
    R --> K[correlation SQL<br/>self-join windows]
    Q --> H[hunt / test / check]
    K --> H
```

## The pipeline

1. **Load.** YAML documents become `Rule`, `Correlation` or `Filter` objects. A rule keeps its
   searches as written. A condition with `| count() ...` is split into a plain condition and a
   `Correlation` attached to the rule, so legacy aggregations and correlation rules share one
   code path from here on.
2. **Collect.** When several files are read, filters are attached to the rules they apply to,
   and rules that only feed a correlation are set aside.
3. **Compile.** The condition is parsed, and each search it uses is compiled into a tree of
   match nodes. Searches the condition never mentions are not compiled. Modifiers are resolved
   here: `windash` becomes alternatives, `base64` becomes the encoded text, `neq` becomes a
   `Not`, and `expand` fills in placeholders. A filter adds its own tree with an `And`.
4. **Render.** The tree is walked once with a `Target`, which holds the dialect, the table, the
   field mapping and the profile's log source routes. The result is a `WHERE` clause.
5. **Run.** `convert` prints the query. `test` and `check` run it on an in-memory SQLite
   database, and `hunt` on an in-memory DuckDB database.

The tree for a small rule, and the SQL it renders to:

```python
from sigma2sql import Target, load_rule, to_where

rule = load_rule(r"""
title: cmd.exe not started by SYSTEM
detection:
  selection:
    Image|endswith: '\cmd.exe'
  filter:
    User: SYSTEM
  condition: selection and not filter
""")
tree = rule.compile()
print(tree)
print(to_where(tree, Target()))
```

```text
And(items=(StrMatch(field='Image', value=SigmaString(parts=(<Wildcard.MANY: '*'>, '\\cmd.exe')), cased=False), Not(item=StrMatch(field='User', value=SigmaString(parts=('SYSTEM',)), cased=False))))
("Image" LIKE '%\\cmd.exe' ESCAPE '\' AND NOT COALESCE("User" = 'SYSTEM' COLLATE NOCASE, FALSE))
```

## Modules

All code is in `src/sigma2sql/`.

| Module | What it does |
| --- | --- |
| `rule.py` | Reads YAML into `Rule`, `Correlation` and `Filter`, and checks their structure. Parses timespans and the legacy `count()` syntax. |
| `collection.py` | Loads many files, keeps per-file errors, attaches filters, finds the rules a correlation refers to and decides which rules report on their own. |
| `condition.py` | Tokenizer and recursive descent parser for `detection.condition`: `and`, `or`, `not`, parentheses, `1 of`, `all of` and `them`. |
| `detection.py` | Compiles searches into match nodes and handles every modifier, including `windash` variants, `base64offset` and placeholders. |
| `expr.py` | The match tree: `StrMatch`, `NumMatch`, `NullMatch`, `Exists`, `Regex`, `Cidr`, `Compare`, `TimePart`, `FieldRef`, `And`, `Or`, `Not`, and `SigmaString` with its wildcards. Knows nothing about SQL. |
| `sql.py` | `Target`, `Route` and `Renderer`: fields, quoting, literals and each match node for each dialect. |
| `correlation.py` | SQL for correlations and `count()` aggregations, built from the pieces in `sql.py`. |
| `profile.py` | Loads profiles and placeholder files and applies them to a `Target`. |
| `profiles/` | The built-in profiles: `sysmon`, `evtx`, `ecs-winlogbeat` and `ocsf`. |
| `runner.py` | In-memory SQLite for `test` and `check`, with `regexp`, `cidr_match` and `sigma_percentile`. |
| `hunt.py` | In-memory DuckDB for `hunt`: reads logs, handles damaged EVTX files, runs each rule and ranks the hits. |
| `sarif.py` | SARIF 2.1.0 reports. |
| `cli.py` | Argument parsing, the order of defaults, profile and options, output and exit codes. |
| `errors.py` | `RuleError` and `UnsupportedRule`. |

## How the dialects differ

The fragments below come from `to_where`. Those for fields and numbers use a JSON column named
`data`; the others use a plain column to stay readable. In the longer ones, `…` stands for the
field.

### Reading a field

With `--nested`, the second column applies.

| Dialect | Top-level key | Nested path |
| --- | --- | --- |
| SQLite | `json_extract("data", '$."Image"')` | `json_extract("data", '$."process"."executable"')` |
| PostgreSQL | `"data"->>'Image'` | `"data"#>>'{"process","executable"}'` |
| DuckDB | `("data"->>'$."Image"')` | `("data"->>'$."process"."executable"')` |
| ClickHouse | `JSONExtract("data", 'Image', 'Nullable(String)')` | `JSONExtract("data", 'process', 'executable', 'Nullable(String)')` |

Without `--nested` a dotted name is one key, so `a.b` does not reach into `a`. When a profile
lists several candidates for a field, they are wrapped in `COALESCE`. The parentheses on DuckDB
are there for versions before 2.0, which parse `a AND b->>c = d` as `(a AND b)->>c = d`. `hunt`
works from DuckDB 1.3 on.

All four give NULL for a missing key. On ClickHouse this is why the type is `Nullable(String)`,
and numbers come back as text.

### Text

Sigma matches without regard to case unless `cased` is set. For `Image: cmd.exe` and
`Image|endswith: '\cmd.exe'`:

| Dialect | Exact value | With a wildcard |
| --- | --- | --- |
| SQLite | `"Image" = 'cmd.exe' COLLATE NOCASE` | `"Image" LIKE '%\\cmd.exe' ESCAPE '\'` |
| PostgreSQL | `LOWER("Image") = 'cmd.exe'` | `"Image" ILIKE '%\\cmd.exe' ESCAPE '\'` |
| DuckDB | `LOWER("Image") = 'cmd.exe'` | `"Image" ILIKE '%\\cmd.exe' ESCAPE '\'` |
| ClickHouse | `lowerUTF8("Image") = 'cmd.exe'` | `"Image" ILIKE '%\\\\cmd.exe'` |

- SQLite's `NOCASE` and `LIKE` fold ASCII only, so non-ASCII letters are case-sensitive there.
- A `cased` value without wildcards is a plain `=` on all four. With wildcards, SQLite uses
  `GLOB`, as its `LIKE` ignores case, and the others use `LIKE`.
- ClickHouse treats a backslash in a string literal as an escape, so literals have their
  backslashes doubled. It has no `ESCAPE` clause, and in `LIKE` the backslash always escapes. A
  backslash in a pattern is therefore written four times.
- ClickHouse's `lower()` only folds ASCII, so `lowerUTF8` is used.

### Keywords

A keyword search has no field. It runs on `--keyword-column` if given, otherwise on the JSON
document as text: `"data"` on SQLite and `CAST("data" AS TEXT)` elsewhere.

That text is the stored JSON, so keywords see its escaping. In the document, the path
`C:\Windows` is stored as `C:\\Windows`, and the keyword `C:\Windows` does not match it. The
same applies to keys: a keyword can match a field name as well as a value.

`test`, `check` and `hunt` on `.evtx` files write each event with Python's `json.dumps` and
`ensure_ascii=False`, so non-ASCII characters stay as they are and a keyword such as `café`
matches. A lone surrogate has no UTF-8 form, so it is replaced with `?`. `hunt` keeps the text
of a JSON log file, so a `\u00e9` in that file stays an escape and the keyword does not match
it. A search on a field is not affected.

### Numbers

In a plain column a number is compared as a number, `"EventID" = 4624`. JSON may hold `4624` or
`"4624"`, so in a JSON column the comparison is on text and both match:

| Dialect | `EventID: 4624` |
| --- | --- |
| SQLite | `CAST(json_extract("data", '$."EventID"') AS TEXT) = '4624'` |
| PostgreSQL | `"data"->>'EventID' = '4624'` |
| DuckDB | `("data"->>'$."EventID"') = '4624'` |
| ClickHouse | `JSONExtract("data", 'EventID', 'Nullable(String)') = '4624'` |

This applies to numbers written as numbers in the rule. A value quoted in the rule, `'4624'`,
is text. On SQLite `json_extract` keeps the JSON type, so such a value matches `"4624"` in an
event but not `4624`. On the other three databases the field is read as text and both match.

In a plain column, comparisons with `lt`, `lte`, `gt` and `gte` are direct: `"Port" < 1024`. In
a JSON column they need a number from a field that may hold anything. Windows logs write `-` in
number and address fields all the time, so a value that is not a number must give NULL, not an
error and not 0:

| Dialect | `Port|lt: 1024` |
| --- | --- |
| SQLite | `CASE WHEN CAST(… AS TEXT) GLOB '*[0-9]*' AND CAST(… AS TEXT) NOT GLOB '*[^0-9.eE+-]*' AND … THEN CAST(… AS REAL) END < 1024` |
| PostgreSQL | `CASE WHEN pg_input_is_valid((…)::text, 'numeric') THEN (…)::numeric END < 1024` |
| DuckDB | `TRY_CAST(… AS DOUBLE) < 1024` |
| ClickHouse | `if(match(…, '^[+-]?([0-9]+[.]?[0-9]*|[.][0-9]+)([eE][+-]?[0-9]+)?$'), toFloat64OrNull(…), NULL) < 1024` |

SQLite's `CAST` alone turns text into 0, which would satisfy `lt`. `GLOB` has no repetition, so
eight more `NOT GLOB` tests, left out above, describe what a number cannot look like: two dots,
a second exponent, a misplaced sign, an exponent with no digit before or after it. ClickHouse's
cast reads `e5` as 0 and `1e+` as 1, and takes `nan` and `inf`, which is why `match` comes
first. PostgreSQL would end the whole query on one bad cast, which is why
`pg_input_is_valid` is there and why `cidr`, comparisons and correlations need PostgreSQL 16 or
newer.

### Regular expressions

| Dialect | `Image|re|i: 'a.b'` | Engine |
| --- | --- | --- |
| SQLite | `"Image" REGEXP '(?i)a.b'` | Python `re`, through the `regexp` function |
| PostgreSQL | `"Image" ~ '(?i)a.b'` | PostgreSQL's own |
| DuckDB | `regexp_matches("Image", '(?i)a.b')` | RE2 |
| ClickHouse | `match("Image", '(?i-s)a.b')` | RE2 |

Flags that are written at the start of a pattern are merged with those from modifiers. Each
engine has its own limits, and a pattern over a limit is reported as unsupported, not changed:

- RE2 has no lookaround or backreferences.
- Repetition counts such as `{300}` may be at most 255 on PostgreSQL and 1000 on DuckDB and
  ClickHouse. SQLite has no such limit.

The flags need translating in two places:

- PostgreSQL's letters for `m` and `s` differ from Python's: `m` becomes `n`, and `m` with `s`
  becomes `w`. Without either flag, `.` matches a newline on PostgreSQL.
- ClickHouse's `match` lets `.` reach newlines by default and Sigma's regexes do not, so
  `(?-s)` is added unless the rule asks for `s`.

### CIDR

Addresses are parsed, never compared as text, so `0:0:0:0:0:0:0:1` is inside `::1/128`. See
[How it is checked](correctness.md) for a case where this matters.

| Dialect | `Ip|cidr: '10.0.0.0/8'` |
| --- | --- |
| SQLite | `cidr_match("Ip", '10.0.0.0/8')` |
| PostgreSQL | `CASE WHEN pg_input_is_valid(("Ip")::text, 'inet') THEN ("Ip")::inet END <<= '10.0.0.0/8'::inet` |
| DuckDB | `cidr_match("Ip", '10.0.0.0/8')` |
| ClickHouse | `((isIPv4String(toString("Ip")) OR isIPv6String(toString("Ip"))) AND isIPAddressInRange(toString("Ip"), '10.0.0.0/8'))` |

`cidr_match` is a Python function on SQLite and DuckDB. `hunt`, `test` and `check` register it;
see [Library use](library.md#sqlite-helper-functions) for running the SQL elsewhere. On
ClickHouse the guard is there because `isIPAddressInRange` raises an error on text that is not
an address.

### Time

Correlations and the modifiers `minute`, `hour`, `day`, `week`, `month` and `year` first turn
the field into seconds since 1970, according to the timestamp format:

| Dialect | ISO text to seconds |
| --- | --- |
| SQLite | `unixepoch(…, 'subsec')` |
| PostgreSQL | `EXTRACT(EPOCH FROM CASE WHEN pg_input_is_valid((…)::text, 'timestamptz') THEN (…)::timestamptz END)` |
| DuckDB | `epoch(TRY_CAST(… AS TIMESTAMPTZ))` |
| ClickHouse | `(toUnixTimestamp64Milli(parseDateTime64BestEffortOrNull(toString(…), 3, 'UTC')) / 1000.0)` |

The parts are then read in UTC, and weeks are ISO 8601 weeks. On SQLite, sigma2sql finds the
Thursday of the event's week and counts from the start of that year. The `subsec` modifier
needs SQLite 3.42 or newer.

### Other differences

- **Null-safe equality.** Correlation groups compare with `IS` on SQLite and `IS NOT DISTINCT
  FROM` elsewhere, so events with a missing group field form a group.
- **Percentiles.** `percentile_cont` on PostgreSQL, `quantile_cont` on DuckDB,
  `quantileExactInclusive` on ClickHouse and the `sigma_percentile` aggregate on SQLite. All
  four interpolate between the closest values.
- **Long lists.** `And` and `Or` are grouped in fifties, because SQLite parses `a OR b OR ...`
  into a tree as deep as the list and stops at depth 1000. On DuckDB, more than 50
  case-insensitive patterns for one field become one `list_filter` over `ilike_escape`, because
  DuckDB keeps memory per `OR` term and thread, and rules with thousands of patterns ran out of
  memory.
- **Result timestamps.** On DuckDB window times are plain UTC `TIMESTAMP` values, as
  `TIMESTAMPTZ` values need `pytz` on the Python side.

## Correlations

Every rule a correlation refers to adds rows to a `base` CTE: the rule's name, the event time,
the group values and the counted field. With a timespan, each event closes a window of its
group:

```console
$ sigma2sql convert examples/rules/brute_force.yml
-- Brute force against one account (9e8d7c6b-5a49-4382-a1b0-c9d8e7f6a505)
WITH base AS (
  SELECT 'failed_logon' AS sigma_rule, unixepoch("timestamp", 'subsec') AS sigma_ts, "TargetUserName" AS "g0" FROM "events" WHERE "EventID" = 4625
),
windows AS (SELECT DISTINCT "g0", sigma_ts FROM base WHERE sigma_ts IS NOT NULL)
SELECT w."g0" AS "TargetUserName", datetime(MIN(b.sigma_ts), 'unixepoch', 'subsec') AS window_start, datetime(w.sigma_ts, 'unixepoch', 'subsec') AS window_end, COUNT(*) AS value
FROM windows w JOIN base b ON b."g0" IS w."g0" AND b.sigma_ts BETWEEN w.sigma_ts - 300 AND w.sigma_ts
GROUP BY w."g0", w.sigma_ts
HAVING COUNT(*) >= 3;

```

Each window that meets the condition gives a row, so a long burst gives one row for each
distinct event time from the point where the threshold is reached. Events without a usable time
do not close a window, see [Event time](correlations.md#event-time). Without a timespan the
query is a plain `GROUP BY` over `base`, and the row has `first_seen` and `last_seen` in place
of the window's start and end.

The aggregate depends on the correlation type:

| Type | Aggregate |
| --- | --- |
| `event_count` | `COUNT(*)` |
| `value_count` | `COUNT(DISTINCT value)` |
| `value_sum`, `value_avg` | `SUM` or `AVG` of the value as a number |
| `value_median`, `value_percentile` | the dialect's percentile function |
| `temporal` | `COUNT(DISTINCT rule)`, by default at least the number of rules |

`temporal` asks whether all the rules fired inside the window, in any order. `temporal_ordered`
is not supported in this version, and such a file is reported as unsupported.

## Why it works this way

**One tree, four renderers.** Sigma's meaning is settled once, in `detection.py` and
`condition.py`. A new dialect only adds rendering, and the behaviour tests in `tests/cases.py`
and `tests/test_correlation.py` run unchanged on all four databases.

**A self-join for windows.** Not every database allows `COUNT(DISTINCT ...)` in a window
function; SQLite rejects it. The self-join allows it, and it works the same on every database.

**`NOT COALESCE(x, FALSE)`.** A test on a missing field is NULL in SQL, and `NOT NULL` is NULL
again. Sigma treats the inner test as "no match", so its negation has to be true. This is why
`not` on a missing field matches.

**No silent changes.** A pattern a database cannot run is reported as unsupported. A rule with
a placeholder you did not provide is skipped. Either is better than SQL that never matches or
always matches without saying so.

**A product filter in `hunt`.** Without it, a Zeek rule of the form `not <address range>`
matches every Windows event, because those events have no such field. The Windows profiles
name their `product` for this reason.

**DuckDB for `hunt`, SQLite for `test`.** DuckDB reads JSON, Parquet and CSV directly and needs
no server, so a directory of logs can be searched with one command. `test` and `check` run in
CI on small files, and SQLite comes with Python, so they need no extra packages.

**Keep what can be read.** Logs from an incident are often damaged, so `hunt` reads what it can
of `.evtx` files and warns about the rest. It fails only when the whole hunt gives no event.
Other formats are read by DuckDB, and a file it cannot read ends the hunt.

## Contributing and development

The project uses [uv](https://docs.astral.sh/uv/). Issues and pull requests go to
[brkozer/sigma2sql](https://github.com/brkozer/sigma2sql).

```bash
uv sync
uv run pytest                                               # SQLite and DuckDB
SIGMA2SQL_PG_DSN=postgresql://postgres:test@localhost/postgres uv run pytest   # + PostgreSQL
SIGMA2SQL_CH_URL=http://localhost:8123/ uv run pytest                          # + ClickHouse
```

CI also runs these, and a pull request should pass them:

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy
```

The behaviour tests in `tests/cases.py` and `tests/test_correlation.py` run unchanged on all
four databases, so a new test of Sigma behaviour belongs there. The example rules and events in
`examples/` were written for this project.

The checks against SigmaHQ need a checkout of its repository. They are described in [How it is
checked](correctness.md).

```bash
git clone --depth 1 https://github.com/SigmaHQ/sigma
uv run python scripts/check_sigmahq.py sigma/rules --dsn ... --clickhouse ... [--profile evtx]
uv run python scripts/check_regression.py sigma --clickhouse ... --evtx
uv run --with pysigma --with pysigma-backend-sqlite python scripts/diff_pysigma.py sigma
```

To rebuild the terminal image from real command output, and to build this site:

```bash
uv run python scripts/demo_svg.py docs/demo.svg
uv sync --group docs
uv run zensical build --strict --clean
```
