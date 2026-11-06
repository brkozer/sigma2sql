# Library use

sigma2sql is a Python package with type hints. Its core needs only PyYAML; `sigma2sql.hunt`
needs the `duckdb` extra, and `evtx` for `.evtx` files.

The names you can import from `sigma2sql` itself are:

| Kind | Names |
| --- | --- |
| Loading | `load_rule`, `load_rule_file`, `load_file`, `load_documents`, `Collection` |
| Documents | `Rule`, `Correlation`, `Filter` |
| Converting | `Target`, `to_query`, `to_where`, `correlation_query` |
| Errors | `RuleError`, `UnsupportedRule` |

Profiles live in `sigma2sql.profile`, the SQLite helpers in `sigma2sql.runner`, and the hunt in
`sigma2sql.hunt`.

The examples on this page run from the root of the repository, where `examples/` is.

## Load rules

`load_rule` takes the text of a file that holds exactly one detection rule. A `Rule` keeps its
searches as written; `compile()` turns them into the [match tree](how-it-works.md).

```python
from sigma2sql import load_rule

text = r"""
title: Shell started from a temp folder
id: 7b1c9f60-0000-4000-8000-000000000001
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|contains: '\Temp\'
  condition: selection
level: medium
"""
rule = load_rule(text)
print(rule.title, rule.level, rule.logsource)
print(rule.compile())
```

```text
Shell started from a temp folder medium {'product': 'windows', 'category': 'process_creation'}
StrMatch(field='Image', value=SigmaString(parts=(<Wildcard.MANY: '*'>, '\\Temp\\', <Wildcard.MANY: '*'>)), cased=False)
```

`load_rule_file` does the same for a file, and `load_file` returns every document in a file:
rules, correlations and filters. `load_documents` is `load_file` for text you already have. All
file functions take a `pathlib.Path`, not a string.

```python
from pathlib import Path

from sigma2sql import load_file, load_rule_file

rule = load_rule_file(Path("examples/rules/office_spawns_shell.yml"))
print(rule.title)

for doc in load_file(Path("examples/rules/brute_force.yml")):
    print(type(doc).__name__, doc.title)
```

```text
Office application starting a shell
Rule Failed logon
Correlation Brute force against one account
```

`Collection.load` reads many files and directories, as the command line does. A file that
cannot be loaded ends up in `errors` as a `(path, reason)` pair, and loading goes on. Filters
are attached to the rules they apply to.

| Member | Meaning |
| --- | --- |
| `rules`, `correlations`, `filters` | the loaded documents |
| `errors` | `(path, reason)` for each file that could not be loaded |
| `standalone()` | the rules that report on their own, so not those that only feed a correlation |
| `resolve(correlation)` | the rules a correlation refers to; `RuleError` if one is missing |
| `unused_filters()` | filters that reached no rule, usually a mistyped id or log source |

```python
from pathlib import Path

from sigma2sql import Collection

col = Collection.load([Path("examples/rules")])
print(len(col.rules), "rules,", len(col.correlations), "correlation,", len(col.errors), "errors")
print([r.title for r in col.standalone()])
corr = col.correlations[0]
print(corr.title, corr.type, corr.timespan, corr.condition)
print([r.title for r in col.resolve(corr)])
```

```text
4 rules, 1 correlation, 0 errors
['PowerShell started with an encoded command', 'Office application starting a shell', 'Successful RDP logon from a public address']
Brute force against one account event_count 300 (('gte', 3.0),)
['Failed logon']
```

## Convert

A `Target` says where the events live. It is a frozen dataclass, so use `dataclasses.replace`
to change a copy.

| Field | Default | Meaning |
| --- | --- | --- |
| `dialect` | `"sqlite"` | `"sqlite"`, `"postgres"`, `"duckdb"` or `"clickhouse"` |
| `table` | `"events"` | table name, `schema.table` allowed |
| `mapping` | `{}` | Sigma field to column or key, or a tuple of candidates of which the first present wins |
| `json_column` | `None` | every event is one JSON object in this column |
| `keyword_column` | `None` | column searched by keyword rules |
| `timestamp` | `"timestamp"` | event time field |
| `timestamp_format` | `"iso"` | `"iso"`, `"epoch_s"` or `"epoch_ms"` |
| `nested` | `False` | dotted names are paths into nested JSON |
| `default_field` | `None` | template or templates for unmapped fields, with `{field}` or `{field_words}` |
| `routes` | `()` | log source routing, normally set by a profile |
| `product` | `None` | `logsource.product` the logs hold; only `hunt` uses it |
| `placeholders` | `{}` | placeholder name to a tuple of values |

`to_query(rule, target, columns="*")` returns one `SELECT`, without a closing semicolon. Use
`columns` to choose what it selects. For a rule with a legacy `count()` aggregation, `columns`
is ignored and the query returns one row per group and window.

```python
from pathlib import Path

from sigma2sql import Target, load_rule_file, to_query

rule = load_rule_file(Path("examples/rules/office_spawns_shell.yml"))
target = Target("postgres", "logs.windows", json_column="event")
print(to_query(rule, target, columns="event->>'CommandLine'"))
```

```text
SELECT event->>'CommandLine' FROM "logs"."windows" WHERE (("event"->>'ParentImage' ILIKE '%\\winword.exe' ESCAPE '\' OR "event"->>'ParentImage' ILIKE '%\\excel.exe' ESCAPE '\' OR "event"->>'ParentImage' ILIKE '%\\powerpnt.exe' ESCAPE '\') AND ("event"->>'Image' ILIKE '%\\cmd.exe' ESCAPE '\' OR "event"->>'Image' ILIKE '%\\powershell.exe' ESCAPE '\' OR "event"->>'Image' ILIKE '%\\wscript.exe' ESCAPE '\' OR "event"->>'Image' ILIKE '%\\cscript.exe' ESCAPE '\' OR "event"->>'Image' ILIKE '%\\mshta.exe' ESCAPE '\'))
```

`to_where(expr, target)` renders only the condition, for a query you build yourself. It takes
the compiled tree, and it does not apply log source routes.

```python
from sigma2sql import Target, load_rule, to_where

rule = load_rule("""
title: Failed logon
detection:
  selection:
    EventID: 4625
  condition: selection
""")
where = to_where(rule.compile(), Target("postgres"))
print(f"SELECT count(*) FROM auth_log WHERE {where}")
```

```text
SELECT count(*) FROM auth_log WHERE "EventID" = 4625
```

`correlation_query(correlation, rules, target)` needs the rules the correlation refers to,
which `Collection.resolve` finds:

```python
from pathlib import Path

from sigma2sql import Collection, Target, correlation_query

col = Collection.load([Path("examples/rules/brute_force.yml")])
corr = col.correlations[0]
target = Target("duckdb", json_column="data", timestamp="UtcTime")
print(correlation_query(corr, col.resolve(corr), target))
```

```text
WITH base AS (
  SELECT 'failed_logon' AS sigma_rule, epoch(TRY_CAST("data"->>'$."UtcTime"' AS TIMESTAMPTZ)) AS sigma_ts, "data"->>'$."TargetUserName"' AS "g0" FROM "events" WHERE "data"->>'$."EventID"' = '4625'
),
windows AS (SELECT DISTINCT "g0", sigma_ts FROM base WHERE sigma_ts IS NOT NULL)
SELECT w."g0" AS "TargetUserName", make_timestamp(CAST((MIN(b.sigma_ts)) * 1000000 AS BIGINT)) AS window_start, make_timestamp(CAST((w.sigma_ts) * 1000000 AS BIGINT)) AS window_end, COUNT(*) AS value
FROM windows w JOIN base b ON b."g0" IS NOT DISTINCT FROM w."g0" AND b.sigma_ts BETWEEN w.sigma_ts - 300 AND w.sigma_ts
GROUP BY w."g0", w.sigma_ts
HAVING COUNT(*) >= 3
```

Placeholder values go into the target, as tuples:

```python
from sigma2sql import Target, load_rule, to_query

rule = load_rule("""
title: Logon from a domain controller
detection:
  selection:
    IpAddress|expand: '%dc_ip_addresses%'
  condition: selection
""")
target = Target(placeholders={"dc_ip_addresses": ("10.0.0.10", "10.0.0.11")})
print(to_query(rule, target))
```

```text
SELECT * FROM "events" WHERE ("IpAddress" = '10.0.0.10' COLLATE NOCASE OR "IpAddress" = '10.0.0.11' COLLATE NOCASE)
```

## Profiles

`sigma2sql.profile` has the functions behind `--profile` and `--placeholders`. See
[Profiles](profiles.md) for the file format.

| Function | Meaning |
| --- | --- |
| `builtin_profiles()` | name to description of the built-in profiles |
| `load_profile(name_or_path)` | the profile as a dict; `ValueError` for an unknown name or key |
| `apply_profile(target, profile)` | a new `Target` with the profile's settings |
| `load_placeholders(path)` | a YAML file as the map `Target.placeholders` expects |

```python
from sigma2sql import Target
from sigma2sql.profile import apply_profile, builtin_profiles, load_profile

print(list(builtin_profiles()))
target = apply_profile(Target("sqlite", json_column="data"), load_profile("sysmon"))
print(target.product, target.timestamp, len(target.routes))
print(target.routes[0])
```

```text
['ecs-winlogbeat', 'evtx', 'ocsf', 'sysmon']
windows UtcTime 23
Route(match={'product': 'windows', 'category': 'process_creation'}, table=None, where={'EventID': 1})
```

`apply_profile` takes any dict in the shape of a profile file, so a profile can be built in
code. The first route that fits a rule's log source decides its table and extra condition.

```python
from sigma2sql import Target, load_rule, to_query
from sigma2sql.profile import apply_profile

rule = load_rule(r"""
title: cmd.exe started
logsource: {product: windows, category: process_creation}
detection:
  selection:
    Image|endswith: '\cmd.exe'
  condition: selection
""")
profile = {
    "nested": True,
    "fields": {"Image": "process.executable"},
    "logsources": [
        {
            "match": {"product": "windows", "category": "process_creation"},
            "table": "process_events",
            "where": {"event.code": "1"},
        }
    ],
}
target = apply_profile(Target("postgres", json_column="doc"), profile)
print(to_query(rule, target))
```

```text
SELECT * FROM "process_events" WHERE (LOWER("doc"#>>'{"event","code"}') = '1' AND "doc"#>>'{"process","executable"}' ILIKE '%\\cmd.exe' ESCAPE '\')
```

Fields already in `target.mapping` win over the profile's:

```python
from sigma2sql import Target
from sigma2sql.profile import apply_profile

profile = {"fields": {"Image": "process.executable", "User": "user.name"}}
target = apply_profile(Target(mapping={"Image": "image_path"}), profile)
print(target.mapping)
```

```text
{'Image': 'image_path', 'User': 'user.name'}
```

## Run rules on SQLite

`sigma2sql.runner` runs rules against events in an in-memory SQLite database. This is what
`test` and `check` use.

| Name | Meaning |
| --- | --- |
| `read_jsonl(text)` | parse JSON Lines into a list of dicts; `ValueError` for bad JSON or a line that is not an object |
| `matching_events(rule, events, base=None)` | indexes of the events a detection rule matches, from 0 |
| `rows(query, events)` | run a query over the events and return named rows |
| `target(base=None)` | `base` pointed at the runner's table |
| `load(events)` | a connection with the events in table `events`, column `data` |
| `connect()` | an empty connection with the helper functions registered |

`matching_events` takes a `Target` for mapping, profile and timestamp settings. Its dialect,
table and JSON column are replaced. Each call builds a new database, so for many rules over a
large set of events use `load` once and run the queries yourself. A rule with a `count()`
aggregation has no event indexes, and `matching_events` fails on it with
`sqlite3.OperationalError`.

```python
from pathlib import Path

from sigma2sql import load_rule_file
from sigma2sql.runner import matching_events, read_jsonl

events = read_jsonl(Path("examples/events.jsonl").read_text(encoding="utf-8"))
rule = load_rule_file(Path("examples/rules/encoded_powershell.yml"))
hits = matching_events(rule, events)
print(hits)
print(events[hits[0]]["CommandLine"])
```

```text
[0, 2]
powershell.exe -NoProfile -enc SQBFAFgA
```

For correlations, build the query with `target()` and run it with `rows`. A `count()` rule
works the same way, with `to_query(rule, target())`:

```python
from pathlib import Path

from sigma2sql import Collection, correlation_query
from sigma2sql.runner import read_jsonl, rows, target

events = read_jsonl(Path("examples/events.jsonl").read_text(encoding="utf-8"))
col = Collection.load([Path("examples/rules/brute_force.yml")])
corr = col.correlations[0]
print(rows(correlation_query(corr, col.resolve(corr), target()), events))
```

```text
[{'TargetUserName': 'admin', 'window_start': '2026-11-01 03:12:01.000', 'window_end': '2026-11-01 03:12:17.000', 'value': 3}]
```

`load` gives you the connection itself:

```python
from sigma2sql.runner import load

conn = load([{"EventID": 1}, {"EventID": 2}])
print(conn.execute("SELECT rowid, data FROM events").fetchall())
```

```text
[(1, '{"EventID": 1}'), (2, '{"EventID": 2}')]
```

### SQLite helper functions

SQL for the `sqlite` dialect can call three functions SQLite does not have. `runner.connect()`
returns a connection that has them:

| Function | Used for | Behaviour |
| --- | --- | --- |
| `regexp(pattern, value)` | the `re` modifier, through the `REGEXP` operator | Python's `re.search`; false for NULL |
| `cidr_match(value, network)` | the `cidr` modifier | Python's `ipaddress`; false for text that is not an address |
| `sigma_percentile(value, fraction)` | `value_median` and `value_percentile` | aggregate with linear interpolation, as PostgreSQL's `percentile_cont`; NULL values are left out |

```python
from sigma2sql.runner import connect

conn = connect()
print(conn.execute("SELECT 'cmd.exe' REGEXP '(?i)^CMD'").fetchone())
print(conn.execute("SELECT regexp('^cmd', 'powershell.exe')").fetchone())
print(conn.execute("SELECT cidr_match('10.1.2.3', '10.0.0.0/8')").fetchone())
print(conn.execute("SELECT cidr_match('-', '10.0.0.0/8')").fetchone())
conn.execute("CREATE TABLE t (v REAL)")
conn.executemany("INSERT INTO t VALUES (?)", [(1,), (2,), (3,), (10,)])
print(conn.execute("SELECT sigma_percentile(v, 0.5), sigma_percentile(v, 0.95) FROM t").fetchone())
```

```text
(1,)
(0,)
(1,)
(0,)
(2.5, 8.949999999999998)
```

The connection is in memory, and it works with your own tables too. To reach a database file,
attach it:

```python
import sqlite3
from pathlib import Path

from sigma2sql import Target, load_rule_file, to_query
from sigma2sql.runner import connect

Path("logons.db").unlink(missing_ok=True)
db = sqlite3.connect("logons.db")
db.execute("CREATE TABLE logons (EventID INTEGER, LogonType INTEGER, IpAddress TEXT)")
db.executemany(
    "INSERT INTO logons VALUES (?, ?, ?)",
    [(4624, 10, "203.0.113.45"), (4624, 10, "10.0.0.5"), (4624, 3, "203.0.113.45")],
)
db.commit()
db.close()

conn = connect()
conn.execute("ATTACH DATABASE 'logons.db' AS logs")
rule = load_rule_file(Path("examples/rules/rdp_from_outside.yml"))
print(conn.execute(to_query(rule, Target("sqlite", "logs.logons"))).fetchall())
```

```text
[(4624, 10, '203.0.113.45')]
```

On DuckDB, `sigma2sql.hunt.connect()` does the same for `cidr_match`, the only helper that
dialect needs, and creates an `events` table with a JSON column `data`.
`sigma2sql.hunt.load_logs` fills it:

```python
from sigma2sql.hunt import connect, load_logs

con = connect()
print(load_logs(con, ["examples/events.jsonl"]))
print(con.execute("SELECT cidr_match('10.1.2.3', '10.0.0.0/8')").fetchone())
```

```text
12
(True,)
```

## Hunt

`sigma2sql.hunt.hunt(rules, paths, base=None, examples=0)` is the `hunt` command without the
printing. `rules` is a `Collection`, `paths` a list of log files or globs and `base` a `Target`
for mapping and timestamp settings. It returns a `Report`.

Unlike the command, it does not pick the `evtx` profile for `.evtx` files. Without that profile
rules do not find their fields there, so pass `apply_profile(Target(), load_profile("evtx"))`
as `base`. Correlations then need the mapping described under [Event
time](profiles.md#event-time).

| `Report` field | Meaning |
| --- | --- |
| `events` | events loaded |
| `hits` | a `Hit` for each matching rule, most severe first |
| `ran` | rules and correlations that ran |
| `skipped` | `(rule, reason)` for each one that could not run |
| `other_logs` | rules left out because they are for another product |
| `warnings` | logs that could only be read in part |

A `Hit` has `rule`, `count`, `examples` (JSON strings) and `rank`, the position of its level in
`sigma2sql.hunt.LEVELS`, or the length of that tuple for no level or any other level.

```python
from pathlib import Path

from sigma2sql import Collection
from sigma2sql.hunt import hunt

report = hunt(Collection.load([Path("examples/rules")]), ["examples/events.jsonl"], examples=1)
print(report.events, report.ran, len(report.skipped), report.other_logs, report.warnings)
for hit in report.hits:
    print(hit.rule.level, hit.count, hit.rule.title)
print(report.hits[1].examples)
```

```text
12 4 0 0 []
high 2 PowerShell started with an encoded command
high 1 Brute force against one account
high 1 Office application starting a shell
medium 1 Successful RDP logon from a public address
['{"TargetUserName":"admin","window_start":"2026-11-01 03:12:01","window_end":"2026-11-01 03:12:17","value":3}']
```

!!! note
    If the `duckdb` or `evtx` package is missing, the functions in `sigma2sql.hunt` raise
    `SystemExit` with the install command, not `ImportError`. A file they cannot read raises
    DuckDB's own exception or `ValueError`.

## SARIF

`sigma2sql.sarif.report(findings, version)` builds a SARIF 2.1.0 report as a dict from a list
of `Finding` objects:

```python
import json
from pathlib import Path

from sigma2sql.sarif import Finding, report

finding = Finding("rule-1", "Example rule", "high", "2 matches", Path("rules/example.yml"))
doc = report([finding], "0.3.0")
print(json.dumps(doc["runs"][0]["results"][0]))
```

```text
{"ruleId": "rule-1", "ruleIndex": 0, "level": "error", "message": {"text": "2 matches"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "rules/example.yml"}}}]}
```

## Errors

There are two exception types:

- `RuleError`: the rule is not valid Sigma.
- `UnsupportedRule`: the rule is valid Sigma, but it uses something sigma2sql cannot translate,
  or the target cannot express it.

Loading checks the structure of a rule. Modifiers and conditions are checked later, when the
rule is compiled, so `to_query` and `rule.compile()` can raise either exception. A rule that
loads may still fail on one dialect only, for example on a regular expression with a lookahead
on DuckDB.

```python
from sigma2sql import RuleError, Target, UnsupportedRule, load_rule, to_query


def attempt(text: str) -> None:
    try:
        print(to_query(load_rule(text), Target()))
    except RuleError as exc:
        print("RuleError:", exc)
    except UnsupportedRule as exc:
        print("UnsupportedRule:", exc)


attempt("title: a\ndetection:\n  condition: s\n")
attempt("title: b\ndetection:\n  s: {Image|nope: x}\n  condition: s\n")
attempt("title: c\ndetection:\n  s: {Image: x}\n  condition: t\n")
attempt("title: d\ndetection:\n  s: [mimikatz]\n  condition: s\n")
```

```text
RuleError: detection has no searches
UnsupportedRule: modifier 'nope' is not supported
RuleError: condition refers to unknown search 't'
UnsupportedRule: keyword searches need a keyword column or a JSON column
```

`load_rule` and `load_rule_file` raise `UnsupportedRule` for a file with several documents, or
with a correlation or a filter. Use `load_file` for such files, for example
`examples/rules/brute_force.yml`.
