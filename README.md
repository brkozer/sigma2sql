# sigma2sql

[![ci](https://github.com/brkozer/sigma2sql/actions/workflows/ci.yml/badge.svg)](https://github.com/brkozer/sigma2sql/actions/workflows/ci.yml)
[![pypi](https://img.shields.io/pypi/v/sigma2sql)](https://pypi.org/project/sigma2sql/)
![python](https://img.shields.io/badge/python-3.12%2B-3776AB)
![license](https://img.shields.io/badge/license-MIT-green)

Run [Sigma](https://sigmahq.io) detection rules as SQL on **SQLite**, **PostgreSQL** and
**DuckDB**: hunt through log files without a SIEM, convert rules for the database your logs
already live in, and unit-test rules before they reach production.

- **Every SigmaHQ rule converts**: 3162 / 3162 on SQLite and DuckDB, 3160 / 3162 on
  PostgreSQL, plus all 45 `count()` aggregation rules SigmaHQ keeps under `unsupported/`.
  Every generated query is executed on all three databases in CI each week.
- **Checked against real events**: all 476 of SigmaHQ's regression samples match as expected,
  and on those events sigma2sql agrees with pySigma on 3074 of 3076 rules; the two
  differences are IPv6 addresses pySigma's text matching misses
  ([details](docs/correctness.md)).
- **Correlations**: event counts, distinct counts, sums and temporal sequences over a sliding
  window, as plain SQL.
- **Your schema**: profiles map Sigma fields to your columns or nested JSON (Sysmon, EVTX
  exports, Elastic/Winlogbeat ECS, OCSF built in) and limit each rule to the right log source.

<p align="center"><img src="https://raw.githubusercontent.com/brkozer/sigma2sql/main/docs/demo.svg" alt="sigma2sql hunting through sample logs, checking rule tests and converting a rule to PostgreSQL" width="100%"></p>

## Install

```bash
pip install "sigma2sql[duckdb]"
# or as a standalone tool
uv tool install "sigma2sql[duckdb]"
```

The `duckdb` extra is needed for `hunt`; `convert`, `test` and `check` only need PyYAML.

## Hunt through log files

```bash
git clone --depth 1 https://github.com/SigmaHQ/sigma
sigma2sql hunt sigma/rules --logs 'logs/*.json' --profile evtx --examples 1
```

`hunt` loads JSON, JSON Lines, Parquet or CSV files into an in-memory DuckDB database, runs
every rule and correlation, and lists the ones that matched, most severe first. On the
examples in this repository:

```console
$ sigma2sql hunt examples/rules --logs examples/events.jsonl
LEVEL         HITS  RULE
high             2  PowerShell started with an encoded command  (examples/rules/encoded_powershell.yml)
high             1  Brute force against one account  (examples/rules/brute_force.yml)
high             1  Office application starting a shell  (examples/rules/office_spawns_shell.yml)
medium           1  Successful RDP logon from a public address  (examples/rules/rdp_from_outside.yml)
4 of 4 rules matched 12 events (0 rules skipped)
```

`--examples N` prints matching events (or correlation results such as
`{"TargetUserName":"admin","window_start":"2026-11-01 03:12:01","window_end":"2026-11-01 03:12:17","value":3}`),
`--format json` gives a machine-readable report and `--fail-on high` a non-zero exit code
when a rule at that level or above fires.

## Convert rules

```console
$ sigma2sql convert examples/rules/office_spawns_shell.yml -d postgres --json-column data
-- Office application starting a shell (8a7f3e91-2c44-4b8e-b0f6-3e5d9c1a7b02)
SELECT * FROM "events" WHERE (("data"->>'ParentImage' ILIKE '%\\winword.exe' ESCAPE '\' OR ...)
  AND ("data"->>'Image' ILIKE '%\\cmd.exe' ESCAPE '\' OR ...));
```

A whole directory works the same way, e.g.
`sigma2sql convert sigma/rules -d postgres -t security.events --json-column event --profile ecs-winlogbeat`.
Without `--json-column` each Sigma field is a column. Unsupported rules are listed on stderr
with the reason, and the command exits non-zero.

| Option | Meaning |
| --- | --- |
| `-d, --dialect` | `sqlite` (default), `postgres` or `duckdb` |
| `-t, --table` | table name, `schema.table` allowed (default `events`) |
| `--json-column` | read fields from this JSON / JSONB column |
| `--keyword-column` | column searched by keyword rules (in JSON mode the whole document) |
| `-p, --profile` | built-in profile or a YAML file (see below) |
| `-m, --mapping` | YAML map from Sigma field to your column or key, applied over the profile |
| `--nested` | dotted names are paths into nested JSON |
| `--timestamp-field`, `--timestamp-format` | event time for correlations (`iso`, `epoch_s`, `epoch_ms`) |

## Correlations

Sigma correlation rules and the older `| count() by ... > N` syntax both become SQL. With a
`timespan`, each event closes a window over the events of the same group before it; the
window's events are found with a self-join, which works the same on all three databases and
allows distinct counts:

```yaml
title: Brute force against one account
correlation:
  type: event_count          # also value_count, value_sum, value_avg, temporal
  rules: [failed_logon]
  group-by: [TargetUserName]
  timespan: 5m
  condition: {gte: 3}
```

Each result row holds the group values, the window's start and end and the counted value.
Rules referenced by a correlation are not reported on their own unless it sets
`generate: true`. `temporal_ordered` is not supported yet.

## Profiles

A profile describes where your events keep Sigma's fields and which events each log source
covers. `sigma2sql profiles` lists the built-in ones:

| Profile | For |
| --- | --- |
| `sysmon` | Sysmon events with their own field names; each category limited to its event ID |
| `evtx` | EVTX exported to JSON by evtx_dump or python-evtx (`Event.System`, `Event.EventData`) |
| `ecs-winlogbeat` | Windows events shipped by Winlogbeat in Elastic Common Schema |
| `ocsf` | OCSF 1.x events, time in epoch milliseconds |

Your own profile is a small YAML file:

```yaml
nested: true
timestamp: "@timestamp"
default_field: "winlog.event_data.{field}"      # fallback for unmapped fields
fields:
  Image: process.executable
  EventID: [event.code, winlog.event_id]         # first one present wins
logsources:
  - match: {product: windows, category: process_creation}
    table: process_events                        # optional: route to a table
    where: {event.code: "1"}                     # optional: extra condition
```

Without a profile, rules are not limited by log source: a network rule can then match a
process event that happens to have the same field values. The built-in profiles cover the
common Windows sources; for other data, add `logsources` entries.

## Test rules

Put example events next to a rule, one JSON object per line:

```
rules/office_spawns_shell.yml
rules/office_spawns_shell.match.jsonl     # every event must match
rules/office_spawns_shell.nomatch.jsonl   # no event may match
```

```console
$ sigma2sql check examples/rules --require-tests
ok   examples/rules/brute_force.yml
ok   examples/rules/encoded_powershell.yml
ok   examples/rules/office_spawns_shell.yml
ok   examples/rules/rdp_from_outside.yml
4 passed, 0 failed, 0 without tests
```

A failure names the rule, the file and the line, e.g. after adding an Outlook-spawned
`cmd.exe` to the match file of a rule that only watches Word, Excel and PowerPoint:

```console
FAIL rules/office_spawns_shell.yml: Office application starting a shell: missed office_spawns_shell.match.jsonl event(s) 1
```

The same check as a GitHub Action:

```yaml
- uses: brkozer/sigma2sql@v0.2.0
  with:
    path: rules
    profile: sysmon          # optional
    require-tests: "true"    # optional
```

`sigma2sql test RULE EVENTS.jsonl` prints the events (or correlation results) a single rule
produces.

## Supported Sigma features

| Feature | SQLite | PostgreSQL | DuckDB |
| --- | --- | --- | --- |
| maps, lists, keywords (with `all`, `re` and string modifiers) | ✓ | ✓ | ✓ |
| `and`, `or`, `not`, `1 of x*`, `all of x*`, `them`, condition lists | ✓ | ✓ | ✓ |
| wildcards and escapes, `contains`, `startswith`, `endswith`, `all`, `cased`, `windash` | ✓ | ✓ | ✓ |
| `base64`, `base64offset`, `utf16`, `utf16le`, `utf16be`, `wide` | ✓ | ✓ | ✓ |
| `re`, `re\|i` | `REGEXP` ¹ | `~` ² | `regexp_matches` ³ |
| `cidr` (IPv4 and IPv6, any notation) | `cidr_match()` ¹ | `inet <<=` | `cidr_match()` ¹ |
| `lt`, `lte`, `gt`, `gte`, `exists`, `fieldref`, `null` | ✓ | ✓ | ✓ |
| correlations, `count()` aggregations | ✓ | ✓ | ✓ |
| `expand` (placeholders), `temporal_ordered`, filter rules | – | – | – |

¹ Not built into the database. `hunt`, `test` and `check` register them; when you run the SQL
elsewhere, register `regexp(pattern, value)` and `cidr_match(value, network)` yourself
(`sigma2sql.runner.connect()` returns a SQLite connection with both).<br>
² PostgreSQL rejects repetition counts above 255; those two rules are reported as unsupported
rather than silently changed.<br>
³ RE2: no lookaround or backreferences; such rules are reported as unsupported on DuckDB.

Matching is case-insensitive by default (ASCII in SQLite, as its `LIKE` and `NOCASE` are);
values in a JSON column match whether they are stored as `4624` or `"4624"`, and `not` on a
missing field is true, as Sigma intends.

## How it works

```mermaid
flowchart LR
    Y[rule files] --> L[loader<br/>rules, correlations,<br/>count aggregations]
    L --> C[condition parser]
    L --> D[search compiler<br/>modifiers, wildcards,<br/>base64, windash]
    C --> E[match tree]
    D --> E
    P[profile<br/>fields, logsources,<br/>timestamp] --> R
    E --> R[renderer<br/>SQLite · PostgreSQL · DuckDB]
    R --> Q[SQL]
    R --> K[correlation SQL<br/>self-join windows]
    Q --> H[hunt / test / check]
    K --> H
```

## Library use

```python
from sigma2sql import Target, load_rule_file, to_query
from sigma2sql.profile import apply_profile, load_profile

rule = load_rule_file("rule.yml")
target = apply_profile(
    Target("postgres", "logs.windows", json_column="event"), load_profile("evtx")
)
print(to_query(rule, target))
```

## Development

```bash
uv sync
uv run pytest                                               # SQLite and DuckDB
SIGMA2SQL_PG_DSN=postgresql://postgres:test@localhost/postgres uv run pytest   # + PostgreSQL
uv run python scripts/check_sigmahq.py sigma/rules --dsn ... [--profile evtx]
uv run python scripts/check_regression.py sigma
uv run --with pysigma --with pysigma-backend-sqlite python scripts/diff_pysigma.py sigma
uv run python scripts/demo_svg.py docs/demo.svg
```

The behaviour tests in `tests/cases.py` and `tests/test_correlation.py` run unchanged on all
three databases. The example rules and events in `examples/` were written for this project.

## License

MIT
