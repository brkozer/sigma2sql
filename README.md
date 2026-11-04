# sigma2sql

[![ci](https://github.com/brkozer/sigma2sql/actions/workflows/ci.yml/badge.svg)](https://github.com/brkozer/sigma2sql/actions/workflows/ci.yml)
![python](https://img.shields.io/badge/python-3.12%2B-3776AB)
![license](https://img.shields.io/badge/license-MIT-green)

Convert [Sigma](https://sigmahq.io) detection rules to SQL for **SQLite** and **PostgreSQL**,
and test a rule against sample events before it goes anywhere near production.

It is a small, dependency-light alternative to a full SIEM pipeline: if your logs already sit in
a database table (or a JSON column), you can hunt with community rules directly.

- **Coverage:** every rule in the [SigmaHQ](https://github.com/SigmaHQ/sigma) repository is
  converted and the generated SQL is executed on SQLite and PostgreSQL 17 in CI each week. On
  SigmaHQ `c68bb91` (2026-11-04) that is **3142 / 3162 rules on SQLite (99.4%)** and
  **3140 / 3162 on PostgreSQL (99.3%)**, with no query rejected by either database.
- **Sigma semantics, not just syntax:** case-insensitive matching by default, wildcard escaping,
  `not` on a missing field, numbers stored as `4624` or `"4624"`.
- **Safe output:** every value is a quoted literal; `'`, `%` and `_` in rules can't change
  the query.

<p align="center"><img src="docs/demo.svg" alt="sigma2sql testing a rule against sample events and converting another to PostgreSQL" width="100%"></p>

## Quick start

```bash
uv tool install git+https://github.com/brkozer/sigma2sql
```

Test a rule against events (one JSON object per line):

```console
$ sigma2sql test examples/rules/encoded_powershell.yml examples/events.jsonl --expect match
{"EventID": 1, "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", ..., "CommandLine": "powershell.exe -NoProfile -enc SQBFAFgA"}
{"EventID": 1, "Image": "C:\\Program Files\\PowerShell\\7\\pwsh.exe", ..., "CommandLine": "pwsh.exe /ec SQBFAFgA"}
PowerShell started with an encoded command: 2 of 8 events matched
```

`--expect match` / `--expect none` makes the exit code usable as a rule unit test in CI.

Convert to SQL, one column per field:

```console
$ sigma2sql convert examples/rules/rdp_from_outside.yml
-- Successful RDP logon from a public address (c2d4e6f8-0a1b-4c3d-8e5f-6a7b8c9d0e03)
SELECT * FROM "events" WHERE (("EventID" = 4624 AND "LogonType" = 10) AND NOT COALESCE((cidr_match("IpAddress", '10.0.0.0/8') OR ...), FALSE));
```

or against a PostgreSQL `jsonb` column:

```console
$ sigma2sql convert examples/rules/office_spawns_shell.yml -d postgres --json-column data
-- Office application starting a shell (8a7f3e91-2c44-4b8e-b0f6-3e5d9c1a7b02)
SELECT * FROM "events" WHERE (("data"->>'ParentImage' ILIKE '%\\winword.exe' ESCAPE '\' OR ...) AND ("data"->>'Image' ILIKE '%\\cmd.exe' ESCAPE '\' OR ...));
```

Pass a directory to convert many rules; unsupported ones are listed on stderr with the reason.

### Options

| Option | Meaning |
| --- | --- |
| `-d, --dialect` | `sqlite` (default) or `postgres` |
| `-t, --table` | table name, `schema.table` allowed (default `events`) |
| `-m, --mapping` | YAML map from Sigma field to your column or JSON key, e.g. `Image: process_path` |
| `--json-column` | read fields as top-level keys of this JSON/JSONB column |
| `--keyword-column` | column searched by keyword rules (in JSON mode the whole document is used) |

## How it works

```mermaid
flowchart LR
    Y[rule.yml] --> L[load_rule<br/>YAML checks]
    L --> C[condition parser<br/>and / or / not, 1 of, all of them]
    L --> D[search compiler<br/>modifiers, wildcards, lists]
    C --> E[match tree]
    D --> E
    E --> S[SQLite renderer]
    E --> P[PostgreSQL renderer]
    S --> R[test runner<br/>in-memory SQLite + JSON events]
```

The rule is compiled once into a dialect-independent tree (`expr.py`); each renderer turns that
tree into SQL. Searches the condition never references are not compiled, so an unsupported
modifier in an unused search does not block the rule.

## Supported Sigma features

| Feature | SQLite | PostgreSQL |
| --- | --- | --- |
| maps (AND), lists (OR), list of maps, keywords | ✓ | ✓ |
| `and`, `or`, `not`, parentheses, `1 of x*`, `all of x*`, `them`, condition lists | ✓ | ✓ |
| `*` / `?` wildcards, `\*` `\?` `\\` escapes | `LIKE` / `GLOB` | `ILIKE` / `LIKE` |
| `contains`, `startswith`, `endswith`, `all`, `cased`, `windash` | ✓ | ✓ |
| `re`, `re\|i` | `REGEXP` ¹ | `~` ² |
| `cidr` | `cidr_match()` ¹ | `inet <<=` |
| `lt`, `lte`, `gt`, `gte`, `exists`, `fieldref`, `null` | ✓ | ✓ |
| `base64`, `base64offset`, `utf16*`, `expand` | – | – |
| aggregations (`\| count()`), `timeframe`, correlation rules | – | – |

¹ SQLite has no built-in `REGEXP` or CIDR function. `sigma2sql.runner.connect()` returns a
connection with both registered; elsewhere, register `regexp(pattern, value)` and
`cidr_match(value, network)` yourself.<br>
² PostgreSQL regexes are close to, but not the same as, Python/PCRE. Repetition counts above
255 are rejected by PostgreSQL, so those rules are reported as unsupported instead of being
silently changed.

Matching is case-insensitive for ASCII, as in SQLite's `LIKE` and `COLLATE NOCASE`.

## Library use

```python
from sigma2sql import Target, load_rule_file, to_query

rule = load_rule_file("rule.yml")
sql = to_query(rule, Target("postgres", table="logs.windows", json_column="event"))
```

## Development

```bash
uv sync
uv run pytest            # SQLite tests
SIGMA2SQL_PG_DSN=postgresql://postgres:test@localhost/postgres uv run pytest   # + PostgreSQL
uv run python scripts/check_sigmahq.py path/to/sigma/rules [dsn]
uv run python scripts/demo_svg.py docs/demo.svg   # regenerate the screenshot
```

The behaviour tests in `tests/cases.py` run unchanged against both databases, so a dialect
can't drift from the other. The example rules in `examples/` were written for this project.

## License

MIT
