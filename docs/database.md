# Hunt in a database

Without `--logs`, `hunt` connects to the database named in the `SIGMA2SQL_DSN` environment
variable and runs the rules there. The rules become SQL and run on the server. Only counts and
example events come back. The rule options and the report are the ones described in [Hunt
through log files](hunt.md). The [exit codes](#exit-codes) differ in a few cases.

This page assumes the database may be a production system. The connection refuses writes, each
query on a server has a time limit, and the password stays out of reports and error messages.
The one gap in that list is a ClickHouse user restricted with `readonly = 1`, which [runs
without the per-query time limit](#a-clickhouse-user-with-readonly-1).

```bash
pip install "sigma2sql[postgres]"
read -rs SIGMA2SQL_DSN    # paste postgresql://reader:password@db.example:5432/logs
export SIGMA2SQL_DSN
```

In the examples on this page, `logs` is a PostgreSQL table with one JSON document per row in a
column called `event`, loaded from `examples/events.jsonl`.

```console
$ sigma2sql hunt examples/rules -t logs --json-column event
LEVEL         HITS  RULE
high             2  PowerShell started with an encoded command  (examples/rules/encoded_powershell.yml)
high             1  Brute force against one account  (examples/rules/brute_force.yml)
high             1  Office application starting a shell  (examples/rules/office_spawns_shell.yml)
medium           1  Successful RDP logon from a public address  (examples/rules/rdp_from_outside.yml)
4 of 4 rules matched 12 events (0 rules skipped)
```

## The address

| Database | Address | Install |
| --- | --- | --- |
| PostgreSQL | `postgresql://user:password@host:5432/dbname` or `postgres://...` | `sigma2sql[postgres]` |
| ClickHouse over HTTP | `clickhouse://user:password@host:8123/dbname` or `http://...` | `sigma2sql` |
| ClickHouse over HTTPS | `clickhouses://user:password@host:8443/dbname` or `https://...` | `sigma2sql` |
| SQLite | `sqlite:/path/to/logs.db` or `sqlite:logs.db` for a relative path | `sigma2sql` |
| DuckDB | `duckdb:/path/to/logs.duckdb` or `duckdb:logs.duckdb` for a relative path | `sigma2sql[duckdb]` |

- Special characters in a user name or password are percent-encoded: `p@ss:w/rd` is written
  `p%40ss%3Aw%2Frd`.
- A PostgreSQL address is passed to libpq, so options such as `?sslmode=require` work, and the
  password can be left out and given in `PGPASSWORD`. The form `host=db dbname=logs` is not
  accepted, only the URL form.
- PostgreSQL needs version 16 or newer for `--since`, correlations, `cidr` and comparisons, as
  the [supported features](features.md) explain.
- ClickHouse is reached through its HTTP interface, so the port is the HTTP port and not the
  native 9000. It defaults to 8123, or 8443 with `clickhouses://`. The path is the database, and
  without one the user's default database is used. Anything after `?` is ignored.
- A redirect from ClickHouse is refused, because following it could send the password to
  another address. The hunt ends with code 2 and `sigma2sql: ClickHouse answered 302`.
- On Windows, a SQLite or DuckDB path is written `sqlite:///C:/logs/events.db`.

Without the `postgres` extra, `hunt` prints the `pip install` line it needs and exits with code
1, as it does for DuckDB. Any other kind of address stops the hunt with code 2, and so does an
address that cannot be read. The message does not repeat the address or its password:

```console
$ SIGMA2SQL_DSN=mysql://reader:pw@db.example/logs sigma2sql hunt failed.yml; echo $?
sigma2sql: unknown kind of database address; expected postgresql://, clickhouse://, clickhouses://, sqlite: or duckdb:
2
$ SIGMA2SQL_DSN='clickhouse://[db.example/logs' sigma2sql hunt failed.yml; echo $?
sigma2sql: the database address cannot be read
2
$ SIGMA2SQL_DSN='clickhouse://reader:pw@db.example:port/logs' sigma2sql hunt failed.yml; echo $?
sigma2sql: Port could not be cast to integer value as 'port'
2
$ SIGMA2SQL_DSN=sqlite: sigma2sql hunt failed.yml; echo $?
sigma2sql: the database address has no file path
2
```

## Why an environment variable

The address usually holds a password. A command-line argument can be read by every user of the
machine through `ps`, and it ends up in shell history, CI logs and process audit logs. The
environment of a process can only be read by the same user and by root. That is why there is
no `--dsn` option. `read -rs`, as above, keeps the address out of the shell history too. In CI,
set the variable from the secret store.

With neither `--logs` nor the variable, `hunt` says what is missing:

```console
$ sigma2sql hunt examples/rules
sigma2sql: give --logs, or set SIGMA2SQL_DSN to a database
```

If `--logs` is given, the files are hunted and the variable is not looked at. The options for
a table and its columns are refused then:

```console
$ sigma2sql hunt examples/rules --logs examples/events.jsonl -t logs
sigma2sql: --table and the column options are for a database
```

## Table and columns

| Option | Default | Meaning |
| --- | --- | --- |
| `-t, --table` | `events` | the table or view to read; dots separate schema and table, and each part is quoted |
| `--json-column` | none | read fields from the JSON document in this column; without it each field is a column |
| `--keyword-column` | none | column searched by keyword rules; without it they search the document in `--json-column` |

Field names and nesting work as in [`convert`](convert.md): `-m`, `--nested` and profiles all
apply. The JSON column has to be a type that the generated SQL can read:

| Database | JSON column type |
| --- | --- |
| PostgreSQL | `jsonb` or `json`; `text` is rejected |
| ClickHouse | `String`; the native `JSON` type is rejected |
| SQLite | `TEXT` |
| DuckDB | `JSON` or `VARCHAR` |

When the type does not fit, each rule fails on its own and the hunt ends with code 2, as no
rule could run:

```console
$ sigma2sql hunt failed.yml -t logs_text --json-column event
skip failed.yml: operator does not exist: text ->> unknown
0 of 0 rules matched 12 events (1 rules skipped)
sigma2sql: no rule could run
```

A `TEXT` or `VARCHAR` column on SQLite or DuckDB can hold anything, and one bad row must not
end a hunt. With `--json-column`, a row that is not valid JSON is read as an event with no
fields, and a warning gives the number of such rows. Here `logs` is a table in a SQLite file
with the 12 example events and two broken rows, which the summary counts:

```console
$ sigma2sql hunt examples/rules -t logs --json-column event
warning: logs: 2 rows are not valid JSON and have no fields
LEVEL         HITS  RULE
high             2  PowerShell started with an encoded command  (examples/rules/encoded_powershell.yml)
high             1  Brute force against one account  (examples/rules/brute_force.yml)
high             1  Office application starting a shell  (examples/rules/office_spawns_shell.yml)
medium           1  Successful RDP logon from a public address  (examples/rules/rdp_from_outside.yml)
4 of 4 rules matched 14 events (0 rules skipped)
```

The warning holds for a rule that needs a field to have a value. As an event with no fields, a
broken row can still match a rule that is only a `not`, and a keyword rule searches its text.
ClickHouse also reads a broken row in a `String` column as having no fields, without a warning.
On PostgreSQL the `jsonb` and `json` types refuse such a row when it is written.

A table with one column per field needs no `--json-column`. A keyword rule then has nothing to
search unless `--keyword-column` names a column. Here `logs_flat` has `EventID`, `Image`,
`CommandLine`, `timestamp` and `raw`:

```console
$ sigma2sql hunt img.yml kw.yml -t logs_flat -e 1
skip kw.yml: keyword searches need a keyword column or a JSON column
LEVEL         HITS  RULE
medium           1  cmd started  (img.yml)
                      {"EventID": 1, "Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "cmd.exe /c mimikatz", "timestamp": "2026-11-05 10:00:00+00:00", "raw": "cmd.exe /c mimikatz"}
1 of 1 rules matched 1 events (1 rules skipped)
$ sigma2sql hunt img.yml kw.yml -t logs_flat --keyword-column raw -e 1
LEVEL         HITS  RULE
high             1  Mimikatz keyword  (kw.yml)
                      {"EventID": 1, "Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "cmd.exe /c mimikatz", "timestamp": "2026-11-05 10:00:00+00:00", "raw": "cmd.exe /c mimikatz"}
medium           1  cmd started  (img.yml)
                      {"EventID": 1, "Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "cmd.exe /c mimikatz", "timestamp": "2026-11-05 10:00:00+00:00", "raw": "cmd.exe /c mimikatz"}
2 of 2 rules matched 1 events (0 rules skipped)
```

A field the table has no column for is refused by the database, and the rule is skipped. This
is `logs_flat` in a SQLite file, where the rule asks for `User`:

```console
$ sigma2sql hunt user.yml img.yml -t logs_flat
skip user.yml: no such column: User
LEVEL         HITS  RULE
medium           1  cmd started  (img.yml)
1 of 1 rules matched 1 events (1 rules skipped)
```

## Profiles

`-p` takes a built-in [profile](profiles.md) or a YAML file, as with log files. No profile is
chosen for you. `windows_logs` below holds the 510 events of SigmaHQ's `.evtx` regression
samples as JSON, in the layout the `evtx` profile expects. Without the profile, the same rule
finds nothing, because it looks for its fields at the top level of each document:

```console
$ sigma2sql hunt sigma/rules/windows/process_creation/proc_creation_win_hh_chm_execution.yml -t windows_logs --json-column event -p evtx
LEVEL         HITS  RULE
low              1  HH.EXE Execution  (sigma/rules/windows/process_creation/proc_creation_win_hh_chm_execution.yml)
1 of 1 rules matched 510 events (0 rules skipped)
$ sigma2sql hunt sigma/rules/windows/process_creation/proc_creation_win_hh_chm_execution.yml -t windows_logs --json-column event
0 of 1 rules matched 510 events (0 rules skipped)
```

[Product scoping](hunt.md#product-scoping) works as it does for files:

```console
$ sigma2sql hunt sigma/rules/linux -t windows_logs --json-column event -p evtx
0 of 0 rules matched 510 events (0 rules skipped)
211 rules are for other log sources
```

Unlike a hunt over files, a database hunt uses the `table` of a profile's `logsources` entry, so
rules can go to different tables. The events in the summary are counted across `--table` and
every table the profile routes to, each table once. `--json-column` wins over a `json_column`
in the profile.

With routes, `--table` is optional. If a table in that list is missing or may not be read, it
is left out of the count, and only the rules that use it are skipped. In this database
`routes.yml` sends process rules to `process_logs` and logon rules to `logon_logs`, and there
is no table called `events`, the default for `-t`. `file.yml` is a rule for a log source with
no route:

```yaml
# routes.yml
json_column: event
logsources:
  - match: {category: process_creation}
    table: process_logs
  - match: {service: security}
    table: logon_logs
```

```console
$ sigma2sql hunt examples/rules file.yml -p routes.yml; echo $?
skip file.yml: relation "events" does not exist
LEVEL         HITS  RULE
high             2  PowerShell started with an encoded command  (examples/rules/encoded_powershell.yml)
high             1  Brute force against one account  (examples/rules/brute_force.yml)
high             1  Office application starting a shell  (examples/rules/office_spawns_shell.yml)
medium           1  Successful RDP logon from a public address  (examples/rules/rdp_from_outside.yml)
4 of 4 rules matched 12 events (1 rules skipped)
0
```

Without routes there is only the one table, and a table that is missing ends the hunt:

```console
$ sigma2sql hunt failed.yml -t nosuch --json-column event; echo $?
sigma2sql: relation "nosuch" does not exist
LINE 1: SELECT COUNT(*) AS n FROM (SELECT 1 AS x FROM "nosuch") q
                                                      ^
2
```

## `--since`

`--since` looks only at events from a moment on. It takes an age, `30s`, `30m`, `12h`, `7d` or
`2w`, or an ISO 8601 date or time. A date or time without a zone is read as UTC.

The event time comes from the same place as for correlations: the `timestamp` field, the
profile's time field, or `--timestamp-field` and `--timestamp-format`. A time in the data
without a zone is also read as UTC.

Events with no readable time are left out. `logons` has five failed logons. Two are from
November, one is from October, one has `-` as its time and one has no time at all:

```console
$ sigma2sql hunt failed.yml -t logons --json-column event
LEVEL         HITS  RULE
high             5  Failed logon  (failed.yml)
1 of 1 rules matched 5 events (0 rules skipped)
$ sigma2sql hunt failed.yml -t logons --json-column event --since 2026-11-01 -e 5
LEVEL         HITS  RULE
high             2  Failed logon  (failed.yml)
                      {"User": "a", "EventID": 4625, "timestamp": "2026-11-05T10:00:00Z"}
                      {"User": "b", "EventID": 4625, "timestamp": "2026-11-05 10:00:00"}
1 of 1 rules matched 2 events (0 rules skipped)
```

The summary counts the events inside the window. A table with rows of which none has a readable
time is an error, because that means a misspelled time field or a wrong format and not a quiet
week:

```console
$ sigma2sql hunt failed.yml -t logons --json-column event --since 2026-11-01 --timestamp-field EventTime; echo $?
sigma2sql: --since: no row of logons has a readable time in EventTime; set --timestamp-field or use a profile
2
```

A window with no events in it, in a table whose times can be read, is not an error:

```console
$ sigma2sql hunt failed.yml -t logons --json-column event --since 2026-12-01; echo $?
0 of 1 rules matched 0 events (0 rules skipped)
0
```

## `--timeout`

`--timeout SECONDS` limits each query on PostgreSQL and ClickHouse. It defaults to 60 and has to
be at least 1. PostgreSQL enforces it with `statement_timeout` and ClickHouse with
`max_execution_time`, so the server stops the work. sigma2sql stops waiting for ClickHouse 30
seconds after the limit, and that counts as a [lost connection](#if-the-connection-is-lost). On
SQLite and DuckDB the option has no effect, and a query runs as long as it needs. A ClickHouse
user with `readonly = 1` [has no limit from this option](#a-clickhouse-user-with-readonly-1).

A rule that reaches the limit is skipped and named on stderr, and the hunt goes on. `slow.yml`
is a correlation over the four million rows of `logs_big`, and `failed.yml` finished in time:

```console
$ sigma2sql hunt slow.yml failed.yml -t logs_big --json-column event --timeout 2; echo $?
skip slow.yml: canceling statement due to statement timeout
LEVEL            HITS  RULE
high          4000000  Failed logon  (failed.yml)
1 of 1 rules matched 4000000 events (1 rules skipped)
0
```

Skipped rules do not change the exit code as long as one rule ran, so a job that depends on the
result should watch that count, or use `--fail-on`. With `--fail-on`, a rule that reached the
limit makes the run incomplete, and a clean result cannot be trusted. The hunt exits with code
2 unless a rule at that level or above matched, which is still code 1:

```console
$ sigma2sql hunt slow.yml failed.yml -t logs_big --json-column event --timeout 2 --fail-on critical; echo $?
skip slow.yml: canceling statement due to statement timeout
LEVEL            HITS  RULE
high          4000000  Failed logon  (failed.yml)
1 of 1 rules matched 4000000 events (1 rules skipped)
sigma2sql: 1 rules hit the time limit, the run is incomplete
2
$ sigma2sql hunt slow.yml failed.yml -t logs_big --json-column event --timeout 2 --fail-on high; echo $?
skip slow.yml: canceling statement due to statement timeout
LEVEL            HITS  RULE
high          4000000  Failed logon  (failed.yml)
1 of 1 rules matched 4000000 events (1 rules skipped)
1
```

The hunt starts by counting the events in the table. If that query reaches the limit, a warning
says so, the table adds nothing to the summary, and the rules still run. A broad `--since` on a
big table can do this. Here the count and `failed.yml` read every row and reach the limit, and
`img.yml` matches nothing and finishes:

```console
$ sigma2sql hunt failed.yml img.yml -t logs_big --json-column event --timeout 1 --since 2026-11-01; echo $?
warning: logs_big: the events could not be counted within the time limit
skip failed.yml: canceling statement due to statement timeout
0 of 1 rules matched 0 events (1 rules skipped)
0
```

The query for a rule's examples has its own limit. If it fails, a warning names the rule and
the hit stays in the report without examples.

## What read-only means

| Database | What sigma2sql does | What it gives |
| --- | --- | --- |
| PostgreSQL | sets `default_transaction_read_only = on` for the session | the server refuses `INSERT`, `UPDATE`, `DELETE`, schema changes, temporary tables and `nextval()`; a statement in the same session could turn the setting off again |
| ClickHouse | sends `readonly=2` with every request, or no settings for a [user with `readonly = 1`](#a-clickhouse-user-with-readonly-1) | the server refuses writes and schema changes, and a query cannot change `readonly`; with `readonly=2` other settings can still be changed, which sigma2sql needs to send its own |
| SQLite | opens the file with `mode=ro` | this connection cannot write to the file |
| DuckDB | opens the file with `read_only=True` | this connection cannot write to the file; the open fails while another process holds the file for writing |

These settings stop writes. They do not limit what can be read, and they are choices made by
the client. Rules and logs may be written by an attacker, so a limit that the server enforces
whatever the client sends is still the right setup: **connect as a database user that has only
`SELECT`, and only on the tables with the logs.**

For PostgreSQL, a reader also needs `USAGE` on the schema if the table is not in `public`:

```sql
CREATE ROLE sigma_reader LOGIN PASSWORD 'choose-one';
GRANT SELECT ON logs TO sigma_reader;
```

For ClickHouse:

```sql
CREATE USER sigma_reader IDENTIFIED WITH sha256_password BY 'choose-one';
GRANT SELECT ON default.logs TO sigma_reader;
```

SQLite and DuckDB have no users. Run `hunt` as an account that can only read the file. A table
the user has no grant on stops the hunt:

```console
$ sigma2sql hunt failed.yml -t logs_text --json-column event
sigma2sql: permission denied for table logs_text
```

### A ClickHouse user with `readonly = 1`

A user whose settings have `readonly = 1` works, and it is the strictest setup. That mode
refuses every setting sent with a query, so sigma2sql notices this when it connects and sends
none:

```console
$ sigma2sql hunt examples/rules -t logs --json-column event
LEVEL         HITS  RULE
high             2  PowerShell started with an encoded command  (examples/rules/encoded_powershell.yml)
high             1  Brute force against one account  (examples/rules/brute_force.yml)
high             1  Office application starting a shell  (examples/rules/office_spawns_shell.yml)
medium           1  Successful RDP logon from a public address  (examples/rules/rdp_from_outside.yml)
4 of 4 rules matched 12 events (0 rules skipped)
```

The limit that remains is that **such a user runs without the per-query time limit**, because
`--timeout` is one of the settings it cannot send. sigma2sql stops waiting `--timeout` plus 30
seconds later and ends the hunt as a [lost connection](#if-the-connection-is-lost), and the
query keeps running on the server. `logs_slow` is a view that is slow to read:

```console
$ time sigma2sql hunt failed.yml -t logs_slow --json-column event --timeout 2; echo $?
sigma2sql: the database connection was lost: timed out

real	0m32.284s
user	0m0.179s
sys	0m0.028s
2
```

To get a limit back, set it on the user, and the server applies it to every query:

```sql
CREATE USER sigma_reader IDENTIFIED WITH sha256_password BY 'choose-one'
    SETTINGS readonly = 1, max_execution_time = 60;
```

The query size setting is left out as well. A rule larger than ClickHouse's default of 256 KiB,
such as SigmaHQ's list of driver hashes, is then skipped with `Max query size exceeded`. Grants
alone, as above, or `readonly = 2` keep both settings.

## Cost on large tables

Rules run one at a time on one connection. Each rule or correlation is one `COUNT(*)` query, a
rule that matched runs one more query if examples are wanted, and a few queries at the start
count the events in each table. Most Sigma rules are substring searches in text or JSON
fields, which no ordinary index can answer, so expect a full scan of the table for each rule.

SigmaHQ's Windows rules on a table of only 510 events, on a small test machine, give an idea of
the number of queries. The two skipped rules use a regular expression that PostgreSQL cannot
run:

```console
$ time sigma2sql hunt sigma/rules/windows -t windows_logs --json-column event -p evtx > /dev/null
skip sigma/rules/windows/process_creation/proc_creation_win_csc_susp_dynamic_compilation.yml: postgres regexes allow at most 255 repetitions: (?:[Pp]rogram[Dd]ata|%(?:[Ll]ocal)?[Aa]pp[Dd]ata%|\\[Aa]pp[Dd]ata\\(?:[Ll]ocal(?:[Ll]ow)?|[Rr]oaming))\\[^\\]{1,256}$
skip sigma/rules/windows/process_creation/proc_creation_win_csc_susp_parent.yml: postgres regexes allow at most 255 repetitions: (?:[Pp]rogram[Dd]ata|%(?:[Ll]ocal)?[Aa]pp[Dd]ata%|\\[Aa]pp[Dd]ata\\(?:[Ll]ocal(?:[Ll]ow)?|[Rr]oaming))\\[^\\]{1,256}$
492 of 2425 rules matched 510 events (2 rules skipped)

real	0m48.075s
user	0m9.173s
sys	0m0.251s
```

- `--timeout` limits one query, not the hunt. With the default of 60 seconds, 2400 rules could
  take 40 hours in the worst case.
- `--since` reduces what a rule matches, not what the server reads. The time is worked out from
  each row, so an index or partitions on the time column are not used. To really read less, point
  `-t` at a view or table that holds only the period you want.
- On a production system, prefer a replica. Start with a few rules and a short `--timeout` to
  see how long one rule takes.
- On a terminal, `rule N of M` on stderr shows how far the hunt has come. A hunt over log
  files has no such line.

## What appears in reports

`--format json`, `--sarif`, `--html`, `--examples` and `--fail-on` work as described in
[Reading the output](hunt.md#reading-the-output).

The HTML page names the database in place of the log paths. It shows the scheme, the host, the
port and the database name, or the file path for SQLite and DuckDB. The user name, the password
and any options are left out. The terminal table, JSON and SARIF do not name the database.

```console
$ sigma2sql hunt examples/rules -t logs --json-column event --html hits.html
LEVEL         HITS  RULE
high             2  PowerShell started with an encoded command  (examples/rules/encoded_powershell.yml)
high             1  Brute force against one account  (examples/rules/brute_force.yml)
high             1  Office application starting a shell  (examples/rules/office_spawns_shell.yml)
medium           1  Successful RDP logon from a public address  (examples/rules/rdp_from_outside.yml)
4 of 4 rules matched 12 events (0 rules skipped)
$ grep -o 'postgresql://[^<]*' hits.html
postgresql://localhost:15432/logs
```

What an example shows depends on the table:

- With `--json-column`, it is the JSON document alone. Other columns of the row stay out of the
  report. A `jsonb` column keeps its own order of keys, not the original one.
- Without it, it is the whole row, every column of the table. Point `-t` at a view if the table
  has columns that should not end up in a report.
- For a correlation, it is a result row with the group, the window and the value.

The HTML page holds up to five examples per rule even without `-e`, so treat it as a copy of
that log data.

If the database cannot be reached, the error from the driver goes to stderr with the password
replaced by `***`. It can name the host and the user:

```console
$ sigma2sql hunt failed.yml -t logs
sigma2sql: connection failed: connection to server at "127.0.0.1", port 15432 failed: FATAL:  password authentication failed for user "sigma_reader"
```

An error from ClickHouse is passed on as the server wrote it, cut at 400 bytes, so it can look
like raw text or JSON:

```console
$ sigma2sql hunt failed.yml -t missing_table --json-column event; echo $?
sigma2sql: {"exception": "Code: 60. DB::Exception: Unknown table expression identifier 'missing_table' in scope SELECT 1 AS x FROM missing_table. (UNKNOWN_TABLE) (version 25.8.33.6 (official build))"}
2
```

## If the connection is lost

A connection that is lost during the hunt ends it with code 2, because no later query could work
either. There is no partial report, and no `--html` or `--sarif` file is written:

```console
$ sigma2sql hunt failed.yml -t logs_sleep --json-column event --html lost.html; echo $?
sigma2sql: the database connection was lost: terminating connection due to administrator command
2
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | The hunt finished. This includes runs with no match, with warnings and, if a rule ran, with skipped rules. |
| 1 | A rule at or above `--fail-on` matched. Also when the `postgres` or `duckdb` extra is missing. |
| 2 | The hunt could not run or could not finish: an address that cannot be used, a failed or lost connection, a missing table or one the user may not read when there is only that table, `--since` on a table where no row has a readable time, no rule that could run, a rule that reached `--timeout` with `--fail-on` set and nothing matched at that level, or a `--sarif` or `--html` file that cannot be written. |

All commands are listed under [Exit codes](cli.md#exit-codes).
