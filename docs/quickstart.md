# Quick start

This page installs sigma2sql and runs one hunt, one conversion and one rule test on the example
rules from the repository.

## Install

sigma2sql needs Python 3.12 or newer.

```bash
pip install "sigma2sql[duckdb,evtx]"
# or as a standalone tool
uv tool install "sigma2sql[duckdb,evtx]"
```

The extras add what `hunt` needs. Leave them out if you do not use it.

| Install | Gives you |
| --- | --- |
| `sigma2sql` | `convert`, `test`, `check` and `profiles`; the only dependency is PyYAML |
| `sigma2sql[duckdb]` | also `hunt` over JSON, Parquet and CSV files |
| `sigma2sql[duckdb,evtx]` | also `hunt` over `.evtx` files |
| `sigma2sql[postgres]` | also `hunt` in a PostgreSQL database, see [Hunt in a database](database.md) |

Check the install:

```console
$ sigma2sql --version
sigma2sql 0.5.2
```

The example rules and events are in the repository, not in the package:

```bash
git clone --depth 1 https://github.com/brkozer/sigma2sql
cd sigma2sql
```

A command that needs a missing extra says so and exits with code 1:

```console
$ sigma2sql hunt examples/rules --logs examples/events.jsonl
sigma2sql hunt needs DuckDB: pip install 'sigma2sql[duckdb]'
```

## First hunt

`hunt` takes rule files or directories, and log files after `--logs`:

```console
$ sigma2sql hunt examples/rules --logs examples/events.jsonl
LEVEL         HITS  RULE
high             2  PowerShell started with an encoded command  (examples/rules/encoded_powershell.yml)
high             1  Brute force against one account  (examples/rules/brute_force.yml)
high             1  Office application starting a shell  (examples/rules/office_spawns_shell.yml)
medium           1  Successful RDP logon from a public address  (examples/rules/rdp_from_outside.yml)
4 of 4 rules matched 12 events (0 rules skipped)
```

The rules that matched are listed, most severe first. The last line says how many rules
matched, how many ran and how many events were loaded.

`--examples N` adds up to N results under each rule, so you can see what fired:

```console
$ sigma2sql hunt examples/rules --logs examples/events.jsonl --examples 1
LEVEL         HITS  RULE
high             2  PowerShell started with an encoded command  (examples/rules/encoded_powershell.yml)
                      {"EventID": 1, "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "ParentImage": "C:\\Windows\\explorer.exe", "CommandLine": "powershell.exe -NoProfile -enc SQBFAFgA"}
high             1  Brute force against one account  (examples/rules/brute_force.yml)
                      {"TargetUserName":"admin","window_start":"2026-11-01 03:12:01","window_end":"2026-11-01 03:12:17","value":3}
high             1  Office application starting a shell  (examples/rules/office_spawns_shell.yml)
                      {"EventID": 1, "Image": "C:\\Windows\\System32\\cmd.exe", "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "CommandLine": "cmd.exe /c whoami"}
medium           1  Successful RDP logon from a public address  (examples/rules/rdp_from_outside.yml)
                      {"EventID": 4624, "LogonType": 10, "IpAddress": "203.0.113.45", "TargetUserName": "admin"}
4 of 4 rules matched 12 events (0 rules skipped)
```

A correlation shows its result row, not an event: the group, the window and the counted value.

To hunt real logs with SigmaHQ's main rule folder:

```bash
git clone --depth 1 https://github.com/SigmaHQ/sigma
sigma2sql hunt sigma/rules --logs 'logs/*.evtx' --examples 1
```

[Hunt through log files](hunt.md) covers the formats, reports and exit codes.

## First conversion

`convert` prints SQL. Here the events sit in a PostgreSQL table with a JSON column called
`data`:

```console
$ sigma2sql convert examples/rules/office_spawns_shell.yml -d postgres --json-column data
-- Office application starting a shell (8a7f3e91-2c44-4b8e-b0f6-3e5d9c1a7b02)
SELECT * FROM "events" WHERE (("data"->>'ParentImage' ILIKE '%\\winword.exe' ESCAPE '\' OR "data"->>'ParentImage' ILIKE '%\\excel.exe' ESCAPE '\' OR "data"->>'ParentImage' ILIKE '%\\powerpnt.exe' ESCAPE '\') AND ("data"->>'Image' ILIKE '%\\cmd.exe' ESCAPE '\' OR "data"->>'Image' ILIKE '%\\powershell.exe' ESCAPE '\' OR "data"->>'Image' ILIKE '%\\wscript.exe' ESCAPE '\' OR "data"->>'Image' ILIKE '%\\cscript.exe' ESCAPE '\' OR "data"->>'Image' ILIKE '%\\mshta.exe' ESCAPE '\'));
```

The default dialect is SQLite and the default table is `events`. Without `--json-column`, each
Sigma field is a column. If your field names differ from Sigma's, pick a built-in profile with
`--profile` or write your own:

```console
$ sigma2sql profiles
ecs-winlogbeat  Windows events shipped by Winlogbeat in Elastic Common Schema (nested JSON); unmapped fields fall back to winlog.event_data
evtx            Windows event logs exported to JSON by evtx_dump or python-evtx (Event.System / Event.EventData)
ocsf            OCSF 1.x events (nested JSON, time in epoch milliseconds), routed by class_uid
sysmon          Sysmon events with their original field names; each Sigma category is limited to its Sysmon event ID
```

See [Convert rules](convert.md) and [Profiles](profiles.md).

## First rule test

A rule can have example events next to it, one JSON object per line.
`<rule>.match.jsonl` holds events it must match, and `<rule>.nomatch.jsonl` holds events it must
not match. `check` runs all of them:

```console
$ sigma2sql check examples/rules --require-tests
ok   examples/rules/brute_force.yml
ok   examples/rules/encoded_powershell.yml
ok   examples/rules/office_spawns_shell.yml
ok   examples/rules/rdp_from_outside.yml
4 passed, 0 failed, 0 without tests
```

`--require-tests` makes a rule without example events a failure. A failure names the rule, the
file and the event's position in it, and the exit code is 1. This is the Office rule with a
`cmd.exe` started by Outlook added as the first line of its match file. The rule only watches
Word, Excel and PowerPoint:

```console
$ sigma2sql check failing
FAIL failing/office_spawns_shell.yml: Office application starting a shell: missed office_spawns_shell.match.jsonl event(s) 1
0 passed, 1 failed, 0 without tests
```

To see what one rule does with a file of events, use `test`. It prints the matching events on
stdout and a count on stderr:

```console
$ sigma2sql test examples/rules/office_spawns_shell.yml examples/events.jsonl
{"EventID": 1, "Image": "C:\\Windows\\System32\\cmd.exe", "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "CommandLine": "cmd.exe /c whoami"}
Office application starting a shell: 1 of 12 events matched
```

[Test rules](testing.md) has the details and the GitHub Action.

## Where next

- [Rule coverage](coverage.md): `sigma2sql coverage` shows which rules can match your logs.
- [Local interface](serve.md): `sigma2sql serve` opens all of this in a page.
- [Hunt in a database](database.md): run the rules where your logs already are.
- [Correlations](correlations.md): event counts, value counts and sequences over a time window.
- [Placeholders](placeholders.md) and [Filters](filters.md): your values and exceptions, kept
  outside the rules.
- [Command line](cli.md): every option of every command.
