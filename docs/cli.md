# Command line

`sigma2sql` has five subcommands. `python -m sigma2sql` runs the same program.

```console
$ sigma2sql --help
usage: sigma2sql [-h] [--version] {convert,test,hunt,check,profiles} ...

Convert Sigma rules to SQL, test them against sample events and hunt through log files.

positional arguments:
  {convert,test,hunt,check,profiles}
    convert             print SQL for rules and correlations
    test                run a rule file against JSON Lines events
    hunt                run rules over EVTX, JSON, Parquet or CSV logs with DuckDB
    check               test rules against their <rule>.match.jsonl /
                        <rule>.nomatch.jsonl files
    profiles            list the built-in profiles

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
$ sigma2sql --version
sigma2sql 0.4.0
```

Results go to stdout. Skipped rules, warnings and summary lines go to stderr, so a command can
be piped or redirected without them. Output is always UTF-8, whatever the console code page,
because rules contain non-ASCII characters. The examples on this page show both streams.

The exit codes of all commands are collected in [Exit codes](#exit-codes).

## Options shared by the rule commands

`convert`, `test`, `hunt` and `check` take the same options for reaching your fields:

| Option | Default | Meaning |
| --- | --- | --- |
| `-p, --profile NAME` | none | built-in profile name or the path of a YAML file, see [Profiles](profiles.md) |
| `-m, --mapping FILE` | none | YAML map of Sigma field to column or key, applied over the profile |
| `--placeholders FILE` | none | YAML map of `%name%` placeholder to a value or a list of values, see [Placeholders](placeholders.md) |
| `--nested` | off | dotted names are paths into nested JSON, not keys with a dot in them |
| `--timestamp-field NAME` | `timestamp` | event time, used by correlations and `count()` rules |
| `--timestamp-format FORMAT` | `iso` | `iso`, `epoch_s` or `epoch_ms` |

Settings are applied in this order: the built-in defaults, the profile, then the options on the
command line. Three details:

- `--mapping` wins over the profile field by field. Each value must be a single string; a list
  of candidates ("first one present wins") is only possible in a profile.
- `json_column` in a profile wins over `--json-column`. None of the built-in profiles set it.
- A `table` in a profile's `logsources` entry wins over `-t` for the rules that entry matches.

The time modifiers (`minute`, `hour` and so on) read the field named in the rule, not
`--timestamp-field`. `--timestamp-format` decides how they read it.

`--timestamp-field` names a path in the event. With a JSON column, a profile's `default_field`
is tried after that path, so `-p evtx --timestamp-field UtcTime` finds Sysmon's time. A
`--mapping` entry for the name wins over both. See [Event time](profiles.md#event-time).

## convert

Print the SQL for rules and correlations.

```text
usage: sigma2sql convert [-h] [-d {sqlite,postgres,duckdb,clickhouse}] [-t TABLE]
                         [--json-column JSON_COLUMN] [--keyword-column KEYWORD_COLUMN]
                         [-p PROFILE] [-m MAPPING] [--placeholders PLACEHOLDERS]
                         [--nested] [--timestamp-field TIMESTAMP_FIELD]
                         [--timestamp-format {iso,epoch_s,epoch_ms}]
                         paths [paths ...]
```

| Option | Default | Meaning |
| --- | --- | --- |
| `paths` | required | rule files or directories, one or more |
| `-d, --dialect` | `sqlite` | `sqlite`, `postgres`, `duckdb` or `clickhouse` |
| `-t, --table` | `events` | table name; dots separate schema and table, and each part is quoted |
| `--json-column` | none | read fields from this JSON column; without it each field is a column |
| `--keyword-column` | none | column searched by keyword rules |

The [shared options](#options-shared-by-the-rule-commands) apply too.

A directory is searched recursively for `.yml` and `.yaml` files, in sorted order. The suffix
can be in upper or lower case. A file named on the command line is read whatever its suffix.
Filter files among the paths are applied to the rules they cover, see [Filters](filters.md).

Each query is printed after a comment with the rule's title and id:

```console
$ sigma2sql convert cmd.yml
-- cmd.exe started
SELECT * FROM "events" WHERE "Image" LIKE '%\\cmd.exe' ESCAPE '\';

$ sigma2sql convert cmd.yml -d postgres -t security.events --json-column data
-- cmd.exe started
SELECT * FROM "security"."events" WHERE "data"->>'Image' ILIKE '%\\cmd.exe' ESCAPE '\';

```

With a mapping file and nested paths:

```console
$ cat nested.yml
Image: process.executable
$ sigma2sql convert cmd.yml -d clickhouse --json-column event --nested -m nested.yml
-- cmd.exe started
SELECT * FROM "events" WHERE JSONExtract("event", 'process', 'executable', 'Nullable(String)') ILIKE '%\\\\cmd.exe';

```

A profile can add a condition for the rule's log source:

```console
$ sigma2sql convert cmd.yml -p sysmon --json-column data
-- cmd.exe started
SELECT * FROM "events" WHERE (CAST(json_extract("data", '$."EventID"') AS TEXT) = '1' AND json_extract("data", '$."Image"') LIKE '%\\cmd.exe' ESCAPE '\');

```

Keyword rules search `--keyword-column` when it is given, and otherwise the whole document in
`--json-column`. With neither, the rule [cannot be converted](convert.md#keyword-rules). A rule
that uses a placeholder is skipped until you [give its value](placeholders.md).

A rule that cannot be converted does not stop the others. It is named on stderr with the reason
and the command exits 1. When there is more than one rule, a count follows:

```console
$ sigma2sql convert bad.yml keyword.yml --keyword-column raw; echo $?
skip bad.yml: modifier 'nosuchmod' is not supported
-- Keyword search
SELECT * FROM "events" WHERE "raw" LIKE '%mimikatz%' ESCAPE '\';

converted 1/2 rules
1
```

Rules that a correlation refers to are not printed on their own unless the correlation sets
`generate: true`. A correlation needs its rules among the paths you pass, in the same file or
another one. See [Several rules](correlations.md#several-rules).

## test

Run one rule file against JSON Lines events and print what it matches. `test` works on an
in-memory SQLite database, so it needs no extra packages.

```text
usage: sigma2sql test [-h] [--expect {match,none}] [-p PROFILE] [-m MAPPING]
                      [--placeholders PLACEHOLDERS] [--nested]
                      [--timestamp-field TIMESTAMP_FIELD]
                      [--timestamp-format {iso,epoch_s,epoch_ms}]
                      rule events
```

| Option | Default | Meaning |
| --- | --- | --- |
| `rule` | required | the rule file |
| `events` | required | one JSON object per line; empty lines are ignored |
| `--expect` | none | `match`: exit 1 unless every rule in the file matches. `none`: exit 1 if anything matches |

The [shared options](#options-shared-by-the-rule-commands) apply too. There is no `--dialect`,
`--table`, `--json-column` or `--keyword-column`, because the events are always loaded into a
table of its own.

For a detection rule, the matching lines of the events file are printed unchanged. For a
correlation or `count()` rule, each result row is printed as JSON. A summary per rule goes to
stderr.

```console
$ sigma2sql test examples/rules/office_spawns_shell.yml examples/events.jsonl --expect none
{"EventID": 1, "Image": "C:\\Windows\\System32\\cmd.exe", "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "CommandLine": "cmd.exe /c whoami"}
Office application starting a shell: 1 of 12 events matched
$ sigma2sql test examples/rules/brute_force.yml examples/events.jsonl
{"TargetUserName": "admin", "window_start": "2026-11-01 03:12:01.000", "window_end": "2026-11-01 03:12:17.000", "value": 3}
Brute force against one account: 1 results
```

Only the given file is loaded. A correlation in `test` therefore needs its rules in the same
file, and filters in other files are not applied. Log source conditions from a profile do
apply, and a profile's `table` is ignored.

Without `--expect` the exit code does not depend on what matched. A rule path that does not
exist or holds no rule files, a rule that cannot be converted, a rule file that cannot be
loaded, an invalid regular expression and an events file that cannot be read all exit 2. A
regular expression is checked before any event is looked at:

```console
$ sigma2sql test bad.yml examples/events.jsonl
sigma2sql: Broken: modifier 'nosuchmod' is not supported
$ sigma2sql test regex/bad_regex.yml examples/events.jsonl
sigma2sql: Unbalanced group: invalid regex '(': missing ), unterminated subpattern at position 0
$ sigma2sql test missing.yml examples/events.jsonl
sigma2sql: missing.yml: no such file or directory
$ sigma2sql test cmd.yml not-an-object.jsonl
sigma2sql: line 1: each event must be a JSON object
```

## hunt

Run rules and correlations over log files with an in-memory DuckDB database, and list the ones
that matched. Needs the `duckdb` extra, and the `evtx` extra for `.evtx` files. See [Hunt
through log files](hunt.md) for a walk-through.

```text
usage: sigma2sql hunt [-h] -l LOGS [LOGS ...] [-e EXAMPLES] [--format {table,json}]
                      [--sarif SARIF] [--html HTML]
                      [--fail-on {critical,high,medium,low,informational}] [-p PROFILE]
                      [-m MAPPING] [--placeholders PLACEHOLDERS] [--nested]
                      [--timestamp-field TIMESTAMP_FIELD]
                      [--timestamp-format {iso,epoch_s,epoch_ms}]
                      rules [rules ...]
```

| Option | Default | Meaning |
| --- | --- | --- |
| `rules` | required | rule files or directories, one or more, filter files included |
| `-l, --logs` | required | log files, one or more; globs such as `'logs/*.json'` |
| `-e, --examples N` | `0` | show up to N matching events or correlation results per rule; a negative N is an error; without it, `--html` still puts up to five on the page |
| `--format` | `table` | `table` or `json` |
| `--sarif FILE` | none | also write the matches to this SARIF file |
| `--html FILE` | none | also write a report to this HTML file, see [`--html`](hunt.md#-html) |
| `--fail-on LEVEL` | none | exit 1 if a rule at this level or above matches: `critical`, `high`, `medium`, `low` or `informational` |

The [shared options](#options-shared-by-the-rule-commands) apply too. `--logs` takes any number
of values, so write the rule paths before it. Quote globs so that they are expanded by
sigma2sql and not by the shell.

The file suffix picks the reader, in upper or lower case:

| Suffix | Read as |
| --- | --- |
| `.json`, `.jsonl`, `.ndjson` | JSON or JSON Lines, one object per event; each element of a JSON array is an event |
| `.parquet` | Parquet, one row per event |
| `.csv`, `.tsv` | delimited text with DuckDB's type detection, one row per event |
| `.evtx` | Windows event log, in the layout of `evtx_dump` |

Any other suffix is an error. All logs of a hunt go into one table, with each event stored as
JSON. Because of that a profile's `table` is ignored in `hunt`; its `where` conditions still
apply.

If any path ends in `.evtx` and you pass no `--profile`, the `evtx` profile is used for the
whole hunt. If other logs are among the paths, `hunt` warns with `all logs are read with the
evtx profile`. `--timestamp-field` and the other options win over the profile, as they do over
any profile.

### Output

```console
$ sigma2sql hunt examples/rules --logs examples/events.jsonl
LEVEL         HITS  RULE
high             2  PowerShell started with an encoded command  (examples/rules/encoded_powershell.yml)
high             1  Brute force against one account  (examples/rules/brute_force.yml)
high             1  Office application starting a shell  (examples/rules/office_spawns_shell.yml)
medium           1  Successful RDP logon from a public address  (examples/rules/rdp_from_outside.yml)
4 of 4 rules matched 12 events (0 rules skipped)
```

Rules are sorted by level, then by hits, highest first, then by title. A rule without a level
shows `-` and comes last. `HITS` counts matching events, or result rows for a correlation. If
nothing matched, no table is printed. In the summary on stderr, `12 events` is the number of
events loaded, not the number that matched.

`--format json` prints one object per matching rule, with the examples parsed, or `[]` with no
match. See [`--format json`](hunt.md#-format-json) for an example.

### Other log sources

A profile can name a `product`. `hunt` then runs only the rules for that product and counts the
rest on stderr. A rule with no `product` is one of the rest, and a correlation runs if one of
its rules is for that product. The built-in `sysmon`, `evtx` and `ecs-winlogbeat` profiles name
`windows`, so a directory with rules for every product can be used as it is:

```console
$ sigma2sql hunt keyword.yml --logs examples/events.jsonl -p sysmon
0 of 0 rules matched 12 events (0 rules skipped)
1 rules are for other log sources
```

### Skipped rules and damaged logs

A rule that cannot be converted, or that DuckDB rejects, is named on stderr and the hunt goes
on. Skipped rules do not change the exit code as long as one rule ran, so a CI job that depends
on `hunt` should watch that count as well.

```console
$ sigma2sql hunt bad.yml examples/rules/rdp_from_outside.yml --logs examples/events.jsonl
skip bad.yml: modifier 'nosuchmod' is not supported
LEVEL         HITS  RULE
medium           1  Successful RDP logon from a public address  (examples/rules/rdp_from_outside.yml)
1 of 1 rules matched 12 events (1 rules skipped)
```

If rules were skipped and none could run, the hunt ends with exit code 2:

```console
$ sigma2sql hunt bad.yml --logs examples/events.jsonl; echo $?
skip bad.yml: modifier 'nosuchmod' is not supported
0 of 0 rules matched 12 events (1 rules skipped)
sigma2sql: no rule could run
2
```

Logs from an incident are often damaged, so `.evtx` files are read as far as possible, with a
warning for what is lost. If that leaves the whole hunt with no event at all, it ends with exit
code 2. See [Damaged files](hunt.md#damaged-files). Other log formats are read by DuckDB, and a
file it cannot read ends the hunt with exit code 2.

### Fail levels and SARIF

`--fail-on` compares a rule's `level` with the given level. The order is `critical`, `high`,
`medium`, `low`, `informational`. A rule with no level, or a level outside this list, never
triggers it.

```console
$ sigma2sql hunt examples/rules --logs examples/events.jsonl --fail-on critical > /dev/null; echo $?
4 of 4 rules matched 12 events (0 rules skipped)
0
$ sigma2sql hunt examples/rules --logs examples/events.jsonl --fail-on high > /dev/null; echo $?
4 of 4 rules matched 12 events (0 rules skipped)
1
```

`--sarif FILE` writes a SARIF 2.1.0 report with one result per matching rule. See
[`--sarif`](hunt.md#-sarif) for its rule ids and levels. A file that cannot be written gives
exit code 2.

### HTML report

`--html FILE` writes one page with the matches, their rule details and examples, the
warnings and the skipped rules. The page needs no network and runs no script. It shows up to
five examples per rule unless `-e` is given, and the first 20 critical or high matches start
open. See [`--html`](hunt.md#-html). A file that cannot be written gives exit code 2.

## check

Test rules against the example events kept next to them, as described in [Test
rules](testing.md). Like `test`, this runs on SQLite and needs no extra packages.

```text
usage: sigma2sql check [-h] [--require-tests] [--sarif SARIF] [-p PROFILE] [-m MAPPING]
                       [--placeholders PLACEHOLDERS] [--nested]
                       [--timestamp-field TIMESTAMP_FIELD]
                       [--timestamp-format {iso,epoch_s,epoch_ms}]
                       paths [paths ...]
```

| Option | Default | Meaning |
| --- | --- | --- |
| `paths` | required | rule files or directories, one or more |
| `--require-tests` | off | fail when a rule file has neither test file |
| `--sarif FILE` | none | also write the failures to this SARIF file |

The [shared options](#options-shared-by-the-rule-commands) apply too.

For `rules/x.yml`, `check` reads `rules/x.match.jsonl` and `rules/x.nomatch.jsonl`, whichever
exist. For a detection rule, every event in the first must match and no event in the second
may. For a correlation or `count()` rule, the first must give at least one result row and the
second none. A file with several rules has each of them tested, except rules that only feed a
correlation.

```console
$ sigma2sql check examples/rules --require-tests
ok   examples/rules/brute_force.yml
ok   examples/rules/encoded_powershell.yml
ok   examples/rules/office_spawns_shell.yml
ok   examples/rules/rdp_from_outside.yml
4 passed, 0 failed, 0 without tests
```

`ok` and `FAIL` lines go to stdout and the summary to stderr. A failure names the rule, the
file and the events, counted from 1 with empty lines left out:

```console
$ sigma2sql check rules
FAIL rules/office_spawns_shell.yml: Office application starting a shell: missed office_spawns_shell.match.jsonl event(s) 1
0 passed, 1 failed, 0 without tests
```

Every rule is loaded and converted, also one without test events, and its regular expressions
are compiled. A failure there fails the run, even if no event reaches the pattern:

```console
$ sigma2sql check regex
FAIL regex/bad_regex.yml: Unbalanced group: invalid regex '(': missing ), unterminated subpattern at position 0
0 passed, 1 failed, 0 without tests
```

Otherwise rule files without test events are counted, and fail only with `--require-tests`:

```console
$ sigma2sql check keyword.yml
0 passed, 0 failed, 1 without tests
$ sigma2sql check keyword.yml --require-tests
FAIL keyword.yml: no keyword.match.jsonl or .nomatch.jsonl
0 passed, 1 failed, 1 without tests
```

Some details follow from each rule file being checked on its own:

- A correlation in a different file from its rules fails with `correlation refers to unknown
  rules`.
- Filters in other files are not applied. A filter file in a checked directory counts as a rule
  file, so `--require-tests` asks for test events for it.

Each rule path that does not exist or holds no rule files is named and ends the run, also next
to a good path, so a mistyped path in CI does not pass:

```console
$ sigma2sql check missing-rules; echo $?
sigma2sql: missing-rules: no such file or directory
2
$ sigma2sql check examples/rules empty; echo $?
sigma2sql: empty: no .yml or .yaml files found
2
```

`--sarif FILE` writes one result per problem, all with the rule id `rule-test` and level
`error`. The file is written when every rule passes too, with an empty result list. A file that
cannot be written gives exit code 2.

The repository is also a GitHub Action that runs `check`, see [Test
rules](testing.md#github-action).

## profiles

List the built-in profiles. This command has no options apart from `--help`.

```console
$ sigma2sql profiles
ecs-winlogbeat  Windows events shipped by Winlogbeat in Elastic Common Schema (nested JSON); unmapped fields fall back to winlog.event_data
evtx            Windows event logs exported to JSON by evtx_dump or python-evtx (Event.System / Event.EventData)
ocsf            OCSF 1.x events (nested JSON, time in epoch milliseconds), routed by class_uid
sysmon          Sysmon events with their original field names; each Sigma category is limited to its Sysmon event ID
```

## Exit codes

| Code | `convert` | `test` | `hunt` | `check` |
| --- | --- | --- | --- | --- |
| 0 | every rule converted | ran; with `--expect`, the expectation held | ran; nothing reached `--fail-on` | every rule loaded and every tested rule passed |
| 1 | a rule or file was skipped | `--expect` did not hold | a rule reached `--fail-on`, or the `duckdb` or `evtx` package is missing | a rule failed, could not be loaded or converted, or has no tests with `--require-tests` |
| 2 | no rules found, also when the paths hold only filters | no rules found, the rule or events could not be read, converted or run, or a regular expression is invalid | no rules found, no rule could run, a log could not be read, damaged `.evtx` files gave no event at all, or the `--sarif` or `--html` file could not be written | no rules found, or the `--sarif` file could not be written |

For all four commands, code 2 also covers bad usage and a profile, mapping or placeholders file
that cannot be loaded. For `test`, `hunt` and `check`, "no rules found" means a rule path that
does not exist or holds no rule files, also next to a good path; a file with only filters
counts as a rule file there. `profiles`, `--help` and `--version` exit 0.

```console
$ sigma2sql convert cmd.yml -p nosuch; echo $?
sigma2sql: unknown profile 'nosuch' (built in: ecs-winlogbeat, evtx, ocsf, sysmon)
2
$ sigma2sql convert cmd.yml -m badmap.yml; echo $?
sigma2sql: mapping: expected a map of field name to column name
2
$ sigma2sql convert emptydir; echo $?
sigma2sql: no .yml or .yaml files found
2
$ sigma2sql hunt examples/rules --logs cmd.yml; echo $?
sigma2sql: cmd.yml: expected .json, .jsonl, .ndjson, .parquet, .csv or .evtx
2
```
