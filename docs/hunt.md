# Hunt through log files

`hunt` runs Sigma rules over log files without a database server. It loads the files into an
in-memory DuckDB database, runs every rule and correlation as SQL, and lists the ones that
matched, most severe first. Most examples here use `examples/` from the repository. The others
run in a scratch folder with small log files in `logs/` and copies of the example rules in
`more/`.

```console
$ sigma2sql hunt examples/rules --logs examples/events.jsonl
LEVEL         HITS  RULE
high             2  PowerShell started with an encoded command  (examples/rules/encoded_powershell.yml)
high             1  Brute force against one account  (examples/rules/brute_force.yml)
high             1  Office application starting a shell  (examples/rules/office_spawns_shell.yml)
medium           1  Successful RDP logon from a public address  (examples/rules/rdp_from_outside.yml)
4 of 4 rules matched 12 events (0 rules skipped)
```

It needs the `duckdb` extra, which asks for DuckDB 1.3 or newer, and `evtx` for `.evtx` files:

```bash
pip install "sigma2sql[duckdb,evtx]"
```

Without them, `hunt` prints the `pip install` line it needs and exits with code 1.

## Rules

Give rule files, directories or both, before `--logs`. A directory is searched recursively for
`.yml` and `.yaml` files, in upper or lower case. A file can hold several documents, as
`brute_force.yml` does: a rule and a [correlation](correlations.md) over it.

A rule that a correlation refers to only feeds that correlation, unless the correlation sets
`generate: true`. That is why the four files above give four results and not five.

[Filter](filters.md) files go in the same list, and `--placeholders` gives the values for
[placeholders](placeholders.md).

## Log formats

`--logs` (`-l`) takes one or more paths. The extension decides how a file is read, in upper or
lower case.

| Extension | Read as |
| --- | --- |
| `.json`, `.jsonl`, `.ndjson` | JSON objects, one event each: JSON Lines, objects one after the other, or a single top-level array |
| `.parquet` | one event per row |
| `.csv`, `.tsv` | one event per row; DuckDB detects the delimiter, the header and the column types |
| `.evtx` | Windows event logs, see [below](#evtx-files) |

Anything else stops the hunt with code 2, including a directory, a compressed file such as
`.jsonl.gz` and a plain `.log`:

```console
$ sigma2sql hunt more/encoded_powershell.yml --logs logs/app.log
sigma2sql: logs/app.log: expected .json, .jsonl, .ndjson, .parquet, .csv or .evtx
```

`.tsv` works too, although the message leaves it out.

Paths can be globs. Quote them so sigma2sql expands them and not your shell. In a quoted glob,
`**` crosses directories for every format except `.evtx`, where it works like a single `*`. A
glob has to end in one of the extensions above, so `'logs/*'` is refused like `logs/app.log`.

A missing file is an error, and so is a glob that matches nothing. One malformed line in a JSON
file also stops the hunt with code 2. The message comes from DuckDB and gives the file and a
line number, which can be one past the bad line. A CSV file whose layout DuckDB cannot detect
stops the hunt too. Only `.evtx` files are read as far as possible.

## How files load

Every event ends up as one row in one table: `events`, with a single JSON column called `data`.
sigma2sql never writes to your log files, and the database is gone when the run ends.

- JSON objects are stored as they are.
- Parquet, CSV and TSV rows are turned into JSON objects with one key per column.
- `.evtx` records are turned into JSON in the layout of `evtx_dump`
  (`Event.System`, `Event.EventData`), through a temporary file.

All files of a run share that table, so formats can be mixed. This run reads two events from a
JSON array and two from a CSV file:

```console
$ sigma2sql hunt more/encoded_powershell.yml --logs logs/array.json logs/process.csv
LEVEL         HITS  RULE
high             2  PowerShell started with an encoded command  (more/encoded_powershell.yml)
1 of 1 rules matched 4 events (0 rules skipped)
```

A value matches whether it is stored as `4624` or `"4624"`. CSV and TSV values go through
DuckDB's type detection first, so the JSON can differ from the text in the file. In a column of
decimals `1.10` becomes `1.1`, and a rule for `'1.10'` does not match it. A file of numbers
with no header line gets columns called `column0`, `column1` and so on.

Without a profile, a Sigma field is looked up as a top-level key of the event. To read other
layouts:

| Option | Effect |
| --- | --- |
| `-p`, `--profile` | a built-in [profile](profiles.md) or a YAML file |
| `-m`, `--mapping` | YAML map from Sigma field to key, applied over the profile |
| `--nested` | dotted names are paths into nested JSON |
| `--timestamp-field`, `--timestamp-format` | event time for [correlations](#correlations) |

Keyword rules search [the JSON text](features.md#keywords) of the whole event. `hunt` has no
`--dialect` or `--table`, as it always runs on its own DuckDB table.

## Reading the output

The table goes to stdout. Warnings, skipped rules and the summary go to stderr, so they stay out
of a redirected report.

Rules are sorted by level, then by number of hits, then by title. A rule without a level shows
`-` and comes last. If nothing matched, the table is left out and only the summary is printed.

The summary is about the run, not about the matches:

```
4 of 4 rules matched 12 events (0 rules skipped)
```

Here 4 rules matched, 4 rules ran and 12 events were loaded. It does not mean that 12 events
matched: the number of matches per rule is in the `HITS` column.

### `--examples`

`-e N`, `--examples N` shows up to N results under each rule. For a detection rule these are
the events as stored. For a correlation they are result rows. They come in no fixed order. If
the query for the examples fails, for example on a time out of range in one result row, a
warning names the rule and the hit stays in the report without examples.

```console
$ sigma2sql hunt more/encoded_powershell.yml --logs logs/process.csv --examples 1
LEVEL         HITS  RULE
high             1  PowerShell started with an encoded command  (more/encoded_powershell.yml)
                      {"EventID":1,"Image":"C:\\Tools\\pwsh.exe","CommandLine":"pwsh.exe -enc SQBFAFgA"}
1 of 1 rules matched 2 events (0 rules skipped)
```

### `--format json`

`--format json` prints the same report as a JSON array on stdout. It is `[]` if nothing matched.

```console
$ sigma2sql hunt examples/rules/brute_force.yml --logs examples/events.jsonl --format json --examples 1
[
  {
    "title": "Brute force against one account",
    "id": "9e8d7c6b-5a49-4382-a1b0-c9d8e7f6a505",
    "level": "high",
    "path": "examples/rules/brute_force.yml",
    "correlation": true,
    "count": 1,
    "examples": [
      {
        "TargetUserName": "admin",
        "window_start": "2026-11-01 03:12:01",
        "window_end": "2026-11-01 03:12:17",
        "value": 3
      }
    ]
  }
]
1 of 1 rules matched 12 events (0 rules skipped)
```

`correlation` is true for correlations and for `count()` aggregations. `examples` is empty
without `--examples`. The events in it are real JSON, so `jq` can read them. Here it picks the
command line from an `.evtx` event:

```console
$ sigma2sql hunt rules --logs logs/curl.evtx --format json --examples 1 2>/dev/null | jq -r '.[].examples[].Event.EventData.CommandLine'
C:\Windows\System32\Curl.exe  -s -A "HttpBrowser/1.0" -m3 www.google.com
```

### `--sarif`

`--sarif FILE` also writes a SARIF 2.1.0 report, whatever `--format` says. Each rule that
matched gives one result, located at the rule file. The parent directory must exist. If the
file cannot be written, the report is still printed and the run ends with code 2, whatever
`--fail-on` says.

```console
$ sigma2sql hunt examples/rules --logs examples/events.jsonl --sarif hits.sarif
LEVEL         HITS  RULE
high             2  PowerShell started with an encoded command  (examples/rules/encoded_powershell.yml)
high             1  Brute force against one account  (examples/rules/brute_force.yml)
high             1  Office application starting a shell  (examples/rules/office_spawns_shell.yml)
medium           1  Successful RDP logon from a public address  (examples/rules/rdp_from_outside.yml)
4 of 4 rules matched 12 events (0 rules skipped)
$ jq '.runs[0].results[0]' hits.sarif
{
  "ruleId": "5f0c2b2e-1d55-4c1a-9a51-7d1b0e3c6a01",
  "ruleIndex": 0,
  "level": "error",
  "message": {
    "text": "PowerShell started with an encoded command: 2 matches in the hunted logs"
  },
  "locations": [
    {
      "physicalLocation": {
        "artifactLocation": {
          "uri": "examples/rules/encoded_powershell.yml"
        }
      }
    }
  ]
}
```

The `ruleId` is the rule's `id`, or its title if it has none. The rule path is relative to the
working directory where possible, as code scanning expects. The file is written even if nothing
matched, with an empty result list.

| Sigma level | SARIF level | `security-severity` |
| --- | --- | --- |
| `critical` | `error` | 9.5 |
| `high` | `error` | 8.0 |
| `medium` | `warning` | 5.5 |
| `low` | `note` | 3.0 |
| `informational` | `note` | 1.0 |
| none or other | `warning` | 5.5 |

### `--fail-on`

Without `--fail-on`, matches do not change the exit code. `--fail-on LEVEL` exits with code 1 if
a rule at that level or above matched. The levels are `critical`, `high`, `medium`, `low` and
`informational`.

```console
$ sigma2sql hunt examples/rules --logs examples/events.jsonl --fail-on high > /dev/null 2>&1; echo $?
1
$ sigma2sql hunt examples/rules --logs examples/events.jsonl --fail-on critical > /dev/null 2>&1; echo $?
0
```

A rule without a level never triggers it, not even with `--fail-on informational`.

## `.evtx` files

`.evtx` files need no export step. If any `--logs` path ends in `.evtx` and you did not pass
`--profile`, the [`evtx` profile](profiles.md) is used. A `--mapping` still applies on top of
it. Here `logs/curl.evtx` is a SigmaHQ regression sample with one Sysmon event, and `rules/`
holds the rule for that sample and a Zeek rule:

```console
$ sigma2sql hunt rules --logs logs/curl.evtx
LEVEL         HITS  RULE
medium           1  Curl.EXE Execution With Custom UserAgent  (rules/proc_creation_win_curl_useragent.yml)
1 of 1 rules matched 1 events (0 rules skipped)
1 rules are for other log sources
```

The last line is [product scoping](#product-scoping) at work.

The choice of profile applies to the whole run. If you mix `.evtx` files with other logs and
pass no `--profile`, a warning says so:

```console
$ sigma2sql hunt rules --logs logs/curl.evtx logs/events.jsonl
warning: all logs are read with the evtx profile
LEVEL         HITS  RULE
medium           1  Curl.EXE Execution With Custom UserAgent  (rules/proc_creation_win_curl_useragent.yml)
1 of 1 rules matched 13 events (0 rules skipped)
1 rules are for other log sources
```

The `evtx` profile looks for `Event.System` and `Event.EventData` in those other events too, and
rules will not match flat JSON events. Hunt them in separate runs. For the same reason, passing
another profile for `.evtx` files only makes sense if it fits their layout.

### Damaged files

Logs from an incident are often damaged, so everything readable is kept and the rest is
reported. A warning does not change the exit code.

| Problem | What happens |
| --- | --- |
| File cut off | warning, the events in the last chunk are not read; a cut exactly between two chunks is not noticed, and a file cut inside its only chunk has no event left |
| Damaged chunk | warning, reading goes on with the next chunk |
| 100 damaged chunks in one file | `gave up after 100 damaged chunks`, the rest of that file is not read |
| Not an EVTX file, or too short for its header | warning, the file is left out |
| Valid header and no chunks | no warning, the file holds no events |
| No event from the whole hunt, and at least one warning | error, exit code 2 |

A file with its second chunk cut off, for example:

```console
$ sigma2sql hunt rules --logs damaged/cut.evtx
warning: damaged/cut.evtx: file is truncated, events in its last chunk are not read
LEVEL         HITS  RULE
medium           1  Curl.EXE Execution With Custom UserAgent  (rules/proc_creation_win_curl_useragent.yml)
1 of 1 rules matched 1 events (0 rules skipped)
1 rules are for other log sources
```

And a file whose first chunk is damaged, where the second chunk is still read:

```console
$ sigma2sql hunt rules --logs damaged/badchunk.evtx
warning: damaged/badchunk.evtx: Failed to parse chunk number 0: Failed to parse chunk header: Invalid EVTX chunk header magic, expected `ElfChnk0`, found `[FF, FF, FF, FF, FF, FF, FF, FF]`
LEVEL         HITS  RULE
medium           1  Curl.EXE Execution With Custom UserAgent  (rules/proc_creation_win_curl_useragent.yml)
1 of 1 rules matched 1 events (0 rules skipped)
1 rules are for other log sources
```

### Several files

The last row of the table is decided for the whole hunt, over all `--logs` values. A bad file
among good ones is a warning, whether sigma2sql or the shell expands the glob:

```console
$ sigma2sql hunt rules --logs mixed/*.evtx
warning: mixed/garbage.evtx: An error occurred while trying to deserialize evtx stream.: Invalid EVTX file header magic, expected `ElfFile0`, found `[AB, 74,  C, 8B, E2, 3A, CA, 6B]`
LEVEL         HITS  RULE
medium           1  Curl.EXE Execution With Custom UserAgent  (rules/proc_creation_win_curl_useragent.yml)
1 of 1 rules matched 1 events (0 rules skipped)
1 rules are for other log sources
```

If no file gave an event, the hunt ends with code 2:

```console
$ sigma2sql hunt rules --logs mixed/garbage.evtx
sigma2sql: no event could be read: mixed/garbage.evtx: An error occurred while trying to deserialize evtx stream.: Invalid EVTX file header magic, expected `ElfFile0`, found `[AB, 74,  C, 8B, E2, 3A, CA, 6B]`
```

## Product scoping

A profile can name the one `product` its logs hold. The built-in `evtx`, `sysmon` and
`ecs-winlogbeat` profiles say `windows`; `ocsf` names none. `hunt` then runs only the rules with
that `logsource.product`, compared without regard to case. The rest are counted on stderr:

```
1 rules are for other log sources
```

This is what makes a directory of all SigmaHQ rules usable as it is. Without it, a Zeek rule of
the form `not <address range>` would match every Windows event, as those have no such field.

- A rule with no `product` at all is also left out when the profile names one.
- A correlation runs if at least one of the rules it refers to is for that product.
- Left-out rules do not count as run or as skipped.

Without a profile, every rule runs on every event. A network rule can then match a process
event that happens to have the same field values. With a profile that names no product, every
rule runs too, and only the profile's logsource conditions limit it.

The profile's logsource conditions still apply within the run. For example, under `evtx` a
`process_creation` rule only sees Sysmon events with ID 1. A `table` set in a profile's
logsource is ignored, as all logs share one table here. [Profiles](profiles.md#product-scoping)
has a worked example.

## Correlations

Correlations and `count()` aggregations run like other rules. Events are placed in time by the
`timestamp` field, read as ISO 8601, unless a profile or the options above say otherwise. A
time without a zone is read as UTC on any machine, and result rows show UTC. Sysmon's `UtcTime`
has no zone, so it comes out as it is in the log.

Check this setting if a correlation stays silent. With a `timespan`, a time field that the
events do not have gives no results and no warning:

```console
$ sigma2sql hunt more/brute_force.yml --logs logs/four.jsonl --timestamp-field EventTime
0 of 1 rules matched 13 events (0 rules skipped)
```

For a correlation, `HITS` counts result rows and not events. Each event closes a window over
the events before it, so one burst can give several rows. Here a fourth failed logon was added
to the example events, and rows close at the third and at the fourth:

```console
$ sigma2sql hunt more/brute_force.yml --logs logs/four.jsonl --examples 5
LEVEL         HITS  RULE
high             2  Brute force against one account  (more/brute_force.yml)
                      {"TargetUserName":"admin","window_start":"2026-11-01 03:12:01","window_end":"2026-11-01 03:12:20","value":4}
                      {"TargetUserName":"admin","window_start":"2026-11-01 03:12:01","window_end":"2026-11-01 03:12:17","value":3}
1 of 1 rules matched 13 events (0 rules skipped)
```

### Time windows on `.evtx` files

The `evtx` profile reads the event time from `Event.System.TimeCreated.#attributes.SystemTime`,
so a correlation works on `.evtx` files with no further options. `corr/` holds a correlation
over the curl event from above:

```console
$ sigma2sql hunt corr --logs logs/curl.evtx --examples 1
LEVEL         HITS  RULE
low              1  Curl started within five minutes  (corr/curl_seen.yml)
                      {"window_start":"2026-08-11 07:52:33.442301","window_end":"2026-08-11 07:52:33.442301","value":1}
1 of 1 rules matched 1 events (0 rules skipped)
```

`--timestamp-field` wins over the profile. The name is read as a path in the event and then,
like a Sigma field, through the profile's `default_field`, so Sysmon's `UtcTime` needs no path:

```console
$ sigma2sql hunt corr --logs logs/curl.evtx --timestamp-field UtcTime --examples 1
LEVEL         HITS  RULE
low              1  Curl started within five minutes  (corr/curl_seen.yml)
                      {"window_start":"2026-08-11 07:52:33.438","window_end":"2026-08-11 07:52:33.438","value":1}
1 of 1 rules matched 1 events (0 rules skipped)
```

[Event time](profiles.md#event-time) has the details.

## Skipped rules

A rule that cannot run is reported and the hunt goes on. Each one gets a `skip` line on stderr
with the reason, and the summary counts them:

```console
$ sigma2sql hunt broken more/encoded_powershell.yml --logs logs/events.jsonl
skip broken/boolean.yml: correlation 'condition' must be a map
skip broken/expand.yml: placeholder %tools% has no value (see --placeholders)
skip broken/lookaround.yml: duckdb (RE2) has no lookaround or backreferences: (?<!foo)bar
skip broken/typo.yml: condition refers to unknown search 'missing'
LEVEL         HITS  RULE
high             2  PowerShell started with an encoded command  (more/encoded_powershell.yml)
1 of 1 rules matched 12 events (4 rules skipped)
```

The reasons are rule files that do not load (bad YAML, an empty file, a file that is not
UTF-8), conditions that name an unknown search, Sigma features that are not supported, such as
a `temporal` correlation with a boolean condition, placeholders without a value, patterns RE2
cannot run, and correlations that refer to rules that were not loaded. If DuckDB itself rejects
a query, the first line of its error is the reason. A bad rule does not end the hunt.

Skipped rules do not change the exit code as long as one rule ran, so in CI look at the summary
as well. If rules were skipped and none could run, the hunt ends with code 2. Rules left out by
[product scoping](#product-scoping) are not skipped, so a run that only has those is not an
error. Each rule path that does not exist or holds no rule files is an error too, also next to
a good path:

```console
$ sigma2sql hunt broken/typo.yml --logs logs/process.csv; echo $?
skip broken/typo.yml: condition refers to unknown search 'missing'
0 of 0 rules matched 2 events (1 rules skipped)
sigma2sql: no rule could run
2
$ sigma2sql hunt more/encoded_powershell.yml missing-rules --logs logs/process.csv; echo $?
sigma2sql: missing-rules: no such file or directory
2
$ sigma2sql hunt empty --logs logs/process.csv; echo $?
sigma2sql: empty: no .yml or .yaml files found
2
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | The hunt finished. This includes runs with no match, with warnings and, if a rule ran, with skipped rules. |
| 1 | A rule at or above `--fail-on` matched. Also when the `duckdb` or `evtx` extra is missing. |
| 2 | The hunt could not run: bad arguments, an unknown profile, an unreadable mapping or placeholder file, a rule path that does not exist or holds no rule files, also next to a good path, no rule that could run, an unsupported file type, a missing or unreadable log file, malformed JSON, a CSV file DuckDB cannot read, a hunt that read no event and gave a warning, or a `--sarif` file that cannot be written. |

All options are listed under [Command line](cli.md).
