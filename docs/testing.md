# Test rules

A rule is code, so it can have tests. Put example events next to the rule, and `sigma2sql
check` tests that the rule fires on the events it should and stays quiet on the rest. No
database or DuckDB is needed: `check` and `test` run in an in-memory SQLite database and only
depend on PyYAML.

## Test files

Test files sit next to the rule and share its name. Each holds one JSON object per line; blank
lines are ignored.

```text
rules/office_spawns_shell.yml
rules/office_spawns_shell.match.jsonl     # every event must match
rules/office_spawns_shell.nomatch.jsonl   # no event may match
```

Either file is enough. A rule with neither counts as having no tests.

Events are written as they look in your logs. Each event is stored whole, and fields are read
from it through the [profile](profiles.md) if you pass one, so a nested layout works the same
way here as in `hunt`.

The rule's `.yml` file can hold several documents. Each detection rule and correlation in it
that would report on its own is tested against the same events, so every event in a match
file has to match every one of them. Rules that only feed a correlation are left out, unless
the correlation sets `generate: true`.

### Correlations

For a correlation the file is one scenario, not a list of independent events:

- `.match.jsonl`: the rule must give at least one result over all the events in the file.
- `.nomatch.jsonl`: the rule must give no result over all of them.

The same applies to the older `| count()` conditions. Events need a time when the correlation
has a `timespan`, in the field `timestamp` unless a profile or `--timestamp-field` says
otherwise. This is the match file of `examples/rules/brute_force.yml`, three failed logons
inside five minutes:

```json
{"EventID": 4625, "TargetUserName": "admin", "timestamp": "2026-11-01T03:12:01Z"}
{"EventID": 4625, "TargetUserName": "admin", "timestamp": "2026-11-01T03:13:30Z"}
{"EventID": 4625, "TargetUserName": "admin", "timestamp": "2026-11-01T03:16:00Z"}
```

`check` loads one rule file at a time, so a correlation and the rules it refers to must be in
the same file. Otherwise the test fails with `correlation refers to unknown rules`.

## check

`check` takes rule files or directories, finds each rule's test files and runs them.
Directories are searched recursively for `.yml` and `.yaml` files.

```console
$ sigma2sql check examples/rules --require-tests
ok   examples/rules/brute_force.yml
ok   examples/rules/encoded_powershell.yml
ok   examples/rules/office_spawns_shell.yml
ok   examples/rules/rdp_from_outside.yml
4 passed, 0 failed, 0 without tests
```

`ok` and `FAIL` lines go to stdout, the summary to stderr. Besides the options below, `check`
takes the [field options](cli.md): `--profile`, `--mapping`, `--placeholders`, `--nested`,
`--timestamp-field` and `--timestamp-format`.

| Option | Meaning |
| --- | --- |
| `--require-tests` | A rule without test files is a failure |
| `--sarif FILE` | Also write the failures to this [SARIF](#sarif) file |

### Profiles in tests

With a profile, `check` applies its field mapping and its log source conditions, so a test can
prove that a rule stays inside its log source. This event has the right image but is not a
process creation:

```json
{"EventID": 3, "Image": "C:\\Windows\\System32\\cmd.exe"}
```

```console
$ sigma2sql check scoped
FAIL scoped/cmd.yml: cmd started: matched cmd.nomatch.jsonl event(s) 1
0 passed, 1 failed, 0 without tests

$ sigma2sql check scoped -p sysmon
ok   scoped/cmd.yml
1 passed, 0 failed, 0 without tests
```

Events written for a profile only make sense with it, so use the same one in CI. The `table`
of a log source is ignored here, and so is `product`: `check` tests every rule it is given.

### What check does not cover

- **Filters.** `check` and `test` load one file at a time, so [filters](filters.md) in other
  files do not apply. A filter in the rule's own `.yml` file does. Keep filter files out of the
  path you check. A filter file counts as a rule without tests, so `--require-tests` fails it,
  and with test files it passes without testing anything.
- **Other databases.** Tests run on SQLite. A rule that passes here can still be
  [unsupported elsewhere](features.md#what-is-not-supported), for example a lookahead on DuckDB.
  A few [value comparisons](features.md#numbers-booleans-and-strings) also differ.
- **Rules without tests.** They are not loaded at all. A rule with no test files is counted as
  `without tests` even if it is not valid Sigma, and a path that does not exist is treated
  the same way. Use `--require-tests` to fail on both.
- **Empty inputs.** A directory with no rule files gives `0 passed, 0 failed, 0 without tests`
  and exit code 0, even with `--require-tests`. A test file with no events passes.

## Failures

A failure names the rule file, the title and the test file. Events are numbered from 1 in the
order they appear; blank lines do not count, so the number can be lower than the line number.
Several events are listed as `1, 3`. The third line of this `.nomatch.jsonl` file is its second
event:

```console
$ sigma2sql check rules
FAIL rules/word_cmd.yml: cmd started by Word: missed word_cmd.match.jsonl event(s) 2
FAIL rules/word_cmd.yml: cmd started by Word: matched word_cmd.nomatch.jsonl event(s) 2
0 passed, 1 failed, 1 without tests
```

| Message | Meaning |
| --- | --- |
| `missed FILE event(s) N` | These events in a match file did not match |
| `matched FILE event(s) N` | These events in a nomatch file matched |
| `no result for FILE` | A correlation gave nothing for its match file |
| `N results for FILE` | A correlation gave results for its nomatch file |
| `no NAME.match.jsonl or .nomatch.jsonl` | No test files, with `--require-tests` |
| `FILE: line N: each event must be a JSON object` | A line holds something else, such as a list |
| anything else | The rule is invalid or unsupported, or a test file is not valid JSON. A JSON syntax error always says `line 1`, whichever line it is on |

A correlation test that fails, with a single event in the match file and all three in the
nomatch file:

```console
$ sigma2sql check brute_force.yml
FAIL brute_force.yml: Brute force against one account: no result for brute_force.match.jsonl
FAIL brute_force.yml: Brute force against one account: 1 results for brute_force.nomatch.jsonl
0 passed, 1 failed, 0 without tests
```

A typing mistake in a modifier fails the test if the rule has test files, and
`--require-tests` catches a rule that has none:

```console
$ sigma2sql check bad --require-tests
FAIL bad/nodetect.yml: no nodetect.match.jsonl or .nomatch.jsonl
FAIL bad/typo.yml: typo: modifier 'endswth' is not supported
0 passed, 2 failed, 1 without tests
```

A regular expression that Python cannot compile is the exception: it is not reported as a
failure, and the run ends there with a traceback and exit code 1.

### Exit codes

| Code | `check` |
| --- | --- |
| 0 | No failures. Rules without tests do not count unless `--require-tests` is set |
| 1 | At least one failure |
| 2 | A bad option, profile, mapping or placeholder file |

## test

`sigma2sql test RULE EVENTS.jsonl` is for looking at one rule while you write it. It prints the
events the rule matches, exactly as they are in the file, and a count on stderr. The rule can
be tested against any events file, with no naming convention.

```console
$ sigma2sql test examples/rules/office_spawns_shell.yml examples/events.jsonl
{"EventID": 1, "Image": "C:\\Windows\\System32\\cmd.exe", "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "CommandLine": "cmd.exe /c whoami"}
Office application starting a shell: 1 of 12 events matched
```

Correlations print their result rows, with the group values, the window and the value:

```console
$ sigma2sql test examples/rules/brute_force.yml examples/events.jsonl
{"TargetUserName": "admin", "window_start": "2026-11-01 03:12:01.000", "window_end": "2026-11-01 03:12:17.000", "value": 3}
Brute force against one account: 1 results
```

`--expect` turns it into a pass or fail. It looks at each rule as a whole, not at each event:

| Option | Exit code 1 when |
| --- | --- |
| `--expect match` | A rule in the file matched nothing |
| `--expect none` | A rule in the file matched anything |

| Code | `test` |
| --- | --- |
| 0 | The rule ran, and `--expect` was met if given |
| 1 | `--expect` was not met |
| 2 | The rule file or the events could not be read, the rule is invalid or unsupported, or an option, profile, mapping or placeholder file is bad |

```console
$ sigma2sql test rules/word_cmd.yml rules/word_cmd.match.jsonl --expect none
{"EventID": 1, "Image": "C:\\Windows\\System32\\cmd.exe", "ParentImage": "C:\\Office\\WINWORD.EXE"}
cmd started by Word: 1 of 2 events matched
```

That run exits with 1.

## GitHub Action

The repository is also an action that runs `check`. It sets up Python, installs sigma2sql from
the same ref and fails the step when `check` fails.

```yaml
- uses: actions/checkout@v7
- uses: brkozer/sigma2sql@v0.3.0
  with:
    path: rules
    profile: sysmon
    require-tests: "true"
```

| Input | Default | Meaning |
| --- | --- | --- |
| `path` | `rules` | Rule files or directories, separated by spaces |
| `profile` | empty | Built-in profile name or path to a profile YAML |
| `require-tests` | `"false"` | Set to `"true"` to pass `--require-tests` |
| `sarif` | empty | Write failures to this SARIF file |
| `python-version` | `"3.12"` | Python used to run sigma2sql |

Since `path` is split on spaces, a path that contains a space cannot be passed. Any other value
of `require-tests` than the exact text `true` leaves it off. The action has no outputs.

## SARIF

`check --sarif FILE` writes the failures as SARIF 2.1.0, which GitHub code scanning and many CI
tools can show. The file is also written when nothing failed, with no results in it, but not
when `check` stops with exit code 2. Each failure is one result on the rule file:

```json
{
  "ruleId": "rule-test",
  "ruleIndex": 0,
  "level": "error",
  "message": {
    "text": "cmd started by Word: missed word_cmd.match.jsonl event(s) 2"
  },
  "locations": [
    {
      "physicalLocation": {
        "artifactLocation": {
          "uri": "rules/word_cmd.yml"
        }
      }
    }
  ]
}
```

All failures share the SARIF rule `rule-test`, with level `error` and security severity `8.0`.
Paths are relative to the working directory where possible, as code scanning expects.
`hunt --sarif` writes the same format for [matches instead of failures](hunt.md).

To see failures as code scanning alerts, upload the file in a later step:

```yaml
name: rules
on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read
  security-events: write

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: brkozer/sigma2sql@v0.3.0
        with:
          path: rules
          profile: sysmon
          require-tests: "true"
          sarif: rules.sarif
      - uses: github/codeql-action/upload-sarif@v4
        if: always()
        with:
          sarif_file: rules.sarif
```

`if: always()` matters: a failed test fails the action's step, and without it the upload is
skipped exactly when there is something to report. `security-events: write` is what lets the
upload create alerts.
