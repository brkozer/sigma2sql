# Correlations

A Sigma correlation counts the matches of other rules: three failed logons for one user in five
minutes, or one address trying many accounts. sigma2sql turns each correlation into a single
SQL statement, so no state is kept between runs.

```yaml
title: Failed logon
id: 3b1f6c0e-7a52-4f3e-9d0a-1c2b3d4e5f04
name: failed_logon
status: experimental
description: A failed Windows logon. Used by the correlation below; not alerted on its own.
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
  condition: selection
level: informational
---
title: Brute force against one account
id: 9e8d7c6b-5a49-4382-a1b0-c9d8e7f6a505
status: experimental
description: Three or more failed logons for the same user within five minutes.
correlation:
  type: event_count
  rules: [failed_logon]
  group-by: [TargetUserName]
  timespan: 5m
  condition:
    gte: 3
level: high
```

```console
$ sigma2sql test examples/rules/brute_force.yml examples/events.jsonl
{"TargetUserName": "admin", "window_start": "2026-11-01 03:12:01.000", "window_end": "2026-11-01 03:12:17.000", "value": 3}
Brute force against one account: 1 results
```

The same file works with [`convert`](convert.md), [`hunt`](hunt.md), `test` and
[`check`](testing.md). `temporal_ordered` is [not supported](#not-supported) in this version.

## Correlation keys

The `correlation` map takes these keys. `title`, `id`, `name` and `level` sit at the top level
of the document, as in any rule.

| Key | Required | Meaning |
| --- | --- | --- |
| `type` | yes | one of the [types](#types) below |
| `rules` | yes | names or ids of the rules to count; a single string is allowed |
| `group-by` | no | fields that split the count; a single string is allowed |
| `timespan` | no | length of the [window](#windows), such as `5m`; without it there is no window |
| `condition` | yes, except for `temporal` | a [threshold](#conditions) on the result |
| `aliases` | no | a different [field per rule](#aliases) for a `group-by` name |
| `generate` | no | also report the [referenced rules](#generate) on their own |

## Types

| Type | `value` in the result | Needs |
| --- | --- | --- |
| `event_count` | number of matching events | |
| `value_count` | number of distinct values of a field | `field` |
| `value_sum` | sum of a field | `field` |
| `value_avg` | average of a field | `field` |
| `value_median` | median of a field | `field` |
| `value_percentile` | a percentile of a field | `field`, `percentile` from 0 to 100 |
| `temporal` | number of different rules that matched | |

`field` goes inside `condition`, as the Sigma specification has it. A `field` key directly
under `correlation` is read too. A `value_*` correlation without either is skipped.

### value_count

One source address trying three different accounts:

```yaml
title: Failed logon
name: failed_logon
logsource: {product: windows, service: security}
detection:
  selection:
    EventID: 4625
  condition: selection
level: informational
---
title: One source tries many accounts
correlation:
  type: value_count
  rules: [failed_logon]
  group-by: [IpAddress]
  timespan: 10m
  condition:
    field: TargetUserName
    gte: 3
level: high
```

```json
{"EventID": 4625, "TargetUserName": "admin", "IpAddress": "198.51.100.23", "timestamp": "2026-11-01T03:12:01Z"}
{"EventID": 4625, "TargetUserName": "backup", "IpAddress": "198.51.100.23", "timestamp": "2026-11-01T03:12:09Z"}
{"EventID": 4625, "TargetUserName": "backup", "IpAddress": "198.51.100.23", "timestamp": "2026-11-01T03:12:12Z"}
{"EventID": 4625, "TargetUserName": "guest", "IpAddress": "198.51.100.23", "timestamp": "2026-11-01T03:12:17Z"}
{"EventID": 4625, "TargetUserName": "admin", "IpAddress": "198.51.100.40", "timestamp": "2026-11-01T03:12:20Z"}
```

```console
$ sigma2sql test value_count.yml spray.jsonl
{"IpAddress": "198.51.100.23", "window_start": "2026-11-01 03:12:01.000", "window_end": "2026-11-01 03:12:17.000", "value": 3}
One source tries many accounts: 1 results
```

`backup` appears twice and counts once. The other address has one account and stays below the
threshold. A missing value is not counted.

### value_sum, value_avg, value_median and value_percentile

These four read a field as a number:

```yaml
title: Connection
name: conn
logsource: {category: network_connection}
detection:
  selection:
    Initiated: 'true'
  condition: selection
---
title: Large upload
correlation:
  type: value_sum
  rules: [conn]
  group-by: [Host]
  timespan: 1h
  condition:
    field: BytesSent
    gt: 1000
level: medium
---
title: High average upload
correlation:
  type: value_avg
  rules: [conn]
  group-by: [Host]
  timespan: 1h
  condition:
    field: BytesSent
    gte: 400
level: low
---
title: Median upload
correlation:
  type: value_median
  rules: [conn]
  group-by: [Host]
  timespan: 1h
  condition:
    field: BytesSent
    gte: 300
level: low
---
title: 90th percentile upload
correlation:
  type: value_percentile
  rules: [conn]
  group-by: [Host]
  timespan: 1h
  condition:
    field: BytesSent
    percentile: 90
    gte: 700
level: low
```

```json
{"Initiated": "true", "Host": "ws1", "BytesSent": 100, "timestamp": "2026-11-01T10:00:00Z"}
{"Initiated": "true", "Host": "ws1", "BytesSent": 300, "timestamp": "2026-11-01T10:10:00Z"}
{"Initiated": "true", "Host": "ws1", "BytesSent": "n/a", "timestamp": "2026-11-01T10:15:00Z"}
{"Initiated": "true", "Host": "ws1", "BytesSent": 900, "timestamp": "2026-11-01T10:20:00Z"}
{"Initiated": "true", "Host": "ws2", "BytesSent": 50, "timestamp": "2026-11-01T10:20:00Z"}
```

```console
$ sigma2sql test value_sum.yml conn.jsonl
{"Host": "ws1", "window_start": "2026-11-01 10:00:00.000", "window_end": "2026-11-01 10:20:00.000", "value": 1300.0}
Large upload: 1 results
{"Host": "ws1", "window_start": "2026-11-01 10:00:00.000", "window_end": "2026-11-01 10:20:00.000", "value": 433.3333333333333}
High average upload: 1 results
{"Host": "ws1", "window_start": "2026-11-01 10:00:00.000", "window_end": "2026-11-01 10:20:00.000", "value": 300.0}
Median upload: 1 results
{"Host": "ws1", "window_start": "2026-11-01 10:00:00.000", "window_end": "2026-11-01 10:20:00.000", "value": 780.0}
90th percentile upload: 1 results
```

A value that is not a number, such as `n/a` here, is left out of the calculation and does not
end the query. The sum of 100, 300 and 900 is 1300, and the average is over those three values.
Percentiles interpolate between the two closest ranks, so the 90th percentile of the same three
values is 780, a value no event holds.

### temporal

`temporal` asks whether all the listed rules matched within the window, in any order:

```yaml
title: Recon command
name: recon
logsource: {product: windows, category: process_creation}
detection:
  selection:
    Image|endswith: '\whoami.exe'
  condition: selection
---
title: New service
name: new_service
logsource: {product: windows, service: system}
detection:
  selection:
    EventID: 7045
  condition: selection
---
title: Recon and a new service on one host
correlation:
  type: temporal
  rules: [recon, new_service]
  group-by: [Host]
  timespan: 10m
level: high
```

```json
{"Image": "C:\\Windows\\System32\\whoami.exe", "Host": "ws1", "timestamp": "2026-11-01T10:00:00Z"}
{"EventID": 7045, "Host": "ws1", "timestamp": "2026-11-01T10:04:00Z"}
{"EventID": 7045, "Host": "ws2", "timestamp": "2026-11-01T10:04:00Z"}
{"Image": "C:\\Windows\\System32\\whoami.exe", "Host": "ws3", "timestamp": "2026-11-01T10:00:00Z"}
{"EventID": 7045, "Host": "ws3", "timestamp": "2026-11-01T11:00:00Z"}
```

```console
$ sigma2sql test temporal.yml temporal.jsonl
{"Host": "ws1", "window_start": "2026-11-01 10:00:00.000", "window_end": "2026-11-01 10:04:00.000", "value": 2}
Recon and a new service on one host: 1 results
```

`ws2` only matched one rule. `ws3` matched both, an hour apart. The default condition is `gte`
the number of rules; write your own numeric `condition` to ask for fewer. `value` is the count
of different rules in the window.

## Conditions

`condition` takes `gt`, `gte`, `lt`, `lte` and `eq`, with a number. Several of them must all
hold:

```yaml
title: Failed logon
name: failed_logon
logsource: {product: windows, service: security}
detection:
  selection:
    EventID: 4625
  condition: selection
level: informational
---
title: Between 2 and 3
correlation:
  type: event_count
  rules: [failed_logon]
  group-by: [TargetUserName]
  condition:
    gte: 2
    lte: 3
```

`burst.jsonl` is the file shown under [Windows](#windows).

```console
$ sigma2sql test range.yml burst.jsonl
{"TargetUserName": "guest", "first_seen": null, "last_seen": null, "value": 3}
Between 2 and 3: 1 results
```

There is no `neq`, and the correlation is skipped if you write one:

```console
$ sigma2sql convert bad_noneq.yml
skip bad_noneq.yml: invalid correlation condition neq: 3
```

`lt` and `lte` only see groups and windows that have at least one event, so a correlation with
a `group-by` or a `timespan` cannot report that something failed to happen. With neither, there
is always one group, even when no event matched, and the row has a `value` of 0:

```yaml
title: Failed logon
name: failed_logon
logsource: {product: windows, service: security}
detection:
  selection:
    EventID: 4625
  condition: selection
level: informational
---
title: Fewer than three failed logons
correlation:
  type: event_count
  rules: [failed_logon]
  condition:
    lt: 3
```

```json
{"EventID": 4624}
```

```console
$ sigma2sql test few.yml none.jsonl
{"first_seen": null, "last_seen": null, "value": 0}
Fewer than three failed logons: 1 results
```

## Windows

With a `timespan`, every event closes a window of its group: the interval from `timespan`
before the event up to the event, both ends included. A window that meets the condition gives a
result row. Windows overlap, so a long burst gives one row per event time once the threshold is
reached:

```yaml
title: Failed logon
name: failed_logon
logsource: {product: windows, service: security}
detection:
  selection:
    EventID: 4625
  condition: selection
level: informational
---
title: Three failed logons in a minute
correlation:
  type: event_count
  rules: failed_logon
  group-by: TargetUserName
  timespan: 1m
  condition:
    gte: 3
level: high
```

```json
{"EventID": 4625, "TargetUserName": "admin", "IpAddress": "198.51.100.23", "timestamp": "2026-11-01T03:12:01Z"}
{"EventID": 4625, "TargetUserName": "admin", "IpAddress": "198.51.100.23", "timestamp": "2026-11-01T03:12:09Z"}
{"EventID": 4625, "TargetUserName": "admin", "IpAddress": "198.51.100.24", "timestamp": "2026-11-01T03:12:17Z"}
{"EventID": 4625, "TargetUserName": "admin", "IpAddress": "198.51.100.24", "timestamp": "2026-11-01T03:12:30Z"}
{"EventID": 4625, "TargetUserName": "admin", "IpAddress": "198.51.100.24", "timestamp": "2026-11-01T03:30:00Z"}
{"EventID": 4625, "TargetUserName": "svc_backup", "IpAddress": "198.51.100.40", "timestamp": "2026-11-01T09:00:00Z"}
{"EventID": 4625, "TargetUserName": "guest", "IpAddress": "198.51.100.23", "timestamp": "not a time"}
{"EventID": 4625, "TargetUserName": "guest", "IpAddress": "198.51.100.23"}
{"EventID": 4625, "TargetUserName": "guest", "IpAddress": "198.51.100.23"}
```

```console
$ sigma2sql test event_count.yml burst.jsonl
{"TargetUserName": "admin", "window_start": "2026-11-01 03:12:01.000", "window_end": "2026-11-01 03:12:17.000", "value": 3}
{"TargetUserName": "admin", "window_start": "2026-11-01 03:12:01.000", "window_end": "2026-11-01 03:12:30.000", "value": 4}
Three failed logons in a minute: 2 results
```

The first three `admin` events reach the threshold at 03:12:17. The fourth gives a second row
with `value` 4. The fifth comes more than 17 minutes later, in a window of its own.
`window_start` is the time of the first event in the window, not `window_end` minus the
timespan.

`timespan` is a whole number with `s`, `m`, `h`, `d` or `w`. Anything else is an error:

```console
$ sigma2sql convert bad_timespan.yml
skip bad_timespan.yml: invalid timespan '1M'; use e.g. 30s, 5m, 1h, 1d
```

Only `timespan` sets a window here. Under `correlation`, a `timeframe` key is not read, and the
correlation then runs without a window, over all events. `timeframe` applies to the [`count()`
syntax](#the-older-count-syntax) only.

### Without a timespan

There is one result per group over everything in the table, with `first_seen` and `last_seen`
in place of the window. Without `group-by`, there is a single group.

```yaml
title: Failed logon
name: failed_logon
logsource: {product: windows, service: security}
detection:
  selection:
    EventID: 4625
  condition: selection
level: informational
---
title: Failed logons overall
correlation:
  type: event_count
  rules: [failed_logon]
  group-by: [TargetUserName]
  condition:
    gte: 3
level: medium
```

```console
$ sigma2sql test nowindow.yml burst.jsonl
{"TargetUserName": "admin", "first_seen": "2026-11-01 03:12:01.000", "last_seen": "2026-11-01 03:30:00.000", "value": 5}
{"TargetUserName": "guest", "first_seen": null, "last_seen": null, "value": 3}
Failed logons overall: 2 results
```

### Event time

A window needs to know when each event happened. The field is called `timestamp` unless a
profile or `--timestamp-field` says otherwise, and it holds ISO 8601 text unless a profile or
`--timestamp-format` says otherwise. The formats are `iso`, `epoch_s` and `epoch_ms`.

```json
{"EventID": 4625, "TargetUserName": "admin", "ts": 1793502721000}
{"EventID": 4625, "TargetUserName": "admin", "ts": 1793502729000}
{"EventID": 4625, "TargetUserName": "admin", "ts": 1793502737000}
```

```console
$ sigma2sql test event_count.yml epoch.jsonl --timestamp-field ts --timestamp-format epoch_ms
{"TargetUserName": "admin", "window_start": "2026-11-01 03:12:01.000", "window_end": "2026-11-01 03:12:17.000", "value": 3}
Three failed logons in a minute: 1 results
```

An event whose time is missing or cannot be read has a NULL time. No query fails because of it.
Such an event does not close a window and is in no window. Without a `timespan` it still
counts, which is why `guest` above has a `value` of 3 and null times.

The field is a path in the event. With a JSON column, a profile's `default_field` is tried after
that path, and a `-m` entry for the field wins over both. See
[Event time](profiles.md#event-time).

A time with no zone is read as UTC by `hunt`, `test` and `check`, on any machine, so all three
show the same time for the same event. A query you run elsewhere can differ: with a time that
has no zone, PostgreSQL and DuckDB use the session's time zone, while SQLite and ClickHouse
read it as UTC.

## Groups

Events are compared per `group-by` value, across all the rules of the correlation. Field names
go through the mapping and the profile like any other field. Events that lack the field are not
dropped: they form a group of their own, with a null value.

```json
{"EventID": 4625, "timestamp": "2026-11-01T03:12:01Z"}
{"EventID": 4625, "timestamp": "2026-11-01T03:12:02Z"}
{"EventID": 4625, "timestamp": "2026-11-01T03:12:03Z"}
```

```console
$ sigma2sql test event_count.yml null_group.jsonl
{"TargetUserName": null, "window_start": "2026-11-01 03:12:01.000", "window_end": "2026-11-01 03:12:03.000", "value": 3}
Three failed logons in a minute: 1 results
```

To leave them out, add `TargetUserName|exists: true` to the rule.

## Several rules

Rules are looked up by `name` or `id`, among everything loaded in that run. They can sit in
other files, as long as you pass those files:

```console
$ sigma2sql convert split/corr.yml
skip split/corr.yml: correlation refers to unknown rules: failed_logon
$ sigma2sql convert split/rule.yml split/corr.yml > /dev/null; echo $?
0
```

`test` and `check` load one file at a time, so for those the rules and the correlation have to
be in the same file.

Each rule contributes its own matches. An event that matches two listed rules therefore counts
twice in `event_count`, and it satisfies a `temporal` correlation over those two rules alone:

```yaml
title: Rule one
name: one
detection:
  selection:
    EventID: 1
  condition: selection
---
title: Rule two
name: two
detection:
  selection:
    Image|endswith: cmd.exe
  condition: selection
---
title: Both rules
correlation:
  type: temporal
  rules: [one, two]
  timespan: 5m
---
title: Counted twice
correlation:
  type: event_count
  rules: [one, two]
  condition:
    gte: 2
```

```json
{"EventID": 1, "Image": "cmd.exe", "timestamp": "2026-11-01T03:12:01Z"}
```

```console
$ sigma2sql test both.yml both.jsonl
{"window_start": "2026-11-01 03:12:01.000", "window_end": "2026-11-01 03:12:01.000", "value": 2}
Both rules: 1 results
{"first_seen": "2026-11-01 03:12:01.000", "last_seen": "2026-11-01 03:12:01.000", "value": 2}
Counted twice: 1 results
```

### aliases

When the rules keep the same value in different fields, give the group a name of your own and
say which field it is in each rule:

```yaml
title: Logon from an address
name: logon
detection:
  selection:
    EventID: 4624
  condition: selection
---
title: Connection from an address
name: conn
detection:
  selection:
    EventID: 3
  condition: selection
---
title: Logon and connection for one address
correlation:
  type: temporal
  rules: [logon, conn]
  group-by: [address]
  timespan: 5m
  aliases:
    address:
      logon: IpAddress
      conn: SourceIp
level: medium
```

```json
{"EventID": 4624, "IpAddress": "198.51.100.7", "timestamp": "2026-11-01T10:00:00Z"}
{"EventID": 3, "SourceIp": "198.51.100.7", "timestamp": "2026-11-01T10:02:00Z"}
```

```console
$ sigma2sql test aliases.yml aliases.jsonl
{"address": "198.51.100.7", "window_start": "2026-11-01 10:00:00.000", "window_end": "2026-11-01 10:02:00.000", "value": 2}
Logon and connection for one address: 1 results
```

The name becomes the result column. A rule without an alias reads a field of that name. The
keys under the alias are the rule's `name`, or its `id` if it has no `name`. An alias keyed by
the `id` of a rule that has a `name` is not applied, and no warning is given.

## generate

A rule used by a correlation only feeds that correlation. It gets no query in `convert` and no
line in `hunt`, as in the Sigma specification. With `generate: true`, it is also reported on
its own:

```yaml
title: Failed logon
name: failed_logon
logsource: {product: windows, service: security}
detection:
  selection:
    EventID: 4625
  condition: selection
level: low
---
title: Three failed logons
correlation:
  type: event_count
  rules: [failed_logon]
  group-by: [TargetUserName]
  timespan: 5m
  generate: true
  condition:
    gte: 3
level: high
```

```console
$ sigma2sql hunt generate.yml --logs burst.jsonl
LEVEL         HITS  RULE
high             2  Three failed logons  (generate.yml)
low              9  Failed logon  (generate.yml)
2 of 2 rules matched 9 events (0 rules skipped)
```

Without `generate`, only `Three failed logons` would be listed. If two correlations use a rule,
one that does not set `generate` is enough to keep the rule hidden.

## The older count() syntax

Rules from before correlations put the count in the condition, with `timeframe` next to it.
SigmaHQ still keeps 45 such rules, in `unsupported/` and `deprecated/`, and they all convert.
They become the same SQL as a correlation over that one rule:

```yaml
title: Many failed logons
logsource: {product: windows, service: security}
detection:
  selection:
    EventID: 4625
  timeframe: 5m
  condition: selection | count() by TargetUserName >= 3
level: high
```

```console
$ sigma2sql test legacy.yml burst.jsonl
{"TargetUserName": "admin", "window_start": "2026-11-01 03:12:01.000", "window_end": "2026-11-01 03:12:17.000", "value": 3}
{"TargetUserName": "admin", "window_start": "2026-11-01 03:12:01.000", "window_end": "2026-11-01 03:12:30.000", "value": 4}
Many failed logons: 2 results
```

`count()` becomes `event_count`. `count(field)` counts distinct values, like `value_count`:

```yaml
title: One source, many accounts
logsource: {product: windows, service: security}
detection:
  selection:
    EventID: 4625
  timeframe: 1h
  condition: selection | count(TargetUserName) by IpAddress > 1
level: high
```

```console
$ sigma2sql test legacy_field.yml spray.jsonl
{"IpAddress": "198.51.100.23", "window_start": "2026-11-01 03:12:01.000", "window_end": "2026-11-01 03:12:09.000", "value": 2}
{"IpAddress": "198.51.100.23", "window_start": "2026-11-01 03:12:01.000", "window_end": "2026-11-01 03:12:12.000", "value": 2}
{"IpAddress": "198.51.100.23", "window_start": "2026-11-01 03:12:01.000", "window_end": "2026-11-01 03:12:17.000", "value": 3}
One source, many accounts: 3 results
```

The form is `selection | count(field) by a, b OP N`, where `field` and `by` are optional, `OP`
is one of `>`, `>=`, `<`, `<=`, `=` or `==`, and `N` is a whole number. `timeframe` is optional
and takes the same values as `timespan`. The rule needs a single condition. Other aggregations
are skipped:

```console
$ sigma2sql convert legacy_sum.yml
skip legacy_sum.yml: aggregation 'sum(Bytes) by Host > 100' is not supported (only count)
```

## Result rows

A row holds the `group-by` fields under their own names, then two times, then `value`.

| Column | With a `timespan` | Without |
| --- | --- | --- |
| one per `group-by` name | group value | group value |
| time of the first event | `window_start` | `first_seen` |
| time of the last event | `window_end` | `last_seen` |
| `value` | the [counted value](#types) of the window | the counted value of the group |

`test` and `hunt` show times in UTC. `test` runs on SQLite and always prints milliseconds.
`hunt` runs on DuckDB and prints a fraction of a second only if the time has one. In `hunt`,
the `HITS` column is the number of rows, so one burst can show as several hits. `--examples N`
prints up to `N` rows, in no particular order, and `--format json` puts them under `examples`
with `"correlation": true`:

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

## Per-dialect notes

The window is a self-join on a `base` query. All four dialects get the same structure:

=== "SQLite"

    ```console
    $ sigma2sql convert event_count.yml --json-column data
    -- Three failed logons in a minute
    WITH base AS (
      SELECT 'failed_logon' AS sigma_rule, unixepoch(json_extract("data", '$."timestamp"'), 'subsec') AS sigma_ts, json_extract("data", '$."TargetUserName"') AS "g0" FROM "events" WHERE CAST(json_extract("data", '$."EventID"') AS TEXT) = '4625'
    ),
    windows AS (SELECT DISTINCT "g0", sigma_ts FROM base WHERE sigma_ts IS NOT NULL)
    SELECT w."g0" AS "TargetUserName", datetime(MIN(b.sigma_ts), 'unixepoch', 'subsec') AS window_start, datetime(w.sigma_ts, 'unixepoch', 'subsec') AS window_end, COUNT(*) AS value
    FROM windows w JOIN base b ON b."g0" IS w."g0" AND b.sigma_ts BETWEEN w.sigma_ts - 60 AND w.sigma_ts
    GROUP BY w."g0", w.sigma_ts
    HAVING COUNT(*) >= 3;
    ```

=== "PostgreSQL"

    ```console
    $ sigma2sql convert event_count.yml --json-column data -d postgres
    -- Three failed logons in a minute
    WITH base AS (
      SELECT 'failed_logon' AS sigma_rule, EXTRACT(EPOCH FROM CASE WHEN pg_input_is_valid(("data"->>'timestamp')::text, 'timestamptz') THEN ("data"->>'timestamp')::timestamptz END) AS sigma_ts, "data"->>'TargetUserName' AS "g0" FROM "events" WHERE "data"->>'EventID' = '4625'
    ),
    windows AS (SELECT DISTINCT "g0", sigma_ts FROM base WHERE sigma_ts IS NOT NULL)
    SELECT w."g0" AS "TargetUserName", to_timestamp(MIN(b.sigma_ts)) AS window_start, to_timestamp(w.sigma_ts) AS window_end, COUNT(*) AS value
    FROM windows w JOIN base b ON b."g0" IS NOT DISTINCT FROM w."g0" AND b.sigma_ts BETWEEN w.sigma_ts - 60 AND w.sigma_ts
    GROUP BY w."g0", w.sigma_ts
    HAVING COUNT(*) >= 3;
    ```

=== "DuckDB"

    ```console
    $ sigma2sql convert event_count.yml --json-column data -d duckdb
    -- Three failed logons in a minute
    WITH base AS (
      SELECT 'failed_logon' AS sigma_rule, epoch(TRY_CAST(("data"->>'$."timestamp"') AS TIMESTAMPTZ)) AS sigma_ts, ("data"->>'$."TargetUserName"') AS "g0" FROM "events" WHERE ("data"->>'$."EventID"') = '4625'
    ),
    windows AS (SELECT DISTINCT "g0", sigma_ts FROM base WHERE sigma_ts IS NOT NULL)
    SELECT w."g0" AS "TargetUserName", make_timestamp(CAST((MIN(b.sigma_ts)) * 1000000 AS BIGINT)) AS window_start, make_timestamp(CAST((w.sigma_ts) * 1000000 AS BIGINT)) AS window_end, COUNT(*) AS value
    FROM windows w JOIN base b ON b."g0" IS NOT DISTINCT FROM w."g0" AND b.sigma_ts BETWEEN w.sigma_ts - 60 AND w.sigma_ts
    GROUP BY w."g0", w.sigma_ts
    HAVING COUNT(*) >= 3;
    ```

=== "ClickHouse"

    ```console
    $ sigma2sql convert event_count.yml --json-column data -d clickhouse
    -- Three failed logons in a minute
    WITH base AS (
      SELECT 'failed_logon' AS sigma_rule, (toUnixTimestamp64Milli(parseDateTime64BestEffortOrNull(toString(JSONExtract("data", 'timestamp', 'Nullable(String)')), 3, 'UTC')) / 1000.0) AS sigma_ts, JSONExtract("data", 'TargetUserName', 'Nullable(String)') AS "g0" FROM "events" WHERE JSONExtract("data", 'EventID', 'Nullable(String)') = '4625'
    ),
    windows AS (SELECT DISTINCT "g0", sigma_ts FROM base WHERE sigma_ts IS NOT NULL)
    SELECT w."g0" AS "TargetUserName", fromUnixTimestamp64Milli(toInt64((MIN(b.sigma_ts)) * 1000), 'UTC') AS window_start, fromUnixTimestamp64Milli(toInt64((w.sigma_ts) * 1000), 'UTC') AS window_end, COUNT(*) AS value
    FROM windows w JOIN base b ON b."g0" IS NOT DISTINCT FROM w."g0" AND b.sigma_ts BETWEEN w.sigma_ts - 60 AND w.sigma_ts
    GROUP BY w."g0", w.sigma_ts
    HAVING COUNT(*) >= 3;
    ```

A self-join rather than a window function, because `value_count` and `temporal` need
`COUNT(DISTINCT ...)` and not every database allows that in a window function. The join
compares every event with the others of its group, so very large groups with a long
`timespan` cost more than a plain count.

The parts that differ:

| | SQLite | PostgreSQL | DuckDB | ClickHouse |
| --- | --- | --- | --- | --- |
| read an `iso` time | `unixepoch` | `EXTRACT(EPOCH ...)` | `epoch(TRY_CAST ...)` | `parseDateTime64BestEffortOrNull` |
| same group | `IS` | `IS NOT DISTINCT FROM` | `IS NOT DISTINCT FROM` | `IS NOT DISTINCT FROM` |
| median, percentile | `sigma_percentile()` | `percentile_cont` | `quantile_cont` | `quantileExactInclusive` |
| time in the result | text | `timestamptz` | `TIMESTAMP`, UTC | `DateTime64`, UTC |

- **SQLite** has no percentile aggregate. Register `sigma_percentile(value, fraction)` or use
  the connection from `sigma2sql.runner.connect()`, as `test` and `check` do.
- **PostgreSQL** needs version 16 or newer, for `pg_input_is_valid`.
- **ClickHouse** was tested on 25.8. Correlations with `group-by` need `IS NOT DISTINCT FROM`
  in `JOIN ON`.

## Not supported

`temporal_ordered` is not supported in this version. Such a file is skipped, with everything
else in it, and `convert` exits 1. Any other error in the keys of a correlation, such as a bad
`timespan` or `condition`, skips the file in the same way:

```console
$ sigma2sql convert ordered.yml
skip ordered.yml: temporal_ordered correlations are not supported
```

A `temporal` correlation with a boolean condition, such as `recon and new_service`, is not
supported either. `condition` has to be a map:

```console
$ sigma2sql convert bad_bool.yml
skip bad_bool.yml: correlation 'condition' must be a map
```

A correlation that names a rule you did not load is skipped on its own. Other rules in the file
still convert:

```console
$ sigma2sql convert bad_unknown.yml
skip bad_unknown.yml: correlation refers to unknown rules: does_not_exist
```
