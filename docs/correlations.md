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
[`check`](testing.md). What is left out is listed under [Not supported](#not-supported).

## Correlation keys

The `correlation` map takes these keys. `title`, `id`, `name` and `level` sit at the top level
of the document, as in any rule.

| Key | Required | Meaning |
| --- | --- | --- |
| `type` | yes | one of the [types](#types) below |
| `rules` | yes | names or ids of the rules to count; a single string is allowed |
| `group-by` | no | fields that split the count; a single string is allowed |
| `timespan` | no | length of the [window](#windows), such as `5m`; without it there is no window |
| `condition` | yes, except for `temporal` and `temporal_ordered` | a [threshold](#conditions) on the result |
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
| `temporal_ordered` | number of steps, the length of `rules` | |

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
the number of different entries in `rules`; write your own numeric `condition` to ask for
fewer. `value` is the count of different rules in the window.

### temporal_ordered

`temporal_ordered` asks whether the listed rules matched in the order of the list, within the
window. Each rule in `rules` is one step of a sequence:

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
title: Recon, then a new service on one host
correlation:
  type: temporal_ordered
  rules: [recon, new_service]
  group-by: [Host]
  timespan: 10m
level: high
```

```json
{"Image": "C:\\Windows\\System32\\whoami.exe", "Host": "ws1", "timestamp": "2026-11-01T10:00:00Z"}
{"EventID": 7045, "Host": "ws1", "timestamp": "2026-11-01T10:04:00Z"}
{"Image": "C:\\Windows\\System32\\whoami.exe", "Host": "ws1", "timestamp": "2026-11-01T10:20:00Z"}
{"EventID": 7045, "Host": "ws1", "timestamp": "2026-11-01T10:21:00Z"}
{"EventID": 7045, "Host": "ws2", "timestamp": "2026-11-01T10:00:00Z"}
{"Image": "C:\\Windows\\System32\\whoami.exe", "Host": "ws2", "timestamp": "2026-11-01T10:04:00Z"}
{"Image": "C:\\Windows\\System32\\whoami.exe", "Host": "ws3", "timestamp": "2026-11-01T10:00:00Z"}
{"EventID": 7045, "Host": "ws3", "timestamp": "2026-11-01T11:00:00Z"}
```

```console
$ sigma2sql test sequence.yml sequence.jsonl
{"Host": "ws1", "window_start": "2026-11-01 10:00:00.000", "window_end": "2026-11-01 10:04:00.000", "value": 2}
{"Host": "ws1", "window_start": "2026-11-01 10:20:00.000", "window_end": "2026-11-01 10:21:00.000", "value": 2}
Recon, then a new service on one host: 2 results
```

`ws1` shows the sequence twice, and each time has its own row. `ws2` has both events in the
wrong order, so it has no row, although a `temporal` correlation over these rules reports it.
`ws3` has them in the right order, an hour apart.

Every example in this section gives the same rows on all four databases. `group-by`, `aliases`
and `generate` work as they do for the other types.

Two things to know about sequences: `rules: [recon, recon]` gives no row for two events in the
same second, see [below](#a-rule-following-itself), and a `timespan` is optional here, though
the Sigma specification expects one.

#### What a row means

A row stands for one start of the sequence: an event of the first rule that the other rules
followed in time.

| Column | Meaning |
| --- | --- |
| one per `group-by` name | group value |
| `window_start` | time of the start event |
| `window_end` | the earliest time the last step was reached from that start |
| `value` | number of steps, so it is the same in every row |

All the steps have to match, so `condition` can be left out. A `gte` with the number of steps
is accepted and changes nothing. Any other condition is [not supported](#not-supported).

In `hunt`, the `HITS` column counts these rows:

```console
$ sigma2sql hunt sequence.yml --logs sequence.jsonl --examples 2
LEVEL         HITS  RULE
high             2  Recon, then a new service on one host  (sequence.yml)
                      {"Host":"ws1","window_start":"2026-11-01 10:00:00","window_end":"2026-11-01 10:04:00","value":2}
                      {"Host":"ws1","window_start":"2026-11-01 10:20:00","window_end":"2026-11-01 10:21:00","value":2}
1 of 1 rules matched 8 events (0 rules skipped)
```

#### One row per start event

Every start event that leads to a complete sequence gets a row, not only the first one of the
group, so a repeated attack is reported each time. A start gets one row however many events
complete it:

```json
{"Image": "C:\\Windows\\System32\\whoami.exe", "Host": "ws1", "timestamp": "2026-11-01T10:00:00Z"}
{"Image": "C:\\Windows\\System32\\whoami.exe", "Host": "ws1", "timestamp": "2026-11-01T10:01:00Z"}
{"EventID": 7045, "Host": "ws1", "timestamp": "2026-11-01T10:02:00Z"}
{"EventID": 7045, "Host": "ws1", "timestamp": "2026-11-01T10:03:00Z"}
```

```console
$ sigma2sql test sequence.yml starts.jsonl
{"Host": "ws1", "window_start": "2026-11-01 10:00:00.000", "window_end": "2026-11-01 10:02:00.000", "value": 2}
{"Host": "ws1", "window_start": "2026-11-01 10:01:00.000", "window_end": "2026-11-01 10:02:00.000", "value": 2}
Recon, then a new service on one host: 2 results
```

Both `whoami` events start a sequence, so there are two rows. An event is not used up by a
sequence: the service at 10:02 ends both, and the one at 10:03 adds no row.

Rows are grouped on the time of the start. Two start events of one group with the same time
therefore give one row:

```json
{"Image": "C:\\Windows\\System32\\whoami.exe", "Host": "ws1", "timestamp": "2026-11-01T10:00:00Z"}
{"Image": "C:\\Windows\\System32\\whoami.exe", "Host": "ws1", "timestamp": "2026-11-01T10:00:00Z"}
{"EventID": 7045, "Host": "ws1", "timestamp": "2026-11-01T10:02:00Z"}
```

```console
$ sigma2sql test sequence.yml same_time.jsonl
{"Host": "ws1", "window_start": "2026-11-01 10:00:00.000", "window_end": "2026-11-01 10:02:00.000", "value": 2}
Recon, then a new service on one host: 1 results
```

#### Equal timestamps

A step has to be no earlier than the step before it, so events with the same time count as in
order. Many logs only have whole seconds, and two events of one second may have happened either
way round. The order of the lines in the file has no effect:

```json
{"EventID": 7045, "Host": "ws1", "timestamp": "2026-11-01T10:00:00Z"}
{"Image": "C:\\Windows\\System32\\whoami.exe", "Host": "ws1", "timestamp": "2026-11-01T10:00:00Z"}
```

```console
$ sigma2sql test sequence.yml equal.jsonl
{"Host": "ws1", "window_start": "2026-11-01 10:00:00.000", "window_end": "2026-11-01 10:00:00.000", "value": 2}
Recon, then a new service on one host: 1 results
```

The exception is [a rule that comes back](#a-rule-following-itself). An event that matches two
different rules can fill both their steps, as with `temporal`, see
[several rules](#several-rules).

#### A rule following itself

A rule may be listed more than once. When it comes back, the step needs an event strictly later
than the last earlier step of that rule, or every single event would be a sequence of its own:

```yaml
title: Recon command
name: recon
logsource: {product: windows, category: process_creation}
detection:
  selection:
    Image|endswith: '\whoami.exe'
  condition: selection
---
title: Recon twice on one host
correlation:
  type: temporal_ordered
  rules: [recon, recon]
  group-by: [Host]
  timespan: 10m
level: high
```

```json
{"Image": "C:\\Windows\\System32\\whoami.exe", "Host": "ws1", "timestamp": "2026-11-01T10:00:00Z"}
{"Image": "C:\\Windows\\System32\\whoami.exe", "Host": "ws2", "timestamp": "2026-11-01T10:00:00Z"}
{"Image": "C:\\Windows\\System32\\whoami.exe", "Host": "ws2", "timestamp": "2026-11-01T10:00:00Z"}
{"Image": "C:\\Windows\\System32\\whoami.exe", "Host": "ws3", "timestamp": "2026-11-01T10:00:00Z"}
{"Image": "C:\\Windows\\System32\\whoami.exe", "Host": "ws3", "timestamp": "2026-11-01T10:03:00Z"}
```

```console
$ sigma2sql test twice.yml twice.jsonl
{"Host": "ws3", "window_start": "2026-11-01 10:00:00.000", "window_end": "2026-11-01 10:03:00.000", "value": 2}
Recon twice on one host: 1 results
```

`ws1` has one event. `ws2` has two, but in the same second, and here equal times do not count.
That is a known limit: the two events are not told apart from one event filling both steps.

The earlier step does not have to be the neighbour in the list. With
`rules: [recon, new_service, recon]`, the third step needs a later event than the first:

```json
{"Image": "C:\\Windows\\System32\\whoami.exe", "Host": "ws1", "timestamp": "2026-11-01T10:00:00Z"}
{"EventID": 7045, "Host": "ws1", "timestamp": "2026-11-01T10:01:00Z"}
{"Image": "C:\\Windows\\System32\\whoami.exe", "Host": "ws1", "timestamp": "2026-11-01T10:02:00Z"}
{"Image": "C:\\Windows\\System32\\whoami.exe", "Host": "ws2", "timestamp": "2026-11-01T10:00:00Z"}
{"EventID": 7045, "Host": "ws2", "timestamp": "2026-11-01T10:01:00Z"}
{"Image": "C:\\Windows\\System32\\whoami.exe", "Host": "ws3", "timestamp": "2026-11-01T10:00:00Z"}
{"EventID": 7045, "Host": "ws3", "timestamp": "2026-11-01T10:00:00Z"}
```

```console
$ sigma2sql test there_and_back.yml there_and_back.jsonl
{"Host": "ws1", "window_start": "2026-11-01 10:00:00.000", "window_end": "2026-11-01 10:02:00.000", "value": 3}
Recon, a new service, recon again: 1 results
```

`ws1` has all three steps. `ws2` stops after the second. `ws3` has only two events, in the same
second, and its one `whoami` event cannot fill both the first step and the third. Against the
other steps equal times still count: with a service at 10:01, as on `ws1`, a `whoami` event at
10:01 would complete the sequence.

#### Timespan

`timespan` is counted from the start event: every step must lie within that time after it, both
ends included. The other types look back from the event that closes the window instead. There
is no limit between two steps other than this one.

```json
{"Image": "C:\\Windows\\System32\\whoami.exe", "Host": "ws1", "timestamp": "2026-11-01T10:00:00Z"}
{"EventID": 7045, "Host": "ws1", "timestamp": "2026-11-01T10:10:00Z"}
{"Image": "C:\\Windows\\System32\\whoami.exe", "Host": "ws2", "timestamp": "2026-11-01T10:00:00Z"}
{"EventID": 7045, "Host": "ws2", "timestamp": "2026-11-01T10:10:01Z"}
```

```console
$ sigma2sql test sequence.yml edge.jsonl
{"Host": "ws1", "window_start": "2026-11-01 10:00:00.000", "window_end": "2026-11-01 10:10:00.000", "value": 2}
Recon, then a new service on one host: 1 results
```

Ten minutes exactly is in the window of `sequence.yml`, one second more is not.

Without a `timespan`, a step can be any time after the one before it, so `ws3` from the first
example is now reported. `no_timespan.yml` is `sequence.yml` without that key and with its own
title. A row still stands for one start, and it keeps `window_start` and `window_end`:

```console
$ sigma2sql test no_timespan.yml sequence.jsonl
{"Host": "ws1", "window_start": "2026-11-01 10:00:00.000", "window_end": "2026-11-01 10:04:00.000", "value": 2}
{"Host": "ws1", "window_start": "2026-11-01 10:20:00.000", "window_end": "2026-11-01 10:21:00.000", "value": 2}
{"Host": "ws3", "window_start": "2026-11-01 10:00:00.000", "window_end": "2026-11-01 11:00:00.000", "value": 2}
Recon, then a new service, any time later: 3 results
```

#### SQL shape

`temporal_ordered` has no `windows` query. It has one CTE per step, named `s0`, `s1` and so on,
and each one keeps the earliest next event of every start:

```console
$ sigma2sql convert sequence.yml
-- Recon, then a new service on one host
WITH base AS (
  SELECT 'recon' AS sigma_rule, unixepoch("timestamp", 'subsec') AS sigma_ts, "Host" AS "g0" FROM "events" WHERE "Image" LIKE '%\\whoami.exe' ESCAPE '\'
  UNION ALL
  SELECT 'new_service' AS sigma_rule, unixepoch("timestamp", 'subsec') AS sigma_ts, "Host" AS "g0" FROM "events" WHERE "EventID" = 7045
),
s0 AS (SELECT DISTINCT "g0", sigma_ts AS t0 FROM base WHERE sigma_rule = 'recon' AND sigma_ts IS NOT NULL),
s1 AS (SELECT p."g0" AS "g0", p.t0 AS t0, MIN(e.sigma_ts) AS t1 FROM s0 p JOIN base e ON e.sigma_rule = 'new_service' AND e."g0" IS p."g0" AND e.sigma_ts >= p.t0 AND e.sigma_ts <= p.t0 + 600 GROUP BY p."g0", p.t0)
SELECT "g0" AS "Host", datetime(t0, 'unixepoch', 'subsec') AS window_start, datetime(t1, 'unixepoch', 'subsec') AS window_end, 2 AS value
FROM s1;

```

`s0` holds the start times of each group, in `t0`, and leaves out events without a time. Each
later CTE joins the one before it to `base`, and asks for the next rule in the same group, at or
after the step before it and within the timespan of `t0`. A rule that comes back also needs a
`>` against its last earlier step. A third step adds `s2` in the same way, with `t1` next to
`t0`. `MIN` keeps the earliest event of the step, as a later one could do no better. There is no
`HAVING`, because a start only reaches the result if every join found an event; that is also
why `value` is a fixed number.

The other dialects have the same CTEs, with the differences in the
[table below](#per-dialect-notes). Each CTE has one row per start, however many events follow
it, so the rows do not multiply from step to step. Each step still compares every start with
the events of its group, so large groups with a long `timespan`, or none, cost more than a
count.

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
timespan. `temporal_ordered` [counts forward from its first step](#timespan) instead.

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
in place of the window. Without `group-by`, there is a single group. `temporal_ordered` is the
exception: it [stays a row per start](#timespan).

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
counts, which is why `guest` above has a `value` of 3 and null times. In `temporal_ordered`,
with or without a `timespan`, such an event cannot be part of a sequence. That holds with a
single rule too, so the event gives no row.

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

Each rule contributes its own matches, and a rule listed twice still contributes them once. In
`temporal_ordered`, each listing is a step of its own. An event that matches two listed rules
counts twice in `event_count`, and it satisfies a `temporal` or `temporal_ordered` correlation
over those two rules alone:

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

`temporal_ordered` always has `window_start` and `window_end`, and they mean
[something a little different](#what-a-row-means).

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

The window is a self-join on a `base` query. All four dialects get the same structure.
`temporal_ordered` has [a shape of its own](#sql-shape), which is also the same on all four:

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

A `temporal` correlation with a boolean condition, such as `recon and new_service`, is not
supported. `condition` has to be a map. Such a file is skipped, with everything else in it, and
`convert` exits 1. Any other error in the keys of a correlation, such as a bad `timespan` or
`condition`, skips the file in the same way:

```console
$ sigma2sql convert bad_bool.yml
skip bad_bool.yml: correlation 'condition' must be a map
```

`temporal_ordered` needs every step in order. Any numeric condition other than `gte` the number
of steps skips the file too:

```console
$ sigma2sql convert fewer_steps.yml
skip fewer_steps.yml: temporal_ordered needs all of its rules, in order
```

A correlation that names a rule you did not load is skipped on its own. Other rules in the file
still convert:

```console
$ sigma2sql convert bad_unknown.yml
skip bad_unknown.yml: correlation refers to unknown rules: does_not_exist
```
