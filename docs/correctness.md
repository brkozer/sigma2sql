# How sigma2sql is checked

Converting a rule is only half the job: the SQL has to match the same events the rule
author meant. sigma2sql is checked four ways, all of them in CI.

| Check | What it shows | Result (SigmaHQ `52f81d6`, 2026-11-05) |
| --- | --- | --- |
| Behaviour tests (`tests/cases.py`, `tests/test_correlation.py`) | Sigma semantics on hand-written events, run unchanged on SQLite, DuckDB, PostgreSQL 17 and ClickHouse 25.8 | all pass on all four |
| Every SigmaHQ rule converted and executed (`scripts/check_sigmahq.py`) | The SQL is valid for each database, with and without profiles | 3807 rules in `rules*/`: SQLite, DuckDB and ClickHouse 3807, PostgreSQL 3804; no query rejected |
| SigmaHQ regression samples (`scripts/check_regression.py`) | Rules fire on the real events SigmaHQ keeps for them | 477/477 samples on SQLite, DuckDB and ClickHouse with identical counts, and from the `.evtx` files through `hunt` |
| pySigma comparison (`scripts/diff_pysigma.py`) | Same results as the reference implementation on every rule × every sample | 3076 of 3078 rules identical; the 2 differences are explained below |

The 3807 are `rules`, `rules-emerging-threats`, `rules-threat-hunting`, `rules-compliance` and
`rules-placeholder`. 27 of them use the `expand` modifier and were measured with a generated
`--placeholders` file; without values they are skipped by design.

The three PostgreSQL gaps are rules whose regular expressions repeat a group more than 255
times, which PostgreSQL rejects; sigma2sql reports them as unsupported rather than changing
the pattern.

Filters were compared separately: 96 combinations of logsource, rule reference and condition
gave the same events as pySigma's `SigmaFilter`.

## Regression samples

SigmaHQ stores real Windows events for many rules under `regression_data/`, exported from
EVTX to JSON (`Event.System`, `Event.EventData`). They are loaded as they are, with the
built-in `evtx` profile, and every rule must produce at least the number of matches SigmaHQ
expects. Getting to all of them needed two profile fixes, not detection fixes: Defender writes
field names with spaces (`New Value` for `NewValue`), and WMI-Activity keeps its data under
`UserData`.

## Differences from pySigma

All 477 samples (510 events after splitting multi-event samples) are flattened into one
table, and each rule is converted by both pySigma's SQLite backend and sigma2sql and run on
the whole table, so every rule is also tested against hundreds of events it must *not*
match.

The comparison found one bug in sigma2sql, now fixed: the `windash` modifier only expanded
values written with `-`, so `CommandLine|windash|contains: ' /accepteula'` missed
`-accepteula`.

The two remaining differences come from how CIDR ranges are matched:

| Rule | Event | sigma2sql | pySigma |
| --- | --- | --- | --- |
| `net_connection_win_wscript_cscript_local_connection` | `DestinationIp: 0:0:0:0:0:0:0:1` | match | no match |
| `net_connection_win_wscript_cscript_outbound_connection` | same event | no match | match |

Sysmon writes the IPv6 loopback address in full form, `0:0:0:0:0:0:0:1`. pySigma expands
`::1/128` into the text `'::1'` and compares strings, so it misses the event in the first
rule and fails to exclude it in the second. sigma2sql parses the address (`inet` in
PostgreSQL, `isIPAddressInRange` in ClickHouse, Python's `ipaddress` in SQLite and DuckDB), so
both rules behave as written. This is reported as
[SigmaHQ/pySigma#609](https://github.com/SigmaHQ/pySigma/issues/609), with a fix in
[#610](https://github.com/SigmaHQ/pySigma/pull/610).
