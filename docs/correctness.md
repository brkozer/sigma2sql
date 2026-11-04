# How sigma2sql is checked

Converting a rule is only half the job: the SQL has to match the same events the rule
author meant. sigma2sql is checked four ways, all of them in CI.

| Check | What it shows | Result (SigmaHQ `c68bb91`, 2026-11-04) |
| --- | --- | --- |
| Behaviour tests (`tests/cases.py`, `tests/test_correlation.py`) | Sigma semantics on hand-written events, run unchanged on SQLite, DuckDB and PostgreSQL 17 | all pass on all three |
| Every SigmaHQ rule converted and executed (`scripts/check_sigmahq.py`) | The SQL is valid for each database, with and without profiles | SQLite 3162/3162, DuckDB 3162/3162, PostgreSQL 3160/3162; no query rejected |
| SigmaHQ regression samples (`scripts/check_regression.py`) | Rules fire on the real events SigmaHQ keeps for them | 476/476 samples on SQLite and DuckDB |
| pySigma comparison (`scripts/diff_pysigma.py`) | Same results as the reference implementation on every rule × every sample | 3074 of 3076 rules identical; the 2 differences are explained below |

The two PostgreSQL gaps are rules whose regular expressions repeat a group more than 255
times, which PostgreSQL rejects; sigma2sql reports them as unsupported rather than changing
the pattern.

## Regression samples

SigmaHQ stores real Windows events for many rules under `regression_data/`, exported from
EVTX to JSON (`Event.System`, `Event.EventData`). They are loaded as they are, with the
built-in `evtx` profile, and every rule must produce at least the number of matches SigmaHQ
expects. Getting to 476/476 needed two profile fixes, not detection fixes: Defender writes
field names with spaces (`New Value` for `NewValue`), and WMI-Activity keeps its data under
`UserData`.

## Differences from pySigma

All 476 sample events (509 after splitting multi-event samples) are flattened into one
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
PostgreSQL, Python's `ipaddress` in SQLite and DuckDB), so both rules behave as written.
