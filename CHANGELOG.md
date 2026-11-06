# Changelog

## Unreleased

- ClickHouse dialect, tested on a real server: all SigmaHQ rules run, and the regression
  samples give the same results as on the other databases.
- `hunt` reads `.evtx` files directly (`pip install "sigma2sql[evtx]"`). Damaged logs are read
  as far as possible, with a warning for what was lost.
- `expand` modifier: `--placeholders` fills in `%name%` values.
- Sigma filters, applied by `convert` and `hunt` with the same rules as pySigma.
- `--sarif FILE` for `hunt` and `check`, and a `sarif` input for the GitHub Action.
- Modifiers `neq`, `re|m`, `re|s` (and the long names `ignorecase`, `multiline`, `dotall`),
  `minute`, `hour`, `day`, `week`, `month`, `year`.
- Correlations `value_median` and `value_percentile`.
- `i`, `m` and `s` without `re` are now an error instead of being ignored.
- Fix: `hunt` over SigmaHQ's whole rule set ran out of memory on any log with events, because
  four rules list thousands of patterns for one field. DuckDB now gets such a list as a single
  test, and a rule that fails no longer ends the hunt. CI runs every query over real events
  now; the check used empty tables before, which is why this went unnoticed.
- Fix: on PostgreSQL one bad value, such as the `-` Windows logs write in `IpAddress`, ended
  the whole query in `cidr`, number comparisons and correlations. Such values are now skipped,
  which needs PostgreSQL 16 or newer.
- Fix: on SQLite text in a number field counted as 0, so `Port|lt: 100` matched `n/a`.
- Fix: `hunt` with a Windows profile also ran rules for other products, and a negated Zeek or
  Cisco rule then matched every Windows event. Profiles can now name their `product`.
- Coverage is now measured on all five SigmaHQ rule folders, not only `rules/`: 3807/3807 on
  SQLite, DuckDB and ClickHouse, 3804/3807 on PostgreSQL. The README used to say "every
  SigmaHQ rule" for `rules/` alone, where 27 placeholder rules elsewhere did not convert.

## 0.2.0 (2026-11-05)

- `hunt`: run a rule directory over JSON, JSON Lines, Parquet or CSV logs with DuckDB, no
  database needed; table or JSON report, `--fail-on LEVEL` for CI.
- DuckDB dialect next to SQLite and PostgreSQL.
- Correlation rules (`event_count`, `value_count`, `value_sum`, `value_avg`, `temporal`, with
  `group-by`, `timespan` and `aliases`) and legacy `| count() by ... > N` aggregations. All 45
  `count()` rules SigmaHQ keeps under `unsupported/` and `deprecated/` convert and run.
- Profiles: field mapping, logsource routing (per-category table and/or extra conditions),
  nested JSON paths, fallback field templates and timestamp settings. Built in: `sysmon`,
  `evtx`, `ecs-winlogbeat`, `ocsf`.
- Modifiers `base64`, `base64offset`, `utf16`, `utf16le`, `utf16be`, `wide`, and keyword
  searches with modifiers (`'|all'`, `'|re'`). SigmaHQ coverage is now 3162/3162 on SQLite and
  DuckDB, 3160/3162 on PostgreSQL.
- `check` command and a GitHub Action that test rules against
  `<rule>.match.jsonl` / `<rule>.nomatch.jsonl` files.
- Correctness checks in CI: SigmaHQ regression samples (476/476 match as expected) and a
  rule-by-rule comparison with pySigma's SQLite backend on real events (see
  `docs/correctness.md`).
- Fix: `windash` now also expands values written with `/` (e.g. ` /accepteula`), and every
  flag in a value.
- `--version`.

## 0.1.0 (2026-11-05)

- First release: Sigma rules to SQLite and PostgreSQL SQL, field mapping, JSON column mode,
  and `test` to run a rule against JSON Lines events.
