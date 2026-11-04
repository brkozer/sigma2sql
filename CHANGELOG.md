# Changelog

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
