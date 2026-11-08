# Changelog

## 0.3.3 (2026-11-08)

- Fix: in JSON mode, keywords with a backslash, a quote, a tab or a newline never matched,
  because the document's text holds them escaped. `C:\Windows` now finds that path on all four
  databases. A rule that doubled the backslashes to work around this has to be changed back.

## 0.3.2 (2026-11-07)

- `temporal_ordered` correlations, on all four databases. A row for every start time of a
  complete sequence in a group, not only the first.
- Fix: a rule listed twice in a correlation counted its events twice. Thanks to @ghostfix-pm
  for reporting this and for the first `temporal_ordered` proposal in #1.

## 0.3.1 (2026-11-07)

- Documentation site: <https://brkozer.github.io/sigma2sql/>.
- Fix: with the `evtx` and `ecs-winlogbeat` profiles, correlations with a `timespan` found
  nothing and gave no error, because `default_field` also moved the time field. This covers
  `hunt` on `.evtx` files. The time is now read from the path the profile gives, then from
  `default_field`. Tests had a flat time field, which is why this went unnoticed; they now run
  these profiles on all four databases.
- Fix: `--timestamp-field` was ignored when `hunt` chose the `evtx` profile by itself.
- Fix: `hunt` read a time with no zone in the machine's time zone. It is UTC now, as in `test`.
- Fix: on DuckDB before 2.0, rules with `and` on JSON fields were skipped, although
  `duckdb>=1.3` is what we ask for. CI now also runs the oldest supported version.
- Fix: SQLite read text such as `10.0.0.1` or `1-2` as a number, and ClickHouse `e5` or `1e+`.
- Fix: non-ASCII keywords did not match on `.evtx` files or in `test` and `check`.
- `check` now loads every rule, also those without test files, and fails on what cannot load
  or convert. An invalid regex is a failure even if no event reaches it. This can turn a
  passing run red.
- `hunt`, `check` and `test` exit 2 on a rule path that does not exist or holds no rule files,
  and `hunt` when no rule could run, so a mistyped path no longer passes in CI.
- A rule file that is not UTF-8 is skipped with a message, and an unwritable `--sarif` file
  exits 2, both without a traceback. `.YML` files count as rule files. `-e` refuses negative
  numbers.
- `hunt` only stops on damaged logs if no event at all could be read, over all `--logs` values.
  One failing `--examples` query no longer ends the hunt, and mixing `.evtx` with other logs
  without a `--profile` gives a warning.
- `check` keeps the other failures of a rule when a test file is broken, and JSON errors name
  the real line.
- The GitHub Action accepts paths on several lines.
- README: the regression samples run on SQLite, DuckDB, ClickHouse and from `.evtx` files, not
  on PostgreSQL as it said, and the library example needed a `Path`.

## 0.3.0 (2026-11-06)

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
