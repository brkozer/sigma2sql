"""Convert Sigma rules to SQL, test them against sample events and hunt through log files."""

from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import sys
from collections.abc import Callable, Sequence
from dataclasses import replace
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path
from typing import Any

import yaml

from sigma2sql import database, html_report
from sigma2sql.collection import Collection, rule_files
from sigma2sql.correlation import correlation_query
from sigma2sql.errors import RuleError, UnsupportedRule
from sigma2sql.expr import regexes
from sigma2sql.hunt import LEVELS, Hit, Report, hunt
from sigma2sql.profile import apply_profile, builtin_profiles, load_placeholders, load_profile
from sigma2sql.rule import Correlation, Document
from sigma2sql.runner import matching_events, read_jsonl, rows
from sigma2sql.runner import target as runner_target
from sigma2sql.sarif import Finding, report
from sigma2sql.sql import DIALECTS, Target, to_query

HTML_EXAMPLES = 5


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sigma2sql", description=__doc__)
    parser.add_argument("--version", action="version", version=f"%(prog)s {version('sigma2sql')}")
    sub = parser.add_subparsers(dest="command", required=True)

    convert = sub.add_parser("convert", help="print SQL for rules and correlations")
    convert.add_argument("paths", nargs="+", type=Path, help="rule files or directories")
    convert.add_argument("-d", "--dialect", choices=DIALECTS, default="sqlite")
    convert.add_argument("-t", "--table", default="events")
    convert.add_argument("--json-column", help="read fields from this JSON column")
    convert.add_argument("--keyword-column", help="column searched by keyword rules")
    _field_options(convert)

    test = sub.add_parser("test", help="run a rule file against JSON Lines events")
    test.add_argument("rule", type=Path)
    test.add_argument("events", type=Path, help="one JSON object per line")
    test.add_argument(
        "--expect",
        choices=("match", "none"),
        help="exit 1 unless every rule in the file matches / nothing matches",
    )
    _field_options(test)

    hunt_p = sub.add_parser(
        "hunt", help="run rules over EVTX, JSON, Parquet or CSV logs with DuckDB"
    )
    hunt_p.add_argument("rules", nargs="+", type=Path, help="rule files or directories")
    hunt_p.add_argument(
        "-l",
        "--logs",
        nargs="+",
        help=f"log files; globs such as 'logs/*.json'. Without it, the database in ${database.ENV}",
    )
    hunt_p.add_argument("-e", "--examples", type=_count, default=0, help="matching events to show")
    hunt_p.add_argument("--format", choices=("table", "json"), default="table")
    hunt_p.add_argument("--sarif", type=Path, help="also write the matches to this SARIF file")
    hunt_p.add_argument("--html", type=Path, help="also write a report to this HTML file")
    hunt_p.add_argument("-t", "--table", help="table holding the events, in a database")
    hunt_p.add_argument("--json-column", help="read fields from this JSON column, in a database")
    hunt_p.add_argument("--keyword-column", help="column searched by keyword rules, in a database")
    hunt_p.add_argument("--since", help="only events since: 7d, 12h, 30m or 2026-11-01")
    hunt_p.add_argument(
        "--timeout",
        type=_positive,
        default=database.DEFAULT_TIMEOUT,
        help="seconds each rule may take on PostgreSQL or ClickHouse (default: %(default)s)",
    )
    hunt_p.add_argument(
        "--fail-on", choices=LEVELS, help="exit 1 if a rule at this level or above matches"
    )
    _field_options(hunt_p)

    check = sub.add_parser(
        "check", help="test rules against their <rule>.match.jsonl / <rule>.nomatch.jsonl files"
    )
    check.add_argument("paths", nargs="+", type=Path, help="rule files or directories")
    check.add_argument(
        "--require-tests", action="store_true", help="fail when a rule has no test events"
    )
    check.add_argument("--sarif", type=Path, help="also write the failures to this SARIF file")
    _field_options(check)

    sub.add_parser("profiles", help="list the built-in profiles")

    args = parser.parse_args(argv)
    # Rules contain non-ASCII (e.g. windash variants); don't depend on the console code page.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="backslashreplace")
    if args.command == "profiles":
        for name, description in builtin_profiles().items():
            print(f"{name:<16}{description}")
        return 0
    try:
        target = _target(args)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        print(f"sigma2sql: {exc}", file=sys.stderr)
        return 2
    if args.command == "convert":
        return _convert(args.paths, target)
    if args.command == "hunt":
        return _hunt(args, target)
    if args.command == "check":
        return _check(args.paths, target, args.require_tests, args.sarif)
    return _test(args.rule, args.events, target, args.expect)


def _positive(text: str) -> int:
    value = int(text)
    if value < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return value


def _since(text: str) -> float:
    match = re.fullmatch(r"(\d+)([smhdw])", text.strip())
    if match:
        seconds = int(match[1]) * {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[match[2]]
        return datetime.now(UTC).timestamp() - seconds
    try:
        when = datetime.fromisoformat(text.strip())
    except ValueError as exc:
        raise ValueError(f"--since: expected 7d, 12h, 30m or a date, not {text!r}") from exc
    return (when if when.tzinfo else when.replace(tzinfo=UTC)).timestamp()


def _count(text: str) -> int:
    value = int(text)
    if value < 0:
        raise argparse.ArgumentTypeError("must not be negative")
    return value


def _is_evtx(path: str) -> bool:
    return Path(path).suffix.lower() == ".evtx"


def _field_options(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "-p", "--profile", help="built-in profile name (see `sigma2sql profiles`) or YAML file"
    )
    p.add_argument("-m", "--mapping", type=Path, help="YAML map of Sigma field -> column/key")
    p.add_argument("--placeholders", type=Path, help="YAML map of %%name%% placeholder to value(s)")
    p.add_argument("--nested", action="store_true", help="dotted names are nested JSON paths")
    p.add_argument("--timestamp-field", help="event time field for correlations")
    p.add_argument("--timestamp-format", choices=("iso", "epoch_s", "epoch_ms"))


def _target(args: argparse.Namespace) -> Target:
    """Defaults, then the profile, then explicit command-line options."""
    try:
        mapping = _load_mapping(args.mapping)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        raise ValueError(f"mapping: {exc}") from exc
    target = Target(
        dialect=getattr(args, "dialect", "sqlite"),
        table=getattr(args, "table", None) or "events",
        mapping=mapping,
        json_column=getattr(args, "json_column", None),
        keyword_column=getattr(args, "keyword_column", None),
    )
    profile = args.profile
    logs = getattr(args, "logs", None) or []
    if args.command == "hunt" and not profile and any(_is_evtx(p) for p in logs):
        # EVTX events have one known layout, so the right profile needs no asking.
        profile = "evtx"
        if not all(_is_evtx(p) for p in logs):
            print("warning: all logs are read with the evtx profile", file=sys.stderr)
    if profile:
        target = apply_profile(target, load_profile(profile))
    if args.placeholders:
        target = replace(target, placeholders=load_placeholders(args.placeholders))
    if args.nested:
        target = replace(target, nested=True)
    if getattr(args, "since", None):
        target = replace(target, since=_since(args.since))
    if args.timestamp_field:
        target = replace(target, timestamp=args.timestamp_field)
    if args.timestamp_format:
        target = replace(target, timestamp_format=args.timestamp_format)
    return target


def _report_errors(col: Collection) -> None:
    for path, reason in col.errors:
        print(f"skip {path}: {reason}", file=sys.stderr)
    for unused in col.unused_filters():
        print(f"warning: filter {unused.path or unused.title} applies to no rule", file=sys.stderr)


def _no_rules(paths: list[Path]) -> bool:
    """Report rule paths that lead nowhere: in CI a mistyped one must not pass."""
    problems: list[str] = []
    for path in paths:
        try:
            if not path.exists():
                problems.append(f"{path}: no such file or directory")
            elif not any(True for _ in rule_files([path])):
                problems.append(f"{path}: no .yml or .yaml files found")
        except OSError as exc:
            problems.append(str(exc))
    for problem in problems:
        print(f"sigma2sql: {problem}", file=sys.stderr)
    return bool(problems)


def _validate(item: Document, col: Collection, target: Target) -> None:
    """What `check` and `test` can refuse without events: SQLite only evaluates a regex for
    an event that gets that far, so a broken one would pass unnoticed."""
    _sql(item, col, runner_target(target))
    rules = col.resolve(item) if isinstance(item, Correlation) else [item]
    for rule in rules:
        for found in regexes(rule.compile(target.placeholders)):
            try:
                re.compile(found.pattern)
            except re.error as exc:
                raise RuleError(f"invalid regex {found.pattern!r}: {exc}") from exc


def _query_failed(item: Document, exc: sqlite3.Error) -> str:
    return f"{item.title}: SQLite could not run the query: {exc}"


def _sql(item: Document, col: Collection, target: Target) -> str:
    if isinstance(item, Correlation):
        return correlation_query(item, col.resolve(item), target)
    return to_query(item, target)


def _convert(paths: list[Path], target: Target) -> int:
    col = Collection.load(paths)
    _report_errors(col)
    items: list[Document] = [*col.standalone(), *col.correlations]
    if not items and not col.errors:
        print("sigma2sql: no .yml or .yaml files found", file=sys.stderr)
        return 2
    failed = 0
    for item in items:
        try:
            query = _sql(item, col, target)
        except (RuleError, UnsupportedRule) as exc:
            failed += 1
            print(f"skip {item.path or item.title}: {exc}", file=sys.stderr)
            continue
        print(f"-- {item.title}" + (f" ({item.id})" if item.id else ""))
        print(query + ";\n")
    total = len(items) + len(col.errors)
    if total > 1:
        print(f"converted {len(items) - failed}/{total} rules", file=sys.stderr)
    return 1 if failed or col.errors else 0


def _test(path: Path, events_path: Path, target: Target, expect: str | None) -> int:
    if _no_rules([path]):
        return 2
    col = Collection.load([path])
    if col.errors:
        _report_errors(col)
        return 2
    try:
        events = read_jsonl(events_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"sigma2sql: {exc}", file=sys.stderr)
        return 2
    text = events_path.read_text(encoding="utf-8")
    lines = [line for line in text.split("\n") if line.strip()]
    matched: list[bool] = []
    items: list[Document] = [*col.standalone(), *col.correlations]
    for item in items:
        try:
            _validate(item, col, target)
            if isinstance(item, Correlation) or item.aggregation is not None:
                found: list[Any] = rows(_sql(item, col, runner_target(target)), events)
                for row in found:
                    print(json.dumps(row, default=str))
                what = "results"
            else:
                found = matching_events(item, events, target)
                for i in found:
                    print(lines[i])
                what = f"of {len(events)} events matched"
        except (RuleError, UnsupportedRule) as exc:
            print(f"sigma2sql: {item.title}: {exc}", file=sys.stderr)
            return 2
        except sqlite3.Error as exc:
            print(f"sigma2sql: {_query_failed(item, exc)}", file=sys.stderr)
            return 2
        print(f"{item.title}: {len(found)} {what}", file=sys.stderr)
        matched.append(bool(found))
    if expect == "match" and not all(matched):
        return 1
    if expect == "none" and any(matched):
        return 1
    return 0


def _write_sarif(path: Path, findings: list[Finding]) -> bool:
    text = json.dumps(report(findings, version("sigma2sql")), indent=2)
    return _write(path, text + "\n")


def _write(path: Path, text: str) -> bool:
    try:
        path.write_text(text, encoding="utf-8", errors="replace")
    except OSError as exc:
        print(f"sigma2sql: {exc}", file=sys.stderr)
        return False
    return True


def _check(paths: list[Path], target: Target, require_tests: bool, sarif: Path | None) -> int:
    if _no_rules(paths):
        return 2
    passed = failed = untested = 0
    findings: list[Finding] = []

    def fail(path: Path, problem: str) -> None:
        print(f"FAIL {path}: {problem}")
        findings.append(Finding("rule-test", "Sigma rule test failed", "high", problem, path))

    for path in rule_files(paths):
        cases = [
            (f, f.name.endswith(".match.jsonl"))
            for f in (path.with_suffix(".match.jsonl"), path.with_suffix(".nomatch.jsonl"))
            if f.exists()
        ]
        problems = _check_rule(path, cases, target)
        if problems:
            failed += 1
            for problem in problems:
                fail(path, problem)
        elif cases:
            passed += 1
            print(f"ok   {path}")
        else:
            untested += 1
            if require_tests:
                failed += 1
                fail(path, f"no {path.stem}.match.jsonl or .nomatch.jsonl")
    print(f"{passed} passed, {failed} failed, {untested} without tests", file=sys.stderr)
    if sarif and not _write_sarif(sarif, findings):
        return 2
    return 1 if failed else 0


def _check_rule(path: Path, cases: list[tuple[Path, bool]], target: Target) -> list[str]:
    col = Collection.load([path])
    if col.errors:
        return [reason for _, reason in col.errors]
    problems: list[str] = []
    items: list[Document] = []
    candidates: list[Document] = [*col.standalone(), *col.correlations]
    for item in candidates:
        try:
            _validate(item, col, target)
            items.append(item)
        except (RuleError, UnsupportedRule) as exc:
            problems.append(f"{item.title}: {exc}")
    for events_path, should_match in cases:
        try:
            events = read_jsonl(events_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            problems.append(f"{events_path.name}: {exc}")
            continue
        for item in items:
            try:
                if isinstance(item, Correlation) or item.aggregation is not None:
                    found = rows(_sql(item, col, runner_target(target)), events)
                    if should_match and not found:
                        problems.append(f"{item.title}: no result for {events_path.name}")
                    elif not should_match and found:
                        problems.append(
                            f"{item.title}: {len(found)} results for {events_path.name}"
                        )
                    continue
                hits = set(matching_events(item, events, target))
            except (RuleError, UnsupportedRule) as exc:
                problems.append(f"{item.title}: {exc}")
                continue
            except sqlite3.Error as exc:
                problems.append(_query_failed(item, exc))
                continue
            wrong = sorted(set(range(len(events))) - hits if should_match else hits)
            if wrong:
                lines = ", ".join(str(i + 1) for i in wrong)
                verb = "missed" if should_match else "matched"
                problems.append(f"{item.title}: {verb} {events_path.name} event(s) {lines}")
    return problems


def _hunt(args: argparse.Namespace, target: Target) -> int:
    if _no_rules(args.rules):
        return 2
    dsn = os.environ.get(database.ENV, "")
    if not args.logs and not dsn:
        print(f"sigma2sql: give --logs, or set {database.ENV} to a database", file=sys.stderr)
        return 2
    if args.logs and (args.table or args.json_column or args.keyword_column):
        print("sigma2sql: --table and the column options are for a database", file=sys.stderr)
        return 2
    col = Collection.load(args.rules)
    _report_errors(col)
    try:
        # A report is little use without events to read, even if none go to the terminal.
        wanted = args.examples or (HTML_EXAMPLES if args.html else 0)
        if args.logs:
            report_ = hunt(col, args.logs, target, wanted, _progress())
        else:
            db = database.connect(dsn, args.timeout)
            try:
                report_ = database.hunt_database(col, db, target, wanted, _progress())
            finally:
                db.close()
    except Exception as exc:  # the drivers raise their own error types
        print(f"sigma2sql: {database.scrub(str(exc), dsn)}", file=sys.stderr)
        return 2
    finally:
        if sys.stderr.isatty():
            print("\r\033[K", end="", file=sys.stderr)
    for warning in report_.warnings:
        print(f"warning: {warning}", file=sys.stderr)
    for item, reason in report_.skipped:
        print(f"skip {item.path or item.title}: {reason}", file=sys.stderr)

    if args.format == "json":
        print(json.dumps([_hit_json(h, args.examples) for h in report_.hits], indent=2))
    else:
        _print_table(report_, args.examples)
    print(
        f"{len(report_.hits)} of {report_.ran} rules matched {report_.events} events"
        f" ({len(report_.skipped) + len(col.errors)} rules skipped)",
        file=sys.stderr,
    )
    if report_.other_logs:
        print(f"{report_.other_logs} rules are for other log sources", file=sys.stderr)
    # Both are attempted: a long hunt must not be lost to one bad path.
    written = not args.sarif or _write_sarif(args.sarif, [_hit_finding(h) for h in report_.hits])
    if args.html:
        page = html_report.render(
            report_,
            col.errors,
            args.logs or [database.describe(dsn)],
            version("sigma2sql"),
            datetime.now(UTC),
        )
        written = _write(args.html, page) and written
    if not written:
        return 2
    if not report_.ran and (report_.skipped or col.errors):
        print("sigma2sql: no rule could run", file=sys.stderr)
        return 2
    if args.fail_on:
        limit = LEVELS.index(args.fail_on)
        if any(h.rank <= limit for h in report_.hits):
            return 1
    return 0


def _progress() -> Callable[[int, int], None] | None:
    if not sys.stderr.isatty():
        return None

    def show(done: int, total: int) -> None:
        print(f"\rrule {done:,} of {total:,}", end="", file=sys.stderr, flush=True)

    return show


def _hit_finding(h: Hit) -> Finding:
    matches = "match" if h.count == 1 else "matches"
    message = f"{h.rule.title}: {h.count} {matches} in the hunted logs"
    return Finding(h.rule.id or h.rule.title, h.rule.title, h.rule.level, message, h.rule.path)


def _print_table(report: Report, examples: int) -> None:
    if not report.hits:
        return
    width = max(4, *(len(str(h.count)) for h in report.hits))
    print(f"{'LEVEL':<14}{'HITS':>{width}}  RULE")
    for h in report.hits:
        where = f"  ({h.rule.path})" if h.rule.path else ""
        print(f"{h.rule.level or '-':<14}{h.count:>{width}}  {h.rule.title}{where}")
        for event in h.examples[:examples]:
            print(f"{'':<14}{'':>{width}}    {event}")


def _example(event: str) -> object:
    try:
        value = json.loads(event)
        # Nested as deep as the report will put it, which is what has to be printable.
        json.dumps([[[value]]], indent=2)
    except RecursionError:  # logs can nest deeper than Python will follow
        return event
    return value


def _hit_json(h: Hit, examples: int) -> dict[str, object]:
    return {
        "title": h.rule.title,
        "id": h.rule.id,
        "level": h.rule.level,
        "path": str(h.rule.path) if h.rule.path else None,
        "correlation": isinstance(h.rule, Correlation) or h.rule.aggregation is not None,
        "count": h.count,
        "examples": [_example(e) for e in h.examples[:examples]],
    }


def _load_mapping(path: Path | None) -> dict[str, str]:
    if path is None:
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in data.items()
    ):
        raise ValueError("expected a map of field name to column name")
    return dict(data)
