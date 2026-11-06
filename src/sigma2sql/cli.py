"""Convert Sigma rules to SQL, test them against sample events and hunt through log files."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from dataclasses import replace
from importlib.metadata import version
from pathlib import Path
from typing import Any

import yaml

from sigma2sql.collection import Collection, rule_files
from sigma2sql.correlation import correlation_query
from sigma2sql.errors import RuleError, UnsupportedRule
from sigma2sql.hunt import LEVELS, Hit, Report, hunt
from sigma2sql.profile import apply_profile, builtin_profiles, load_placeholders, load_profile
from sigma2sql.rule import Correlation, Document
from sigma2sql.runner import matching_events, read_jsonl, rows
from sigma2sql.runner import target as runner_target
from sigma2sql.sql import DIALECTS, Target, to_query


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

    hunt_p = sub.add_parser("hunt", help="run rules over JSON, Parquet or CSV logs with DuckDB")
    hunt_p.add_argument("rules", nargs="+", type=Path, help="rule files or directories")
    hunt_p.add_argument(
        "-l", "--logs", nargs="+", required=True, help="log files; globs such as 'logs/*.json'"
    )
    hunt_p.add_argument("-e", "--examples", type=int, default=0, help="matching events to show")
    hunt_p.add_argument("--format", choices=("table", "json"), default="table")
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
    _field_options(check)

    sub.add_parser("profiles", help="list the built-in profiles")

    args = parser.parse_args(argv)
    # Rules contain non-ASCII (e.g. windash variants); don't depend on the console code page.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
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
        return _check(args.paths, target, args.require_tests)
    return _test(args.rule, args.events, target, args.expect)


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
        table=getattr(args, "table", "events"),
        mapping=mapping,
        json_column=getattr(args, "json_column", None),
        keyword_column=getattr(args, "keyword_column", None),
    )
    if args.profile:
        target = apply_profile(target, load_profile(args.profile))
    if args.placeholders:
        target = replace(target, placeholders=load_placeholders(args.placeholders))
    if args.nested:
        target = replace(target, nested=True)
    if args.timestamp_field:
        target = replace(target, timestamp=args.timestamp_field)
    if args.timestamp_format:
        target = replace(target, timestamp_format=args.timestamp_format)
    return target


def _report_errors(col: Collection) -> None:
    for path, reason in col.errors:
        print(f"skip {path}: {reason}", file=sys.stderr)


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
    col = Collection.load([path])
    if col.errors:
        _report_errors(col)
        return 2
    try:
        events = read_jsonl(events_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"sigma2sql: {exc}", file=sys.stderr)
        return 2
    lines = [line for line in events_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    matched: list[bool] = []
    items: list[Document] = [*col.standalone(), *col.correlations]
    for item in items:
        try:
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
        print(f"{item.title}: {len(found)} {what}", file=sys.stderr)
        matched.append(bool(found))
    if expect == "match" and not all(matched):
        return 1
    if expect == "none" and any(matched):
        return 1
    return 0


def _check(paths: list[Path], target: Target, require_tests: bool) -> int:
    passed = failed = untested = 0
    for path in rule_files(paths):
        cases = [
            (f, f.name.endswith(".match.jsonl"))
            for f in (path.with_suffix(".match.jsonl"), path.with_suffix(".nomatch.jsonl"))
            if f.exists()
        ]
        if not cases:
            untested += 1
            if require_tests:
                failed += 1
                print(f"FAIL {path}: no {path.stem}.match.jsonl or .nomatch.jsonl")
            continue
        problems = _check_rule(path, cases, target)
        if problems:
            failed += 1
            for problem in problems:
                print(f"FAIL {path}: {problem}")
        else:
            passed += 1
            print(f"ok   {path}")
    print(f"{passed} passed, {failed} failed, {untested} without tests", file=sys.stderr)
    return 1 if failed else 0


def _check_rule(path: Path, cases: list[tuple[Path, bool]], target: Target) -> list[str]:
    col = Collection.load([path])
    if col.errors:
        return [reason for _, reason in col.errors]
    problems: list[str] = []
    items: list[Document] = [*col.standalone(), *col.correlations]
    for events_path, should_match in cases:
        try:
            events = read_jsonl(events_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            return [f"{events_path.name}: {exc}"]
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
            wrong = sorted(set(range(len(events))) - hits if should_match else hits)
            if wrong:
                lines = ", ".join(str(i + 1) for i in wrong)
                verb = "missed" if should_match else "matched"
                problems.append(f"{item.title}: {verb} {events_path.name} event(s) {lines}")
    return problems


def _hunt(args: argparse.Namespace, target: Target) -> int:
    col = Collection.load(args.rules)
    _report_errors(col)
    try:
        report = hunt(col, args.logs, target, args.examples)
    except Exception as exc:  # DuckDB raises its own error types for unreadable files
        print(f"sigma2sql: {exc}", file=sys.stderr)
        return 2
    for item, reason in report.skipped:
        print(f"skip {item.path or item.title}: {reason}", file=sys.stderr)

    if args.format == "json":
        print(json.dumps([_hit_json(h) for h in report.hits], indent=2))
    else:
        _print_table(report)
    print(
        f"{len(report.hits)} of {report.ran} rules matched {report.events} events"
        f" ({len(report.skipped) + len(col.errors)} rules skipped)",
        file=sys.stderr,
    )
    if args.fail_on:
        limit = LEVELS.index(args.fail_on)
        if any(h.rank <= limit for h in report.hits):
            return 1
    return 0


def _print_table(report: Report) -> None:
    if not report.hits:
        return
    width = max(4, *(len(str(h.count)) for h in report.hits))
    print(f"{'LEVEL':<14}{'HITS':>{width}}  RULE")
    for h in report.hits:
        where = f"  ({h.rule.path})" if h.rule.path else ""
        print(f"{h.rule.level or '-':<14}{h.count:>{width}}  {h.rule.title}{where}")
        for event in h.examples:
            print(f"{'':<14}{'':>{width}}    {event}")


def _hit_json(h: Hit) -> dict[str, object]:
    return {
        "title": h.rule.title,
        "id": h.rule.id,
        "level": h.rule.level,
        "path": str(h.rule.path) if h.rule.path else None,
        "correlation": isinstance(h.rule, Correlation) or h.rule.aggregation is not None,
        "count": h.count,
        "examples": [json.loads(e) for e in h.examples],
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
