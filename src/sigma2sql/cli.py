"""Convert Sigma rules to SQL, test them against sample events and hunt through log files."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterator, Sequence
from pathlib import Path

import yaml

from sigma2sql.errors import RuleError, UnsupportedRule
from sigma2sql.hunt import LEVELS, Hit, Report, hunt
from sigma2sql.rule import Rule, load_rule_file
from sigma2sql.runner import matching_events, read_jsonl
from sigma2sql.sql import DIALECTS, Target, to_query


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sigma2sql", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    convert = sub.add_parser("convert", help="print SQL for one or more rules")
    convert.add_argument("paths", nargs="+", type=Path, help="rule files or directories")
    convert.add_argument("-d", "--dialect", choices=DIALECTS, default="sqlite")
    convert.add_argument("-t", "--table", default="events")
    convert.add_argument("-m", "--mapping", type=Path, help="YAML map of Sigma field -> column")
    convert.add_argument("--json-column", help="read fields from this JSON column")
    convert.add_argument("--keyword-column", help="column searched by keyword rules")

    test = sub.add_parser("test", help="run a rule against JSON Lines events")
    test.add_argument("rule", type=Path)
    test.add_argument("events", type=Path, help="one JSON object per line")
    test.add_argument("-m", "--mapping", type=Path, help="YAML map of Sigma field -> event key")
    test.add_argument(
        "--expect", choices=("match", "none"), help="exit 1 unless the rule matches / matches none"
    )

    hunt_p = sub.add_parser("hunt", help="run rules over JSON, Parquet or CSV logs with DuckDB")
    hunt_p.add_argument("rules", nargs="+", type=Path, help="rule files or directories")
    hunt_p.add_argument(
        "-l", "--logs", nargs="+", required=True, help="log files; globs such as 'logs/*.json'"
    )
    hunt_p.add_argument("-m", "--mapping", type=Path, help="YAML map of Sigma field -> event key")
    hunt_p.add_argument("-e", "--examples", type=int, default=0, help="matching events to show")
    hunt_p.add_argument("--format", choices=("table", "json"), default="table")
    hunt_p.add_argument(
        "--fail-on", choices=LEVELS, help="exit 1 if a rule at this level or above matches"
    )

    args = parser.parse_args(argv)
    # Rules contain non-ASCII (e.g. windash variants); don't depend on the console code page.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    try:
        mapping = _load_mapping(args.mapping)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        print(f"sigma2sql: mapping: {exc}", file=sys.stderr)
        return 2
    if args.command == "convert":
        target = Target(
            dialect=args.dialect,
            table=args.table,
            mapping=mapping,
            json_column=args.json_column,
            keyword_column=args.keyword_column,
        )
        return _convert(args.paths, target)
    if args.command == "hunt":
        return _hunt(args, mapping)
    return _test(args.rule, args.events, mapping, args.expect)


def _convert(paths: list[Path], target: Target) -> int:
    files = list(_rule_files(paths))
    if not files:
        print("sigma2sql: no .yml or .yaml files found", file=sys.stderr)
        return 2
    failed = 0
    for path in files:
        try:
            rule = load_rule_file(path)
            query = to_query(rule, target)
        except (RuleError, UnsupportedRule, OSError) as exc:
            failed += 1
            print(f"skip {path}: {exc}", file=sys.stderr)
            continue
        print(f"-- {rule.title}" + (f" ({rule.id})" if rule.id else ""))
        print(query + ";\n")
    if len(files) > 1:
        print(f"converted {len(files) - failed}/{len(files)} rules", file=sys.stderr)
    return 1 if failed else 0


def _test(rule_path: Path, events_path: Path, mapping: dict[str, str], expect: str | None) -> int:
    try:
        rule = load_rule_file(rule_path)
        events = read_jsonl(events_path.read_text(encoding="utf-8"))
        hits = matching_events(rule, events, mapping)
    except (RuleError, UnsupportedRule, OSError, ValueError) as exc:
        print(f"sigma2sql: {exc}", file=sys.stderr)
        return 2
    lines = [line for line in events_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    for i in hits:
        print(lines[i])
    print(f"{rule.title}: {len(hits)} of {len(events)} events matched", file=sys.stderr)
    if expect == "match" and not hits:
        return 1
    if expect == "none" and hits:
        return 1
    return 0


def _hunt(args: argparse.Namespace, mapping: dict[str, str]) -> int:
    rules: list[Rule] = []
    broken = 0
    for path in _rule_files(args.rules):
        try:
            rules.append(load_rule_file(path))
        except (RuleError, UnsupportedRule, OSError) as exc:
            broken += 1
            print(f"skip {path}: {exc}", file=sys.stderr)
    try:
        report = hunt(rules, args.logs, mapping, args.examples)
    except Exception as exc:  # DuckDB raises its own error types for unreadable files
        print(f"sigma2sql: {exc}", file=sys.stderr)
        return 2
    for rule, reason in report.skipped:
        print(f"skip {rule.path or rule.title}: {reason}", file=sys.stderr)

    if args.format == "json":
        print(json.dumps([_hit_json(h) for h in report.hits], indent=2))
    else:
        _print_table(report)
    print(
        f"{len(report.hits)} of {report.ran} rules matched {report.events} events"
        f" ({len(report.skipped) + broken} rules skipped)",
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
        "count": h.count,
        "examples": [json.loads(e) for e in h.examples],
    }


def _rule_files(paths: list[Path]) -> Iterator[Path]:
    for path in paths:
        if path.is_dir():
            yield from sorted(p for p in path.rglob("*") if p.suffix in (".yml", ".yaml"))
        else:
            yield path


def _load_mapping(path: Path | None) -> dict[str, str]:
    if path is None:
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in data.items()
    ):
        raise ValueError("expected a map of field name to column name")
    return dict(data)
