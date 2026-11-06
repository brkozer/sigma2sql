"""Run SigmaHQ's regression samples through sigma2sql.

    uv run python scripts/check_regression.py path/to/sigma [--clickhouse URL] [--verbose]

SigmaHQ keeps real event samples for many rules under `regression_data/` (EVTX files with a
JSON export next to them) and the number of matches each rule must produce. This loads the
JSON samples with the built-in `evtx` profile, runs each rule on SQLite and DuckDB (and
ClickHouse, given its address) and checks the match count. Exits 1 if any rule finds fewer
matches than SigmaHQ expects or the databases disagree.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from dataclasses import replace
from pathlib import Path
from typing import Any

import yaml

from sigma2sql import Rule, RuleError, Target, UnsupportedRule, load_file, to_query
from sigma2sql.hunt import connect as duckdb_connect
from sigma2sql.profile import apply_profile, load_profile
from sigma2sql.runner import matching_events

RULE_DIRS = ("rules", "rules-emerging-threats", "rules-threat-hunting", "rules-dfir")


def read_events(path: Path) -> list[dict[str, Any]]:
    """Samples hold one or more (pretty-printed, concatenated) JSON objects."""
    text = path.read_text(encoding="utf-8")
    decoder = json.JSONDecoder()
    events: list[dict[str, Any]] = []
    i = 0
    while True:
        while i < len(text) and text[i].isspace():
            i += 1
        if i >= len(text):
            return events
        event, i = decoder.raw_decode(text, i)
        events.append(event)


def duckdb_matches(rule: Rule, events: list[dict[str, Any]], target: Target) -> int:
    con = duckdb_connect()
    con.executemany("INSERT INTO events VALUES (?)", [(json.dumps(e),) for e in events])
    tgt = replace(target, dialect="duckdb", table="events", json_column="data")
    tgt = replace(tgt, routes=tuple(replace(r, table=None) for r in tgt.routes))
    count: int = con.execute(f"SELECT COUNT(*) FROM ({to_query(rule, tgt)}) q").fetchone()[0]
    return count


def clickhouse_matches(url: str, rule: Rule, events: list[dict[str, Any]], target: Target) -> int:
    def run(query: str) -> str:
        request = urllib.request.Request(f"{url}?max_query_size=4194304", data=query.encode())
        try:
            with urllib.request.urlopen(request) as response:
                return str(response.read().decode())
        except urllib.error.HTTPError as exc:
            raise RuntimeError(exc.read().decode()) from exc

    run("DROP TABLE IF EXISTS events")
    run("CREATE TABLE events (data String) ENGINE = Memory")
    rows = "\n".join(json.dumps({"data": json.dumps(e)}) for e in events)
    run(f"INSERT INTO events FORMAT JSONEachRow\n{rows}")
    tgt = replace(target, dialect="clickhouse", table="events", json_column="data")
    tgt = replace(tgt, routes=tuple(replace(r, table=None) for r in tgt.routes))
    return int(run(f"SELECT COUNT(*) FROM ({to_query(rule, tgt)}) q"))


def main(root: Path, verbose: bool, clickhouse: str | None = None) -> int:
    rules: dict[str, Rule] = {}
    for name in RULE_DIRS:
        for path in sorted((root / name).rglob("*.yml")):
            try:
                docs = load_file(path)
            except (RuleError, UnsupportedRule):
                continue
            for doc in docs:
                if isinstance(doc, Rule) and doc.id:
                    rules[doc.id] = doc

    target = apply_profile(Target(), load_profile("evtx"))
    tested = 0
    passed = {"sqlite": 0, "duckdb": 0}
    if clickhouse:
        passed["clickhouse"] = 0
    failures: list[str] = []
    for info_path in sorted((root / "regression_data").rglob("info.yml")):
        info = yaml.safe_load(info_path.read_text(encoding="utf-8")) or {}
        rule_id = str((info.get("rule_metadata") or [{}])[0].get("id"))
        for test in info.get("regression_tests_info") or []:
            sample = root / Path(str(test["path"])).with_suffix(".json")
            rule = rules.get(rule_id)
            if rule is None or not sample.exists():
                continue
            tested += 1
            events = read_events(sample)
            expected = int(test.get("match_count", 1))
            results = {
                "sqlite": len(matching_events(rule, events, target)),
                "duckdb": duckdb_matches(rule, events, target),
            }
            if clickhouse:
                results["clickhouse"] = clickhouse_matches(clickhouse, rule, events, target)
            if len(set(results.values())) > 1:
                failures.append(f"databases disagree on {rule.title}: {results}")
            for engine, found in results.items():
                if found >= expected:
                    passed[engine] += 1
                else:
                    failures.append(
                        f"{engine}: {rule.title} ({rule.path}): {found} of {expected} matches"
                    )
            if verbose:
                print(f"{rule.title}: {results} expected {expected}")

    for engine, count in passed.items():
        print(f"{engine}: {count}/{tested} regression samples matched as expected")
    for failure in failures:
        print(failure, file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sigma", type=Path, help="SigmaHQ repository checkout")
    parser.add_argument("--clickhouse", help="ClickHouse HTTP URL")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()
    sys.exit(main(args.sigma, args.verbose, args.clickhouse))
