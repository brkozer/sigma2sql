"""Convert every rule in a SigmaHQ checkout and execute the SQL on each database.

    uv run python scripts/check_sigmahq.py path/to/sigma/rules [--dsn DSN]
        [--clickhouse URL] [--profile NAME] [--placeholders FILE] [--samples SIGMA_REPO]

Prints how many rules convert per dialect and fails if any generated query is rejected
by the database. PostgreSQL and ClickHouse are skipped unless their address is given.

With --samples the tables hold SigmaHQ's regression events, so every query really runs over
rows. An empty table hides errors that only appear at run time: a cast of a bad value, or a
rule too large for the database's memory.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

from check_regression import read_events

from sigma2sql import RuleError, Target, UnsupportedRule, load_rule_file, to_query
from sigma2sql.hunt import connect as duckdb_connect
from sigma2sql.profile import apply_profile, load_placeholders, load_profile
from sigma2sql.runner import connect as sqlite_connect


class AnyPlaceholder(dict[str, tuple[Any, ...]]):
    """Gives every placeholder a value, to test rules that wait for the user's values."""

    def __contains__(self, key: object) -> bool:
        return True

    def __missing__(self, key: str) -> tuple[Any, ...]:
        return ("example",)


def clickhouse_runner(url: str, events: list[str]) -> Callable[[str], Any]:
    def run(query: str) -> bytes:
        # The largest SigmaHQ rule, a list of driver hashes, exceeds the 256 KiB default.
        request = urllib.request.Request(f"{url}?max_query_size=4194304", data=query.encode())
        try:
            with urllib.request.urlopen(request) as response:
                return bytes(response.read())
        except urllib.error.HTTPError as exc:
            raise RuntimeError(exc.read().decode()) from exc

    run("DROP TABLE IF EXISTS events")
    run("CREATE TABLE events (data String) ENGINE = Memory")
    if events:
        rows = "\n".join(json.dumps({"data": e}) for e in events)
        run(f"INSERT INTO events FORMAT JSONEachRow\n{rows}")
    return run


def main(
    rules_dir: str,
    dsn: str | None,
    clickhouse: str | None,
    profile: str | None,
    placeholders: str | None,
    samples: str | None,
) -> int:
    events: list[str] = []
    if samples:
        for sample in sorted((Path(samples) / "regression_data").rglob("*.json")):
            events += [json.dumps(e) for e in read_events(sample)]
        print(f"{len(events)} sample events loaded")
    base = Target(json_column="data")
    if placeholders == "any":
        base = replace(base, placeholders=AnyPlaceholder())
    elif placeholders:
        base = replace(base, placeholders=load_placeholders(Path(placeholders)))
    if profile:
        base = apply_profile(base, load_profile(profile))
        base = replace(base, routes=tuple(replace(r, table=None) for r in base.routes))
    files = sorted(Path(rules_dir).rglob("*.yml"))
    lite = sqlite_connect()
    lite.execute("CREATE TABLE events (data TEXT)")
    lite.executemany("INSERT INTO events VALUES (?)", [(e,) for e in events])
    duck = duckdb_connect()
    if events:
        duck.executemany("INSERT INTO events VALUES (?)", [(e,) for e in events])
    engines: dict[str, Callable[[str], Any]] = {
        "sqlite": lambda q: lite.execute(q).fetchall(),
        "duckdb": lambda q: duck.execute(q).fetchall(),
    }
    if dsn:
        import psycopg

        pg = psycopg.connect(dsn, autocommit=True)
        pg.execute("CREATE TEMP TABLE events (data jsonb)")
        for event in events:
            pg.execute("INSERT INTO events VALUES (%s)", (event.replace("\\u0000", ""),))
        engines["postgres"] = lambda q: pg.execute(q.replace("%", "%%"))
    if clickhouse:
        engines["clickhouse"] = clickhouse_runner(clickhouse, events)

    converted = dict.fromkeys(engines, 0)
    failures: list[str] = []
    for path in files:
        try:
            rule = load_rule_file(path)
        except (RuleError, UnsupportedRule):
            continue
        for dialect, run in engines.items():
            try:
                query = to_query(rule, replace(base, dialect=dialect))  # type: ignore[arg-type]
            except (RuleError, UnsupportedRule):
                continue
            converted[dialect] += 1
            try:
                run(query)
            except Exception as exc:
                failures.append(f"{dialect} {path.name}: {str(exc).splitlines()[0]}")

    for dialect, count in converted.items():
        print(f"{dialect}: {count}/{len(files)} rules converted ({count / len(files):.1%})")
    for failure in failures:
        print(failure, file=sys.stderr)
    print(f"{len(failures)} queries rejected by the database")
    return 1 if failures else 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rules")
    parser.add_argument("--dsn", help="PostgreSQL connection string")
    parser.add_argument("--clickhouse", help="ClickHouse HTTP URL")
    parser.add_argument("--profile", help="built-in profile name or YAML file")
    parser.add_argument("--placeholders", help="YAML file of values, or `any` for a dummy value")
    parser.add_argument("--samples", help="SigmaHQ checkout: run over its regression events")
    args = parser.parse_args()
    sys.exit(
        main(args.rules, args.dsn, args.clickhouse, args.profile, args.placeholders, args.samples)
    )
