"""Convert every rule in a SigmaHQ checkout and execute the SQL on SQLite, DuckDB and PostgreSQL.

    uv run python scripts/check_sigmahq.py path/to/sigma/rules [postgres-dsn]

Prints how many rules convert per dialect and fails if any generated query is rejected
by the database. Without a DSN PostgreSQL is skipped.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from sigma2sql import RuleError, Target, UnsupportedRule, load_rule_file, to_query
from sigma2sql.hunt import connect as duckdb_connect
from sigma2sql.runner import connect as sqlite_connect


def main(rules_dir: str, dsn: str | None) -> int:
    files = sorted(Path(rules_dir).rglob("*.yml"))
    lite = sqlite_connect()
    lite.execute("CREATE TABLE events (data TEXT)")
    duck = duckdb_connect()
    engines: dict[str, Callable[[str], Any]] = {
        "sqlite": lambda q: lite.execute(q).fetchall(),
        "duckdb": lambda q: duck.execute(q).fetchall(),
    }
    if dsn:
        import psycopg

        pg = psycopg.connect(dsn, autocommit=True)
        pg.execute("CREATE TEMP TABLE events (data jsonb)")
        engines["postgres"] = lambda q: pg.execute(q.replace("%", "%%"))

    converted = dict.fromkeys(engines, 0)
    failures: list[str] = []
    for path in files:
        try:
            rule = load_rule_file(path)
        except (RuleError, UnsupportedRule):
            continue
        for dialect, run in engines.items():
            try:
                query = to_query(rule, Target(dialect, json_column="data"))  # type: ignore[arg-type]
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
    if len(sys.argv) not in (2, 3):
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1], sys.argv[2] if len(sys.argv) == 3 else None))
