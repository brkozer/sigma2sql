"""Convert every rule in a SigmaHQ checkout and execute the SQL on SQLite and PostgreSQL.

    uv run python scripts/check_sigmahq.py path/to/sigma/rules [postgres-dsn]

Prints how many rules convert per dialect and fails if any generated query is rejected
by the database. Without a DSN only SQLite is checked.
"""

from __future__ import annotations

import sys
from pathlib import Path

from sigma2sql import RuleError, Target, UnsupportedRule, load_rule_file, to_query
from sigma2sql.runner import connect


def main(rules_dir: str, dsn: str | None) -> int:
    files = sorted(Path(rules_dir).rglob("*.yml"))
    lite = connect()
    lite.execute("CREATE TABLE events (data TEXT)")
    pg = None
    if dsn:
        import psycopg

        pg = psycopg.connect(dsn, autocommit=True)
        pg.execute("CREATE TEMP TABLE events (data jsonb)")

    converted = {"sqlite": 0, "postgres": 0}
    failures: list[str] = []
    for path in files:
        try:
            rule = load_rule_file(path)
            lite_sql = to_query(rule, Target("sqlite", json_column="data"))
        except (RuleError, UnsupportedRule):
            continue
        converted["sqlite"] += 1
        try:
            lite.execute(lite_sql).fetchall()
        except Exception as exc:
            failures.append(f"sqlite {path.name}: {exc}")
        if pg is None:
            continue
        try:
            pg_sql = to_query(rule, Target("postgres", json_column="data"))
        except UnsupportedRule:
            continue
        converted["postgres"] += 1
        try:
            pg.execute(pg_sql.replace("%", "%%"))
        except Exception as exc:
            failures.append(f"postgres {path.name}: {str(exc).splitlines()[0]}")

    for dialect, count in converted.items():
        if dialect == "postgres" and pg is None:
            continue
        print(f"{dialect}: {count}/{len(files)} rules converted ({count / len(files):.1%})")
    for failure in failures:
        print(failure, file=sys.stderr)
    print(f"{len(failures)} queries rejected by the database")
    return 1 if failures else 0


if __name__ == "__main__":
    if len(sys.argv) not in (2, 3):
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1], sys.argv[2] if len(sys.argv) == 3 else None))
