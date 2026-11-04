"""Compare sigma2sql with pySigma's SQLite backend on real events.

    uv run --with pysigma --with pysigma-backend-sqlite \\
        python scripts/diff_pysigma.py path/to/sigma [--show N]

Every SigmaHQ regression sample (476 real Windows events) is flattened into one SQLite
table. Every rule under `rules/` is then converted by both tools and run on that table,
and the sets of matching events are compared. Each rule sees every event, so this checks
non-matches as well as matches.
"""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
from pathlib import Path
from typing import Any

from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection

from sigma2sql import Rule, RuleError, Target, UnsupportedRule, load_documents, to_query
from sigma2sql.runner import connect

sys.path.insert(0, str(Path(__file__).parent))
from check_regression import read_events  # noqa: E402

MISSING = re.compile(r"no such column: (\S+)")


def flatten(event: dict[str, Any]) -> dict[str, Any]:
    """Event.System basics plus EventData (and UserData) fields as top-level columns."""
    e = event.get("Event", {})
    system = e.get("System", {})
    eid = system.get("EventID")
    row: dict[str, Any] = {
        "EventID": eid.get("#text") if isinstance(eid, dict) else eid,
        "Channel": system.get("Channel"),
        "Computer": system.get("Computer"),
        "Provider_Name": (system.get("Provider") or {}).get("#attributes", {}).get("Name"),
    }
    data = dict(e.get("EventData") or {})
    for value in (e.get("UserData") or {}).values():
        if isinstance(value, dict):
            data.update(value)
    for key, value in data.items():
        if key.startswith("#"):
            continue
        if isinstance(value, dict | list):
            value = json.dumps(value)
        row[key] = value
        row.setdefault(key.replace(" ", ""), value)  # "New Value" is NewValue in rules
    return row


def run(db: sqlite3.Connection, query: str) -> set[int]:
    """Run a query, adding any column it needs (as all-NULL) until it succeeds."""
    for _ in range(50):
        try:
            return {row[0] for row in db.execute(query)}
        except sqlite3.OperationalError as exc:
            m = MISSING.search(str(exc))
            if not m:
                raise
            db.execute(f'ALTER TABLE logs ADD COLUMN "{m[1].strip(chr(34))}"')
    raise RuntimeError(f"too many missing columns: {query[:200]}")


def main(root: Path, show: int) -> int:
    rows = [
        flatten(e)
        for p in sorted((root / "regression_data").rglob("*.json"))
        for e in read_events(p)
    ]
    # SQLite column names ignore case, so ProcessId and processId share one column.
    columns: dict[str, str] = {}
    for r in rows:
        for k in r:
            columns.setdefault(k.lower(), k)
    db = connect()
    db.execute("CREATE TABLE logs (" + ", ".join(f'"{c}"' for c in columns.values()) + ")")
    for r in rows:
        merged: dict[str, Any] = {}
        for k, v in r.items():
            if v is not None:
                merged.setdefault(columns[k.lower()], v)
        names = ", ".join(f'"{k}"' for k in merged)
        marks = ", ".join("?" for _ in merged)
        db.execute(f"INSERT INTO logs ({names}) VALUES ({marks})", list(merged.values()))

    backend = sqliteBackend()
    target = Target("sqlite", "logs")
    stats = {"compared": 0, "agree": 0, "differ": 0, "only_pysigma": 0, "only_sigma2sql": 0}
    stats.update({"neither": 0, "matched_something": 0})
    differences: list[str] = []
    for path in sorted((root / "rules").rglob("*.yml")):
        text = path.read_text(encoding="utf-8")
        try:
            docs = load_documents(text, path)
            ours_q = to_query(docs[0], target, "rowid") if isinstance(docs[0], Rule) else None
        except (RuleError, UnsupportedRule):
            ours_q = None
        try:
            theirs = backend.convert(SigmaCollection.from_yaml(text))
            theirs_q = theirs[0].replace("SELECT * FROM logs", "SELECT rowid FROM logs", 1)
        except Exception:
            theirs_q = None
        if ours_q is None and theirs_q is None:
            stats["neither"] += 1
            continue
        if ours_q is None:
            stats["only_pysigma"] += 1
            continue
        if theirs_q is None:
            stats["only_sigma2sql"] += 1
            continue
        stats["compared"] += 1
        ours, theirs_rows = run(db, ours_q), run(db, theirs_q)
        if ours or theirs_rows:
            stats["matched_something"] += 1
        if ours == theirs_rows:
            stats["agree"] += 1
            continue
        stats["differ"] += 1
        differences.append(
            f"{path.relative_to(root)}: sigma2sql {sorted(ours)} pySigma {sorted(theirs_rows)}"
        )

    print(f"events: {len(rows)}")
    for key, value in stats.items():
        print(f"{key}: {value}")
    for line in differences[:show]:
        print(line)
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sigma", type=Path)
    parser.add_argument("--show", type=int, default=50, help="differences to list")
    args = parser.parse_args()
    sys.exit(main(args.sigma, args.show))
