"""A small ClickHouse HTTP client for the tests. Set SIGMA2SQL_CH_URL to enable them."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

import pytest

URL = os.environ.get("SIGMA2SQL_CH_URL")


def execute(query: str, data: str = "") -> str:
    assert URL
    params = urllib.parse.urlencode({"output_format_json_quote_64bit_integers": 0})
    body = (query + "\n" + data).encode()
    request = urllib.request.Request(f"{URL}?{params}", data=body)
    try:
        with urllib.request.urlopen(request) as response:
            return str(response.read().decode())
    except urllib.error.HTTPError as exc:
        raise AssertionError(f"{exc.read().decode()}\n{query}") from exc


def load(events: list[dict[str, Any]]) -> None:
    """Fill the `events` table: a row number `n` and the event as JSON text in `data`."""
    execute("DROP TABLE IF EXISTS events")
    execute("CREATE TABLE events (n Int32, data String) ENGINE = Memory")
    rows = [json.dumps({"n": i, "data": json.dumps(e)}) for i, e in enumerate(events)]
    if rows:
        execute("INSERT INTO events FORMAT JSONEachRow", "\n".join(rows))


def clickhouse_rows(query: str, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not URL:
        pytest.skip("SIGMA2SQL_CH_URL not set")
    load(events)
    out = execute(query + " FORMAT JSONEachRow")
    return [json.loads(line) for line in out.splitlines()]
