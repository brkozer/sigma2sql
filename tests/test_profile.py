from __future__ import annotations

import json
import os
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from sigma2sql import Target, load_rule, to_query
from sigma2sql.cli import main
from sigma2sql.profile import apply_profile, builtin_profiles, load_profile
from sigma2sql.runner import matching_events

PROC = "logsource: {product: windows, category: process_creation}\n"
NET = "logsource: {product: windows, category: network_connection}\n"


def rule(logsource: str, detection: str) -> Any:
    body = "\n".join("  " + line for line in detection.splitlines())
    return load_rule(f"title: t\n{logsource}detection:\n{body}\n")


def sqlite(r: Any, events: list[dict[str, Any]], tgt: Target) -> list[int]:
    return matching_events(r, events, tgt)


def duckdb(r: Any, events: list[dict[str, Any]], tgt: Target) -> list[int]:
    pytest.importorskip("duckdb")
    from sigma2sql.hunt import connect

    con = connect()
    con.execute("CREATE TABLE ev (n INTEGER, data JSON)")
    con.executemany(
        "INSERT INTO ev VALUES (?, ?)", [(i, json.dumps(e)) for i, e in enumerate(events)]
    )
    tgt = replace(tgt, dialect="duckdb", table="ev", json_column="data")
    tgt = replace(tgt, routes=tuple(replace(x, table=None) for x in tgt.routes))
    return [row[0] for row in con.execute(to_query(r, tgt, "n") + " ORDER BY n").fetchall()]


def postgres(r: Any, events: list[dict[str, Any]], tgt: Target) -> list[int]:
    dsn = os.environ.get("SIGMA2SQL_PG_DSN")
    if not dsn:
        pytest.skip("SIGMA2SQL_PG_DSN not set")
    import psycopg

    tgt = replace(tgt, dialect="postgres", table="ev", json_column="data")
    tgt = replace(tgt, routes=tuple(replace(x, table=None) for x in tgt.routes))
    with psycopg.connect(dsn, autocommit=True) as con, con.cursor() as cur:
        cur.execute("CREATE TEMP TABLE ev (n int, data jsonb)")
        for i, e in enumerate(events):
            cur.execute("INSERT INTO ev VALUES (%s, %s)", (i, json.dumps(e)))
        cur.execute(to_query(r, tgt, "n").replace("%", "%%") + " ORDER BY n")
        return [row[0] for row in cur.fetchall()]


ENGINES = [sqlite, duckdb, postgres]
Engine = Callable[[Any, list[dict[str, Any]], Target], list[int]]


@pytest.mark.parametrize("engine", ENGINES, ids=lambda f: f.__name__)
def test_nested_mapping(engine: Engine) -> None:
    tgt = Target(mapping={"Image": "process.executable"}, nested=True)
    events = [
        {"process": {"executable": "C:\\Windows\\cmd.exe"}},
        {"process": {"executable": "C:\\Windows\\notepad.exe"}},
        {"process.executable": "C:\\Windows\\cmd.exe"},
    ]
    assert engine(rule(PROC, "s: {Image|endswith: '\\cmd.exe'}\ncondition: s"), events, tgt) == [0]


@pytest.mark.parametrize("engine", ENGINES, ids=lambda f: f.__name__)
def test_ecs_profile(engine: Engine) -> None:
    tgt = apply_profile(Target(), load_profile("ecs-winlogbeat"))
    sysmon = {"channel": "Microsoft-Windows-Sysmon/Operational"}
    events = [
        {
            "event": {"code": "1"},
            "winlog": {**sysmon, "event_data": {"IntegrityLevel": "High"}},
            "process": {"executable": "C:\\Windows\\System32\\cmd.exe"},
        },
        {
            "event": {"code": "3"},
            "winlog": {**sysmon, "event_data": {"IntegrityLevel": "High"}},
            "process": {"executable": "C:\\Windows\\System32\\cmd.exe"},
        },
        {
            "event": {"code": "1"},
            "winlog": {**sysmon, "event_data": {"IntegrityLevel": "Medium"}},
            "process": {"executable": "C:\\Windows\\System32\\cmd.exe"},
        },
    ]
    detection = "s:\n  Image|endswith: '\\cmd.exe'\n  IntegrityLevel: High\ncondition: s"
    assert engine(rule(PROC, detection), events, tgt) == [0]


@pytest.mark.parametrize("engine", ENGINES, ids=lambda f: f.__name__)
def test_sysmon_profile_limits_categories(engine: Engine) -> None:
    tgt = apply_profile(Target(), load_profile("sysmon"))
    events = [
        {"EventID": 1, "Image": "C:\\Windows\\notepad.exe"},
        {"EventID": 3, "Image": "C:\\Windows\\notepad.exe", "DestinationPort": 443},
    ]
    r = rule(NET, "s: {Image|endswith: '\\notepad.exe'}\ncondition: s")
    assert engine(r, events, tgt) == [1]
    # Without the profile the process-creation event matches the network rule too.
    assert engine(r, events, Target()) == [0, 1]


def test_routes_choose_tables(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    profile = tmp_path / "p.yml"
    profile.write_text(
        "fields: {Image: exe}\n"
        "logsources:\n"
        "  - match: {category: process_creation}\n"
        "    table: telemetry.proc\n"
        "    where: {kind: start}\n"
    )
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "proc.yml").write_text(
        f"title: proc\n{PROC}detection:\n  s: {{Image: x}}\n  condition: s\n"
    )
    (rules / "net.yml").write_text(
        f"title: net\n{NET}detection:\n  s: {{Image: x}}\n  condition: s\n"
    )
    assert main(["convert", str(rules), "-p", str(profile), "-d", "postgres"]) == 0
    out = capsys.readouterr().out
    assert (
        'FROM "telemetry"."proc" WHERE (LOWER("kind") = \'start\' AND LOWER("exe") = \'x\')' in out
    )
    assert 'FROM "events" WHERE LOWER("exe") = \'x\'' in out


def test_cli_overrides_profile(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    mapping = tmp_path / "m.yml"
    mapping.write_text("Image: my_image\n")
    rule_file = tmp_path / "r.yml"
    rule_file.write_text(f"title: r\n{PROC}detection:\n  s: {{Image: x}}\n  condition: s\n")
    args = ["convert", str(rule_file), "-p", "ocsf", "-m", str(mapping), "--json-column", "j"]
    assert main(args) == 0
    out = capsys.readouterr().out
    assert 'json_extract("j", \'$."my_image"\')' in out
    assert 'json_extract("j", \'$."class_uid"\')' in out


def test_profiles_command(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["profiles"]) == 0
    names = [line.split()[0] for line in capsys.readouterr().out.splitlines()]
    assert names == ["ecs-winlogbeat", "evtx", "ocsf", "sysmon"]
    assert set(builtin_profiles()) == set(names)


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("colour: red\n", "unknown profile keys"),
        ("default_field: winlog\n", "{field}"),
        ("logsources: [{table: x}]\n", "match"),
        ("timestamp_format: weekly\n", "timestamp_format"),
    ],
)
def test_bad_profiles(tmp_path: Path, text: str, message: str) -> None:
    path = tmp_path / "bad.yml"
    path.write_text(text)
    with pytest.raises(ValueError, match=message):
        apply_profile(Target(), load_profile(str(path)))


def test_unknown_profile_name() -> None:
    with pytest.raises(ValueError, match="built in: ecs-winlogbeat, evtx, ocsf, sysmon"):
        load_profile("splunk")


@pytest.mark.parametrize("engine", ENGINES, ids=lambda f: f.__name__)
def test_evtx_profile_candidates(engine: Engine) -> None:
    """EventID may be a number or {"#text": n}; Defender spells NewValue as "New Value"."""
    tgt = apply_profile(Target(), load_profile("evtx"))
    events = [
        {"Event": {"System": {"EventID": 5007}, "EventData": {"New Value": "HKLM\Exclusions\x"}}},
        {
            "Event": {
                "System": {"EventID": {"#attributes": {"Qualifiers": 0}, "#text": 5007}},
                "EventData": {"NewValue": "HKLM\Exclusions\y"},
            }
        },
        {"Event": {"System": {"EventID": 5007}, "EventData": {"OldValue": "HKLM\Exclusions\z"}}},
    ]
    detection = "s:\n  EventID: 5007\n  NewValue|contains: '\Exclusions\'\ncondition: s"
    assert engine(rule("", detection), events, tgt) == [0, 1]
