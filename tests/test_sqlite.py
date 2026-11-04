from __future__ import annotations

from typing import Any

import pytest

from cases import CASES, rule_for
from sigma2sql import Target
from sigma2sql.runner import matching_events


@pytest.mark.parametrize(
    ("name", "detection", "events", "expected"), CASES, ids=[c[0] for c in CASES]
)
def test_case(name: str, detection: str, events: list[dict[str, Any]], expected: list[int]) -> None:
    assert matching_events(rule_for(detection), events) == expected


def test_mapping_renames_fields() -> None:
    rule = rule_for("sel: {Image|endswith: '\\cmd.exe'}\ncondition: sel")
    events = [{"process.executable": "C:\\Windows\\cmd.exe"}]
    assert matching_events(rule, events, Target(mapping={"Image": "process.executable"})) == [0]
