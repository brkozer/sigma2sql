"""SARIF 2.1.0 reports, which GitHub code scanning and many CI tools can display."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFO_URI = "https://github.com/brkozer/sigma2sql"
# Sigma level -> SARIF level and the score GitHub turns into a severity label.
LEVELS = {
    "critical": ("error", "9.5"),
    "high": ("error", "8.0"),
    "medium": ("warning", "5.5"),
    "low": ("note", "3.0"),
    "informational": ("note", "1.0"),
}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    level: str | None
    message: str
    path: Path | None


def report(findings: list[Finding], version: str) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for finding in findings:
        level, severity = LEVELS.get(finding.level or "", ("warning", "5.5"))
        rule = {
            "id": finding.rule_id,
            "shortDescription": {"text": finding.title},
            "properties": {"security-severity": severity},
        }
        rules.setdefault(finding.rule_id, rule)
        result: dict[str, Any] = {
            "ruleId": finding.rule_id,
            "ruleIndex": list(rules).index(finding.rule_id),
            "level": level,
            "message": {"text": finding.message},
        }
        if finding.path:
            location = {"artifactLocation": {"uri": _uri(finding.path)}}
            result["locations"] = [{"physicalLocation": location}]
        results.append(result)
    driver = {
        "name": "sigma2sql",
        "version": version,
        "informationUri": INFO_URI,
        "rules": list(rules.values()),
    }
    return {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [{"tool": {"driver": driver}, "results": results}],
    }


def _uri(path: Path) -> str:
    """Relative to the working directory where possible, as code scanning expects."""
    if path.is_absolute():
        try:
            return path.relative_to(Path.cwd()).as_posix()
        except ValueError:
            return path.as_uri()
    return path.as_posix()
