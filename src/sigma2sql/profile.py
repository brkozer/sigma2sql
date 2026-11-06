"""Profiles: reusable field mappings, logsource routing and timestamp settings.

A profile is a YAML file:

    description: one line shown by `sigma2sql profiles`
    json_column: data            # optional
    nested: true                 # dotted names are paths into nested JSON
    timestamp: "@timestamp"
    timestamp_format: iso        # iso, epoch_s or epoch_ms
    default_field: "winlog.event_data.{field}"
    fields:
      Image: process.executable
      EventID: [Event.System.EventID.#text, Event.System.EventID]   # first present wins
    logsources:
      - match: {product: windows, category: process_creation}
        table: process_events    # optional
        where: {event.code: "1"} # optional, in target field names

Built-in profiles ship in `sigma2sql/profiles/`; pass a name or a path.
"""

from __future__ import annotations

from dataclasses import replace
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from sigma2sql.sql import Route, Target

KEYS = {
    "description",
    "json_column",
    "nested",
    "timestamp",
    "timestamp_format",
    "default_field",
    "fields",
    "logsources",
}


def builtin_profiles() -> dict[str, str]:
    """Name -> description of the profiles that ship with sigma2sql."""
    out: dict[str, str] = {}
    for entry in sorted(resources.files("sigma2sql.profiles").iterdir(), key=lambda e: e.name):
        if entry.name.endswith(".yml"):
            data = yaml.safe_load(entry.read_text(encoding="utf-8")) or {}
            out[entry.name.removesuffix(".yml")] = str(data.get("description", ""))
    return out


def load_profile(name_or_path: str) -> dict[str, Any]:
    path = Path(name_or_path)
    if path.suffix in (".yml", ".yaml") or path.exists():
        text = path.read_text(encoding="utf-8")
    else:
        entry = resources.files("sigma2sql.profiles").joinpath(f"{name_or_path}.yml")
        if not entry.is_file():
            known = ", ".join(builtin_profiles())
            raise ValueError(f"unknown profile {name_or_path!r} (built in: {known})")
        text = entry.read_text(encoding="utf-8")
    data = yaml.safe_load(text) or {}
    if not isinstance(data, dict):
        raise ValueError("a profile must be a YAML map")
    unknown = set(data) - KEYS
    if unknown:
        raise ValueError(f"unknown profile keys: {', '.join(sorted(unknown))}")
    return data


def apply_profile(target: Target, profile: dict[str, Any]) -> Target:
    """Target with the profile's settings; fields already in `target.mapping` win."""
    fields = profile.get("fields") or {}
    if not isinstance(fields, dict):
        raise ValueError("profile 'fields' must be a map")
    routes: list[Route] = []
    for item in profile.get("logsources") or []:
        if not isinstance(item, dict) or not isinstance(item.get("match"), dict):
            raise ValueError("each profile logsource needs a 'match' map")
        where = item.get("where")
        if where is not None and not isinstance(where, dict):
            raise ValueError("profile logsource 'where' must be a map")
        routes.append(
            Route(
                match={str(k): str(v) for k, v in item["match"].items()},
                table=item.get("table"),
                where=where,
            )
        )
    template = profile.get("default_field")
    templates = None
    if template is not None:
        templates = tuple(template) if isinstance(template, list) else (str(template),)
        if not all("{field" in t for t in templates):
            raise ValueError("profile 'default_field' must contain {field} or {field_words}")
    fmt = profile.get("timestamp_format", target.timestamp_format)
    if fmt not in ("iso", "epoch_s", "epoch_ms"):
        raise ValueError(f"invalid timestamp_format {fmt!r}")
    return replace(
        target,
        mapping={**{str(k): _target_field(v) for k, v in fields.items()}, **target.mapping},
        json_column=profile.get("json_column", target.json_column),
        nested=bool(profile.get("nested", target.nested)),
        timestamp=str(profile.get("timestamp", target.timestamp)),
        timestamp_format=fmt,
        default_field=templates if templates is not None else target.default_field,
        routes=(*target.routes, *routes),
    )


def load_placeholders(path: Path) -> dict[str, tuple[Any, ...]]:
    """A YAML map of placeholder name to one value or a list of values."""
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError("expected a map of placeholder name to values")
    out: dict[str, tuple[Any, ...]] = {}
    for name, value in data.items():
        values = value if isinstance(value, list) else [value]
        if not values or not all(isinstance(v, str | int | float) for v in values):
            raise ValueError(f"placeholder {name!r} needs a string, a number or a list of them")
        out[str(name)] = tuple(values)
    return out


def _target_field(value: Any) -> str | tuple[str, ...]:
    if isinstance(value, list):
        if not value or not all(isinstance(v, str) for v in value):
            raise ValueError("a profile field list must hold field names")
        return tuple(value)
    return str(value)
