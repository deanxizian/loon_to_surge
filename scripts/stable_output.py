from __future__ import annotations

import json
from pathlib import Path


def json_without_key(data: object, key: str) -> object:
    if isinstance(data, dict):
        return {item_key: item_value for item_key, item_value in data.items() if item_key != key}
    return data


def json_payload_matches(path: Path, candidate: dict[str, object], ignored_key: str) -> bool:
    if not path.exists():
        return False

    try:
        existing = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False

    return json_without_key(existing, ignored_key) == json_without_key(candidate, ignored_key)


def previous_timestamp(path: Path, key: str) -> str | None:
    if not path.exists():
        return None

    try:
        existing = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None

    value = existing.get(key)
    return value if isinstance(value, str) and value else None


def file_contents_match(source: Path, target: Path) -> bool:
    return target.exists() and source.read_bytes() == target.read_bytes()


def tree_contents_match(source: Path, target: Path, excluded_names: set[str]) -> bool:
    if not target.exists():
        return False

    source_files = sorted(path.relative_to(source) for path in source.rglob("*") if path.is_file())
    target_files = sorted(
        path.relative_to(target)
        for path in target.rglob("*")
        if path.is_file() and path.name not in excluded_names
    )
    if source_files != target_files:
        return False

    return all((source / relative).read_bytes() == (target / relative).read_bytes() for relative in source_files)
