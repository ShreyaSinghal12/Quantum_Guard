"""Configuration loading shared by every QuantumGuard module."""
from __future__ import annotations

import copy
import json
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_ROOT.parent
DEFAULT_CONFIG_DIR = PROJECT_ROOT / "config"


class QGError(Exception):
    """User-facing error with a readable message."""


def load_json(name: str, config_dir: str | Path | None = None) -> dict:
    directory = Path(config_dir) if config_dir else DEFAULT_CONFIG_DIR
    path = directory / name
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise QGError(f"Config file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise QGError(f"Invalid JSON in {path}: {exc}") from exc


def deep_merge(base: dict, override: dict | None) -> dict:
    """Return a copy of base with override values merged in (dicts merge recursively)."""
    result = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result
