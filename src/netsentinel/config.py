"""Config loading: YAML file + optional override file + `key.sub=value` CLI overrides."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import yaml


def _deep_merge(base: dict, extra: dict) -> dict:
    out = copy.deepcopy(base)
    for key, value in extra.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def _set_dotted(cfg: dict, dotted: str, raw: str) -> None:
    *parents, leaf = dotted.split(".")
    node = cfg
    for part in parents:
        node = node.setdefault(part, {})
        if not isinstance(node, dict):
            raise ValueError(f"Cannot set {dotted!r}: {part!r} is not a mapping")
    node[leaf] = yaml.safe_load(raw)  # "0.1" -> float, "null" -> None, "[a,b]" -> list


def load_yaml(path: str | Path) -> dict[str, Any]:
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"Config file not found: {path}")
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Top level of {path} must be a mapping")
    return data


def load_config(
    path: str | Path = "configs/default.yaml",
    override: str | Path | None = None,
    sets: list[str] | None = None,
) -> dict[str, Any]:
    cfg = load_yaml(path)
    if override:
        cfg = _deep_merge(cfg, load_yaml(override))
    for item in sets or []:
        key, sep, value = item.partition("=")
        if not sep:
            raise ValueError(f"Override must look like key=value, got {item!r}")
        _set_dotted(cfg, key.strip(), value)
    return cfg
