"""utils.py — Shared utilities."""
import json
import yaml
from datetime import datetime, timezone
from pathlib import Path


def timestamp_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def severity_label(score: int) -> str:
    if score >= 15:
        return "CRITICAL"
    if score >= 10:
        return "HIGH"
    if score >= 5:
        return "MEDIUM"
    return "LOW"


def load_json(path: str) -> dict | list:
    with open(path) as f:
        return json.load(f)


def load_config(path: str) -> dict:
    p = Path(path)
    with open(p) as f:
        if p.suffix in (".yaml", ".yml"):
            return yaml.safe_load(f)
        return json.load(f)
