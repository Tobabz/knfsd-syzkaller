"""Resolve paths recorded in report/attr-env-baseline.json.

The baseline stores repository-relative paths so that a checkout can live at
any location. ``env/...`` entries follow ``KOOV_ENV_DIR`` (default: the
repository's own ``env/``), every other relative path is taken from the
repository root, and absolute paths are returned unchanged.
"""
from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENV_DIR = Path(os.environ.get("KOOV_ENV_DIR", str(ROOT / "env")))


def resolve_env_path(value: str) -> str:
    path = Path(value)
    if path.is_absolute():
        return value
    if path.parts[:1] == ("env",):
        return str(ENV_DIR.joinpath(*path.parts[1:]))
    return str(ROOT / path)
