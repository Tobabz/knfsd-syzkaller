"""Canonical JSON for versioned, content-addressed Stage 1 data.

This is a repository serialization contract, not a signature or a claim
that a guest-supplied document is authoritative.
"""

from __future__ import annotations

import json
import math
from typing import TypeVar

from pydantic import BaseModel

from .artifacts import ArtifactStore

Model = TypeVar("Model", bound=BaseModel)


def canonical_json(value: object) -> bytes:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _invalid_constant(value: str) -> None:
    raise ValueError(f"non-JSON constant: {value}")


def _finite_float(value: str) -> float:
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("JSON number is out of range")
    return result


def parse_json(data: bytes) -> object:
    return json.loads(data.decode("utf-8"), object_pairs_hook=_unique_object,
                      parse_constant=_invalid_constant,
                      parse_float=_finite_float)


def put_record(store: ArtifactStore, value: BaseModel) -> str:
    return store.put(canonical_json(value))


def load_record(store: ArtifactStore, ref: str, model: type[Model]) -> Model:
    data = store.get(ref)
    parse_json(data)  # reject duplicate keys and non-finite JSON numbers first
    value = model.model_validate_json(data)
    if canonical_json(value) != data:
        raise ValueError("record is not in its canonical serialized form")
    return value
