import math

import pytest
from pydantic import ConfigDict

from agent_pipeline.artifacts import ArtifactStore
from agent_pipeline.contracts import Record
from agent_pipeline.data import canonical_json, load_record, parse_json, put_record


class Example(Record):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)
    name: str
    values: tuple[int, ...] = ()


def test_canonical_order_and_unicode():
    assert canonical_json({"z": 1, "a": "한글"}) == \
        canonical_json({"a": "한글", "z": 1})
    assert canonical_json({"a": "한글"}) == '{"a":"한글"}'.encode()


def test_roundtrip_is_immutable_and_stable(tmp_path):
    store = ArtifactStore(tmp_path)
    original = Example(name="input", values=(1, 2))
    ref = put_record(store, original)
    assert put_record(store, original) == ref
    assert load_record(store, ref, Example) == original
    with pytest.raises(ValueError):
        original.name = "changed"


@pytest.mark.parametrize("data", [
    b'{"name":"a","name":"b","values":[]}',
    b'{"outer":{"key":1,"key":2}}',
    b'NaN', b'Infinity', b'-Infinity', b'1e999', b'-1e999', b'\xff',
])
def test_ambiguous_or_non_json_input_refused(data):
    with pytest.raises(ValueError):
        parse_json(data)


@pytest.mark.parametrize("data", [
    b'{"values":[],"name":"input"}',
    b'{ "name":"input", "values":[] }',
    b'{"name":"input"}',
    b'{"name":"input","values":[true]}',
    b'{"name":"input","values":["1"]}',
    b'{"name":"input","values":[],"unknown":1}',
])
def test_load_requires_canonical_schema_representation(tmp_path, data):
    store = ArtifactStore(tmp_path)
    ref = store.put(data)
    with pytest.raises(ValueError):
        load_record(store, ref, Example)


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf])
def test_cannot_store_non_json_number(value):
    with pytest.raises(ValueError):
        canonical_json({"value": value})
