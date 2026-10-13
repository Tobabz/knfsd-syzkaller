import pytest

from .fakes import World


@pytest.fixture
def world(tmp_path):
    return World(tmp_path)


@pytest.fixture
def make_world(tmp_path):
    n = 0

    def make(**kw):
        nonlocal n
        n += 1
        d = tmp_path / f"w{n}"
        d.mkdir()
        return World(d, **kw)
    return make
