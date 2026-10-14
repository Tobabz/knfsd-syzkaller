import pytest

from .fakes import World


def _no_unexpected_failures(w):
    # A failure recorded where a test injected none is a bug, not a lost
    # answer.
    n = len(w.store.effect_failures())
    assert n == w.expected_failures, w.store.effect_failures()


@pytest.fixture
def world(tmp_path):
    w = World(tmp_path)
    yield w
    _no_unexpected_failures(w)


@pytest.fixture
def make_world(tmp_path):
    n = 0
    made = []

    def make(**kw):
        nonlocal n
        n += 1
        d = tmp_path / f"w{n}"
        d.mkdir()
        made.append(World(d, **kw))
        return made[-1]
    yield make
    for w in made:
        _no_unexpected_failures(w)
