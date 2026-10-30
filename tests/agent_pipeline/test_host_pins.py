"""A host file that no longer matches its pin fails closed and says how to
pin it again (#136)."""

import pytest

from agent_pipeline.stage1.host.pins import (PinError, pin_file,
                                             verify_file)


def test_a_rebuilt_file_fails_with_the_way_to_pin_it_again(tmp_path):
    path = tmp_path / "vmlinux"
    path.write_bytes(b"built")
    pin = pin_file("kernel", path)
    verify_file(pin, path)
    path.write_bytes(b"rebuilt")
    with pytest.raises(PinError, match="does not match its pin") as raised:
        verify_file(pin, path)
    assert "generate SPEC" in str(raised.value)
    assert "check-pins" in str(raised.value)
    path.unlink()
    with pytest.raises(PinError, match="missing file"):
        verify_file(pin, path)
