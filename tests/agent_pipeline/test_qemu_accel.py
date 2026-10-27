"""QEMU accelerator choice: KVM when the host has it, TCG otherwise."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_pipeline import qemu_accel
from agent_pipeline.qemu_accel import (AccelError, accel_of, check_kvm,
                                       from_env, qemu_args, resolve, slowdown)


def test_auto_prefers_kvm_and_falls_back_to_tcg():
    assert resolve("auto", probe=lambda _: True) == "kvm"
    assert resolve("auto", probe=lambda _: False) == "tcg"
    assert resolve("tcg", probe=lambda _: True) == "tcg"
    assert resolve("kvm", probe=lambda _: False) == "kvm"
    with pytest.raises(AccelError, match="unknown"):
        resolve("hvf")


def test_environment_overrides_auto(monkeypatch):
    monkeypatch.setenv(qemu_accel.ENV_OVERRIDE, "tcg")
    assert from_env(probe=lambda _: True) == "tcg"
    monkeypatch.delenv(qemu_accel.ENV_OVERRIDE)
    assert from_env(probe=lambda _: True) == "kvm"


def test_arguments_and_slowdown_round_trip():
    for accel in ("kvm", "tcg"):
        assert accel_of(qemu_args(accel)) == accel
        assert accel_of(" ".join(qemu_args(accel))) == accel
    # syz-manager raises its own slowdown only on this spelling.
    assert "-accel tcg" in " ".join(qemu_args("tcg"))
    assert slowdown("kvm") == 1
    assert slowdown("tcg") == qemu_accel.TCG_SLOWDOWN
    assert accel_of("-m 4096 -smp 4") is None


def test_missing_kvm_device_is_reported(tmp_path):
    with pytest.raises(AccelError, match="unavailable"):
        check_kvm(tmp_path / "kvm")
    assert not qemu_accel.kvm_usable(tmp_path / "kvm")
    with pytest.raises(AccelError, match="character device"):
        check_kvm(Path(__file__))
