"""Pins for host files too large or too private for the CAS.

A KASAN vmlinux, a qcow2 guest image and the syzkaller binaries are host
files.  The execution harness descriptor names each one by the digest of a
small canonical ``HostFilePin`` record holding the file's own SHA-256 and
size.  The collector and the target-PC tool refuse a file whose bytes do
not match its pin, so a descriptor approval still binds the exact files.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from ...contracts import Sha256
from ...data import canonical_json


class PinError(RuntimeError):
    """A host file is missing or differs from its pin."""


class HostFilePin(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["host-file-pin.v1"] = "host-file-pin.v1"
    name: str = Field(min_length=1, max_length=128)
    sha256: Sha256
    size: int = Field(ge=0)


class InstrumentationManifest(BaseModel):
    """The remote KCOV instrumentation a kernel was built with: the kernel
    patch series in order and the kernel .config."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["kcov-instrumentation.v1"] = \
        "kcov-instrumentation.v1"
    kernel_patches: tuple[HostFilePin, ...] = Field(min_length=1)
    kernel_config: HostFilePin


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def pin_file(name: str, path: Path) -> HostFilePin:
    path = Path(path)
    if not path.is_file():
        raise PinError(f"{name}: not a regular file: {path}")
    return HostFilePin(name=name, sha256=file_sha256(path),
                       size=path.stat().st_size)


def pin_ref(pin: BaseModel) -> str:
    return hashlib.sha256(canonical_json(pin)).hexdigest()


class PinCache:
    """Remembers file digests by (device, inode, size, mtime) so a multi-GB
    guest image is not hashed on every lease.  A changed file misses."""

    def __init__(self, path: Path | None) -> None:
        self.path = None if path is None else Path(path)
        self.entries: dict[str, str] = {}
        if self.path is not None and self.path.is_file():
            try:
                self.entries = dict(json.loads(self.path.read_text()))
            except (ValueError, TypeError):
                self.entries = {}

    @staticmethod
    def _key(path: Path) -> str:
        st = os.stat(path)
        return f"{Path(path).resolve()}|{st.st_dev}|{st.st_ino}|" \
               f"{st.st_size}|{st.st_mtime_ns}"

    def sha256(self, path: Path) -> str:
        key = self._key(path)
        if key not in self.entries:
            self.entries[key] = file_sha256(path)
            if self.path is not None:
                tmp = self.path.with_suffix(".tmp")
                tmp.write_text(json.dumps(self.entries, sort_keys=True))
                os.replace(tmp, self.path)
        return self.entries[key]


def verify_file(pin: HostFilePin, path: Path,
                cache: PinCache | None = None) -> None:
    path = Path(path)
    if not path.is_file():
        raise PinError(f"{pin.name}: missing file {path}")
    size = path.stat().st_size
    digest = (cache or PinCache(None)).sha256(path)
    if size != pin.size or digest != pin.sha256:
        raise PinError(f"{pin.name}: {path} does not match its pin "
                       f"(sha256 {digest}, pinned {pin.sha256})")
