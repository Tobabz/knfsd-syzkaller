"""ArtifactStore checks use only isolated temporary files."""

import errno
import hashlib
import os
import socket
import stat
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from agent_pipeline.artifacts import (
    ArtifactIntegrityError, ArtifactLimitError, ArtifactStore, InvalidDigest,
)


@pytest.fixture
def store(tmp_path):
    return ArtifactStore(tmp_path / "artifacts")


def test_put_get_and_idempotent_reuse(store):
    data = b"collected bytes\x00\xff"
    ref = store.put(data)
    assert ref == hashlib.sha256(data).hexdigest()
    inode = store._path(ref).stat().st_ino
    assert store.get(ref) == data
    assert store.put(data) == ref
    assert store._path(ref).stat().st_ino == inode
    assert store.has(ref)
    assert not list(store.root.rglob(".pending-*"))


def test_empty_artifact(store):
    ref = store.put(b"")
    assert store.get(ref, max_bytes=1) == b""


@pytest.mark.parametrize("digest", [
    "", "a" * 63, "a" * 65, "A" * 64, "z" * 64, "a" * 64 + "\n",
    "../outside", "/etc/passwd", "aa/../outside", "aa" + "/" * 62,
    b"a" * 64, None, 123,
])
@pytest.mark.parametrize("operation", ["get", "has", "_path"])
def test_rejects_invalid_digest_before_path_use(store, digest, operation):
    with pytest.raises(InvalidDigest):
        getattr(store, operation)(digest)
    assert list(store.root.iterdir()) == []


def test_missing_artifact_is_not_present(store):
    digest = "a" * 64
    assert not store.has(digest)
    with pytest.raises(FileNotFoundError):
        store.get(digest)


@pytest.mark.parametrize("where", ["object", "shard"])
@pytest.mark.parametrize("code", [
    errno.EIO, errno.EMFILE, errno.ENFILE, errno.EACCES, errno.ENXIO, errno.ENODEV,
])
def test_open_availability_errors_are_preserved(store, monkeypatch, where, code):
    data = b"available again after retry"
    ref = store.put(data)
    target = ref if where == "object" else ref[:2]
    real_open = os.open
    failure = OSError(code, os.strerror(code), target)

    def unavailable(path, flags, mode=0o777, *, dir_fd=None):
        if path == target and dir_fd is not None:
            raise failure
        return real_open(path, flags, mode, dir_fd=dir_fd)

    with monkeypatch.context() as patch:
        patch.setattr(os, "open", unavailable)
        for operation in (lambda: store.get(ref), lambda: store.has(ref),
                          lambda: store.put(data)):
            with pytest.raises(OSError) as caught:
                operation()
            assert caught.value is failure

    assert store.get(ref) == data
    assert store.has(ref)
    assert store.put(data) == ref
    assert not list(store.root.rglob(".pending-*"))


@pytest.mark.parametrize("replacement", [b"corrupt", b"trunc", b""])
def test_corruption_is_never_reused_or_overwritten(store, replacement):
    data = b"original"
    ref = store.put(data)
    path = store._path(ref)
    path.write_bytes(replacement)
    for operation in (lambda: store.get(ref), lambda: store.has(ref),
                      lambda: store.put(data)):
        with pytest.raises(ArtifactIntegrityError):
            operation()
    assert path.read_bytes() == replacement
    assert not list(store.root.rglob(".pending-*"))


def test_store_and_per_read_limits(tmp_path):
    store = ArtifactStore(tmp_path / "artifacts", max_artifact_bytes=4)
    ref = store.put(b"1234")
    assert store.get(ref, max_bytes=4) == b"1234"
    with pytest.raises(ArtifactLimitError):
        store.get(ref, max_bytes=3)
    with pytest.raises(ArtifactLimitError):
        store.put(b"12345")
    # A caller's larger read limit cannot increase the store-wide cap.
    oversized = b"x" * 5
    digest = hashlib.sha256(oversized).hexdigest()
    path = store._path(digest)
    path.parent.mkdir(exist_ok=True)
    path.write_bytes(oversized)
    with pytest.raises(ArtifactLimitError):
        store.get(digest, max_bytes=100)
    with pytest.raises(ArtifactLimitError):
        store.has(digest)


def test_read_limit_still_applies_if_file_grew_since_stat(store, monkeypatch):
    ref = store.put(b"1234")
    real_fstat = os.fstat

    def stale_fstat(fd):
        fields = list(real_fstat(fd))
        fields[6] = 1  # st_size at the instant before a concurrent growth.
        return os.stat_result(fields)

    monkeypatch.setattr(os, "fstat", stale_fstat)
    with pytest.raises(ArtifactLimitError):
        store.get(ref, max_bytes=1)


@pytest.mark.parametrize("limit", [0, -1, True, 1.5, "4"])
def test_invalid_limits_are_not_coerced(tmp_path, limit):
    with pytest.raises(ValueError):
        ArtifactStore(tmp_path / "invalid", max_artifact_bytes=limit)
    store = ArtifactStore(tmp_path / "valid")
    ref = store.put(b"a")
    with pytest.raises(ValueError):
        store.get(ref, max_bytes=limit)


@pytest.mark.parametrize("data", ["text", bytearray(b"mutable"), memoryview(b"view")])
def test_requires_bytes(store, data):
    with pytest.raises(TypeError):
        store.put(data)


@pytest.mark.parametrize("kind", ["symlink", "dangling_symlink", "directory", "fifo"])
def test_nonregular_objects_are_rejected_without_blocking(store, tmp_path, kind):
    data = b"original"
    ref = hashlib.sha256(data).hexdigest()
    path = store._path(ref)
    path.parent.mkdir()
    outside = tmp_path / "outside"
    if kind == "symlink":
        outside.write_bytes(data)
        path.symlink_to(outside)
    elif kind == "dangling_symlink":
        path.symlink_to(outside)
    elif kind == "directory":
        path.mkdir()
    else:
        os.mkfifo(path)
    for operation in (lambda: store.get(ref), lambda: store.has(ref),
                      lambda: store.put(data)):
        with pytest.raises(ArtifactIntegrityError):
            operation()
    if kind == "symlink":
        assert outside.read_bytes() == data


def test_socket_object_is_invalid_even_when_open_fails(store, tmp_path):
    data = b"original"
    ref = store.put(data)
    path = store._path(ref)
    path.unlink()
    # Bind a short name first to stay within AF_UNIX's pathname limit.
    socket_path = tmp_path / "socket"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as endpoint:
        endpoint.bind(str(socket_path))
        socket_path.rename(path)
        for operation in (lambda: store.get(ref), lambda: store.has(ref),
                          lambda: store.put(data)):
            with pytest.raises(ArtifactIntegrityError):
                operation()


@pytest.mark.parametrize("kind", ["symlink", "regular_file"])
def test_invalid_shard_cannot_redirect_reads_or_writes(store, tmp_path, kind):
    data = b"original"
    ref = hashlib.sha256(data).hexdigest()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / ref).write_bytes(data)
    shard = store.root / ref[:2]
    if kind == "symlink":
        shard.symlink_to(outside, target_is_directory=True)
    else:
        shard.write_bytes(b"not a directory")
    for operation in (lambda: store.get(ref), lambda: store.has(ref),
                      lambda: store.put(data)):
        with pytest.raises(ArtifactIntegrityError):
            operation()
    assert list(outside.iterdir()) == [outside / ref]


def test_root_shard_entry_is_synced_before_publishing(store, monkeypatch):
    real_fsync = os.fsync
    real_link = os.link
    events = []
    root_inode = store.root.stat().st_ino

    def fsync(fd):
        info = os.fstat(fd)
        if info.st_ino == root_inode and stat.S_ISDIR(info.st_mode):
            events.append("root")
        elif stat.S_ISDIR(info.st_mode):
            events.append("shard")
        else:
            events.append("file")
        return real_fsync(fd)

    def link(*args, **kwargs):
        events.append("publish")
        return real_link(*args, **kwargs)

    monkeypatch.setattr(os, "fsync", fsync)
    monkeypatch.setattr(os, "link", link)
    ref = store.put(b"new shard")
    assert events == ["root", "file", "publish", "shard"]
    assert store.get(ref) == b"new shard"


def test_retry_after_directory_sync_failure_syncs_existing_object(store, monkeypatch):
    real_fsync = os.fsync
    root_inode = store.root.stat().st_ino
    shard_syncs = []

    def fsync(fd):
        info = os.fstat(fd)
        if stat.S_ISDIR(info.st_mode) and info.st_ino != root_inode:
            shard_syncs.append(info.st_ino)
            if len(shard_syncs) == 1:
                raise OSError("injected directory sync failure")
        return real_fsync(fd)

    monkeypatch.setattr(os, "fsync", fsync)
    with pytest.raises(OSError, match="injected"):
        store.put(b"retry")
    # Bytes were linked but the prior operation could not confirm durability.
    ref = store.put(b"retry")
    assert store.get(ref) == b"retry"
    assert len(shard_syncs) == 2
    assert not list(store.root.rglob(".pending-*"))


def test_concurrent_writers_publish_once_without_overwrite(store, monkeypatch):
    real_link = os.link
    barrier = Barrier(2)

    def link(*args, **kwargs):
        barrier.wait(timeout=5)
        return real_link(*args, **kwargs)

    monkeypatch.setattr(os, "link", link)
    with ThreadPoolExecutor(max_workers=2) as pool:
        refs = list(pool.map(store.put, [b"same bytes", b"same bytes"]))
    assert refs[0] == refs[1]
    assert store.get(refs[0]) == b"same bytes"
    assert not list(store.root.rglob(".pending-*"))


def test_corrupt_concurrent_winner_is_rejected(store, monkeypatch):
    def corrupt_winner(source, destination, *, src_dir_fd, dst_dir_fd, **kwargs):
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                     0o600, dir_fd=dst_dir_fd)
        with os.fdopen(fd, "wb") as stream:
            stream.write(b"wrong bytes")
        raise FileExistsError(destination)

    monkeypatch.setattr(os, "link", corrupt_winner)
    with pytest.raises(ArtifactIntegrityError):
        store.put(b"original")
    assert not list(store.root.rglob(".pending-*"))


def test_publish_failure_cleans_up_temporary_bytes(store, monkeypatch):
    def fail(*args, **kwargs):
        raise OSError("injected publish failure")

    monkeypatch.setattr(os, "link", fail)
    with pytest.raises(OSError, match="injected"):
        store.put(b"original")
    assert not store.has(hashlib.sha256(b"original").hexdigest())
    assert not list(store.root.rglob(".pending-*"))
