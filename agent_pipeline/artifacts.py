"""Bounded SHA-256 content-addressed storage on a trusted host filesystem.

Digests establish byte integrity, not the provenance of the writer. Existing
objects are verified before reuse and are never overwritten by ``put``.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


DEFAULT_MAX_ARTIFACT_BYTES = 64 * 1024 * 1024


class ArtifactError(ValueError):
    """An artifact reference or its stored bytes are invalid."""


class InvalidDigest(ArtifactError):
    """A reference is not a lowercase, 64-character SHA-256 digest."""


class ArtifactIntegrityError(ArtifactError):
    """Stored bytes or the filesystem object do not match the reference."""


class ArtifactLimitError(ArtifactError):
    """An artifact exceeds the configured byte limit."""


def validate_digest(sha: str) -> str:
    if not isinstance(sha, str) or re.fullmatch(r"[0-9a-f]{64}", sha) is None:
        raise InvalidDigest("expected a lowercase SHA-256 digest")
    return sha


def _positive_limit(value: int) -> int:
    if type(value) is not int or value < 1:
        raise ValueError("byte limit must be a positive integer")
    return value


class ArtifactStore:
    def __init__(self, root: Path, *,
                 max_artifact_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES) -> None:
        self.max_artifact_bytes = _positive_limit(max_artifact_bytes)
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        # The caller selects a trusted root; object names never select paths.
        self.root = self.root.resolve(strict=True)

    def _path(self, sha: str) -> Path:
        validate_digest(sha)
        return self.root / sha[:2] / sha

    @contextmanager
    def _shard(self, sha: str, *, create: bool = False) -> Iterator[int]:
        validate_digest(sha)
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        root_fd = os.open(self.root, flags)
        try:
            if create:
                try:
                    os.mkdir(sha[:2], dir_fd=root_fd)
                except FileExistsError:
                    pass
                # Persist the shard's link in the root, including a shard
                # concurrently created by another writer. Provisioning the
                # storage root itself remains the caller's responsibility.
                os.fsync(root_fd)
            try:
                shard_fd = os.open(sha[:2], flags, dir_fd=root_fd)
            except FileNotFoundError:
                raise
            except OSError as exc:
                raise ArtifactIntegrityError("artifact shard is not a directory") from exc
            try:
                yield shard_fd
            finally:
                os.close(shard_fd)
        finally:
            os.close(root_fd)

    def _read(self, shard_fd: int, sha: str, limit: int) -> bytes:
        # O_NONBLOCK also prevents a malicious FIFO from blocking validation.
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        try:
            fd = os.open(sha, flags, dir_fd=shard_fd)
        except FileNotFoundError:
            raise
        except OSError as exc:
            raise ArtifactIntegrityError("artifact is not a readable regular file") from exc
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise ArtifactIntegrityError("artifact is not a regular file")
            stream = os.fdopen(fd, "rb")
        except BaseException:
            os.close(fd)
            raise
        with stream:
            if info.st_size > limit:
                raise ArtifactLimitError("artifact exceeds the byte limit")
            data = stream.read(limit + 1)
            if len(data) > limit:
                raise ArtifactLimitError("artifact exceeds the byte limit")
            if len(data) != info.st_size or hashlib.sha256(data).hexdigest() != sha:
                raise ArtifactIntegrityError(f"artifact {sha} does not match its digest")
        return data

    def put(self, data: bytes) -> str:
        if not isinstance(data, bytes):
            raise TypeError("artifact data must be immutable bytes")
        if len(data) > self.max_artifact_bytes:
            raise ArtifactLimitError("artifact exceeds the byte limit")
        sha = hashlib.sha256(data).hexdigest()
        with self._shard(sha, create=True) as shard_fd:
            try:
                self._read(shard_fd, sha, self.max_artifact_bytes)
            except FileNotFoundError:
                pass
            else:
                # A previous publish may have linked successfully but failed
                # its directory fsync. Reuse must finish that durability step.
                os.fsync(shard_fd)
                return sha
            tmp = f".pending-{uuid.uuid4().hex}"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600,
                         dir_fd=shard_fd)
            try:
                with os.fdopen(fd, "wb") as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
                try:
                    # Atomic create without replacing another writer's object.
                    os.link(tmp, sha, src_dir_fd=shard_fd, dst_dir_fd=shard_fd,
                            follow_symlinks=False)
                except FileExistsError:
                    self._read(shard_fd, sha, self.max_artifact_bytes)
                os.fsync(shard_fd)
            finally:
                os.unlink(tmp, dir_fd=shard_fd)
        return sha

    def get(self, sha: str, *, max_bytes: int | None = None) -> bytes:
        limit = self.max_artifact_bytes
        if max_bytes is not None:
            limit = min(limit, _positive_limit(max_bytes))
        with self._shard(sha) as shard_fd:
            return self._read(shard_fd, sha, limit)

    def has(self, sha: str) -> bool:
        """Return false only for absence; corruption is an error, not a hit."""
        try:
            self.get(sha)
        except FileNotFoundError:
            return False
        return True
