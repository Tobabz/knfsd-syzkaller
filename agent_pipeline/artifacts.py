"""SHA-256 content-addressed artifacts (decision record, decision 3)."""

from __future__ import annotations

import hashlib
import os
import tempfile
from pathlib import Path


class ArtifactStore:
    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, sha: str) -> Path:
        return self.root / sha[:2] / sha

    def put(self, data: bytes) -> str:
        sha = hashlib.sha256(data).hexdigest()
        path = self._path(sha)
        if path.exists():
            return sha
        path.parent.mkdir(exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=path.parent)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
        except BaseException:
            os.unlink(tmp)
            raise
        return sha

    def get(self, sha: str) -> bytes:
        data = self._path(sha).read_bytes()
        if hashlib.sha256(data).hexdigest() != sha:
            raise ValueError(f"artifact {sha} does not match its digest")
        return data

    def has(self, sha: str) -> bool:
        return self._path(sha).exists()
