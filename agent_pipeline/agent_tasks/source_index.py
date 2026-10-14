"""Immutable, bounded Git-backed kernel source lookup.

``GitKernelSourceIndex`` reads only objects reachable from the exact commit
object supplied to each operation.  It never asks Git for ``HEAD`` or for
worktree content.  Search, caller and callee results are deliberately lexical
source matches; they are useful navigation hints, not compiler or call-graph
claims.  Callees are returned only from conservatively delimited C function
bodies, and an ambiguous body produces no cross-function guesses.
"""

from __future__ import annotations

from bisect import bisect_right
from dataclasses import dataclass
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import subprocess
import time
from typing import Mapping, Sequence

from .tools import (MAX_SOURCE_BYTES, MAX_SOURCE_LINES, SOURCE_PREFIXES,
                    IndexedMatch)


DEFAULT_TIMEOUT_SECONDS = 10.0
DEFAULT_MAX_BLOB_BYTES = 4 * 1024 * 1024
DEFAULT_MAX_SCAN_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_TREE_BYTES = 8 * 1024 * 1024
DEFAULT_MAX_TREE_ENTRIES = 50_000
DEFAULT_MAX_RESULTS = 256
DEFAULT_MAX_MATCH_BYTES = 2 * 1024
DEFAULT_MAX_QUERY_BYTES = 512
MAX_ROOTS = 32
MAX_PATH_BYTES = 4096
MAX_STDERR_BYTES = 32 * 1024
MAX_METADATA_BYTES = 16 * 1024
_IO_CHUNK = 64 * 1024
_SIGNATURE_SCAN_CHARS = 16 * 1024
_MAX_FUNCTION_CANDIDATES = 4096

_SYMBOL_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_OID_FORMATS = {"sha1": 40, "sha256": 64}
_CALL_KEYWORDS = frozenset({
    "if", "for", "while", "switch", "sizeof", "typeof", "__typeof__",
    "__typeof", "_Alignof", "alignof", "_Static_assert", "static_assert",
})


class SourceIndexError(RuntimeError):
    """Base class for failures from the immutable source index."""


class RepositoryError(SourceIndexError):
    """The caller-provided path is not a usable local Git repository."""


class InvalidCommitError(SourceIndexError, ValueError):
    """A revision is not an exact, existing commit object ID."""


class InvalidSourcePathError(SourceIndexError, ValueError):
    """A source path or root is malformed or outside the trusted roots."""


class SourceContentError(SourceIndexError):
    """A selected object is not regular UTF-8 text source content."""


class SourceIndexLimitError(SourceIndexError):
    """A caller or repository exceeded a configured hard resource bound."""


class SourceIndexTimeoutError(SourceIndexError, TimeoutError):
    """In-process source parsing exceeded the operation deadline."""


class GitCommandError(SourceIndexError):
    """A bounded local Git subprocess could not complete successfully."""


class GitTimeoutError(GitCommandError, TimeoutError):
    """A local Git subprocess exceeded its deadline."""


class GitOutputLimitError(GitCommandError):
    """A local Git subprocess exceeded its output allowance."""


class MalformedGitOutputError(GitCommandError):
    """Git returned output that did not match the validated wire format."""


@dataclass(frozen=True)
class _ProcessResult:
    returncode: int
    stdout: bytes
    stderr: bytes


class _BoundedProcess:
    """Collect a subprocess through fixed-size nonblocking pipe reads."""

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str],
        timeout: float,
        stdout_limit: int,
        stderr_limit: int,
        input_data: bytes | None = None,
    ) -> _ProcessResult:
        if timeout <= 0:
            raise GitTimeoutError("local Git command deadline expired")
        if stdout_limit < 0 or stderr_limit < 0:
            raise ValueError("subprocess output limits must be non-negative")
        command = tuple(argv)
        if not command or any(not isinstance(item, str) or "\x00" in item
                              for item in command):
            raise GitCommandError("invalid subprocess argv")

        try:
            process = subprocess.Popen(
                command,
                cwd=os.fspath(cwd),
                env=dict(env),
                stdin=(subprocess.PIPE if input_data is not None
                       else subprocess.DEVNULL),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                close_fds=True,
            )
        except OSError as exc:
            raise GitCommandError(
                f"could not start local Git command: {exc}") from exc

        assert process.stdout is not None
        assert process.stderr is not None
        selector = selectors.DefaultSelector()
        stdout = bytearray()
        stderr = bytearray()
        pending = memoryview(input_data or b"")
        deadline = time.monotonic() + timeout

        def register_read(stream: object, label: str) -> None:
            descriptor = stream.fileno()  # type: ignore[attr-defined]
            os.set_blocking(descriptor, False)
            selector.register(stream, selectors.EVENT_READ, label)

        register_read(process.stdout, "stdout")
        register_read(process.stderr, "stderr")
        if process.stdin is not None:
            os.set_blocking(process.stdin.fileno(), False)
            selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")

        def close_registered(stream: object) -> None:
            try:
                selector.unregister(stream)
            except (KeyError, ValueError):
                pass
            try:
                stream.close()  # type: ignore[attr-defined]
            except OSError:
                pass

        def abort() -> None:
            if process.poll() is None:
                process.kill()
            try:
                process.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                pass
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    close_registered(stream)

        try:
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise GitTimeoutError("local Git command timed out")
                try:
                    events = selector.select(remaining)
                except InterruptedError:
                    continue
                except OSError as exc:
                    raise GitCommandError(
                        f"local Git pipe polling failed: {exc}") from exc
                if not events:
                    raise GitTimeoutError("local Git command timed out")
                for key, _ in events:
                    stream = key.fileobj
                    if key.data == "stdin":
                        if not pending:
                            close_registered(stream)
                            continue
                        try:
                            written = os.write(
                                stream.fileno(), pending[:_IO_CHUNK])
                        except (BrokenPipeError, OSError):
                            close_registered(stream)
                            continue
                        pending = pending[written:]
                        if not pending:
                            close_registered(stream)
                        continue

                    try:
                        chunk = os.read(stream.fileno(), _IO_CHUNK)
                    except BlockingIOError:
                        continue
                    except OSError as exc:
                        raise GitCommandError(
                            f"local Git pipe read failed: {exc}") from exc
                    if not chunk:
                        close_registered(stream)
                        continue
                    target = stdout if key.data == "stdout" else stderr
                    limit = (stdout_limit if key.data == "stdout"
                             else stderr_limit)
                    target.extend(chunk)
                    if len(target) > limit:
                        raise GitOutputLimitError(
                            f"local Git {key.data} exceeded {limit} bytes")

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise GitTimeoutError("local Git command timed out")
            try:
                returncode = process.wait(timeout=remaining)
            except subprocess.TimeoutExpired as exc:
                raise GitTimeoutError("local Git command timed out") from exc
        except BaseException:
            abort()
            raise
        finally:
            selector.close()

        return _ProcessResult(
            returncode=returncode,
            stdout=bytes(stdout),
            stderr=bytes(stderr),
        )


@dataclass(frozen=True)
class _Root:
    prefix: str
    directory: bool

    def contains(self, path: str) -> bool:
        if self.directory:
            return path == self.prefix or path.startswith(self.prefix + "/")
        return path.startswith(self.prefix)


@dataclass(frozen=True)
class _TreeEntry:
    mode: str
    object_type: str
    oid: str
    size: int | None
    path: str


class GitKernelSourceIndex:
    """A host-side ``KernelSourceIndex`` over immutable local Git objects.

    Search is literal and callers/callees are conservative lexical C
    navigation.  In particular, macros, declarations and indirect-call-like
    syntax can appear in caller results.  Callee extraction masks comments and
    literals and only scans brace-balanced bodies associated with the requested
    symbol; it returns no result when such a body cannot be delimited safely.
    """

    def __init__(
        self,
        repository: str | os.PathLike[str],
        *,
        trusted_roots: Sequence[str] = SOURCE_PREFIXES,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        max_blob_bytes: int = DEFAULT_MAX_BLOB_BYTES,
        max_scan_bytes: int = DEFAULT_MAX_SCAN_BYTES,
        max_tree_bytes: int = DEFAULT_MAX_TREE_BYTES,
        max_tree_entries: int = DEFAULT_MAX_TREE_ENTRIES,
        max_results: int = DEFAULT_MAX_RESULTS,
        max_match_bytes: int = DEFAULT_MAX_MATCH_BYTES,
        max_query_bytes: int = DEFAULT_MAX_QUERY_BYTES,
        git_binary: str = "git",
    ) -> None:
        try:
            repo = Path(repository).expanduser().resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise RepositoryError(
                f"local Git repository does not exist: {repository!s}") from exc
        if not repo.is_dir():
            raise RepositoryError("local Git repository path is not a directory")
        if (not isinstance(git_binary, str) or not git_binary
                or "\x00" in git_binary):
            raise RepositoryError("git binary must be a non-empty argv value")
        if not isinstance(timeout_seconds, (int, float)) \
                or isinstance(timeout_seconds, bool) or timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        for name, value in (
            ("max_blob_bytes", max_blob_bytes),
            ("max_scan_bytes", max_scan_bytes),
            ("max_tree_bytes", max_tree_bytes),
            ("max_tree_entries", max_tree_entries),
            ("max_results", max_results),
            ("max_match_bytes", max_match_bytes),
            ("max_query_bytes", max_query_bytes),
        ):
            if type(value) is not int or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if max_scan_bytes < max_blob_bytes:
            raise ValueError("max_scan_bytes must cover at least one blob")

        self._repo = repo
        self._git_binary = git_binary
        self._timeout = float(timeout_seconds)
        self._max_blob_bytes = max_blob_bytes
        self._max_scan_bytes = max_scan_bytes
        self._max_tree_bytes = max_tree_bytes
        self._max_tree_entries = max_tree_entries
        self._max_results = max_results
        self._max_match_bytes = max_match_bytes
        self._max_query_bytes = max_query_bytes
        self._process = _BoundedProcess()
        self._env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "LANG": "C",
            "LC_ALL": "C",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_PAGER": "cat",
            "GIT_TERMINAL_PROMPT": "0",
        }

        deadline = self._new_deadline()
        git_dir = self._git(
            ("rev-parse", "--absolute-git-dir"), deadline=deadline,
            stdout_limit=MAX_METADATA_BYTES,
            error_type=RepositoryError,
        ).stdout
        try:
            git_dir_text = git_dir.decode("utf-8", errors="strict").strip()
        except UnicodeDecodeError as exc:
            raise RepositoryError("Git directory path is not valid UTF-8") from exc
        if (not git_dir_text or "\x00" in git_dir_text
                or not Path(git_dir_text).is_absolute()
                or not Path(git_dir_text).is_dir()):
            raise RepositoryError("Git returned an invalid local Git directory")

        object_format = self._git(
            ("rev-parse", "--show-object-format=storage"), deadline=deadline,
            stdout_limit=64, error_type=RepositoryError,
        ).stdout
        try:
            format_name = object_format.decode("ascii", errors="strict").strip()
        except UnicodeDecodeError as exc:
            raise RepositoryError("Git object format is malformed") from exc
        try:
            self._oid_length = _OID_FORMATS[format_name]
        except KeyError as exc:
            raise RepositoryError(
                f"unsupported Git object format: {format_name!r}") from exc

        if isinstance(trusted_roots, (str, bytes)):
            raise InvalidSourcePathError(
                "trusted_roots must be a sequence of repository roots")
        if not trusted_roots or len(trusted_roots) > MAX_ROOTS:
            raise InvalidSourcePathError(
                f"trusted_roots must contain 1..{MAX_ROOTS} roots")
        self._trusted_roots = tuple(
            self._normalise_root(root, check_trust=False)
            for root in trusted_roots)

    def read(
        self,
        commit: str,
        path: str,
        start_line: int,
        end_line: int,
        max_bytes: int,
    ) -> str | None:
        """Read an inclusive, byte-bounded line range from one commit blob."""

        deadline = self._new_deadline()
        pinned = self._validate_commit(commit, deadline)
        normal_path = self._normalise_source_path(path)
        if (type(start_line) is not int or type(end_line) is not int
                or start_line < 1 or end_line < start_line):
            raise SourceIndexLimitError("source line range is invalid")
        if end_line - start_line + 1 > MAX_SOURCE_LINES:
            raise SourceIndexLimitError(
                f"source reads are limited to {MAX_SOURCE_LINES} lines")
        if type(max_bytes) is not int or not 1 <= max_bytes <= MAX_SOURCE_BYTES:
            raise SourceIndexLimitError(
                f"source read limit must be 1..{MAX_SOURCE_BYTES} bytes")

        entry = self._resolve_path(pinned, normal_path, deadline)
        if entry is None:
            return None
        text = self._load_texts((entry,), deadline)[0]
        lines = text.splitlines(keepends=True)
        selected = "".join(lines[start_line - 1:end_line])
        return self._utf8_prefix(selected, max_bytes)

    def search(
        self,
        commit: str,
        query: str,
        roots: tuple[str, ...],
        max_results: int,
    ) -> Sequence[IndexedMatch]:
        """Return deterministic literal matches from trusted commit roots."""

        deadline = self._new_deadline()
        pinned = self._validate_commit(commit, deadline)
        needle = self._validate_query(query)
        limit = self._validate_result_limit(max_results)
        selected_roots = self._normalise_roots(roots)
        entries = self._scan_entries(pinned, selected_roots, deadline)
        texts = self._load_texts(entries, deadline)
        results: list[IndexedMatch] = []
        for entry, text in zip(entries, texts, strict=True):
            self._check_deadline(deadline)
            for line_number, line in enumerate(text.split("\n"), start=1):
                if line_number % 1024 == 0:
                    self._check_deadline(deadline)
                position = line.find(needle)
                if position < 0:
                    continue
                results.append(IndexedMatch(
                    path=entry.path,
                    line=line_number,
                    text=self._match_snippet(line, position, len(needle)),
                ))
                if len(results) == limit:
                    return tuple(results)
        return tuple(results)

    def callers(
        self,
        commit: str,
        symbol: str,
        roots: tuple[str, ...],
        max_results: int,
    ) -> Sequence[IndexedMatch]:
        """Return lexical ``symbol(`` matches, including possible macros.

        Comments and string/character literals are masked.  Declarations,
        definitions and function-like macros remain possible matches because
        this index intentionally does not claim semantic call-graph precision.
        """

        deadline = self._new_deadline()
        pinned = self._validate_commit(commit, deadline)
        checked_symbol = self._validate_symbol(symbol)
        limit = self._validate_result_limit(max_results)
        selected_roots = self._normalise_roots(roots)
        entries = self._scan_entries(pinned, selected_roots, deadline)
        texts = self._load_texts(entries, deadline)
        pattern = re.compile(
            rf"(?<![A-Za-z0-9_]){re.escape(checked_symbol)}\s*\(")
        results: list[IndexedMatch] = []
        for entry, text in zip(entries, texts, strict=True):
            self._check_deadline(deadline)
            masked = self._mask_c(text, deadline)
            original_lines = text.split("\n")
            for line_number, line in enumerate(masked.split("\n"), start=1):
                if line_number % 1024 == 0:
                    self._check_deadline(deadline)
                match = pattern.search(line)
                if match is None:
                    continue
                original = original_lines[line_number - 1]
                results.append(IndexedMatch(
                    path=entry.path,
                    line=line_number,
                    text=self._match_snippet(
                        original, match.start(), len(checked_symbol)),
                    symbol=checked_symbol,
                ))
                if len(results) == limit:
                    return tuple(results)
        return tuple(results)

    def callees(
        self,
        commit: str,
        path: str,
        symbol: str,
        max_results: int,
    ) -> Sequence[IndexedMatch]:
        """Return bounded lexical call-like tokens from delimited C bodies.

        A token followed by ``(`` can be a macro or other C construct.  Results
        therefore describe lexical matches only.  If the requested function's
        body cannot be brace-delimited without crossing a declaration or outer
        expression boundary, this method returns no guesses for that candidate.
        """

        deadline = self._new_deadline()
        pinned = self._validate_commit(commit, deadline)
        normal_path = self._normalise_source_path(path)
        checked_symbol = self._validate_symbol(symbol)
        limit = self._validate_result_limit(max_results)
        entry = self._resolve_path(pinned, normal_path, deadline)
        if entry is None:
            raise FileNotFoundError(normal_path)
        text = self._load_texts((entry,), deadline)[0]
        masked = self._mask_c(text, deadline)
        bodies = self._function_bodies(masked, checked_symbol, deadline)
        if not bodies:
            return ()

        call_pattern = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
        newline_offsets = [
            index for index, character in enumerate(text) if character == "\n"]
        original_lines = text.split("\n")
        results: list[IndexedMatch] = []
        for body_start, body_end in bodies:
            self._check_deadline(deadline)
            for match in call_pattern.finditer(masked, body_start, body_end):
                if len(results) % 128 == 0:
                    self._check_deadline(deadline)
                callee = match.group(1)
                if callee in _CALL_KEYWORDS:
                    continue
                line_number = bisect_right(newline_offsets, match.start()) + 1
                original = original_lines[line_number - 1]
                line_start = (newline_offsets[line_number - 2] + 1
                              if line_number > 1 else 0)
                column = match.start() - line_start
                results.append(IndexedMatch(
                    path=normal_path,
                    line=line_number,
                    text=self._match_snippet(original, column, len(callee)),
                    symbol=callee,
                ))
                if len(results) == limit:
                    return tuple(results)
        return tuple(results)

    def _new_deadline(self) -> float:
        return time.monotonic() + self._timeout

    @staticmethod
    def _check_deadline(deadline: float) -> None:
        if time.monotonic() >= deadline:
            raise SourceIndexTimeoutError(
                "source indexing operation exceeded its deadline")

    def _git(
        self,
        args: Sequence[str],
        *,
        deadline: float,
        stdout_limit: int,
        input_data: bytes | None = None,
        allowed_codes: tuple[int, ...] = (0,),
        error_type: type[SourceIndexError] = GitCommandError,
    ) -> _ProcessResult:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise GitTimeoutError("local Git operation deadline expired")
        result = self._process.run(
            (self._git_binary, "--no-pager", "--no-replace-objects", "-C",
             os.fspath(self._repo), *args),
            cwd=self._repo,
            env=self._env,
            timeout=remaining,
            stdout_limit=stdout_limit,
            stderr_limit=MAX_STDERR_BYTES,
            input_data=input_data,
        )
        if result.returncode not in allowed_codes:
            detail = result.stderr.decode("utf-8", errors="replace").strip()
            detail = detail[:512] if detail else "no diagnostic"
            subcommand = args[0] if args else "command"
            raise error_type(
                f"local git {subcommand} failed with exit status "
                f"{result.returncode}: {detail}")
        return result

    def _validate_commit(self, commit: str, deadline: float) -> str:
        if (not isinstance(commit, str)
                or re.fullmatch(
                    rf"[0-9a-f]{{{self._oid_length}}}", commit) is None):
            raise InvalidCommitError(
                "commit must be a canonical full object ID")
        result = self._git(
            ("cat-file", "-t", "--", commit),
            deadline=deadline,
            stdout_limit=64,
            allowed_codes=(0, 1, 128),
        )
        if result.returncode != 0 or result.stdout != b"commit\n":
            raise InvalidCommitError(
                "object ID is missing or does not identify a commit")
        return commit

    def _normalise_repo_path(self, path: str) -> str:
        if not isinstance(path, str) or not path:
            raise InvalidSourcePathError(
                "source path must be a non-empty string")
        if len(path.encode("utf-8")) > MAX_PATH_BYTES:
            raise InvalidSourcePathError("source path is too long")
        if "\\" in path or any(ord(character) < 32 or ord(character) == 127
                                for character in path):
            raise InvalidSourcePathError(
                "source path contains a forbidden control or separator")
        pure = PurePosixPath(path)
        if (pure.is_absolute() or not pure.parts
                or any(part in ("", ".", "..") for part in pure.parts)
                or pure.as_posix() != path):
            raise InvalidSourcePathError(
                "source path must be normalized and repository-relative")
        return path

    def _normalise_root(self, root: str, *, check_trust: bool) -> _Root:
        if not isinstance(root, str) or not root:
            raise InvalidSourcePathError("source root must be non-empty")
        directory = root.endswith("/")
        clean = root[:-1] if directory else root
        clean = self._normalise_repo_path(clean)
        candidate = _Root(clean, directory)
        if check_trust and not self._root_is_trusted(candidate):
            raise InvalidSourcePathError(
                "source root is outside the configured trusted roots")
        return candidate

    def _root_is_trusted(self, root: _Root) -> bool:
        return any(
            trusted.contains(root.prefix)
            or (root.directory and root.prefix == trusted.prefix)
            for trusted in self._trusted_roots)

    def _normalise_roots(self, roots: tuple[str, ...]) -> tuple[_Root, ...]:
        if isinstance(roots, (str, bytes)) or not roots or len(roots) > MAX_ROOTS:
            raise InvalidSourcePathError(
                f"search roots must contain 1..{MAX_ROOTS} trusted roots")
        normal = tuple(self._normalise_root(root, check_trust=True)
                       for root in roots)
        return tuple(sorted(set(normal), key=lambda item: (
            item.prefix, not item.directory)))

    def _normalise_source_path(self, path: str) -> str:
        normal = self._normalise_repo_path(path)
        if not any(root.contains(normal) for root in self._trusted_roots):
            raise InvalidSourcePathError(
                "source path is outside the configured trusted roots")
        return normal

    def _validate_query(self, query: str) -> str:
        if (not isinstance(query, str) or not query
                or "\x00" in query or "\n" in query or "\r" in query):
            raise SourceIndexLimitError(
                "literal query must be non-empty and single-line")
        if len(query.encode("utf-8")) > self._max_query_bytes:
            raise SourceIndexLimitError(
                f"literal query exceeds {self._max_query_bytes} bytes")
        return query

    def _validate_symbol(self, symbol: str) -> str:
        if (not isinstance(symbol, str) or len(symbol) > 256
                or _SYMBOL_RE.fullmatch(symbol) is None):
            raise SourceIndexLimitError("C symbol is malformed")
        return symbol

    def _validate_result_limit(self, max_results: int) -> int:
        if (type(max_results) is not int
                or not 1 <= max_results <= self._max_results):
            raise SourceIndexLimitError(
                f"max_results must be 1..{self._max_results}")
        return max_results

    def _resolve_path(
        self,
        commit: str,
        path: str,
        deadline: float,
    ) -> _TreeEntry | None:
        output = self._git(
            ("ls-tree", "-r", "-z", "-l", "--full-tree", commit, "--",
             f":(top,literal){path}"),
            deadline=deadline,
            stdout_limit=MAX_METADATA_BYTES + len(path.encode("utf-8")),
        ).stdout
        entries = self._parse_tree_output(output)
        if not entries:
            return None
        if len(entries) != 1 or entries[0].path != path:
            raise MalformedGitOutputError(
                "Git path lookup returned an unexpected source path")
        entry = entries[0]
        self._validate_regular_blob(entry)
        return entry

    def _scan_entries(
        self,
        commit: str,
        roots: tuple[_Root, ...],
        deadline: float,
    ) -> tuple[_TreeEntry, ...]:
        bases: set[str] = set()
        for root in roots:
            if root.directory:
                bases.add(root.prefix)
            else:
                parent = PurePosixPath(root.prefix).parent.as_posix()
                if parent in ("", "."):
                    raise InvalidSourcePathError(
                        "top-level lexical prefixes are not allowed")
                bases.add(parent)
        pruned: list[str] = []
        for base in sorted(bases, key=lambda item: (item.count("/"), item)):
            if any(base == prior or base.startswith(prior + "/")
                   for prior in pruned):
                continue
            pruned.append(base)

        pathspecs = tuple(f":(top,literal){base}" for base in pruned)
        output = self._git(
            ("ls-tree", "-r", "-z", "-l", "--full-tree", commit, "--",
             *pathspecs),
            deadline=deadline,
            stdout_limit=self._max_tree_bytes,
        ).stdout
        all_entries = self._parse_tree_output(output)
        if len(all_entries) > self._max_tree_entries:
            raise SourceIndexLimitError(
                f"tree scan exceeds {self._max_tree_entries} entries")

        selected: list[_TreeEntry] = []
        total_bytes = 0
        for entry in all_entries:
            if not any(entry.path == base or entry.path.startswith(base + "/")
                       for base in pruned):
                raise MalformedGitOutputError(
                    "Git tree scan returned a path outside its argv roots")
            if not any(root.contains(entry.path) for root in roots):
                continue
            if not any(root.contains(entry.path)
                       for root in self._trusted_roots):
                raise MalformedGitOutputError(
                    "Git tree scan escaped the configured trusted roots")
            self._validate_regular_blob(entry)
            assert entry.size is not None
            total_bytes += entry.size
            if total_bytes > self._max_scan_bytes:
                raise SourceIndexLimitError(
                    f"source scan exceeds {self._max_scan_bytes} bytes")
            selected.append(entry)
        return tuple(selected)

    def _parse_tree_output(self, output: bytes) -> tuple[_TreeEntry, ...]:
        if not output:
            return ()
        if not output.endswith(b"\x00"):
            raise MalformedGitOutputError("Git tree output is not NUL-terminated")
        records = output[:-1].split(b"\x00")
        entries: list[_TreeEntry] = []
        seen_paths: set[str] = set()
        oid_pattern = re.compile(rb"[0-9a-f]{%d}" % self._oid_length)
        for record in records:
            try:
                metadata, raw_path = record.split(b"\t", 1)
            except ValueError as exc:
                raise MalformedGitOutputError(
                    "Git tree record is missing its path separator") from exc
            fields = metadata.split()
            if len(fields) != 4:
                raise MalformedGitOutputError(
                    "Git tree record has unexpected metadata")
            raw_mode, raw_type, raw_oid, raw_size = fields
            if oid_pattern.fullmatch(raw_oid) is None:
                raise MalformedGitOutputError(
                    "Git tree record has an invalid object ID")
            try:
                mode = raw_mode.decode("ascii", errors="strict")
                object_type = raw_type.decode("ascii", errors="strict")
                oid = raw_oid.decode("ascii", errors="strict")
                path = raw_path.decode("utf-8", errors="strict")
            except UnicodeDecodeError as exc:
                raise MalformedGitOutputError(
                    "Git tree record is not valid UTF-8/ASCII") from exc
            if (re.fullmatch(r"[0-7]{6}", mode) is None
                    or object_type not in {"blob", "tree", "commit"}):
                raise MalformedGitOutputError(
                    "Git tree record has an invalid mode or object type")
            try:
                normal_path = self._normalise_repo_path(path)
            except InvalidSourcePathError as exc:
                raise MalformedGitOutputError(
                    "Git tree returned a malformed source path") from exc
            if normal_path in seen_paths:
                raise MalformedGitOutputError(
                    "Git tree output contains a duplicate path")
            seen_paths.add(normal_path)
            if raw_size == b"-":
                size = None
            elif raw_size.isdigit():
                size = int(raw_size)
            else:
                raise MalformedGitOutputError(
                    "Git tree record has an invalid object size")
            if (object_type == "blob") != (size is not None):
                raise MalformedGitOutputError(
                    "Git tree object type and size are inconsistent")
            entries.append(_TreeEntry(
                mode=mode,
                object_type=object_type,
                oid=oid,
                size=size,
                path=normal_path,
            ))
        return tuple(sorted(entries, key=lambda entry: entry.path))

    def _validate_regular_blob(self, entry: _TreeEntry) -> None:
        if (entry.object_type != "blob" or entry.size is None
                or re.fullmatch(r"100[0-7]{3}", entry.mode) is None):
            raise SourceContentError(
                f"source path is not a regular Git blob: {entry.path}")
        if entry.size > self._max_blob_bytes:
            raise SourceIndexLimitError(
                f"source blob exceeds {self._max_blob_bytes} bytes: "
                f"{entry.path}")

    def _load_texts(
        self,
        entries: Sequence[_TreeEntry],
        deadline: float,
    ) -> tuple[str, ...]:
        if not entries:
            return ()
        total_size = sum(entry.size or 0 for entry in entries)
        if total_size > self._max_scan_bytes:
            raise SourceIndexLimitError(
                f"source scan exceeds {self._max_scan_bytes} bytes")
        request = b"".join(entry.oid.encode("ascii") + b"\n"
                           for entry in entries)
        framing = len(entries) * (self._oid_length + 64) + 1
        output = self._git(
            ("cat-file", "--batch"),
            deadline=deadline,
            stdout_limit=total_size + framing,
            input_data=request,
        ).stdout
        position = 0
        texts: list[str] = []
        for entry in entries:
            header_end = output.find(b"\n", position)
            if header_end < 0 or header_end - position > self._oid_length + 64:
                raise MalformedGitOutputError(
                    "Git batch output has a malformed object header")
            header = output[position:header_end].split()
            if len(header) != 3:
                raise MalformedGitOutputError(
                    "Git batch output has unexpected object metadata")
            raw_oid, raw_type, raw_size = header
            if (raw_oid != entry.oid.encode("ascii") or raw_type != b"blob"
                    or not raw_size.isdigit()
                    or int(raw_size) != entry.size):
                raise MalformedGitOutputError(
                    "Git batch output does not match the selected tree blob")
            content_start = header_end + 1
            content_end = content_start + (entry.size or 0)
            if content_end >= len(output) or output[content_end] != 0x0A:
                raise MalformedGitOutputError(
                    "Git batch output has invalid object framing")
            content = output[content_start:content_end]
            position = content_end + 1
            if b"\x00" in content:
                raise SourceContentError(
                    f"binary source blob is rejected: {entry.path}")
            try:
                texts.append(content.decode("utf-8", errors="strict"))
            except UnicodeDecodeError as exc:
                raise SourceContentError(
                    f"source blob is not valid UTF-8: {entry.path}") from exc
        if position != len(output):
            raise MalformedGitOutputError(
                "Git batch output contains trailing data")
        return tuple(texts)

    @staticmethod
    def _utf8_prefix(value: str, max_bytes: int) -> str:
        encoded = value.encode("utf-8")
        if len(encoded) <= max_bytes:
            return value
        return encoded[:max_bytes].decode("utf-8", errors="ignore")

    def _match_snippet(self, line: str, position: int, width: int) -> str:
        encoded = line.encode("utf-8")
        if len(encoded) <= self._max_match_bytes:
            return line
        prefix_bytes = line[:position].encode("utf-8")
        match_bytes = line[position:position + width].encode("utf-8")
        start = max(0, len(prefix_bytes) - self._max_match_bytes // 4)
        end = min(len(encoded), start + self._max_match_bytes)
        if end - start < len(match_bytes):
            start = len(prefix_bytes)
            end = min(len(encoded), start + self._max_match_bytes)
        while start < end and encoded[start] & 0xC0 == 0x80:
            start += 1
        while end > start and end < len(encoded) \
                and encoded[end] & 0xC0 == 0x80:
            end -= 1
        return encoded[start:end].decode("utf-8", errors="strict")

    def _mask_c(self, text: str, deadline: float) -> str:
        masked = list(text)
        index = 0
        state = "normal"
        while index < len(text):
            if index % _IO_CHUNK == 0:
                self._check_deadline(deadline)
            character = text[index]
            following = text[index + 1] if index + 1 < len(text) else ""
            if state == "normal":
                if character == "/" and following == "/":
                    masked[index] = masked[index + 1] = " "
                    state = "line-comment"
                    index += 2
                    continue
                if character == "/" and following == "*":
                    masked[index] = masked[index + 1] = " "
                    state = "block-comment"
                    index += 2
                    continue
                if character in ('"', "'"):
                    masked[index] = " "
                    state = "string" if character == '"' else "char"
                    index += 1
                    continue
                index += 1
                continue
            if state == "line-comment":
                if character == "\n":
                    state = "normal"
                else:
                    masked[index] = " "
                index += 1
                continue
            if state == "block-comment":
                if character == "*" and following == "/":
                    masked[index] = masked[index + 1] = " "
                    state = "normal"
                    index += 2
                else:
                    if character != "\n":
                        masked[index] = " "
                    index += 1
                continue
            quote = '"' if state == "string" else "'"
            if character == "\\":
                masked[index] = " "
                if following:
                    if following != "\n":
                        masked[index + 1] = " "
                    index += 2
                else:
                    index += 1
                continue
            if character == quote:
                masked[index] = " "
                state = "normal"
            elif character != "\n":
                masked[index] = " "
            index += 1
        return "".join(masked)

    def _matching_delimiter(
        self,
        text: str,
        start: int,
        opening: str,
        closing: str,
        deadline: float,
        *,
        end: int | None = None,
    ) -> int | None:
        depth = 0
        stop = len(text) if end is None else min(len(text), end)
        for index in range(start, stop):
            if (index - start) % _IO_CHUNK == 0:
                self._check_deadline(deadline)
            if text[index] == opening:
                depth += 1
            elif text[index] == closing:
                depth -= 1
                if depth == 0:
                    return index
                if depth < 0:
                    return None
        return None

    def _function_bodies(
        self,
        masked: str,
        symbol: str,
        deadline: float,
    ) -> tuple[tuple[int, int], ...]:
        definition = re.compile(
            rf"(?<![A-Za-z0-9_]){re.escape(symbol)}\s*\(")
        bodies: list[tuple[int, int]] = []
        position = 0
        candidates = 0
        while position < len(masked):
            self._check_deadline(deadline)
            match = definition.search(masked, position)
            if match is None:
                break
            position = match.end()
            candidates += 1
            if candidates > _MAX_FUNCTION_CANDIDATES:
                raise SourceIndexLimitError(
                    "too many lexical function candidates in one blob")
            open_paren = masked.find("(", match.start() + len(symbol))
            if open_paren < 0:
                continue
            close_paren = self._matching_delimiter(
                masked, open_paren, "(", ")", deadline,
                end=open_paren + _SIGNATURE_SCAN_CHARS)
            if close_paren is None:
                continue
            scan_end = min(len(masked), close_paren + _SIGNATURE_SCAN_CHARS)
            paren_depth = 0
            bracket_depth = 0
            body_start: int | None = None
            cursor = close_paren + 1
            while cursor < scan_end:
                if (cursor - close_paren) % _IO_CHUNK == 0:
                    self._check_deadline(deadline)
                character = masked[cursor]
                if character == "(":
                    paren_depth += 1
                elif character == ")":
                    if paren_depth == 0:
                        break
                    paren_depth -= 1
                elif character == "[":
                    bracket_depth += 1
                elif character == "]":
                    if bracket_depth == 0:
                        break
                    bracket_depth -= 1
                elif paren_depth == 0 and bracket_depth == 0:
                    if character in ";=,}":
                        break
                    if character == "{":
                        body_start = cursor
                        break
                cursor += 1
            if body_start is None:
                continue
            body_end = self._matching_delimiter(
                masked, body_start, "{", "}", deadline)
            if body_end is None:
                continue
            span = (body_start + 1, body_end)
            bodies.append(span)
            position = body_end + 1
        return tuple(bodies)


__all__ = [
    "GitCommandError",
    "GitKernelSourceIndex",
    "GitOutputLimitError",
    "GitTimeoutError",
    "InvalidCommitError",
    "InvalidSourcePathError",
    "MalformedGitOutputError",
    "RepositoryError",
    "SourceContentError",
    "SourceIndexError",
    "SourceIndexLimitError",
    "SourceIndexTimeoutError",
]
