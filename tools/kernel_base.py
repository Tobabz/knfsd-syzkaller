"""Single source of truth for the kernel/syzkaller base and kernel tag helpers.

``bundle/patches/BASE`` records the last base the checked-in series is known to
apply to. bootstrap and fport-apply.sh read it; bump-kernel.py updates it.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BASE_FILE = ROOT / "bundle" / "patches" / "BASE"
KERNEL_URL = "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git"
KEYS = ("kernel_tag", "kernel_commit", "syzkaller_commit")

_TAG = re.compile(r"^v(\d+)\.(\d+)(?:\.(\d+))?(?:-rc(\d+))?$")
_SHA = re.compile(r"^[0-9a-f]{40}$")


def read_base(path: Path | None = None) -> dict[str, str]:
    path = path or BASE_FILE
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if not sep:
            raise ValueError("%s: malformed line %r" % (path, line))
        values[key.strip()] = value.strip()
    missing = [key for key in KEYS if key not in values]
    if missing:
        raise ValueError("%s: missing %s" % (path, ", ".join(missing)))
    parse_tag(values["kernel_tag"])
    for key in ("kernel_commit", "syzkaller_commit"):
        if not _SHA.match(values[key]):
            raise ValueError("%s: %s is not a 40-hex commit" % (path, key))
    return values


def write_base(values: dict[str, str], path: Path | None = None) -> None:
    path = path or BASE_FILE
    lines = ["# Last base the checked-in patch series is known to apply to.",
             "# Updated by tools/bump-kernel.py; read by bootstrap and fport-apply.sh."]
    lines += ["%s=%s" % (key, values[key]) for key in KEYS]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_tag(tag: str) -> tuple[int, int, int, int | None]:
    """(major, minor, patch, rc) for v7.3-rc4 / v7.3 / v6.1.5; rc is None for a release."""
    match = _TAG.match(tag)
    if match is None:
        raise ValueError("not a kernel release tag: %r" % tag)
    major, minor, patch, rc = match.groups()
    return int(major), int(minor), int(patch or 0), None if rc is None else int(rc)


def tag_key(tag: str) -> tuple[int, int, int, int, int]:
    """Sort key in which every rc precedes its release (v7.3-rc4 < v7.3 < v7.4-rc1)."""
    major, minor, patch, rc = parse_tag(tag)
    return major, minor, patch, 1 if rc is None else 0, rc or 0


def tag_version_fields(tag: str) -> tuple[str, str, str, str]:
    """The (VERSION, PATCHLEVEL, SUBLEVEL, EXTRAVERSION) a tree at this tag has in its Makefile."""
    major, minor, patch, rc = parse_tag(tag)
    return str(major), str(minor), str(patch), "" if rc is None else "-rc%d" % rc


def latest_tag(url: str = KERNEL_URL) -> str:
    """Newest release or rc tag in the repository (rc included)."""
    output = subprocess.run(["git", "ls-remote", "--tags", "--refs", url, "v*"],
                            capture_output=True, text=True, timeout=300, check=True).stdout
    tags = []
    for line in output.splitlines():
        ref = line.split("\t")[-1]
        tag = ref.removeprefix("refs/tags/")
        try:
            parse_tag(tag)
        except ValueError:
            continue
        tags.append(tag)
    if not tags:
        raise RuntimeError("no release tags found at %s" % url)
    return max(tags, key=tag_key)
