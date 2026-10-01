#!/usr/bin/env python3
"""Move the kernel base to a newer release or rc tag.

  bump-kernel.py TAG|latest [--kernel-repo URL] [--work DIR] [--keep]
  bump-kernel.py --export DIR [--keep]       (after resolving conflicts by hand)

The kernel series (bundle/patches/kernel) is applied with ``git am -3`` to a
shallow clone of TAG in a scratch directory; ``latest`` is the newest release or
rc tag of the repository.

* Clean apply: bundle/patches/BASE is updated and the patch files stay as they are.
* Conflict: the scratch clone is left in the middle of ``git am``. Resolve it with
  plain git (edit, ``git add``, ``git am --continue``), then run ``--export DIR``
  to write the rebased series back into bundle/patches/kernel and update BASE.

Conflict resolutions are remembered (git rerere) in cache/rr-cache-kernel, so a
conflict that was already resolved once is replayed on the next release.
bootstrap then builds and verifies the new base.
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import kernel_base  # noqa: E402

ROOT = kernel_base.ROOT
BUNDLE = Path(os.environ.get("KOOV_BUNDLE", str(ROOT / "bundle" / "patches")))
RR_CACHE = ROOT / "cache" / "rr-cache-kernel"
MARKER = "bump-base"


def git(repo: Path, *args: str, check: bool = True, capture: bool = False):
    return subprocess.run(["git", "-C", str(repo), *args], check=check, text=True,
                          capture_output=capture)


def head(repo: Path) -> str:
    return git(repo, "rev-parse", "HEAD", capture=True).stdout.strip()


def update_base(tag: str, commit: str) -> None:
    base_path = BUNDLE / "BASE"
    values = kernel_base.read_base(base_path)
    values["kernel_tag"], values["kernel_commit"] = tag, commit
    kernel_base.write_base(values, base_path)


def save_rr_cache(scratch: Path) -> None:
    source = scratch / ".git" / "rr-cache"
    if source.is_dir():
        RR_CACHE.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(source, RR_CACHE, dirs_exist_ok=True)


def read_marker(scratch: Path) -> tuple[str, str]:
    tag, commit = (scratch / ".git" / MARKER).read_text(encoding="utf-8").split()
    return tag, commit


def series_files() -> list[Path]:
    return sorted((BUNDLE / "kernel").glob("*.patch"))


def apply_series(args) -> int:
    tag = kernel_base.latest_tag(args.kernel_repo) if args.target == "latest" else args.target
    kernel_base.parse_tag(tag)
    current = kernel_base.read_base(BUNDLE / "BASE")["kernel_tag"]
    if tag == current:
        print("BASE is already %s" % tag)
        return 0
    if kernel_base.tag_key(tag) < kernel_base.tag_key(current):
        print("warning: %s is older than the current BASE %s" % (tag, current))
    scratch = Path(args.work) / tag
    if scratch.exists():
        sys.exit("%s exists; remove it, or finish it with --export" % scratch)
    scratch.parent.mkdir(parents=True, exist_ok=True)
    print("cloning %s (shallow) into %s" % (tag, scratch), flush=True)
    subprocess.run(["git", "clone", "-q", "--branch", tag, "--depth", "1",
                    args.kernel_repo, str(scratch)], check=True)
    commit = head(scratch)
    (scratch / ".git" / MARKER).write_text("%s %s\n" % (tag, commit), encoding="utf-8")
    for key, value in (("rerere.enabled", "true"), ("rerere.autoUpdate", "true"),
                       ("user.email", "bump@knfsd-fuzz.invalid"), ("user.name", "bump-kernel")):
        git(scratch, "config", key, value)
    if RR_CACHE.is_dir():
        shutil.copytree(RR_CACHE, scratch / ".git" / "rr-cache", dirs_exist_ok=True)
    patches = series_files()
    if not patches:
        sys.exit("no patches in %s" % (BUNDLE / "kernel"))
    print("applying %d patches with git am -3" % len(patches), flush=True)
    result = git(scratch, "am", "-3", *map(str, patches), check=False)
    if result.returncode != 0:
        print("\nconflict. The clone is left mid-am in:\n  %s\n"
              "Resolve it with git (edit, git add, git am --continue) until the series is\n"
              "applied, then run:\n  %s --export %s"
              % (scratch, Path(sys.argv[0]).name, scratch), file=sys.stderr)
        return 1
    update_base(tag, commit)
    save_rr_cache(scratch)
    if not args.keep:
        shutil.rmtree(scratch)
    print("series applies cleanly to %s (%s); BASE updated, patch files unchanged" % (tag, commit))
    print("next: run tools/bootstrap-kcov-env.py to build and verify it")
    return 0


def export_series(args) -> int:
    scratch = Path(args.export).resolve()
    tag, commit = read_marker(scratch)
    if (scratch / ".git" / "rebase-apply").exists():
        sys.exit("git am is still in progress in %s; finish it first" % scratch)
    with tempfile.TemporaryDirectory() as tmp:
        git(scratch, "format-patch", "-q", "-o", tmp, "%s..HEAD" % commit)
        new = sorted(Path(tmp).glob("*.patch"))
        if not new:
            sys.exit("no commits above %s in %s" % (commit, scratch))
        old = [p.name for p in series_files()]
        names = old if len(old) == len(new) else [p.name for p in new]
        kernel_dir = BUNDLE / "kernel"
        for path in series_files():
            path.unlink()
        for path, name in zip(new, names):
            shutil.copyfile(path, kernel_dir / name)
        (kernel_dir / "series").write_text("\n".join(names) + "\n", encoding="utf-8")
    update_base(tag, commit)
    save_rr_cache(scratch)
    if not args.keep:
        shutil.rmtree(scratch)
    print("exported %d patches rebased onto %s (%s); BASE updated" % (len(new), tag, commit))
    print("next: run tools/bootstrap-kcov-env.py to build and verify it")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("target", nargs="?", help="release/rc tag, or 'latest'")
    parser.add_argument("--export", metavar="DIR",
                        help="finish a bump whose conflicts were resolved by hand")
    parser.add_argument("--kernel-repo", default=kernel_base.KERNEL_URL)
    parser.add_argument("--work", default=str(ROOT / "cache" / "kernel-bump"),
                        help="scratch parent directory")
    parser.add_argument("--keep", action="store_true", help="keep the scratch clone")
    args = parser.parse_args(argv)
    if bool(args.target) == bool(args.export):
        parser.error("give exactly one of TAG|latest or --export DIR")
    return export_series(args) if args.export else apply_series(args)


if __name__ == "__main__":
    raise SystemExit(main())
