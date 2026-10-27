#!/usr/bin/env python3
"""Build a Harness Generation patch set's harness for its validation.

The operator's build step of ``python -m agent_pipeline.stage1.host
validate`` (``docs/design/02-llm-agent/07-harness-gap-issue.md`` §5.2).
``generate`` writes it into ``validate.json``; the validator runs it as the
generation OS user, without network, in the patched tree:

  harness-generation-build.py TREE ENV BASE_ENV --base-bundle DIR [options]

ENV gets the layout of a ``tools/bootstrap-kcov-env.py`` env (``linux/``,
``images/``, ``syzkaller/``) and ``syz-bridge/`` (``bundle/``,
``checkout/``) for ``generate``.  What it builds depends on what the patch
set changed against this checkout, the one BASE_ENV was built from:

* nothing the builds read (a spec, a smoke program, a host tool): ENV
  links to BASE_ENV and the base bundle, so nothing is rebuilt;
* the kernel or syzkaller series, the kernel configs, the baker, the lane
  or the guest dependencies: the tree's own bootstrap builds ENV for the
  one variant, cloning from BASE_ENV's trees as local mirrors; a changed
  syzkaller series also rebuilds the parser bundle (Go).

The tree's tools run here, as the generation user; this checkout's code
decides what they produced.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

HOST = Path(__file__).resolve().parents[1]

#: What each build reads from the repository.
INPUTS = {
    "kernel": ("bundle/patches/kernel", "bundle/patches/kernel.config",
               "bundle/patches/kernel-kcsan.config", "bundle/patches/BASE"),
    "syzkaller": ("bundle/patches/syzkaller", "bundle/patches/BASE"),
    "image": ("bundle/baker", "bundle/lane", "bundle/src/guest-deps-lane.tar.gz",
              "tools/bootstrap-kcov-env.py", "tools/make-base-image.sh"),
}


def digest(root: Path, paths) -> str:
    """Names and bytes of every file under ``paths``; a missing path counts."""
    h = hashlib.sha256()
    for rel in paths:
        base = root / rel
        files = sorted(p for p in base.rglob("*") if p.is_file()) \
            if base.is_dir() else [base]
        for path in files:
            h.update(str(path.relative_to(root)).encode() + b"\0")
            h.update(path.read_bytes() if path.is_file() else b"<missing>")
            h.update(b"\0")
    return h.hexdigest()


def changed(tree: Path, host: Path = HOST) -> list[str]:
    return [name for name, paths in INPUTS.items()
            if digest(tree, paths) != digest(host, paths)]


def link_base(env: Path, base_env: Path, base_bundle: Path) -> None:
    for name in ("linux", "images", "syzkaller"):
        (env / name).symlink_to(base_env / name)
    link_bundle(env, base_bundle)


def link_bundle(env: Path, base_bundle: Path) -> None:
    """``syz-bridge`` holds ``bundle/`` and the ``checkout/`` beside it."""
    (env / "syz-bridge").symlink_to(base_bundle.resolve().parent)


def run(argv, cwd: Path) -> None:
    print("+ " + " ".join(str(a) for a in argv), flush=True)
    subprocess.run([str(a) for a in argv], cwd=cwd, check=True)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("tree", type=Path)
    ap.add_argument("env", type=Path)
    ap.add_argument("base_env", type=Path)
    ap.add_argument("--base-bundle", type=Path, required=True,
                    help="the host spec's syzkaller_bundle")
    ap.add_argument("--variant", default="kasan")
    ap.add_argument("--version", help="NFS version of the lane image "
                    "(default: BASE_ENV's manifest)")
    ap.add_argument("--base-image", type=Path,
                    default=HOST / "artifacts" / "bookworm-base.img")
    ap.add_argument("--ssh-key", type=Path,
                    default=HOST / "artifacts" / "bookworm.id_rsa")
    ap.add_argument("--kernel-repo", type=Path,
                    help="local kernel mirror (default: BASE_ENV/linux)")
    ap.add_argument("--syz-repo", type=Path,
                    help="local syzkaller mirror (default: BASE_ENV/syzkaller)")
    ap.add_argument("--go", default="go", help="Go 1.26.0 for the bundle")
    ap.add_argument("--jobs", type=int, default=os.cpu_count() or 8)
    args = ap.parse_args(argv)
    tree, env, base_env = (p.resolve() for p in (args.tree, args.env,
                                                 args.base_env))
    what = changed(tree)
    print(json.dumps({"changed": what}), flush=True)
    if not what:
        link_base(env, base_env, args.base_bundle)
        return 0
    version = args.version or json.loads(
        (base_env / "manifest.json").read_text())["nfs_version"]
    run([sys.executable, tree / "tools" / "bootstrap-kcov-env.py", env,
         "--kernel-repo", args.kernel_repo or base_env / "linux",
         "--syz-repo", args.syz_repo or base_env / "syzkaller",
         "--base-image", args.base_image, "--ssh-key", args.ssh_key,
         "--deps-tar", tree / "bundle" / "src" / "guest-deps-lane.tar.gz",
         "--version", version, "--variant", args.variant,
         # The validation boots its own guests.
         "--jobs", args.jobs, "--skip-verify"], cwd=tree)
    if "syzkaller" in what:
        run([sys.executable, tree / "tools" / "syzkaller" / "build.py",
             "--source", env / "syzkaller", "--output", env / "syz-bridge",
             "--go", args.go], cwd=tree)
    else:
        link_bundle(env, args.base_bundle)
    return 0


if __name__ == "__main__":
    sys.exit(main())
