#!/usr/bin/env python3
"""Generate or drift-check CallAdmissionProfile from explicit pinned inputs."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent_pipeline.admission_generation import (  # noqa: E402
    AuthorityGenerationError,
    DriftDetected,
    PinnedSyzkallerInputs,
    generate_call_admission_profile,
    write_or_check_profile,
)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--syzkaller-checkout", type=Path, required=True,
                        help="existing pinned syzkaller git checkout")
    parser.add_argument("--expected-commit", required=True,
                        help="full lowercase commit expected at checkout HEAD")
    parser.add_argument("--patch-series", type=Path, required=True,
                        help="exact applied patch-series bytes")
    parser.add_argument("--build-root", type=Path, required=True,
                        help="root containing every build-manifest path")
    parser.add_argument("--build-manifest", type=Path, required=True,
                        help="canonical syzkaller-build-manifest.v1 JSON")
    parser.add_argument("--call-table", type=Path, required=True,
                        help="canonical trusted syzkaller-call-table.v1 build export")
    parser.add_argument("--target", required=True,
                        help="exact syzkaller target, for example linux/amd64")
    parser.add_argument("--mapping", type=Path, required=True,
                        help="canonical call-admission-source.v1 JSON")
    parser.add_argument("--hcap", type=Path, required=True,
                        help="canonical HCAP containing mapped capability IDs")
    parser.add_argument("--output", type=Path, required=True,
                        help="canonical generated profile path")
    parser.add_argument("--check", action="store_true",
                        help="fail on drift without changing the output")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    inputs = PinnedSyzkallerInputs(
        checkout=args.syzkaller_checkout,
        expected_commit=args.expected_commit,
        patch_series=args.patch_series,
        build_root=args.build_root,
        build_manifest=args.build_manifest,
        call_table=args.call_table,
        target=args.target,
    )
    try:
        profile = generate_call_admission_profile(
            inputs, mapping_path=args.mapping, hcap_path=args.hcap)
        digest = write_or_check_profile(profile, args.output, check=args.check)
    except DriftDetected as error:
        print(f"drift: {error}", file=sys.stderr)
        return 1
    except (AuthorityGenerationError, OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    action = "checked" if args.check else "generated"
    print(f"{action} profile={digest} target={profile.identity.target} "
          f"commit={profile.identity.syzkaller_commit}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
