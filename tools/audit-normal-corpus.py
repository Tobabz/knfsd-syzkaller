#!/usr/bin/env python3
"""Classify NFS corpus roots and enforce the broad-to-profile promotion gate."""

import argparse
import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "bundle/corpus/nfs-normal/manifest.json"
CALL_RE = re.compile(r"^(?:r\d+\s*=\s*)?([A-Za-z0-9_.$]+)\(")
PROFILE_RE = re.compile(
    r"^syz_open_nfs_lane_profile\$client[01]_"
    r"(knfsd_v3|knfsd_v40|knfsd_v41|knfsd_v42|ganesha_v41)$")
PROFILE_NAMES = {
    "knfsd_v3": "knfsd-v3",
    "knfsd_v40": "knfsd-v40",
    "knfsd_v41": "knfsd-v41",
    "knfsd_v42": "knfsd-v42",
    "ganesha_v41": "ganesha-v41",
}


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def program_files(parser, source, syz_db, temporary):
    if source.is_dir():
        return sorted(path for path in source.iterdir() if path.is_file())
    if not source.is_file():
        parser.error("input does not exist: %s" % source)
    if source.suffix != ".db":
        return [source]
    if not syz_db.is_file():
        parser.error("missing syz-db: %s" % syz_db)
    unpacked = temporary / "unpacked"
    subprocess.run([str(syz_db), "unpack", str(source), str(unpacked)],
                   check=True, capture_output=True, text=True)
    return sorted(path for path in unpacked.iterdir() if path.is_file())


def replay_results(parser, path, profile):
    if path is None:
        parser.error("--promotion-profile requires --replay-evidence")
    try:
        evidence = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        parser.error("cannot read replay evidence: %s" % error)
    if (evidence.get("schema") != 1 or evidence.get("fixture") != "single" or
            evidence.get("profile") != profile):
        parser.error("replay evidence must be schema 1 for the matching single profile")
    results = {}
    for result in evidence.get("results", []):
        digest = result.get("sha256")
        runs = result.get("runs")
        if not isinstance(digest, str) or digest in results:
            parser.error("replay evidence contains a missing or duplicate sha256")
        if not isinstance(runs, int) or isinstance(runs, bool) or runs < 1:
            parser.error("each replay result must record a positive integer run count")
        results[digest] = result.get("passed") is True
    return results


def inspect(path, allowed_profiles, promotion_profile, replayed):
    data = path.read_bytes()
    calls = []
    for line in data.decode(errors="replace").splitlines():
        match = CALL_RE.match(line.strip())
        if match:
            calls.append(match.group(1))
    profiles = []
    profile_roots = 0
    for call in calls:
        match = PROFILE_RE.match(call)
        if match:
            profile_roots += 1
            profiles.append(PROFILE_NAMES[match.group(1)])
    profiles = sorted(set(profiles))
    raw_roots = sum(
        call.startswith("syz_socket_connect_nfs$") or
        call.startswith("syz_socket_connect_nfs_pair$")
        for call in calls)
    raw_ganesha_roots = sum(
        call.startswith("syz_socket_connect_nfs_pair$") and call.endswith("_ganesha")
        for call in calls)
    roots = profile_roots + raw_roots
    raw_allowed = (set(allowed_profiles) == {
        "knfsd-v3", "knfsd-v40", "knfsd-v41", "knfsd-v42",
    } or allowed_profiles == ["knfsd-v3"])
    disallowed = sorted(set(profiles) - set(allowed_profiles))
    mixed = len(profiles) > 1
    hybrid = bool(profiles and raw_roots)
    digest = sha256(data)
    reasons = []
    if roots == 0:
        reasons.append("no_nfs_root")
    if disallowed:
        reasons.append("disallowed_profile")
    if raw_ganesha_roots:
        reasons.append("disallowed_raw_backend")
    if raw_roots and not raw_allowed:
        reasons.append("raw_root_not_allowed")

    promotion_ready = None
    replay_passed = None
    if promotion_profile:
        if mixed:
            reasons.append("mixed_profiles")
        if hybrid:
            reasons.append("profile_and_raw_roots")
        if profiles and profiles != [promotion_profile]:
            reasons.append("profile_mismatch")
        if not profiles and raw_roots and promotion_profile != "knfsd-v3":
            reasons.append("raw_root_only_allowed_for_knfsd_v3")
        replay_passed = replayed.get(digest, False)
        if not replay_passed:
            reasons.append("matching_single_fixture_replay_missing_or_failed")
        promotion_ready = not reasons

    return {
        "file": path.name,
        "sha256": digest,
        "calls": len(calls),
        "nfs_roots": roots,
        "profile_roots": profile_roots,
        "raw_roots": raw_roots,
        "raw_ganesha_roots": raw_ganesha_roots,
        "profiles": profiles,
        "mixed_profiles": mixed,
        "profile_and_raw_roots": hybrid,
        "disallowed_profiles": disallowed,
        "runtime_admissible": (roots > 0 and not disallowed and
                               not raw_ganesha_roots and
                               (raw_roots == 0 or raw_allowed)),
        "promotion_ready": promotion_ready,
        "matching_replay_passed": replay_passed,
        "reasons": reasons,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="program, directory, or corpus.db")
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--fixture", choices=("broad-knfsd",))
    selection.add_argument("--profile", choices=tuple(PROFILE_NAMES.values()),
                           help="audit a stable runtime corpus without promoting it")
    selection.add_argument("--promotion-profile", choices=tuple(PROFILE_NAMES.values()))
    parser.add_argument("--replay-evidence", type=Path,
                        help="schema-1 single-fixture replay result JSON")
    parser.add_argument("--strict-runtime", action="store_true",
                        help="fail if any runtime input has no NFS root or a disallowed profile")
    parser.add_argument("--syz-db", type=Path,
                        default=ROOT / "env/syzkaller/bin/syz-db")
    parser.add_argument("--output", type=Path, help="write JSON here instead of stdout")
    args = parser.parse_args()

    manifest = json.loads(MANIFEST.read_text())
    if args.fixture:
        fixture = manifest["experimental_fixtures"][args.fixture]
        allowed = fixture["profiles"]
        replayed = {}
        policy = {
            "selection": {"kind": "fixture", "name": args.fixture},
            "mixed_profile_runtime": fixture["mixed_profile_runtime"],
            "promotion_policy": fixture["promotion_policy"],
        }
    elif args.profile:
        allowed = [args.profile]
        replayed = {}
        policy = {
            "selection": {"kind": "profile", "name": args.profile},
            "mixed_profile_runtime": "rejected",
        }
    else:
        allowed = [args.promotion_profile]
        replayed = replay_results(parser, args.replay_evidence, args.promotion_profile)
        policy = {
            "selection": {"kind": "promotion", "profile": args.promotion_profile},
            "nfs_root_required": True,
            "single_profile_required": True,
            "matching_single_fixture_replay_required": True,
        }

    with tempfile.TemporaryDirectory(prefix="nfs-corpus-audit-") as directory:
        files = program_files(parser, args.input, args.syz_db, Path(directory))
        results = [inspect(path, allowed, args.promotion_profile, replayed)
                   for path in files]
    report = {
        "schema": 1,
        "input": str(args.input.resolve()),
        "policy": policy,
        "programs": len(results),
        "runtime_admissible": sum(result["runtime_admissible"] for result in results),
        "with_nfs_root": sum(result["nfs_roots"] > 0 for result in results),
        "no_nfs_root": sum(result["nfs_roots"] == 0 for result in results),
        "profile_only": sum(bool(result["profiles"]) and result["raw_roots"] == 0
                            for result in results),
        "raw_only": sum(not result["profiles"] and result["raw_roots"] > 0
                        for result in results),
        "profile_and_raw": sum(result["profile_and_raw_roots"] for result in results),
        "one_profile": sum(len(result["profiles"]) == 1 for result in results),
        "mixed_profiles": sum(result["mixed_profiles"] for result in results),
        "disallowed_profile": sum(bool(result["disallowed_profiles"])
                                  for result in results),
        "raw_root_not_allowed": sum("raw_root_not_allowed" in result["reasons"]
                                    for result in results),
        "profile_counts": {
            profile: sum(profile in result["profiles"] for result in results)
            for profile in PROFILE_NAMES.values()
        },
        "promotion_ready": (sum(bool(result["promotion_ready"]) for result in results)
                            if args.promotion_profile else None),
        "results": results,
    }
    encoded = json.dumps(report, indent=2) + "\n"
    if args.output:
        if args.output.exists() or args.output.is_symlink():
            parser.error("refusing to overwrite: %s" % args.output)
        args.output.write_text(encoded)
    else:
        print(encoded, end="")

    if not results:
        raise SystemExit(1)
    if args.promotion_profile and report["promotion_ready"] != report["programs"]:
        raise SystemExit(1)
    if args.strict_runtime and report["runtime_admissible"] != report["programs"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
