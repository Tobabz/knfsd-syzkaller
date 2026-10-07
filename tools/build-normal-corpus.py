#!/usr/bin/env python3
"""Build and verify a profile-specific corpus.db from canonical NFS seeds."""

import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "bundle/corpus/nfs-normal"
MANIFEST = CORPUS / "manifest.json"


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_manifest(parser):
    try:
        manifest = json.loads(MANIFEST.read_text())
    except (OSError, json.JSONDecodeError) as error:
        parser.error("cannot read manifest: %s" % error)
    if manifest.get("schema") != 3 or manifest.get("purpose") != "mutation_seed":
        parser.error("manifest must be schema 3 mutation_seed")
    entries = manifest.get("programs")
    if not isinstance(entries, list):
        parser.error("manifest programs must be a list")
    by_path = {}
    for entry in entries:
        path = entry.get("path")
        if not path or path in by_path:
            parser.error("manifest contains a missing or duplicate program path")
        source = CORPUS / path
        if not source.is_file():
            parser.error("missing canonical seed: %s" % source)
        if sha256(source) != entry.get("sha256"):
            parser.error("canonical seed hash mismatch: %s" % source)
        by_path[path] = entry
    return manifest, by_path


def select_programs(parser, manifest, by_path, profile, fixture):
    if profile:
        definition = manifest.get("profiles", {}).get(profile)
        if definition is None:
            parser.error("profile is absent from manifest: %s" % profile)
        names = definition.get("programs", [])
        selection = {"kind": "profile", "name": profile,
                     "profiles": [profile]}
    else:
        definition = manifest.get("experimental_fixtures", {}).get(fixture)
        if definition is None:
            parser.error("fixture is absent from manifest: %s" % fixture)
        profiles = definition.get("profiles", [])
        names = []
        for name in profiles:
            profile_definition = manifest.get("profiles", {}).get(name)
            if profile_definition is None:
                parser.error("fixture references unknown profile: %s" % name)
            names.extend(profile_definition.get("programs", []))
        selection = {"kind": "fixture", "name": fixture,
                     "profiles": profiles}
    names = sorted(set(names))
    if not names:
        parser.error("selection contains no programs")
    unknown = sorted(set(names) - set(by_path))
    if unknown:
        parser.error("selection references unknown programs: %s" % ", ".join(unknown))
    return names, selection


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="new corpus.db path")
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--profile", choices=(
        "knfsd-v3", "knfsd-v40", "knfsd-v41", "knfsd-v42",
        "ganesha-v41"))
    selection.add_argument("--fixture", choices=("broad-knfsd",))
    parser.add_argument("--syz-db", type=Path,
                        default=ROOT / "env/syzkaller/bin/syz-db")
    args = parser.parse_args()

    output = args.output.resolve()
    metadata = Path(str(output) + ".json")
    for candidate in (output, metadata):
        if candidate.exists() or candidate.is_symlink():
            parser.error("refusing to overwrite: %s" % candidate)
    if not args.syz_db.is_file():
        parser.error("missing syz-db: %s" % args.syz_db)

    manifest, by_path = load_manifest(parser)
    names, selected = select_programs(
        parser, manifest, by_path, args.profile, args.fixture)
    output.parent.mkdir(parents=True, exist_ok=True)

    try:
        with tempfile.TemporaryDirectory(prefix="nfs-corpus-") as directory:
            temporary = Path(directory)
            inputs = temporary / "inputs"
            unpacked = temporary / "unpacked"
            inputs.mkdir()
            for name in names:
                shutil.copyfile(CORPUS / name, inputs / name)
            subprocess.run([
                str(args.syz_db), "-os", "linux", "-arch", "amd64",
                "pack", str(inputs), str(output),
            ], check=True)
            subprocess.run([
                str(args.syz_db), "unpack", str(output), str(unpacked),
            ], check=True, capture_output=True, text=True)
            unpacked_count = sum(path.is_file() for path in unpacked.iterdir())
            if unpacked_count != len(names):
                raise RuntimeError(
                    "packed corpus has %d programs, expected %d" %
                    (unpacked_count, len(names)))
            benchmark = subprocess.run([
                str(args.syz_db), "-os", "linux", "-arch", "amd64",
                "bench", str(output),
            ], check=True, capture_output=True, text=True).stdout.strip()
            if "corpus size: %d" % len(names) not in benchmark:
                raise RuntimeError("syz-db bench reported an unexpected corpus size")

        record = {
            "schema": 1,
            "purpose": "mutation_seed",
            "selection": selected,
            "program_count": len(names),
            "programs": [
                {"path": name, "sha256": by_path[name]["sha256"]}
                for name in names
            ],
            "corpus_db": {"path": output.name, "sha256": sha256(output)},
            "syz_db": {
                "path": str(args.syz_db.resolve()),
                "sha256": sha256(args.syz_db),
                "bench": benchmark.splitlines(),
            },
        }
        metadata.write_text(json.dumps(record, indent=2) + "\n")
    except Exception:
        output.unlink(missing_ok=True)
        metadata.unlink(missing_ok=True)
        raise

    print("corpus=%s programs=%d sha256=%s metadata=%s" %
          (output, len(names), record["corpus_db"]["sha256"], metadata))


if __name__ == "__main__":
    main()
