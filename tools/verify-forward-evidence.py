#!/usr/bin/env python3
"""Check evidence-forward-port.sha256 against the commit/index, not local files.

The manifest is edited by concurrent workstreams. A worktree hash check can
pass while the commit names an ignored file or an uncommitted version of a
tracked file. Run this against the index before committing and HEAD after.
"""
import argparse
import hashlib
from pathlib import Path
import re
import subprocess
import sys


REPO = Path(__file__).resolve().parent.parent
MANIFEST = 'report/evidence-forward-port.sha256'
RECORD = re.compile(r'^([0-9a-f]{64})  (.+)$')


def object_bytes(spec):
    result = subprocess.run(['git', '-C', str(REPO), 'show', spec],
                            capture_output=True)
    return result.stdout if result.returncode == 0 else None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tree', help='tree-ish to check, e.g. HEAD; '
                        'default is the staged index')
    args = parser.parse_args()
    label = args.tree or 'index'
    prefix = args.tree if args.tree else ''
    raw = object_bytes(f'{prefix}:{MANIFEST}')
    if raw is None:
        parser.error(f'cannot read manifest from {label}')
    try:
        lines = raw.decode('utf-8').splitlines()
    except UnicodeDecodeError as error:
        parser.error(f'invalid UTF-8 in manifest: {error}')
    errors = []
    seen = set()
    entries = 0
    for number, line in enumerate(lines, 1):
        if not line.strip() or line.startswith('#'):
            continue
        match = RECORD.fullmatch(line)
        if not match:
            errors.append(f'line {number}: invalid checksum record')
            continue
        expected, path = match.groups()
        if (Path(path).is_absolute() or '..' in Path(path).parts or
                path.startswith('-') or ':' in path or '\n' in path):
            errors.append(f'line {number}: unsafe path {path!r}')
            continue
        if path in seen:
            errors.append(f'line {number}: duplicate path {path}')
            continue
        seen.add(path)
        entries += 1
        content = object_bytes(f'{prefix}:{path}')
        if content is None:
            errors.append(f'line {number}: absent in {label}: {path}')
            continue
        actual = hashlib.sha256(content).hexdigest()
        if actual != expected:
            errors.append(f'line {number}: hash mismatch in {label}: {path} '
                          f'(listed {expected[:12]}, actual {actual[:12]})')
    for error in errors:
        print('FAIL', error, file=sys.stderr)
    print(f'{label}: {entries} unique entries, {len(errors)} error(s)')
    return 1 if errors else 0


if __name__ == '__main__':
    sys.exit(main())
