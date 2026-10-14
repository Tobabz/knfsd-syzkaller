#!/usr/bin/env python3
"""Pinned RFC XDR sources: extract, regenerate and verify.

WHAT THIS IS

  The NFSv4 XDR under schema/nfs4/ is not written by hand.  Each .x file is
  the output of the extraction script printed in its RFC, run on that RFC's
  plain text, and a SOURCES manifest pins the SHA-256 of every RFC text and
  of every file made from it.  This script is the only writer of those files.

  The NFSv4 XDR also uses names it never declares, because rpcgen takes them
  from the C environment: the basic typedefs (stated only in a comment),
  authsys_parms and the auth flavor constants.  The `prelude` file holds
  them, built by the same kind of rule from the same pinned texts, so no
  definition is ever typed from memory.

MANIFEST (one directive per line, `#` starts a comment line)

  rfc N SHA256              https://www.rfc-editor.org/rfc/rfcN.txt hashes
                            to SHA256
  extract FILE N SHA256 CMD FILE is the shell pipeline CMD run on RFC N's
                            text (stdin), byte for byte.  CMD must be a line
                            of RFC N exactly (its own `///` script).
  prelude FILE SHA256       FILE is built from the `typedefs` and `copy`
                            lines that follow, in order
  fragment FILE SHA256      FILE is built from the `copy` lines that follow:
                            a definition an RFC states only in its prose,
                            not in its `///` XDR (RFC 8435 and RFC 8154
                            restate layouttype4 that way)
  typedefs FILE...          every `typedef` line each FILE states inside a
                            comment; the files must all state the same ones
                            (prelude only)
  copy N KEYWORD NAME       the definition `KEYWORD NAME {` ... `};` in RFC N,
                            which must occur exactly once and not span a page

USAGE

  rfc_xdr.py MANIFEST --check                committed files match their pins
                                             (offline; build.sh runs this)
  rfc_xdr.py MANIFEST --verify [--rfc-dir D] fetch the RFCs (or read
                                             D/rfcN.txt), check their pins,
                                             rebuild every file and compare
  rfc_xdr.py MANIFEST --write  [--rfc-dir D] the same, but write the files;
                                             fails if a pin then differs
"""

import argparse
import hashlib
import os
import re
import subprocess
import sys
import urllib.request
from pathlib import Path

RFC_URL = "https://www.rfc-editor.org/rfc/rfc{}.txt"


class SourceError(Exception):
    pass


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def parse_manifest(path):
    m = {"rfc": {}, "extract": [], "prelude": None, "built": []}
    hexpin = re.compile(r"[0-9a-f]{64}")
    for no, raw in enumerate(Path(path).read_text().split("\n"), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        where = f"{path}:{no}"
        kw, _, rest = line.partition(" ")
        if kw == "rfc":
            args = rest.split()
            if len(args) != 2 or not args[0].isdigit() or \
                    not hexpin.fullmatch(args[1]):
                raise SourceError(f"{where}: rfc N SHA256")
            m["rfc"][args[0]] = args[1]
        elif kw == "extract":
            args = rest.split(None, 3)
            if len(args) != 4 or not hexpin.fullmatch(args[2]):
                raise SourceError(f"{where}: extract FILE N SHA256 CMD")
            m["extract"].append({"file": args[0], "rfc": args[1],
                                 "sha256": args[2], "cmd": args[3]})
        elif kw in ("prelude", "fragment"):
            args = rest.split()
            if len(args) != 2 or not hexpin.fullmatch(args[1]) or \
                    (kw == "prelude" and m["prelude"]):
                raise SourceError(f"{where}: one prelude FILE SHA256"
                                  if kw == "prelude" else
                                  f"{where}: fragment FILE SHA256")
            if any(b["file"] == args[0] for b in m["built"]) or \
                    any(e["file"] == args[0] for e in m["extract"]):
                raise SourceError(f"{where}: {args[0]} is built twice")
            b = {"kind": kw, "file": args[0], "sha256": args[1],
                 "parts": []}
            m["built"].append(b)
            if kw == "prelude":
                m["prelude"] = b
        elif kw in ("typedefs", "copy"):
            args = rest.split()
            if not m["built"]:
                raise SourceError(f"{where}: {kw} before prelude or "
                                  f"fragment")
            if kw == "copy" and len(args) != 3:
                raise SourceError(f"{where}: copy N KEYWORD NAME")
            if kw == "typedefs" and (not args or
                                     m["built"][-1]["kind"] != "prelude"):
                raise SourceError(f"{where}: typedefs FILE... in a prelude")
            m["built"][-1]["parts"].append((kw, args))
        else:
            raise SourceError(f"{where}: unknown directive {kw}")
    for e in m["extract"]:
        if e["rfc"] not in m["rfc"]:
            raise SourceError(f"{path}: extract {e['file']}: RFC "
                              f"{e['rfc']} is not pinned")
    for b in m["built"]:
        if not b["parts"]:
            raise SourceError(f"{path}: {b['kind']} {b['file']} is empty")
        for kw, args in b["parts"]:
            if kw == "copy" and args[0] not in m["rfc"]:
                raise SourceError(f"{path}: copy: RFC {args[0]} is not "
                                  f"pinned")
    return m


def load_rfc(n, pin, rfc_dir):
    if rfc_dir:
        data = (Path(rfc_dir) / f"rfc{n}.txt").read_bytes()
    else:
        with urllib.request.urlopen(RFC_URL.format(n), timeout=60) as r:
            data = r.read()
    got = sha256(data)
    if got != pin:
        raise SourceError(f"RFC {n}: sha256 {got}, pinned {pin}; the "
                          f"published text changed or the pin is wrong")
    return data


def run_extract(e, rfc_text):
    """Run the RFC's own extraction pipeline on the RFC text."""
    lines = rfc_text.decode("utf-8-sig").split("\n")
    if e["cmd"] not in (ln.strip() for ln in lines):
        raise SourceError(f"{e['file']}: extraction command is not a line "
                          f"of RFC {e['rfc']}")
    env = {"LC_ALL": "C", "PATH": os.environ.get("PATH", "/usr/bin:/bin")}
    p = subprocess.run(["sh", "-c", e["cmd"]], input=rfc_text, env=env,
                       capture_output=True, check=False)
    if p.returncode != 0 or p.stderr:
        raise SourceError(f"{e['file']}: extraction failed "
                          f"(exit {p.returncode}): {p.stderr.decode()!r}")
    return p.stdout


_COMMENT_TYPEDEF = re.compile(r"^ \* (typedef\s.*;)\s*$")


def commented_typedefs(name, text):
    out = [" ".join(m.group(1).split())
           for m in map(_COMMENT_TYPEDEF.match, text.decode("ascii")
                        .split("\n")) if m]
    if not out:
        raise SourceError(f"{name}: no typedef stated in a comment")
    return out


def copy_definition(n, rfc_text, keyword, name):
    lines = rfc_text.decode("utf-8-sig").split("\n")
    head = f"{keyword} {name} {{"
    starts = [i for i, ln in enumerate(lines) if ln.strip() == head]
    if len(starts) != 1:
        raise SourceError(f"RFC {n}: `{head}` occurs {len(starts)} times")
    first = starts[0]
    for last in range(first, len(lines)):
        ln = lines[last]
        if "\f" in ln or re.search(r"\[Page \d+\]\s*$", ln):
            raise SourceError(f"RFC {n}: {keyword} {name} spans a page")
        if ln.strip() == "};":
            break
    else:
        raise SourceError(f"RFC {n}: {keyword} {name} has no `}};`")
    indent = len(lines[first]) - len(lines[first].lstrip(" "))
    body = []
    for ln in lines[first:last + 1]:
        if ln[:indent].strip():
            raise SourceError(f"RFC {n}: {keyword} {name} is not indented "
                              f"consistently")
        body.append(ln[indent:].rstrip())
    return first + 1, last + 1, body


PRELUDE_HEAD = [
    " * XDR that the NFSv4 sources use but do not declare, because rpcgen",
    " * takes it from the C environment.  normalize.py reads this file",
    " * before each source (the `prelude` annotation).  Every definition",
    " * is copied by rule from pinned RFC text; see SOURCES.",
]
FRAGMENT_HEAD = [
    " * XDR that an RFC states in its prose but not in its `///` XDR,",
    " * copied by rule from the pinned RFC text; see SOURCES.  normalize.py",
    " * applies it as an `extension` of the minor versions that name it.",
    " * Code Components of the RFC: Simplified (Revised) BSD License, whose",
    " * text heads rfc8276.x; see THIRD-PARTY-LICENSES.md.",
]


def build_file(b, files, rfcs):
    out = [
        "/*",
        " * GENERATED by tools/nfs-proxy/schema/rfc_xdr.py from SOURCES -- "
        "DO NOT EDIT.",
        " *",
    ] + (PRELUDE_HEAD if b["kind"] == "prelude" else FRAGMENT_HEAD) + [
        " */",
    ]
    for kw, args in b["parts"]:
        out.append("")
        if kw == "typedefs":
            stated = [commented_typedefs(f, files[f]) for f in args]
            for f, s in zip(args[1:], stated[1:]):
                if s != stated[0]:
                    raise SourceError(f"{f} states other typedefs than "
                                      f"{args[0]}")
            out.append(f"/* {', '.join(args)}: stated only inside a "
                       f"comment */")
            out.extend(stated[0])
        else:
            n, keyword, name = args
            first, last, body = copy_definition(n, rfcs[n], keyword, name)
            out.append(f"/* RFC {n} lines {first}-{last} */")
            out.extend(body)
    return ("\n".join(out) + "\n").encode("ascii")


def rebuild(manifest, rfc_dir):
    """Every file the manifest describes, rebuilt from the pinned RFCs."""
    m = parse_manifest(manifest)
    rfcs = {n: load_rfc(n, pin, rfc_dir) for n, pin in m["rfc"].items()}
    files = {}
    for e in m["extract"]:
        files[e["file"]] = run_extract(e, rfcs[e["rfc"]])
    for b in m["built"]:
        for kw, args in b["parts"]:
            for f in args if kw == "typedefs" else ():
                if f not in files:
                    raise SourceError(f"typedefs: {f} is not extracted")
        files[b["file"]] = build_file(b, files, rfcs)
    return m, files


def pins(m):
    out = {e["file"]: e["sha256"] for e in m["extract"]}
    for b in m["built"]:
        out[b["file"]] = b["sha256"]
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("manifest")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--check", action="store_true")
    g.add_argument("--verify", action="store_true")
    g.add_argument("--write", action="store_true")
    ap.add_argument("--rfc-dir")
    a = ap.parse_args(argv)
    base = Path(a.manifest).parent
    bad = []
    try:
        if a.check:
            m = parse_manifest(a.manifest)
            for f, pin in pins(m).items():
                got = sha256((base / f).read_bytes())
                if got != pin:
                    bad.append(f"{f}: sha256 {got}, pinned {pin}")
        else:
            m, files = rebuild(a.manifest, a.rfc_dir)
            for f, data in files.items():
                if a.write:
                    (base / f).write_bytes(data)
                elif (base / f).read_bytes() != data:
                    bad.append(f"{f}: differs from what its RFC rule gives")
                if sha256(data) != pins(m)[f]:
                    bad.append(f"{f}: rebuilt sha256 {sha256(data)}, "
                               f"pinned {pins(m)[f]}")
    except (SourceError, OSError, UnicodeDecodeError) as e:
        print(f"rfc_xdr: {e}", file=sys.stderr)
        return 2
    for b in bad:
        print(f"rfc_xdr: {b}", file=sys.stderr)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
