#!/usr/bin/env python3
"""Pinned RFC XDR sources: extract, regenerate and verify.

WHAT THIS IS

  The NFSv4 XDR under schema/nfs4/ is not written by hand.  Each .x file is
  the output of the extraction script printed in its RFC, run on that RFC's
  plain text, and a SOURCES manifest pins the SHA-256 of every RFC text and
  of every file made from it.  This script is the only writer of those files.

  RFC 1813 (NFSv3) prints no extraction script: its XDR is spread through
  the prose, one definition at a time, and its size constants are stated
  as prose ("NFS3_FHSIZE 64").  schema/nfs3/nfs3.x is assembled from it by
  the same rules, one `copy` or `constant` line per definition.

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
  assemble FILE SHA256      FILE is a whole XDR source built from the
                            `copy` and `constant` lines that follow, in
                            order, for an RFC that prints its XDR only in
                            its prose (RFC 1813)
  typedefs FILE...          every `typedef` line each FILE states inside a
                            comment; the files must all state the same ones
                            (prelude only)
  copy N KEYWORD NAME [as NEW]
                            the definition of NAME in RFC N, which must occur
                            exactly once: `struct`/`enum NAME {`, `union NAME
                            switch (...) {` or `program NAME {` up to the
                            closing `}...;` at the same indentation, or the
                            one-line `typedef ... NAME...;` (which may occur
                            more than once if every occurrence is the same).
                            A page break inside is dropped only when it is a
                            whole one: the `[Page N]` footer, the form feed
                            and the `RFC N` running header.  `as NEW` renames
                            the definition, for a name the RFC itself uses
                            elsewhere (assemble only; the file says so)
  constant N NAME           `const NAME = V;` from the prose line `NAME V` of
                            RFC N, which must occur exactly once (assemble
                            only)

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
        elif kw in ("prelude", "fragment", "assemble"):
            args = rest.split()
            if len(args) != 2 or not hexpin.fullmatch(args[1]) or \
                    (kw == "prelude" and m["prelude"]):
                raise SourceError(f"{where}: one prelude FILE SHA256"
                                  if kw == "prelude" else
                                  f"{where}: {kw} FILE SHA256")
            if any(b["file"] == args[0] for b in m["built"]) or \
                    any(e["file"] == args[0] for e in m["extract"]):
                raise SourceError(f"{where}: {args[0]} is built twice")
            b = {"kind": kw, "file": args[0], "sha256": args[1],
                 "parts": []}
            m["built"].append(b)
            if kw == "prelude":
                m["prelude"] = b
        elif kw in ("typedefs", "copy", "constant"):
            args = rest.split()
            if not m["built"]:
                raise SourceError(f"{where}: {kw} before prelude, "
                                  f"fragment or assemble")
            into = m["built"][-1]["kind"]
            if kw == "copy" and not (
                    len(args) == 3 or
                    (len(args) == 5 and args[3] == "as" and
                     into == "assemble")):
                raise SourceError(f"{where}: copy N KEYWORD NAME"
                                  + (" [as NEW]" if into == "assemble"
                                     else ""))
            if kw == "copy" and args[1] not in COPY_KEYWORDS:
                raise SourceError(f"{where}: copy of a {args[1]}")
            if kw == "constant" and (len(args) != 2 or
                                     into != "assemble"):
                raise SourceError(f"{where}: constant N NAME in an "
                                  f"assemble")
            if kw == "typedefs" and (not args or into != "prelude"):
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
            if kw in ("copy", "constant") and args[0] not in m["rfc"]:
                raise SourceError(f"{path}: {kw}: RFC {args[0]} is not "
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


COPY_KEYWORDS = ("struct", "enum", "union", "program", "typedef")
_FOOTER = re.compile(r"\[Page \d+\]\s*$")


def _page_break(lines, i, n):
    """The number of lines of a whole page break starting at lines[i], the
    footer, or 0.  Only footer, form feed and running header make one; the
    header may share the form feed's line."""
    if not _FOOTER.search(lines[i]) or i + 1 >= len(lines) or \
            not lines[i + 1].startswith("\f"):
        return 0
    j = i + 1 if lines[i + 1] != "\f" else i + 2
    if j < len(lines) and lines[j].lstrip("\f").startswith(f"RFC {n} "):
        return j + 1 - i
    return 0


def _join_pages(n, lines, first, keyword, name):
    """lines[first:] up to the definition's end with whole page breaks and
    the blank lines around them dropped.  Returns (last, body) where last
    is the index of the definition's final line."""
    indent = len(lines[first]) - len(lines[first].lstrip(" "))
    out, i = [], first
    while i < len(lines):
        ln = lines[i]
        if "\f" in ln or _FOOTER.search(ln):
            k = _page_break(lines, i, n)
            if not k:
                raise SourceError(f"RFC {n}: {keyword} {name} spans a "
                                  f"page break that is not whole")
            while out and not out[-1].strip():
                out.pop()
            i += k
            while i < len(lines) and not lines[i].strip():
                i += 1
            continue
        if ln.strip() and ln[:indent].strip():
            raise SourceError(f"RFC {n}: {keyword} {name} is not indented "
                              f"consistently")
        out.append(ln[indent:].rstrip())
        if i > first and len(ln) - len(ln.lstrip(" ")) == indent and \
                re.fullmatch(r"\}(\s*=\s*\w+)?\s*;", ln.strip()):
            return i, out
        i += 1
    raise SourceError(f"RFC {n}: {keyword} {name} has no `}};`")


def copy_definition(n, rfc_text, keyword, name):
    lines = rfc_text.decode("utf-8-sig").split("\n")
    if keyword == "typedef":
        decl = re.compile(r"typedef\s.*\b" + re.escape(name) +
                          r"\s*(\[[^\]]*\]|<[^>]*>)?\s*;")
        found = [(i, " ".join(ln.split())) for i, ln in enumerate(lines)
                 if decl.fullmatch(ln.strip())]
        if not found or len({t for _, t in found}) != 1:
            raise SourceError(f"RFC {n}: `typedef ... {name};` occurs "
                              f"{len(found)} times, differently"
                              if found else
                              f"RFC {n}: `typedef ... {name};` occurs 0 "
                              f"times")
        return found[0][0] + 1, found[0][0] + 1, [found[0][1]]
    if keyword == "union":
        head = re.compile(r"union " + re.escape(name) +
                          r" switch \(.*\) \{")
    else:
        head = re.compile(re.escape(f"{keyword} {name} {{"))
    starts = [i for i, ln in enumerate(lines) if head.fullmatch(ln.strip())]
    if len(starts) != 1:
        raise SourceError(f"RFC {n}: `{keyword} {name}` occurs "
                          f"{len(starts)} times")
    last, body = _join_pages(n, lines, starts[0], keyword, name)
    return starts[0] + 1, last + 1, body


def prose_constant(n, rfc_text, name):
    lines = rfc_text.decode("utf-8-sig").split("\n")
    rx = re.compile(re.escape(name) + r" (\d+)")
    found = [(i, m.group(1)) for i, m in
             ((i, rx.fullmatch(ln.strip())) for i, ln in enumerate(lines))
             if m]
    if len(found) != 1:
        raise SourceError(f"RFC {n}: `{name} N` occurs {len(found)} times")
    return found[0][0] + 1, f"const {name} = {found[0][1]};"


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
ASSEMBLE_HEAD = [
    " * XDR that an RFC prints only in its prose, one definition at a time,",
    " * assembled by rule from the pinned RFC text in the order SOURCES",
    " * lists it.  Each definition is copied verbatim, dedented, with whole",
    " * page breaks dropped; a size constant the RFC states as prose",
    " * (`NAME V`) becomes `const NAME = V;`.  See SOURCES.",
]


def build_file(b, files, rfcs):
    out = [
        "/*",
        " * GENERATED by tools/nfs-proxy/schema/rfc_xdr.py from SOURCES -- "
        "DO NOT EDIT.",
        " *",
    ] + {"prelude": PRELUDE_HEAD, "fragment": FRAGMENT_HEAD,
         "assemble": ASSEMBLE_HEAD}[b["kind"]] + [
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
        elif kw == "constant":
            n, name = args
            line, decl = prose_constant(n, rfcs[n], name)
            out.append(f"/* RFC {n} line {line}, stated as prose */")
            out.append(decl)
        else:
            n, keyword, name = args[:3]
            first, last, body = copy_definition(n, rfcs[n], keyword, name)
            where = (f"line {first}" if first == last else
                     f"lines {first}-{last}")
            if len(args) == 5:
                new = args[4]
                old = f"{keyword} {name}"
                if not body[0].startswith(old + " "):
                    raise SourceError(f"RFC {n}: cannot rename {name}")
                body[0] = f"{keyword} {new}" + body[0][len(old):]
                out.append(f"/* RFC {n} {where}, renamed from {name} */")
            else:
                out.append(f"/* RFC {n} {where} */")
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
