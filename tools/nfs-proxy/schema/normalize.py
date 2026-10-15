#!/usr/bin/env python3
"""Protocol Schema Normalizer: pinned XDR + semantic annotations -> C tables.

WHAT THIS IS

  The build-time half of the NFS Semantic Decoder (design 03-nfs-proxy/02 §1,
  §3, §4).  It reads XDR source (RFC 4506 language, plus the RFC 5531 `program`
  definition) and a small annotation file, and writes one C file of constant
  tables per protocol family.  The proxy's runtime decoder (src/nfs_decode.c)
  interprets those tables; it never sees XDR text.

  Wire layout comes only from the XDR.  The annotation file never restates a
  field, an offset or a width.  It names the family, the program/version to
  expose, which unions are COMPOUND operation boundaries, and short branch
  names for union case labels.  Everything else in a semantic path is an XDR
  identifier.

  Names an XDR source uses but takes from rpcgen's C environment (the NFSv4
  basic typedefs, authsys_parms) come from a `prelude` file read before it,
  which rfc_xdr.py builds from pinned RFC text like the sources themselves.

  NFSv4 extensions (RFC 8178), such as RFC 8276 and RFC 9754 for 4.2, are
  `extension` files applied after a minor version's source by fixed rules
  (Parser.extend); `alias-arm` is the one annotation that states a layout
  fact, for a case value an extension declares without an arm.

WHAT IT REFUSES

  Anything the runtime cannot decode with a proven boundary is a build error,
  not a runtime guess: float/double/quadruple, type cycles other than the
  XDR linked-list idiom (`struct T { ...; T *next; }`), optional-data outside
  that idiom, arrays of zero-size elements, union case values that are not
  members of the discriminant's type, duplicate case values, and nesting
  deeper than the runtime's fixed limit.

  A semantic path must name one position in the schema (array and list
  elements and repeated operations repeat it), so anything that would give
  two positions one path is refused too: duplicate struct members or
  procedure names, a union arm whose branch repeats the discriminant's name,
  two arm declarations sharing a branch, one union named as the operation
  of both directions, and the rest that schema/README.md lists.  A path must
  also name a position some message carries, so a non-void procedure beside
  the minor-version selector, a non-void default arm that no discriminant
  value selects, and an array of bound 0 are refused as well.

  The parser reads every declaration in a file, so its refusals (syntax,
  float/double/quadruple, multi-argument procedures, duplicate member or
  procedure names) apply even to declarations nothing reaches.  The other
  checks see only what an exposed procedure reaches.

DETERMINISM

  Same XDR + same annotations => byte-identical output.  Types are numbered in
  reachability order from the exposed procedures, so unreferenced
  declarations (for example the callback program in an NFSv4 .x file) do not
  appear and do not perturb indices.  schema_id is the SHA-256 of the
  canonical JSON of the normalized schema, so it changes exactly when decode
  behaviour or a semantic path can change, and not when an XDR comment does.

USAGE

  normalize.py ANNOTATION --out FILE.c     write the tables
  normalize.py ANNOTATION --check FILE.c   fail if FILE.c is stale
  normalize.py ANNOTATION --json           print the normalized schemas
"""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

FORMAT = "nfsp-protocol-schema/1"
UNBOUNDED = 0xFFFFFFFF
# Must match NFSP_DECODE_MAX_DEPTH in src/nfs_decode.h.
MAX_DEPTH = 64
NONE = 0xFFFF
# A path word an annotation supplies: no `.` or `[]`, so a path still splits
# back into the words that built it.
IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
# RFC 8276's instruction for lines to splice into an existing definition.
ADDITION = re.compile(r"/\*\s*Following lines are to be added to\s+"
                      r"(?:(enum|union)\s+)?([A-Za-z_]\w*)\s*\*/\s*"
                      r"/\*[ \t]*\n(.*?)\n[ \t]*\*/", re.S)


class SchemaError(Exception):
    pass


# ---------------------------------------------------------------- lexer

_TOKEN = re.compile(r"""
    (?P<ws>\s+)
  | (?P<comment>/\*.*?\*/)
  | (?P<num>-?(?:0[xX][0-9a-fA-F]+|[0-9]+))
  | (?P<ident>[A-Za-z_][A-Za-z0-9_]*)
  | (?P<punct>[{}()\[\]<>;:,=*])
""", re.X | re.S)

KEYWORDS = {
    "bool", "case", "const", "default", "double", "quadruple", "enum",
    "float", "hyper", "int", "opaque", "string", "struct", "switch",
    "typedef", "union", "unsigned", "void", "program", "version",
}


def tokenize(text, origin):
    # `%` lines are rpcgen pass-through (RFC 5531 §12 implementations use
    # them for C headers); they carry no XDR and are dropped.
    lines = [("" if ln.lstrip().startswith("%") else ln)
             for ln in text.split("\n")]
    text = "\n".join(lines)
    pos, line, out = 0, 1, []
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m:
            raise SchemaError(f"{origin}:{line}: unexpected character "
                              f"{text[pos]!r}")
        kind = m.lastgroup
        val = m.group(kind)
        if kind not in ("ws", "comment"):
            out.append((kind, val, line))
        line += val.count("\n")
        pos = m.end()
    out.append(("eof", "", line))
    return out


def parse_int(tok):
    neg = tok.startswith("-")
    body = tok[1:] if neg else tok
    try:
        if body.lower().startswith("0x"):
            v = int(body, 16)
        elif len(body) > 1 and body.startswith("0"):
            v = int(body, 8)
        else:
            v = int(body, 10)
    except ValueError:
        raise SchemaError(f"bad number {tok!r}") from None
    return -v if neg else v


# ---------------------------------------------------------------- parser
#
# AST:
#   TypeSpec  ("int"|"uint"|"hyper"|"uhyper"|"bool"|"void"|"opaque"|"string",)
#             ("ref", name) | ("enum", [(name, Value)]) |
#             ("struct", [Decl]) | ("union", Decl, [([Value], Decl)], Decl?)
#   Decl      dict(name, spec, shape) shape in plain|fixed|var|optional,
#             with "size" (Value or None for <>)
#   Value     ("lit", int) | ("id", name)

class Parser:
    def __init__(self, toks, origin):
        self.t = toks
        self.i = 0
        self.origin = origin
        self.consts = {}         # name -> Value
        self.types = {}          # name -> (kind, payload); kind typedef|spec
        self.enumconsts = {}     # enum constant -> Value
        self.programs = {}       # name -> {"number", "versions"}
        self.extending = False   # inside extend()
        self.widening = None     # the enum an extension is restating
        self.base_enums = {}     # enum -> values as the source declared them
        self.order = []          # declaration order of type names

    def err(self, msg):
        _, val, line = self.t[self.i]
        raise SchemaError(f"{self.origin}:{line}: {msg} (at {val!r})")

    def peek(self, k=0):
        return self.t[self.i + k]

    def take(self, kind=None, val=None):
        tk = self.t[self.i]
        if kind and tk[0] != kind:
            self.err(f"expected {kind}")
        if val is not None and tk[1] != val:
            self.err(f"expected {val!r}")
        self.i += 1
        return tk[1]

    def accept(self, val):
        if self.t[self.i][1] == val and self.t[self.i][0] != "eof":
            self.i += 1
            return True
        return False

    def ident(self):
        tk = self.t[self.i]
        if tk[0] != "ident" or tk[1] in KEYWORDS:
            self.err("expected identifier")
        self.i += 1
        return tk[1]

    def value(self):
        tk = self.t[self.i]
        if tk[0] == "num":
            self.i += 1
            return ("lit", parse_int(tk[1]))
        return ("id", self.ident())

    def define(self, name, entry):
        if self.widening == name:
            # An extension restates an enum with more values (RFC 9754
            # open_delegation_type4; RFC 8435 and RFC 8154 layouttype4).
            # Each restates the enum as the source declared it plus its own
            # values, so every value of the source must stay as it was, and
            # the enum becomes the union of all restatements, whatever their
            # order.  One name with two values, or one value with two
            # names, is an error.
            cur = list(self.types[name][1][1])
            base = self.base_enums.setdefault(name, list(cur))
            new = dict(entry[1][1])
            if any(new.get(n) != v for n, v in base):
                self.err(f"extension of enum {name} changes or drops a "
                         f"value of the source")
            have = dict(cur)
            for n, v in entry[1][1]:
                if n in have:
                    if have[n] != v:
                        self.err(f"extension of enum {name} gives {n} "
                                 f"another value")
                    continue
                cur.append((n, v))
                have[n] = v
            values = [self.resolve_lit(v) for _, v in cur]
            if len(set(values)) != len(values):
                self.err(f"extension of enum {name} gives one value two "
                         f"names")
            self.types[name] = ("spec", ("enum", cur))
            return
        if name in self.types or name in self.consts or \
                name in self.enumconsts:
            self.err(f"redefinition of {name}")
        self.types[name] = entry
        self.order.append(name)

    def resolve_lit(self, v, seen=()):
        """An enum value as a number where the namespace already has it,
        for comparing values; an unknown name stays as it is."""
        while v[0] == "id" and v[1] not in seen:
            seen = seen + (v[1],)
            nxt = self.consts.get(v[1], self.enumconsts.get(v[1]))
            if nxt is None:
                return v
            v = nxt
        return v[1] if v[0] == "lit" else v

    def include(self, toks, origin):
        """Parse another file into the same namespace (a prelude, then the
        source).  A name defined twice is still a redefinition error."""
        self.t, self.i, self.origin = toks, 0, origin
        return self.parse()

    def extend(self, text, origin):
        """Apply an NFSv4 extension file (RFC 8178) on top of the source:
        new definitions join the namespace, an enum restated with more
        values replaces the old one, and the RFC's own instruction blocks

            /* Following lines are to be added to [enum|union] NAME */
            /*
            ...lines...
            */

        add their lines to NAME (RFC 8276).  Nothing else may change an
        existing definition."""
        additions = []

        def take_block(m):
            lines = []
            for ln in m.group(3).split("\n"):
                ln = re.sub(r"/\*.*?\*/", "", ln).strip()
                if ln:
                    lines.append(ln)
            line = text.count("\n", 0, m.start()) + 1
            additions.append((m.group(1), m.group(2), " ".join(lines), line))
            return "\n" * m.group(0).count("\n")

        rest = ADDITION.sub(take_block, text)
        self.extending = True
        try:
            self.include(tokenize(rest, origin), origin)
        finally:
            self.extending = False
        for kind, name, body, line in additions:
            where = f"{origin}:{line}"
            entry = self.types.get(name)
            if entry is None or entry[0] != "spec" or \
                    entry[1][0] not in ("enum", "union") or \
                    (kind and entry[1][0] != kind):
                raise SchemaError(f"{where}: no {kind or 'enum or union'} "
                                  f"{name} to add to")
            p = Parser(tokenize(body, origin), origin)
            p.consts, p.types, p.enumconsts = \
                self.consts, self.types, self.enumconsts
            if entry[1][0] == "enum":
                vals = list(entry[1][1])
                while p.peek()[0] != "eof":
                    n = p.ident()
                    p.take(val="=")
                    v = p.value()
                    if n in self.enumconsts or n in self.consts:
                        raise SchemaError(f"{where}: redefinition of {n}")
                    self.enumconsts[n] = v
                    vals.append((n, v))
                    p.accept(",")
                self.types[name] = ("spec", ("enum", vals))
            else:
                _, disc, arms, default = entry[1]
                arms = list(arms)
                while p.peek()[0] != "eof":
                    labels = []
                    while p.accept("case"):
                        labels.append(p.value())
                        p.take(val=":")
                    if not labels:
                        p.err("expected case")
                    d = p.decl()
                    p.take(val=";")
                    arms.append((labels, d))
                self.types[name] = ("spec", ("union", disc, arms, default))
        return self

    def parse(self):
        while self.peek()[0] != "eof":
            w = self.peek()[1]
            if w == "const":
                self.take()
                name = self.ident()
                self.take(val="=")
                v = self.value()
                self.take(val=";")
                if name in self.consts or name in self.enumconsts:
                    self.err(f"redefinition of {name}")
                self.consts[name] = v
            elif w == "typedef":
                self.take()
                d = self.decl()
                if d["spec"] == ("void",):
                    self.err("typedef of void")
                self.take(val=";")
                self.define(d["name"], ("typedef", d))
            elif w in ("enum", "struct", "union"):
                self.take()
                name = self.ident()
                old = self.types.get(name)
                if self.extending and w == "enum" and old is not None and \
                        old[0] == "spec" and old[1][0] == "enum":
                    self.widening = name
                try:
                    spec = self.body(w)
                    self.take(val=";")
                    self.define(name, ("spec", spec))
                finally:
                    self.widening = None
            elif w == "program":
                self.program()
            else:
                self.err("expected a definition")
        return self

    def body(self, kind):
        if kind == "enum":
            self.take(val="{")
            vals = []
            while True:
                n = self.ident()
                self.take(val="=")
                v = self.value()
                restated = self.widening is not None and \
                    (n, v) in self.types[self.widening][1][1]
                if (n in self.enumconsts or n in self.consts) and \
                        not restated:
                    self.err(f"redefinition of {n}")
                self.enumconsts[n] = v
                vals.append((n, v))
                if not self.accept(","):
                    break
            self.take(val="}")
            return ("enum", vals)
        if kind == "struct":
            self.take(val="{")
            fields = []
            while not self.accept("}"):
                d = self.decl()
                self.take(val=";")
                if d["spec"] == ("void",):
                    self.err("void struct member")
                if any(f["name"] == d["name"] for f in fields):
                    # RFC 4506 §6.4; it would also be one path for two
                    # nodes
                    self.err(f"duplicate member {d['name']}")
                fields.append(d)
            if not fields:
                self.err("empty struct")
            return ("struct", fields)
        # union
        self.take(val="switch")
        self.take(val="(")
        disc = self.decl()
        self.take(val=")")
        self.take(val="{")
        arms, default = [], None
        while True:
            if self.accept("default"):
                self.take(val=":")
                default = self.decl()
                self.take(val=";")
                self.take(val="}")
                break
            if self.accept("}"):
                break
            labels = []
            while self.accept("case"):
                labels.append(self.value())
                self.take(val=":")
            if not labels:
                self.err("expected case or default")
            d = self.decl()
            self.take(val=";")
            arms.append((labels, d))
        if not arms:
            self.err("union without cases")
        return ("union", disc, arms, default)

    def typespec(self):
        w = self.peek()[1]
        if self.peek()[0] != "ident":
            self.err("expected type")
        if w == "unsigned":
            self.take()
            if self.accept("int"):
                return ("uint",)
            if self.accept("hyper"):
                return ("uhyper",)
            return ("uint",)          # bare `unsigned` (RFC 4506 §6.3)
        if w in ("int", "hyper", "bool", "void", "opaque", "string"):
            self.take()
            return {"int": ("int",), "hyper": ("hyper",), "bool": ("bool",),
                    "void": ("void",), "opaque": ("opaque",),
                    "string": ("string",)}[w]
        if w in ("float", "double", "quadruple"):
            self.err(f"{w} is not supported: no NFS XDR uses it and the "
                     f"runtime has no decoder for it")
        if w in ("enum", "struct", "union"):
            self.take()
            if self.peek()[1] == "{" or (w == "union" and
                                          self.peek()[1] == "switch"):
                return self.body(w)
            return ("ref", self.ident())   # C-style `struct name`
        return ("ref", self.ident())

    def decl(self):
        spec = self.typespec()
        if spec == ("void",):
            return {"name": None, "spec": spec, "shape": "plain",
                    "size": None}
        if self.accept("*"):
            # opaque and string are not type-specifiers (RFC 4506 §6.3), so
            # they have no optional-data form; without this they would
            # silently become opaque<> and string<>.
            if spec == ("opaque",):
                self.err("opaque must be declared with [] or <>")
            if spec == ("string",):
                self.err("string must be declared with <>")
            return {"name": self.ident(), "spec": spec, "shape": "optional",
                    "size": None}
        name = self.ident()
        if self.accept("["):
            size = self.value()
            self.take(val="]")
            shape = "fixed"
        elif self.accept("<"):
            size = None if self.peek()[1] == ">" else self.value()
            self.take(val=">")
            shape = "var"
        else:
            shape, size = "plain", None
        if spec == ("string",) and shape != "var":
            self.err("string must be declared with <>")
        if spec == ("opaque",) and shape not in ("fixed", "var"):
            self.err("opaque must be declared with [] or <>")
        return {"name": name, "spec": spec, "shape": shape, "size": size}

    def program(self):
        self.take(val="program")
        pname = self.ident()
        self.take(val="{")
        versions = {}
        while self.accept("version"):
            vname = self.ident()
            self.take(val="{")
            procs = []
            while not self.accept("}"):
                ret = self.proc_type()
                proc = self.ident()
                if any(p["name"] == proc for p in procs):
                    self.err(f"duplicate procedure {proc}")
                self.take(val="(")
                arg = self.proc_type()
                if self.peek()[1] == ",":
                    self.err("multi-argument procedures are not supported")
                self.take(val=")")
                self.take(val="=")
                num = self.value()
                self.take(val=";")
                procs.append({"name": proc, "arg": arg, "res": ret,
                              "number": num})
            self.take(val="=")
            vnum = self.value()
            self.take(val=";")
            versions[vname] = {"number": vnum, "procs": procs}
        self.take(val="}")
        self.take(val="=")
        num = self.value()
        self.take(val=";")
        self.programs[pname] = {"number": num, "versions": versions}

    def proc_type(self):
        spec = self.typespec()
        if spec[0] not in ("void", "ref", "int", "uint", "hyper", "uhyper",
                           "bool"):
            self.err("procedure argument/result must be a named type")
        return spec


# ---------------------------------------------------------------- annotations

def parse_annotations(path):
    """Line-oriented: `keyword args...`, `#` comments.  See tools/nfs-proxy/
    schema/README.md for the grammar."""
    ann = {"family": None, "program": None, "procedure_prefix": "",
           "leaf": ("args", "result"), "operations": {}, "status_type": None,
           "minor_field": None, "minors": [], "branches": {}, "source": None,
           "preludes": [], "notice": [], "extensions": [], "aliases": {}}
    for no, raw in enumerate(Path(path).read_text().split("\n"), 1):
        line = raw.split("#", 1)[0].split()
        if not line:
            continue
        kw, args = line[0], line[1:]
        where = f"{path}:{no}"

        def want(n):
            if len(args) != n:
                raise SchemaError(f"{where}: {kw} takes {n} argument(s)")

        if kw == "family":
            want(1)
            if not re.fullmatch(r"[a-z][a-z0-9]*", args[0]):
                raise SchemaError(f"{where}: family must be [a-z][a-z0-9]*")
            ann["family"] = args[0]
        elif kw == "program":
            want(2)
            ann["program"] = tuple(args)
        elif kw == "procedure-prefix":
            want(1)
            ann["procedure_prefix"] = args[0]
        elif kw == "leaf":
            want(2)
            for leaf in args:
                if not IDENT.fullmatch(leaf):
                    raise SchemaError(f"{where}: leaf must be an identifier")
            ann["leaf"] = tuple(args)
        elif kw == "operation":
            want(4)
            direction, union, leaf, prefix = args
            if direction not in ("request", "response"):
                raise SchemaError(f"{where}: direction must be request or "
                                  f"response")
            if not IDENT.fullmatch(leaf):
                raise SchemaError(f"{where}: leaf must be an identifier")
            if direction in ann["operations"]:
                raise SchemaError(f"{where}: second {direction} operation")
            ann["operations"][direction] = (union, leaf, prefix)
        elif kw == "status-type":
            want(1)
            ann["status_type"] = args[0]
        elif kw == "minor-field":
            want(2)
            ann["minor_field"] = tuple(args)
        elif kw == "minor":
            want(2)
            ann["minors"].append((int(args[0]), args[1]))
        elif kw == "source":
            want(1)
            ann["source"] = args[0]
        elif kw == "prelude":
            want(1)
            ann["preludes"].append(args[0])
        elif kw == "extension":
            want(2)
            ann["extensions"].append((int(args[0]), args[1]))
        elif kw == "alias-arm":
            want(3)
            union, label, like = args
            arms = ann["aliases"].setdefault(union, [])
            if any(a[0] == label for a in arms):
                raise SchemaError(f"{where}: second alias-arm for {label}")
            arms.append((label, like))
        elif kw == "notice":
            if not args:
                raise SchemaError(f"{where}: notice takes text")
            ann["notice"].append(" ".join(args))
        elif kw == "branch":
            want(2)
            if not re.fullmatch(r"[a-z][a-z0-9_]*", args[1]):
                raise SchemaError(f"{where}: branch name must be "
                                  f"[a-z][a-z0-9_]*")
            if args[0] in ann["branches"]:
                raise SchemaError(f"{where}: second branch for {args[0]}")
            ann["branches"][args[0]] = args[1]
        else:
            raise SchemaError(f"{where}: unknown keyword {kw}")
    if not ann["family"] or not ann["program"]:
        raise SchemaError(f"{path}: family and program are required")
    if bool(ann["minors"]) == bool(ann["source"]):
        raise SchemaError(f"{path}: give either one `source` or `minor` "
                          f"lines")
    if ann["minors"] and not ann["minor_field"]:
        raise SchemaError(f"{path}: `minor` needs `minor-field`")
    if ann["minor_field"] and not ann["minors"]:
        raise SchemaError(f"{path}: `minor-field` needs `minor` lines")
    minors = [m for m, _ in ann["minors"]]
    if len(set(minors)) != len(minors):
        raise SchemaError(f"{path}: duplicate minor version")
    return ann


# ---------------------------------------------------------------- normalizer

def u32(v, what):
    if not -(1 << 31) <= v < (1 << 32):
        raise SchemaError(f"{what}: {v} does not fit 32 bits")
    return v & 0xFFFFFFFF


class Normalizer:
    """One XDR specification + annotations -> one normalized schema."""

    def __init__(self, spec, ann, minor):
        self.p = spec
        self.ann = ann
        self.minor = minor
        self.prefix_layout = None
        self.nodes = []          # list of dict, index = type id
        self.by_name = {}        # named type -> index (also in-progress)
        self.by_key = {}         # structural key -> index (anonymous)
        self.used_branches = set()
        self.used_aliases = set()

    # -- values

    def resolve(self, v, seen=()):
        if v[0] == "lit":
            return v[1]
        name = v[1]
        if name in ("TRUE", "FALSE") and name not in self.p.consts and \
                name not in self.p.enumconsts:
            return 1 if name == "TRUE" else 0
        if name in seen:
            raise SchemaError(f"constant cycle through {name}")
        if name in self.p.consts:
            return self.resolve(self.p.consts[name], seen + (name,))
        if name in self.p.enumconsts:
            return self.resolve(self.p.enumconsts[name], seen + (name,))
        raise SchemaError(f"undefined constant {name}")

    # -- nodes

    def add(self, node, key=None):
        if key is not None and key in self.by_key:
            return self.by_key[key]
        self.nodes.append(node)
        idx = len(self.nodes) - 1
        if idx >= NONE:
            raise SchemaError("too many types for a 16-bit index")
        if key is not None:
            self.by_key[key] = idx
        return idx

    def prim(self, kind):
        names = {"int": "int", "uint": "unsigned int", "hyper": "hyper",
                 "uhyper": "unsigned hyper", "bool": "bool"}
        return self.add({"kind": kind, "name": names[kind]}, ("prim", kind))

    def named(self, name):
        if name in self.by_name:
            return self.by_name[name]
        if name not in self.p.types:
            raise SchemaError(f"undefined type {name}")
        kind, payload = self.p.types[name]
        if kind == "typedef":
            d = payload
            if d["shape"] == "plain" and d["spec"][0] in (
                    "ref", "int", "uint", "hyper", "uhyper", "bool"):
                # A plain alias names the same wire type.  It does not get a
                # node of its own; the first name to reach a node keeps it.
                self.by_name[name] = None        # cycle guard
                idx = self.spec(d["spec"], name)
                self.by_name[name] = idx
                return idx
            self.by_name[name] = None
            idx = self.shaped(d, name)
            self.by_name[name] = idx
            return idx
        spec = payload
        if spec[0] in ("struct", "union"):
            # Reserve the index before the members so a self-reference
            # (the linked-list idiom) resolves to this node.
            idx = self.add({"kind": spec[0], "name": name})
            self.by_name[name] = idx
            self.fill(idx, spec, name)
            return idx
        idx = self.spec(spec, name)
        self.by_name[name] = idx
        return idx

    def spec(self, spec, name=None):
        k = spec[0]
        if k in ("int", "uint", "hyper", "uhyper", "bool"):
            return self.prim(k)
        if k == "ref":
            idx = self.named(spec[1])
            if idx is None:
                raise SchemaError(f"type {spec[1]} is defined through itself")
            return idx
        if k == "enum":
            vals = []
            for n, v in spec[1]:
                vals.append((n, u32(self.resolve(v), f"enum {name}.{n}")))
            return self.add({"kind": "enum", "name": name, "values": vals},
                            None if name else ("enum", tuple(vals)))
        if k in ("struct", "union"):
            idx = self.add({"kind": k, "name": name})
            self.fill(idx, spec, name)
            return idx
        raise SchemaError(f"type {k} cannot appear here")

    def shaped(self, d, name=None):
        spec, shape = d["spec"], d["shape"]
        where = f"{name or d['name']}"
        size = None
        if d["size"] is not None:
            size = self.resolve(d["size"])
            if not 0 <= size <= UNBOUNDED:
                raise SchemaError(f"{where}: size {size} out of range")
        if spec == ("opaque",):
            kind = "opaque_fixed" if shape == "fixed" else "opaque_var"
            bound = size if size is not None else UNBOUNDED
            return self.add({"kind": kind, "name": name, "bound": bound},
                            None if name else (kind, bound))
        if spec == ("string",):
            bound = size if size is not None else UNBOUNDED
            return self.add({"kind": "string", "name": name, "bound": bound},
                            None if name else ("string", bound))
        if shape == "plain":
            if name is None:
                return self.spec(spec)
            # `typedef struct {...} name;` and friends
            return self.spec(spec, name)
        sub = self.spec(spec)
        if shape == "optional":
            return self.add({"kind": "optional", "name": name, "sub": sub},
                            None if name else ("optional", sub))
        kind = "array_fixed" if shape == "fixed" else "array_var"
        bound = size if size is not None else UNBOUNDED
        if bound == 0:
            # Its count is always 0, so `<array>[]` would name an element
            # no message carries.
            raise SchemaError(f"{where}: an array of bound 0 has no element")
        return self.add({"kind": kind, "name": name, "sub": sub,
                         "bound": bound},
                        None if name else (kind, sub, bound))

    def decl_type(self, d):
        return self.shaped(d)

    def fill(self, idx, spec, name):
        node = self.nodes[idx]
        if spec[0] == "struct":
            fields = []
            decls = spec[1]
            for n, d in enumerate(decls):
                if d["shape"] == "optional" and n == len(decls) - 1 and \
                        name is not None and \
                        self.ref_target(d["spec"]) == name:
                    # struct T { ...; T *next; }: the XDR linked list.
                    node["listed"] = d["name"]
                    continue
                fields.append((d["name"], self.decl_type(d)))
            if not fields:
                raise SchemaError(f"struct {name}: no members besides the "
                                  f"list link")
            node["fields"] = fields
            node["listed"] = node.get("listed")
            return
        _, disc, arms, default = spec
        if disc["shape"] != "plain":
            raise SchemaError(f"union {name}: discriminant must be plain")
        dt = self.decl_type(disc)
        dk = self.nodes[dt]["kind"]
        if dk not in ("int", "uint", "enum", "bool"):
            raise SchemaError(f"union {name}: discriminant of kind {dk}")
        node["disc"] = (disc["name"], dt)
        out = []
        seen = set()
        for labels, d in arms:
            t = None if d["spec"] == ("void",) else self.decl_type(d)
            for lab in labels:
                v = self.case_value(name, dt, lab)
                if v in seen:
                    raise SchemaError(f"union {name}: duplicate case {v}")
                seen.add(v)
                out.append({"value": v, "label": self.label_text(lab),
                            "decl": d["name"], "type": t})
        for label, like in self.ann["aliases"].get(name, ()):
            # alias-arm: a case value the XDR declares without an arm, which
            # implementations encode with another case's arm (README).  Only
            # where the label exists; normalize() refuses one used nowhere.
            if label not in self.p.enumconsts and label not in self.p.consts:
                continue
            v = self.case_value(name, dt, ("id", label))
            if v in seen:
                raise SchemaError(f"union {name}: alias-arm {label} already "
                                  f"has an arm")
            target = [a for a in out if a["label"] == like]
            if not target:
                raise SchemaError(f"union {name}: alias-arm {label}: no arm "
                                  f"for {like}")
            seen.add(v)
            out.append({"value": v, "label": label,
                        "decl": target[0]["decl"], "type": target[0]["type"]})
            self.used_aliases.add((name, label))
        if len(out) + (default is not None) > NONE:
            # An arm index, the default's included, is a uint16_t, and
            # NFSP_SCHEMA_NONE (0xffff) means "no default": the runtime
            # would skip an arm at that index.
            raise SchemaError(f"union {name}: too many case labels for a "
                              f"16-bit arm index")
        node["arms"] = out
        if default is not None:
            t = None if default["spec"] == ("void",) else \
                self.decl_type(default)
            node["default"] = {"label": "default", "decl": default["name"],
                               "type": t}
            # The decoder refuses a discriminant its type does not declare,
            # so when every value has a case the default is never decoded,
            # and `<union>.default` would name a value no message carries.
            # A void default names nothing.
            if t is not None and self.covered(dt, seen):
                raise SchemaError(f"union {name}: every {dk} value has a "
                                  f"case, so the default arm is never "
                                  f"decoded")
        else:
            node["default"] = None

    def covered(self, dt, seen):
        node = self.nodes[dt]
        if node["kind"] == "bool":
            return {0, 1} <= seen
        if node["kind"] == "enum":
            return {v for _, v in node["values"]} <= seen
        return False

    def ref_target(self, spec):
        # Follow plain typedef aliases to the struct name they denote.
        seen = set()
        while spec[0] == "ref":
            name = spec[1]
            if name in seen:
                raise SchemaError(f"type {name} is defined through itself")
            seen.add(name)
            kind, payload = self.p.types.get(name, (None, None))
            if kind == "typedef" and payload["shape"] == "plain":
                spec = payload["spec"]
                continue
            return name
        return None

    def label_text(self, lab):
        return lab[1] if lab[0] == "id" else str(lab[1])

    def case_value(self, uname, dt, lab):
        node = self.nodes[dt]
        v = self.resolve(lab)
        where = f"union {uname}: case {self.label_text(lab)}"
        if node["kind"] == "enum":
            v = u32(v, where)
            if v not in {x for _, x in node["values"]}:
                raise SchemaError(f"{where} is not a member of "
                                  f"{node['name'] or 'its enum'}")
            return v
        if node["kind"] == "bool":
            if v not in (0, 1):
                raise SchemaError(f"{where}: not a bool")
            return v
        if node["kind"] == "int" and not -(1 << 31) <= v < (1 << 31):
            raise SchemaError(f"{where}: out of int range")
        if node["kind"] == "uint" and not 0 <= v < (1 << 32):
            raise SchemaError(f"{where}: out of unsigned int range")
        return v & 0xFFFFFFFF

    # -- whole schema

    def run(self):
        pname, vname = self.ann["program"]
        prog = self.p.programs.get(pname)
        if prog is None:
            raise SchemaError(f"program {pname} not in the XDR")
        ver = prog["versions"].get(vname)
        if ver is None:
            raise SchemaError(f"version {vname} not in program {pname}")
        procs = []
        prefix = self.ann["procedure_prefix"]
        for pr in sorted(ver["procs"], key=lambda x: self.resolve(x["number"])):
            nm = pr["name"]
            if prefix and not nm.startswith(prefix):
                raise SchemaError(f"procedure {nm} lacks prefix {prefix}")
            if nm == prefix:
                raise SchemaError(f"procedure {nm} is only the prefix")
            arg = None if pr["arg"] == ("void",) else self.spec(pr["arg"])
            res = None if pr["res"] == ("void",) else self.spec(pr["res"])
            for t in (arg, res):
                if t is not None and self.nodes[t].get("listed"):
                    raise SchemaError(f"procedure {nm}: linked-list element "
                                      f"as a whole argument or result")
            procs.append({"number": u32(self.resolve(pr["number"]), nm),
                          "name": nm[len(prefix):], "arg": arg, "res": res})
        nums = [p["number"] for p in procs]
        if len(set(nums)) != len(nums):
            raise SchemaError("duplicate procedure number")
        self.check_structure()
        self.annotate({p["name"] for p in procs})
        self.check_directions(procs)
        sel = None
        if self.ann["minor_field"]:
            sel = self.selector(procs)
            # Only the selector's argument carries the minor version that
            # picks a schema, so the decoder decodes no other procedure's
            # CALL or REPLY (src/nfs_decode.c): any value of one would have
            # a path no message carries.
            for p in procs:
                if p["number"] != sel["procedure"] and \
                        (p["arg"] is not None or p["res"] is not None):
                    raise SchemaError(f"procedure {p['name']} carries no "
                                      f"minor version, so it must be void")
        depth = max([self.depth(p["arg"]) for p in procs] +
                    [self.depth(p["res"]) for p in procs] + [0])
        if depth > MAX_DEPTH:
            raise SchemaError(f"nesting depth {depth} exceeds {MAX_DEPTH}")
        return {
            "format": FORMAT,
            "family": self.ann["family"],
            "program": u32(self.resolve(prog["number"]), pname),
            "version": u32(self.resolve(ver["number"]), vname),
            "minor": self.minor,
            "leaf": list(self.ann["leaf"]),
            "status_type": self.status_type(),
            "selector": sel,
            "max_depth": depth,
            "procedures": procs,
            "types": self.nodes,
        }

    def status_type(self):
        st = self.ann["status_type"]
        if st is None:
            return None
        idx = self.by_name.get(st)
        if idx is None or self.nodes[idx]["kind"] != "enum":
            raise SchemaError(f"status-type {st} is not a reachable enum")
        return idx

    def check_structure(self):
        # Min encoded size, and refusal of cycles other than the list link.
        state = {}
        self.minsize = {}

        def visit(i):
            if state.get(i) == "done":
                return self.minsize[i]
            if state.get(i) == "busy":
                raise SchemaError(f"type cycle through "
                                  f"{self.nodes[i]['name'] or i}")
            state[i] = "busy"
            n = self.nodes[i]
            k = n["kind"]
            if k in ("int", "uint", "bool", "enum"):
                m = 4
            elif k == "hyper" or k == "uhyper":
                m = 8
            elif k == "opaque_fixed":
                m = (n["bound"] + 3) & ~3
            elif k in ("opaque_var", "string"):
                m = 4
            elif k == "array_var":
                visit(n["sub"])
                m = 4
            elif k == "array_fixed":
                m = n["bound"] * visit(n["sub"])
            elif k == "optional":
                sub = self.nodes[n["sub"]]
                if sub["kind"] != "struct" or not sub.get("listed"):
                    raise SchemaError(
                        f"optional-data {n['name'] or ''} is not an XDR "
                        f"linked list (struct T {{ ...; T *next; }}); "
                        f"other uses are not supported")
                visit(n["sub"])
                m = 4
            elif k == "struct":
                m = sum(visit(t) for _, t in n["fields"])
                if n.get("listed"):
                    m += 4
            elif k == "union":
                visit(n["disc"][1])
                arms = list(n["arms"]) + ([n["default"]] if n["default"]
                                          else [])
                m = 4 + min(0 if a["type"] is None else visit(a["type"])
                            for a in arms)
            else:
                raise SchemaError(f"unknown kind {k}")
            if m > UNBOUNDED:
                # min_size is a uint32_t, and no record can be this long
                raise SchemaError(f"{k} {n['name'] or ''}: smallest "
                                  f"encoding exceeds 32 bits")
            if k in ("array_fixed", "array_var"):
                sub = self.nodes[n["sub"]]
                if sub["kind"] == "struct" and sub.get("listed"):
                    raise SchemaError("array of linked-list elements")
                if self.minsize[n["sub"]] == 0:
                    raise SchemaError("array of zero-size elements")
            state[i] = "done"
            self.minsize[i] = m
            return m

        for i in range(len(self.nodes)):
            visit(i)
        # A listed struct may only be reached through its list head.
        for n in self.nodes:
            for t in self.children(n):
                c = self.nodes[t]
                if c["kind"] == "struct" and c.get("listed") and \
                        n["kind"] != "optional":
                    raise SchemaError(f"linked-list element {c['name']} used "
                                      f"outside a list head")
        for i, n in enumerate(self.nodes):
            n["min_size"] = self.minsize[i]

    def children(self, n):
        k = n["kind"]
        if k in ("array_fixed", "array_var", "optional"):
            return [n["sub"]]
        if k == "struct":
            return [t for _, t in n["fields"]]
        if k == "union":
            arms = list(n["arms"]) + ([n["default"]] if n["default"] else [])
            return [n["disc"][1]] + [a["type"] for a in arms
                                     if a["type"] is not None]
        return []

    def check_directions(self, procs):
        """The decoder promotes an operation union to an operation of the
        message it is read in.  One reached in the other direction's
        message would be a second operation list with another schema
        position under the same path, so it is refused."""
        for p in procs:
            for t, mine, other in ((p["arg"], "request", "response"),
                                   (p["res"], "response", "request")):
                todo, seen = [t] if t is not None else [], set()
                while todo:
                    i = todo.pop()
                    if i in seen:
                        continue
                    seen.add(i)
                    n = self.nodes[i]
                    if n.get("operations") == other:
                        raise SchemaError(
                            f"procedure {p['name']}: {other} operation union "
                            f"{n['name']} reached in the {mine}")
                    todo.extend(self.children(n))

    def depth(self, i, memo=None):
        if i is None:
            return 0
        if memo is None:
            memo = {}
        if i in memo:
            return memo[i]
        n = self.nodes[i]
        d = 1 + max([self.depth(c, memo) for c in self.children(n)] + [0])
        memo[i] = d
        return d

    def annotate(self, procedures):
        # Besides naming arms, this proves that no two schema positions
        # share a path: under a union the discriminant and the chosen arm are
        # the only children, and an operation's arms are path roots beside
        # the procedures.  Struct members are unique from the parser.
        ops = {}
        for direction, (uname, leaf, prefix) in self.ann["operations"].items():
            idx = self.by_name.get(uname)
            if idx is None or self.nodes[idx]["kind"] != "union":
                raise SchemaError(f"operation union {uname} is not a "
                                  f"reachable union")
            if idx in ops:
                # One arm component cannot be both .args and .result.
                raise SchemaError(f"operation union {uname} is named for "
                                  f"both request and response")
            ops[idx] = (direction, leaf, prefix)
        branches = self.ann["branches"]
        for i, n in enumerate(self.nodes):
            if n["kind"] != "union":
                continue
            uname = n["name"] or "(anonymous)"
            disc = n["disc"][0]
            if i in ops:
                direction, leaf, prefix = ops[i]
                n["operations"] = direction
                if leaf == disc:
                    raise SchemaError(f"operation union {uname}: leaf "
                                      f"{leaf} repeats the discriminant name")
                for a in n["arms"]:
                    if not a["label"].startswith(prefix):
                        raise SchemaError(f"operation label {a['label']} "
                                          f"lacks prefix {prefix}")
                    a["branch"] = a["label"][len(prefix):]
                    if not a["branch"]:
                        raise SchemaError(f"operation label {a['label']} is "
                                          f"only the prefix")
                    if a["branch"] in procedures:
                        raise SchemaError(f"operation {a['branch']} has the "
                                          f"name of a procedure")
                    a["component"] = None if a["type"] is None else leaf
                if n["default"] is not None:
                    raise SchemaError(f"operation union {n['name']} has a "
                                      f"default arm")
                continue
            by_branch = {}
            for a in n["arms"] + ([n["default"]] if n["default"] else []):
                lab = a["label"]
                if lab in branches:
                    self.used_branches.add(lab)
                    br = branches[lab]
                elif lab == "default":
                    br = "default"
                else:
                    br = lab.lower()
                a["branch"] = br
                if a["type"] is None:
                    a["component"] = None
                    continue
                if self.nodes[a["type"]]["kind"] == "struct":
                    a["component"] = br              # spliced struct arm
                else:
                    a["component"] = f"{br}.{a['decl']}"
                if br == disc:
                    raise SchemaError(f"union {uname}: branch {br} of case "
                                      f"{lab} repeats the discriminant name")
                prev = by_branch.setdefault(br, a)
                if (prev["decl"], prev["type"]) != (a["decl"], a["type"]):
                    raise SchemaError(f"union {uname}: cases {prev['label']} "
                                      f"and {lab} are different arms with "
                                      f"one branch {br}")

    def selector(self, procs):
        sname, fname = self.ann["minor_field"]
        sidx = self.by_name.get(sname)
        if sidx is None or self.nodes[sidx]["kind"] != "struct":
            raise SchemaError(f"minor-field struct {sname} not reachable")
        names = [f for f, _ in self.nodes[sidx]["fields"]]
        if fname not in names:
            raise SchemaError(f"{sname} has no field {fname}")
        fi = names.index(fname)
        if self.nodes[self.nodes[sidx]["fields"][fi][1]]["kind"] != "uint":
            raise SchemaError(f"{sname}.{fname} is not unsigned int")
        sel = [p["number"] for p in procs if p["arg"] == sidx]
        if len(sel) != 1:
            raise SchemaError(f"exactly one procedure must take {sname}")
        prefix = [t for _, t in self.nodes[sidx]["fields"][:fi + 1]]
        # Compared across minors by layout; kept out of the schema so the
        # schema_id does not depend on it.
        memo = {}
        self.prefix_layout = [self.layout(t, memo) for t in prefix]
        return {"procedure": sel[0], "field": fi,
                "prefix": [self.canon(t) for t in prefix]}

    def canon(self, i):
        """Structural form of a type, independent of table indices.

        A type already written out is referred to by its position in the
        order of first appearance, so a shared subtype costs one entry per
        use and the form stays linear in the number of types."""
        order = {}

        def visit(i):
            if i in order:
                return ["ref", order[i]]
            order[i] = len(order)
            n = self.nodes[i]
            k = n["kind"]
            form = [k, n.get("bound")]
            if k == "enum":
                form.append([v for _, v in n["values"]])
            elif k == "struct":
                form.append([visit(t) for _, t in n["fields"]])
                form.append(bool(n.get("listed")))
            elif k == "union":
                form.append(visit(n["disc"][1]))
                arms = list(n["arms"]) + (
                    [dict(n["default"], value="default")]
                    if n["default"] else [])
                form.append([[a["value"], None if a["type"] is None
                              else visit(a["type"])] for a in arms])
            else:
                form.extend(visit(c) for c in self.children(n))
            return form

        return visit(i)

    def layout(self, i, memo):
        """Digest of the wire layout of type `i`: kind, bound, enum values,
        union cases, and the layouts of its parts in order.  Names and
        which declaration a part uses do not count, so two types with the
        same layout have the same digest, shared or not.  Memoized per
        type, so linear in the number of types."""
        if i in memo:
            if memo[i] is None:
                raise SchemaError(f"type {self.nodes[i]['name']} contains "
                                  f"itself")
            return memo[i]
        memo[i] = None
        n = self.nodes[i]
        k = n["kind"]
        form = [k, n.get("bound")]
        if k == "enum":
            form.append([v for _, v in n["values"]])
        elif k == "struct":
            form.append([self.layout(t, memo) for _, t in n["fields"]])
            form.append(bool(n.get("listed")))
        elif k == "union":
            form.append(self.layout(n["disc"][1], memo))
            arms = list(n["arms"]) + ([dict(n["default"], value="default")]
                                      if n["default"] else [])
            form.append([[a["value"], None if a["type"] is None
                          else self.layout(a["type"], memo)] for a in arms])
        else:
            form.extend(self.layout(c, memo) for c in self.children(n))
        memo[i] = hashlib.sha256(json.dumps(
            form, separators=(",", ":")).encode()).hexdigest()
        return memo[i]


def normalize(ann_path):
    ann = parse_annotations(ann_path)
    base = Path(ann_path).parent
    sources = ([(None, ann["source"])] if ann["source"]
               else sorted(ann["minors"]))
    preludes = [(p, (base / p).read_bytes()) for p in ann["preludes"]]
    extensions = [(m, f, (base / f).read_bytes())
                  for m, f in ann["extensions"]]
    for m, f, _ in extensions:
        if m not in dict(sources):
            raise SchemaError(f"extension {f}: no minor {m}")
    schemas = []
    layouts = []
    used = set()
    used_aliases = set()
    for minor, src in sources:
        path = base / src
        data = path.read_bytes()
        spec = None
        for name, text in preludes + [(src, data)]:
            toks = tokenize(text.decode("ascii"), str(name))
            spec = Parser(toks, str(name)).parse() if spec is None \
                else spec.include(toks, str(name))
        mine = [(f, t) for m, f, t in extensions if m == minor]
        for f, t in mine:
            spec.extend(t.decode("ascii"), f)
        norm = Normalizer(spec, ann, minor)
        try:
            sch = norm.run()
        except SchemaError as e:
            raise SchemaError(f"{src}: {e}") from None
        layouts.append(norm.prefix_layout)
        used |= norm.used_branches
        used_aliases |= norm.used_aliases
        canon = json.dumps(sch, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(canon.encode()).hexdigest()
        tag = ann["family"] + (f".{minor}" if minor is not None else "")
        sch["schema_id"] = f"{tag}/sha256:{digest}"
        sch["source"] = {"file": src,
                         "sha256": hashlib.sha256(data).hexdigest()}
        sch["preludes"] = [{"file": p, "sha256": hashlib.sha256(t).hexdigest()}
                           for p, t in preludes]
        sch["extensions"] = [{"file": f,
                              "sha256": hashlib.sha256(t).hexdigest()}
                             for f, t in mine]
        schemas.append(sch)
    stale = {(u, l) for u, arms in ann["aliases"].items()
             for l, _ in arms} - used_aliases
    if stale:
        raise SchemaError(f"alias-arm {', '.join(sorted(l for _, l in stale))}"
                          f" applies in no minor version")
    unused = set(ann["branches"]) - used
    if unused:
        # A stale annotation would silently stop naming anything.
        raise SchemaError(f"branch annotation for {', '.join(sorted(unused))}"
                          f" matches no reachable union case")
    if len(schemas) > 1:
        for s, lay in zip(schemas[1:], layouts[1:]):
            if lay != layouts[0] or \
                    s["selector"]["procedure"] != \
                    schemas[0]["selector"]["procedure"]:
                raise SchemaError("minor versions disagree on the layout "
                                  "before the minor-version field")
            if (s["program"], s["version"]) != (schemas[0]["program"],
                                                schemas[0]["version"]):
                raise SchemaError("minor versions disagree on program/"
                                  "version")
    return ann, schemas


# ---------------------------------------------------------------- C output

KIND_C = {
    "void": "NFSP_XK_VOID", "int": "NFSP_XK_INT", "uint": "NFSP_XK_UINT",
    "hyper": "NFSP_XK_HYPER", "uhyper": "NFSP_XK_UHYPER",
    "bool": "NFSP_XK_BOOL", "enum": "NFSP_XK_ENUM",
    "opaque_fixed": "NFSP_XK_OPAQUE_FIXED", "opaque_var": "NFSP_XK_OPAQUE_VAR",
    "string": "NFSP_XK_STRING", "array_fixed": "NFSP_XK_ARRAY_FIXED",
    "array_var": "NFSP_XK_ARRAY_VAR", "optional": "NFSP_XK_LIST",
    "struct": "NFSP_XK_STRUCT", "union": "NFSP_XK_UNION",
}


def cstr(s):
    return "NULL" if s is None else '"' + s + '"'


def emit_c(ann_path, ann, schemas):
    fam = ann["family"]
    out = []
    w = out.append
    w("/* GENERATED by tools/nfs-proxy/schema/normalize.py -- DO NOT EDIT.")
    w(" *")
    for line in ann["notice"]:
        w(f" * {line}")
    if ann["notice"]:
        w(" *")
    w(f" * annotations: {Path(ann_path).name}")
    for p in schemas[0]["preludes"]:
        w(f" * prelude:     {p['file']} sha256:{p['sha256']}")
    for s in schemas:
        w(f" * source:      {s['source']['file']} "
          f"sha256:{s['source']['sha256']}")
        for x in s["extensions"]:
            w(f" * extension:   {x['file']} sha256:{x['sha256']}")
        w(f" * schema_id:   {s['schema_id']}")
    w(" *")
    w(" * build.sh regenerates this file and fails when it differs, so an")
    w(" * edit here cannot survive; change the XDR or annotations instead.")
    w(" */")
    w("#include <stddef.h>")
    w("")
    w('#include "schema.h"')
    w("")
    for s in schemas:
        sym = f"{fam}_{s['minor']}" if s["minor"] is not None else fam
        types, fields, arms, enums = [], [], [], []
        for ti, n in enumerate(s["types"]):
            k = n["kind"]
            first = count = 0
            sub = NONE
            bound = n.get("bound", 0) or 0
            flags = []
            dflt = "NFSP_SCHEMA_NONE"
            disc_name = None
            if k == "enum":
                first, count = len(enums), len(n["values"])
                enums.extend(n["values"])
            elif k == "struct":
                first, count = len(fields), len(n["fields"])
                fields.extend(n["fields"])
                if n.get("listed"):
                    flags.append("NFSP_STF_LISTED")
            elif k == "union":
                sub = n["disc"][1]
                disc_name = n["disc"][0]
                first = len(arms)
                allarms = list(n["arms"])
                if n["default"] is not None:
                    dflt = str(len(n["arms"]))
                    allarms.append(dict(n["default"], value=0))
                count = len(allarms)
                arms.extend(allarms)
                if n.get("operations") == "request":
                    flags.append("NFSP_STF_OPS_REQUEST")
                elif n.get("operations") == "response":
                    flags.append("NFSP_STF_OPS_RESPONSE")
            elif k in ("array_fixed", "array_var", "optional"):
                sub = n["sub"]
            if ti == s["status_type"]:
                flags.append("NFSP_STF_STATUS")
            types.append((n.get("name"), KIND_C[k], "|".join(flags) or "0",
                          sub, bound, first, count, dflt, disc_name,
                          n["min_size"]))
        w(f"/* ---- {s['schema_id']} */")
        w("")
        w(f"static const struct nfsp_schema_type {sym}_types[] = {{")
        for i, (name, kind, flags, sub, bound, first, count, dflt, dname,
                mins) in enumerate(types):
            subs = "NFSP_SCHEMA_NONE" if sub == NONE else str(sub)
            bnd = "NFSP_XDR_UNBOUNDED" if bound == UNBOUNDED else f"{bound}u"
            w(f"\t/* {i:4d} */ {{ {cstr(name)}, {kind}, {flags}, {subs}, "
              f"{bnd}, {first}u, {count}u, {dflt}, {cstr(dname)}, "
              f"{mins}u }},")
        w("};")
        w("")
        w(f"static const struct nfsp_schema_field {sym}_fields[] = {{")
        if not fields:
            w("\t{ NULL, 0 },\t/* placeholder: no structs */")
        for name, t in fields:
            w(f"\t{{ {cstr(name)}, {t} }},")
        w("};")
        w("")
        w(f"static const struct nfsp_schema_arm {sym}_arms[] = {{")
        if not arms:
            w("\t{ 0, NULL, NULL, NULL, NFSP_SCHEMA_NONE },"
              "\t/* placeholder: no unions */")
        for a in arms:
            t = "NFSP_SCHEMA_NONE" if a["type"] is None else str(a["type"])
            w(f"\t{{ 0x{a['value']:08x}u, {cstr(a['label'])}, "
              f"{cstr(a['branch'])}, {cstr(a['component'])}, {t} }},")
        w("};")
        w("")
        w(f"static const struct nfsp_schema_enumval {sym}_enums[] = {{")
        if not enums:
            w("\t{ 0, NULL },\t/* placeholder: no enums */")
        for name, v in enums:
            w(f"\t{{ 0x{v:08x}u, {cstr(name)} }},")
        w("};")
        w("")
        w(f"static const struct nfsp_schema_proc {sym}_procs[] = {{")
        for p in s["procedures"]:
            a = "NFSP_SCHEMA_NONE" if p["arg"] is None else str(p["arg"])
            r = "NFSP_SCHEMA_NONE" if p["res"] is None else str(p["res"])
            w(f"\t{{ {p['number']}u, {cstr(p['name'])}, {a}, {r} }},")
        w("};")
        w("")
        sel = s["selector"]
        w(f"const struct nfsp_protocol_schema nfsp_schema_{sym} = {{")
        w(f"\t.schema_id = {cstr(s['schema_id'])},")
        w(f"\t.family = {cstr(s['family'])},")
        w(f"\t.program = {s['program']}u,")
        w(f"\t.version = {s['version']}u,")
        w(f"\t.has_minor = {0 if s['minor'] is None else 1},")
        w(f"\t.minor = {s['minor'] or 0}u,")
        w(f"\t.request_leaf = {cstr(s['leaf'][0])},")
        w(f"\t.response_leaf = {cstr(s['leaf'][1])},")
        w(f"\t.types = {sym}_types,")
        w(f"\t.ntypes = {len(types)}u,")
        w(f"\t.fields = {sym}_fields,")
        w(f"\t.arms = {sym}_arms,")
        w(f"\t.enums = {sym}_enums,")
        w(f"\t.procs = {sym}_procs,")
        w(f"\t.nprocs = {len(s['procedures'])}u,")
        w(f"\t.selector_proc = {sel['procedure'] if sel else 0}u,")
        w(f"\t.selector_field = {sel['field'] if sel else 0}u,")
        w(f"\t.max_depth = {s['max_depth']}u,")
        w("};")
        w("")
    syms = [f"{fam}_{s['minor']}" if s["minor"] is not None else fam
            for s in schemas]
    w(f"static const struct nfsp_protocol_schema *const {fam}_schemas[] = {{")
    for sym in syms:
        w(f"\t&nfsp_schema_{sym},")
    w("};")
    w("")
    w(f"const struct nfsp_schema_family nfsp_schema_family_{fam} = {{")
    w(f"\t.family = {cstr(fam)},")
    w(f"\t.program = {schemas[0]['program']}u,")
    w(f"\t.version = {schemas[0]['version']}u,")
    w(f"\t.has_minor = {0 if schemas[0]['minor'] is None else 1},")
    w(f"\t.schemas = {fam}_schemas,")
    w(f"\t.nschemas = {len(schemas)}u,")
    w("};")
    return "\n".join(out) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("annotation")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--out")
    g.add_argument("--check")
    g.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    try:
        ann, schemas = normalize(a.annotation)
    except (SchemaError, OSError, UnicodeDecodeError) as e:
        print(f"normalize: {e}", file=sys.stderr)
        return 2
    if a.json:
        json.dump(schemas, sys.stdout, indent=1, sort_keys=True)
        print()
        return 0
    text = emit_c(a.annotation, ann, schemas)
    if a.out:
        Path(a.out).write_text(text)
        return 0
    try:
        cur = Path(a.check).read_text()
    except OSError as e:
        print(f"normalize: {e}", file=sys.stderr)
        return 1
    if cur != text:
        print(f"normalize: {a.check} is stale; regenerate with\n"
              f"  {sys.argv[0]} {a.annotation} --out {a.check}",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
