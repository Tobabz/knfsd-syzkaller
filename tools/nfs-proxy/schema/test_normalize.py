#!/usr/bin/env python3
"""Tests for normalize.py: refusals, naming rules, schema_id, determinism.

The decoder's own tests (test/test_nfs_decode.c) prove that the tables are
interpreted correctly.  These prove the tables say what the XDR says, and
that every construct the runtime could only guess at is refused at build
time.  Run: python3 -m unittest tools/nfs-proxy/schema/test_normalize.py
"""

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import normalize as nz  # noqa: E402

TEST_SCHEMA = HERE.parent / "test" / "schema"

HEAD = """
typedef unsigned int uint32_t;
enum st { S_OK = 0, S_ERR = 1 };
"""

PROGRAM = """
program P {
    version V {
        void PROC_NULL(void) = 0;
        RES PROC_DO(ARGS) = 1;
    } = 1;
} = 0x20000123;
"""

ANN = """
family t
program P V
procedure-prefix PROC_
source t.x
"""


class Tmp:
    def __init__(self, xdr, ann=ANN, extra=None):
        self.dir = Path(tempfile.mkdtemp())
        (self.dir / "t.x").write_text(xdr)
        (self.dir / "t.ann").write_text(ann)
        for name, text in (extra or {}).items():
            (self.dir / name).write_text(text)

    def __enter__(self):
        return self.dir / "t.ann"

    def __exit__(self, *exc):
        shutil.rmtree(self.dir)


def norm(body, ann=ANN, extra=None):
    with Tmp(HEAD + body + PROGRAM, ann, extra) as a:
        return nz.normalize(a)


def types_by_name(schema):
    return {t["name"]: t for t in schema["types"] if t.get("name")}


class Refusals(unittest.TestCase):
    def refused(self, body, needle, ann=ANN):
        with self.assertRaises(nz.SchemaError) as cm:
            norm(body, ann)
        self.assertIn(needle, str(cm.exception))

    def test_float(self):
        self.refused("struct ARGS { float f; }; struct RES { st s; };",
                     "float is not supported")

    def test_optional_outside_list(self):
        self.refused("struct ARGS { uint32_t *p; }; struct RES { st s; };",
                     "not an XDR linked list")

    def test_cycle(self):
        self.refused("struct ARGS { ARGS inner; }; struct RES { st s; };",
                     "type cycle")

    def test_link_not_last_is_refused(self):
        self.refused("struct ARGS { ARGS *next; uint32_t x; };"
                     "struct RES { st s; };", "not an XDR linked list")

    def test_case_not_in_enum(self):
        self.refused("struct ARGS { uint32_t x; };"
                     "union RES switch (st s) { case S_OK: void; case 7: "
                     "void; };", "is not a member of st")

    def test_duplicate_case(self):
        self.refused("struct ARGS { uint32_t x; };"
                     "union RES switch (st s) { case S_OK: void; case S_OK: "
                     "uint32_t y; };", "duplicate case")

    def test_bool_case_range(self):
        self.refused("struct ARGS { uint32_t x; };"
                     "union RES switch (bool b) { case 2: void; };",
                     "not a bool")

    def test_zero_size_element(self):
        self.refused("struct ARGS { opaque e[0]; };"
                     "struct RES { ARGS a<>; };", "zero-size")

    def test_list_element_used_plainly(self):
        self.refused("struct ent { uint32_t x; ent *next; };"
                     "struct ARGS { ent e; }; struct RES { ent *h; };",
                     "outside a list head")

    def test_unknown_type(self):
        self.refused("struct ARGS { nosuch x; }; struct RES { st s; };",
                     "undefined type nosuch")

    def test_unknown_constant(self):
        self.refused("struct ARGS { opaque x<NOSUCH>; }; "
                     "struct RES { st s; };", "undefined constant NOSUCH")

    def test_string_needs_angle(self):
        self.refused("struct ARGS { string s[4]; }; struct RES { st s; };",
                     "string must be declared with <>")

    def test_stale_branch_annotation(self):
        self.refused("struct ARGS { uint32_t x; }; struct RES { st s; };",
                     "matches no reachable union case",
                     ANN + "branch S_OK ok\n")

    def test_operation_union_must_exist(self):
        self.refused("struct ARGS { uint32_t x; }; struct RES { st s; };",
                     "not a reachable union",
                     ANN + "operation request nosuch args OP_\n")

    def test_depth_limit(self):
        chain = "struct d0 { uint32_t x; };\n"
        for i in range(1, nz.MAX_DEPTH + 2):
            chain += f"struct d{i} {{ d{i - 1} x; }};\n"
        self.refused(chain + f"typedef d{nz.MAX_DEPTH + 1} ARGS;"
                     "struct RES { st s; };", "nesting depth")

    def test_multi_argument_procedure(self):
        xdr = HEAD + "struct A { uint32_t x; };" + """
program P { version V { void PROC_DO(A, A) = 1; } = 1; } = 1;"""
        with Tmp(xdr) as a:
            with self.assertRaises(nz.SchemaError) as cm:
                nz.normalize(a)
        self.assertIn("multi-argument", str(cm.exception))


class Naming(unittest.TestCase):
    def test_arm_components(self):
        (sch,) = norm_ok("""
struct okres { uint32_t n; };
union RES switch (st status) {
case S_OK:  okres resok;
case S_ERR: uint32_t why;
default:    void;
};
struct ARGS { uint32_t x; };
""", ANN + "branch S_OK ok\n")
        res = types_by_name(sch)["RES"]
        arms = {a["label"]: a for a in res["arms"]}
        self.assertEqual(arms["S_OK"]["component"], "ok")       # spliced
        self.assertEqual(arms["S_ERR"]["component"], "s_err.why")
        self.assertIsNone(res["default"]["component"])          # void

    def test_unreachable_declarations_are_pruned(self):
        (sch,) = norm_ok("struct ARGS { uint32_t x; };"
                         "struct RES { st s; };"
                         "struct junk { nosuch y; };")
        self.assertNotIn("junk", types_by_name(sch))

    def test_list_link_is_not_a_member(self):
        (sch,) = norm_ok("struct ent { uint32_t x; ent *next; };"
                         "struct ARGS { uint32_t x; };"
                         "struct RES { ent *head; };")
        ent = types_by_name(sch)["ent"]
        self.assertEqual(ent["listed"], "next")
        self.assertEqual([f for f, _ in ent["fields"]], ["x"])
        self.assertEqual(ent["min_size"], 8)

    def test_procedure_prefix_stripped(self):
        (sch,) = norm_ok("struct ARGS { uint32_t x; }; struct RES { st s; };")
        self.assertEqual([p["name"] for p in sch["procedures"]],
                         ["NULL", "DO"])


def norm_ok(body, ann=ANN):
    _, schemas = norm(body, ann)
    return schemas


class Identity(unittest.TestCase):
    BODY = "struct ARGS { uint32_t x; }; struct RES { st s; };"

    def test_comment_does_not_change_schema_id(self):
        (a,) = norm_ok(self.BODY)
        (b,) = norm_ok("/* a comment */\n" + self.BODY)
        self.assertEqual(a["schema_id"], b["schema_id"])
        self.assertNotEqual(a["source"]["sha256"], b["source"]["sha256"])

    def test_layout_changes_schema_id(self):
        (a,) = norm_ok(self.BODY)
        (b,) = norm_ok(self.BODY.replace("uint32_t x", "hyper x"))
        self.assertNotEqual(a["schema_id"], b["schema_id"])

    def test_naming_changes_schema_id(self):
        body = ("struct ARGS { uint32_t x; };"
                "union RES switch (st s) { case S_OK: uint32_t v; "
                "default: void; };")
        (a,) = norm_ok(body)
        (b,) = norm_ok(body, ANN + "branch S_OK ok\n")
        self.assertNotEqual(a["schema_id"], b["schema_id"])

    def test_output_is_deterministic(self):
        ann = TEST_SCHEMA / "tproto.ann"
        a = nz.emit_c(ann, *nz.normalize(ann))
        b = nz.emit_c(ann, *nz.normalize(ann))
        self.assertEqual(a, b)


class Minors(unittest.TestCase):
    MANN = ANN.replace("source t.x\n", "") + \
        "minor-field ARGS minor\nminor 0 t.x\nminor 1 u.x\n"

    def test_prefix_must_agree(self):
        x0 = HEAD + "struct ARGS { uint32_t minor; }; struct RES { st s; };"
        x1 = HEAD + "struct ARGS { hyper pad; uint32_t minor; };" \
            "struct RES { st s; };"
        with Tmp(x0 + PROGRAM, self.MANN, {"u.x": x1 + PROGRAM}) as a:
            with self.assertRaises(nz.SchemaError) as cm:
                nz.normalize(a)
        self.assertIn("disagree", str(cm.exception))

    def test_ids_differ_per_minor(self):
        x = HEAD + "struct ARGS { uint32_t minor; }; struct RES { st s; };"
        with Tmp(x + PROGRAM, self.MANN, {"u.x": x + PROGRAM}) as a:
            _, schemas = nz.normalize(a)
        self.assertEqual([s["minor"] for s in schemas], [0, 1])
        self.assertNotEqual(schemas[0]["schema_id"], schemas[1]["schema_id"])


class Preludes(unittest.TestCase):
    """`prelude FILE`: XDR the sources use but take from their environment
    (the NFSv4 basic typedefs and authsys_parms)."""

    XDR = "struct ARGS { uint32_t x; }; struct RES { st s; };"
    PRE = "typedef unsigned int uint32_t;\nenum st { S_OK = 0 };\n"

    def run_with(self, prelude, xdr):
        ann = ANN + "prelude p.x\n"
        with Tmp(xdr + PROGRAM, ann, {"p.x": prelude}) as a:
            return nz.normalize(a)

    def test_prelude_supplies_names(self):
        _, (sch,) = self.run_with(self.PRE, self.XDR)
        self.assertEqual(sch["preludes"][0]["file"], "p.x")
        self.assertIn("st", types_by_name(sch))

    def test_missing_name_is_refused_with_its_source(self):
        with Tmp(self.XDR + PROGRAM) as a:
            with self.assertRaises(nz.SchemaError) as cm:
                nz.normalize(a)
        self.assertIn("t.x: undefined type uint32_t", str(cm.exception))

    def test_prelude_cannot_be_redefined(self):
        with self.assertRaises(nz.SchemaError) as cm:
            self.run_with(self.PRE, "typedef int uint32_t;" + self.XDR)
        self.assertIn("t.x:1: redefinition of uint32_t", str(cm.exception))

    def test_prelude_comment_keeps_schema_id(self):
        _, (a,) = self.run_with(self.PRE, self.XDR)
        _, (b,) = self.run_with("/* c */\n" + self.PRE, self.XDR)
        self.assertEqual(a["schema_id"], b["schema_id"])
        self.assertNotEqual(a["preludes"][0]["sha256"],
                            b["preludes"][0]["sha256"])

    def test_notice_is_in_the_header_not_the_schema_id(self):
        _, (a,) = self.run_with(self.PRE, self.XDR)
        ann = ANN + "prelude p.x\nnotice Some  license, see X.\n"
        with Tmp(self.XDR + PROGRAM, ann, {"p.x": self.PRE}) as path:
            ann_d, (b,) = nz.normalize(path)
            text = nz.emit_c(path, ann_d, [b])
        self.assertIn(" * Some license, see X.\n", text)
        self.assertEqual(a["schema_id"], b["schema_id"])

    def test_prelude_is_in_the_header(self):
        ann = ANN + "prelude p.x\n"
        with Tmp(self.XDR + PROGRAM, ann, {"p.x": self.PRE}) as a:
            text = nz.emit_c(a, *nz.normalize(a))
        self.assertIn(" * prelude:     p.x sha256:", text)


NFS4_ANN = HERE / "nfs4" / "nfs4.ann"


class Nfs4(unittest.TestCase):
    """Properties of the real NFSv4 schemas that the decoder relies on."""

    @classmethod
    def setUpClass(cls):
        _, cls.schemas = nz.normalize(NFS4_ANN)

    def test_minors_and_program(self):
        self.assertEqual([s["minor"] for s in self.schemas], [0, 1, 2])
        for s in self.schemas:
            self.assertEqual((s["program"], s["version"]), (100003, 4))
            self.assertEqual([p["name"] for p in s["procedures"]],
                             ["NULL", "COMPOUND"])
            self.assertEqual((s["selector"]["procedure"],
                              s["selector"]["field"]), (1, 1))

    def test_every_result_starts_with_its_status(self):
        # nfs_decode.c reads an operation's status from the first leaf of
        # its result; this holds for every nfs_resop4 arm of every minor.
        for s in self.schemas:
            types = s["types"]
            ops = [t for t in types if t.get("operations") == "response"]
            self.assertEqual(len(ops), 1)
            for arm in ops[0]["arms"]:
                i = arm["type"]
                while types[i]["kind"] in ("struct", "union"):
                    t = types[i]
                    i = t["fields"][0][1] if t["kind"] == "struct" \
                        else t["disc"][1]
                self.assertEqual(i, s["status_type"],
                                 f"{s['schema_id']} {arm['label']}")

    def test_operations_per_minor(self):
        # RFC 7531 has 38 arms (OP_ACCESS..OP_RELEASE_LOCKOWNER and
        # OP_ILLEGAL), RFC 5662 adds 19, RFC 7863 adds 13.
        counts = [len(next(t for t in s["types"]
                           if t.get("operations") == "request")["arms"])
                  for s in self.schemas]
        self.assertEqual(counts, [38, 57, 70])


class Committed(unittest.TestCase):
    """The committed tables match their XDR (build.sh checks this too,
    through --check; this keeps the unit tests self-contained)."""

    def test_tables_are_fresh(self):
        for ann, out in ((TEST_SCHEMA / "tproto.ann",
                          TEST_SCHEMA.parent / "schema_tproto.c"),
                         (TEST_SCHEMA / "tflat.ann",
                          TEST_SCHEMA.parent / "schema_tflat.c"),
                         (NFS4_ANN, HERE.parent / "src" / "schema_nfs4.c")):
            text = nz.emit_c(ann, *nz.normalize(ann))
            self.assertEqual(text, out.read_text(), f"{out.name} is stale")


if __name__ == "__main__":
    unittest.main()
