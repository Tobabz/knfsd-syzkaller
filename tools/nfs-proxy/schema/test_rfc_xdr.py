#!/usr/bin/env python3
"""Tests for rfc_xdr.py: pins, the RFC's own extraction rule, the prelude.

Synthetic "RFC" texts stand in for the real ones, so these run offline.
The real RFCs are checked by `rfc_xdr.py nfs4/SOURCES --verify` and
`rfc_xdr.py nfs3/SOURCES --verify`, which need the network.  Run: python3 tools/nfs-proxy/schema/test_rfc_xdr.py
"""

import contextlib
import hashlib
import io
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import rfc_xdr  # noqa: E402

CMD = """grep "^  *///" | sed 's?^  */// ??' | sed 's?^  *///$??'"""

RFC1 = """\
RFC 9991                     Example                       October 2026

   To extract the XDR:

      @CMD@

    /// /*
    ///  * typedef unsigned int    uint32_t;
    ///  */
    ///
    /// struct a { uint32_t x; };
""".replace("@CMD@", CMD)

XDR1 = """\
/*
 * typedef unsigned int    uint32_t;
 */

struct a { uint32_t x; };
"""

RFC2 = """\
RFC 9992                     Base                          October 2026

         enum flavor {
            F_NONE = 0,
            F_SYS  = 1
         };

         struct parms {
            unsigned int stamp;
         };
"""


def h(data):
    return hashlib.sha256(data.encode() if isinstance(data, str)
                          else data).hexdigest()


def quiet(argv):
    """rfc_xdr.main(argv) without its diagnostics on stderr."""
    with contextlib.redirect_stderr(io.StringIO()):
        return rfc_xdr.main(argv)


class Tree:
    """A manifest, its RFC directory and committed files in a temp dir."""

    def __init__(self, rfc1=RFC1, rfc2=RFC2, cmd=CMD, extra=""):
        self.dir = Path(tempfile.mkdtemp())
        self.rfcs = self.dir / "rfcs"
        self.rfcs.mkdir()
        (self.rfcs / "rfc9991.txt").write_text(rfc1)
        (self.rfcs / "rfc9992.txt").write_text(rfc2)
        self.prelude = self.build_prelude()
        self.manifest = self.dir / "SOURCES"
        self.manifest.write_text(
            f"rfc 9991 {h(rfc1)}\n"
            f"rfc 9992 {h(rfc2)}\n"
            f"extract a.x 9991 {h(XDR1)} {cmd}\n"
            f"prelude p.x {h(self.prelude)}\n"
            f"typedefs a.x\n"
            f"copy 9992 enum flavor\n"
            f"copy 9992 struct parms\n" + extra)
        (self.dir / "a.x").write_text(XDR1)
        (self.dir / "p.x").write_text(self.prelude)

    @staticmethod
    def build_prelude():
        head = rfc_xdr.build_file(
            {"kind": "prelude", "parts": []}, {}, {}).decode()
        return head + """
/* a.x: stated only inside a comment */
typedef unsigned int uint32_t;

/* RFC 9992 lines 3-6 */
enum flavor {
   F_NONE = 0,
   F_SYS  = 1
};

/* RFC 9992 lines 8-10 */
struct parms {
   unsigned int stamp;
};
"""

    def run(self, mode):
        return quiet([str(self.manifest), mode, "--rfc-dir", str(self.rfcs)])

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        shutil.rmtree(self.dir)


class Extraction(unittest.TestCase):
    def test_verify_matches_committed_files(self):
        with Tree() as t:
            self.assertEqual(t.run("--verify"), 0)
            self.assertEqual(quiet([str(t.manifest), "--check"]), 0)

    def test_utf8_rfc_text_with_bom(self):
        # RFC 9754 and later v3-format RFCs are UTF-8 with a BOM.
        with Tree(rfc1="\ufeff" + RFC1) as t:
            self.assertEqual(t.run("--verify"), 0)

    def test_write_reproduces_files(self):
        with Tree() as t:
            (t.dir / "a.x").write_text("stale\n")
            (t.dir / "p.x").write_text("stale\n")
            self.assertEqual(t.run("--write"), 0)
            self.assertEqual((t.dir / "a.x").read_text(), XDR1)
            self.assertEqual((t.dir / "p.x").read_text(), t.prelude)

    def test_edited_file_fails_check_and_verify(self):
        with Tree() as t:
            (t.dir / "a.x").write_text(XDR1 + "/* edit */\n")
            self.assertEqual(quiet([str(t.manifest), "--check"]), 1)
            self.assertEqual(t.run("--verify"), 1)

    def test_changed_rfc_is_refused(self):
        with Tree() as t:
            (t.rfcs / "rfc9991.txt").write_text(RFC1 + "\n")
            self.assertEqual(t.run("--verify"), 2)

    def test_command_must_be_the_rfcs_own(self):
        other = "grep '^ *///' | sed 's?^ */// ??' | sed 's?^ *///$??'"
        with Tree(cmd=other) as t:
            with self.assertRaises(rfc_xdr.SourceError) as cm:
                rfc_xdr.rebuild(t.manifest, t.rfcs)
        self.assertIn("not a line of RFC 9991", str(cm.exception))

    def test_typedefs_must_agree(self):
        with Tree() as t:
            files = {"a.x": XDR1.encode(),
                     "b.x": XDR1.replace("unsigned int", "int").encode()}
            b = {"kind": "prelude",
                 "parts": [("typedefs", ["a.x", "b.x"])]}
            with self.assertRaises(rfc_xdr.SourceError) as cm:
                rfc_xdr.build_file(b, files, {})
        self.assertIn("b.x states other typedefs", str(cm.exception))


class Fragment(unittest.TestCase):
    """A definition an RFC states only in its prose (RFC 8435, RFC 8154)."""

    def fragment(self, t):
        return rfc_xdr.build_file(
            {"kind": "fragment", "parts": [("copy", ["9992", "enum",
                                                     "flavor"])]},
            {}, {"9992": (t.rfcs / "rfc9992.txt").read_bytes()})

    def test_fragment_is_built_and_pinned(self):
        with Tree() as t:
            frag = self.fragment(t)
            (t.dir / "f.x").write_bytes(frag)
            with open(t.manifest, "a") as f:
                f.write(f"fragment f.x {rfc_xdr.sha256(frag)}\n"
                        f"copy 9992 enum flavor\n")
            m, files = rfc_xdr.rebuild(t.manifest, t.rfcs)
            self.assertEqual(files["f.x"], frag)
            self.assertIn("f.x", rfc_xdr.pins(m))
            self.assertEqual(rfc_xdr.main([str(t.manifest), "--check"]), 0)
        text = frag.decode()
        self.assertIn("enum flavor {", text)
        self.assertIn("not in its `///` XDR", text)
        self.assertNotIn("typedef", text)

    def test_fragment_refusals(self):
        for extra, needle in (
                ("fragment f.x {}\ntypedefs a.x\n", "in a prelude"),
                ("fragment f.x {}\n", "is empty"),
                ("fragment a.x {}\ncopy 9992 enum flavor\n",
                 "built twice")):
            with Tree(extra=extra.format("0" * 64)) as t:
                with self.assertRaises(rfc_xdr.SourceError) as cm:
                    rfc_xdr.parse_manifest(t.manifest)
            self.assertIn(needle, str(cm.exception))


class Copy(unittest.TestCase):
    def copy(self, text, keyword="struct", name="parms"):
        return rfc_xdr.copy_definition("9992", text.encode(), keyword, name)

    def test_copy_is_dedented_and_located(self):
        first, last, body = self.copy(RFC2)
        self.assertEqual((first, last), (8, 10))
        self.assertEqual(body, ["struct parms {", "   unsigned int stamp;",
                                "};"])

    def test_definition_must_be_unique(self):
        with self.assertRaises(rfc_xdr.SourceError):
            self.copy(RFC2 + RFC2)

    def test_page_break_is_refused(self):
        paged = RFC2.replace(
            "            unsigned int stamp;\n",
            "\nThurlow   Standards Track   [Page 9]\n\f\n"
            "            unsigned int stamp;\n")
        with self.assertRaises(rfc_xdr.SourceError) as cm:
            self.copy(paged)
        self.assertIn("spans a page", str(cm.exception))


# An RFC that prints its XDR only in its prose, the way RFC 1813 does:
# a size stated as `NAME V`, a typedef stated twice, definitions that cross
# a page break, a union, a program, and a name the program spells
# differently from its declaration.
RFC3 = """\
RFC 9993                     Prose XDR                     October 2026

   X_SIZE 8
      The size of a verifier.

   u32
         typedef unsigned long u32;

      enum xstat {
         X_OK  = 0,
         X_ERR = 1
      };

      struct xargs {
           opaque  verf[X_SIZE];
           u32     n;



Someone                      Informational                     [Page 2]
\f
RFC 9993                     Prose XDR                     October 2026


           u32     m;
      };

      union xres switch (xstat status) {
      case X_OK:
           u32  n;
      default:
           void;
      };

      struct XPINGargs {
           u32  v;
      };

      program X_PROGRAM {
         version X_V1 {
            xres X_DO(xargs) = 1;
            void X_PING(XPING1args) = 2;
         } = 1;
      } = 0x20000999;

   Appendix: the same typedef, restated.

         typedef unsigned long u32;
"""

ASSEMBLE = """\
assemble x.x {pin}
constant 9993 X_SIZE
copy 9993 typedef u32
copy 9993 enum xstat
copy 9993 struct xargs
copy 9993 union xres
copy 9993 struct XPINGargs as XPING1args
copy 9993 program X_PROGRAM
"""


class Assemble(unittest.TestCase):
    """An XDR source assembled from an RFC's prose (RFC 1813)."""

    def tree(self, rfc3=RFC3, body=ASSEMBLE):
        t = Tree()
        (t.rfcs / "rfc9993.txt").write_text(rfc3)
        with open(t.manifest, "a") as f:
            f.write(f"rfc 9993 {h(rfc3)}\n" + body.format(pin="0" * 64))
        return t

    def build(self, rfc3=RFC3, body=ASSEMBLE):
        with self.tree(rfc3, body) as t:
            return rfc_xdr.rebuild(t.manifest, t.rfcs)[1]["x.x"].decode()

    def test_assembled_in_order(self):
        x = self.build()
        self.assertIn("/* RFC 9993 line 3, stated as prose */\n"
                      "const X_SIZE = 8;\n", x)
        self.assertIn("/* RFC 9993 line 7 */\ntypedef unsigned long u32;\n",
                      x)
        order = [x.index(k) for k in ("const X_SIZE", "typedef", "enum xstat",
                                      "struct xargs", "union xres",
                                      "struct XPING1args",
                                      "program X_PROGRAM")]
        self.assertEqual(order, sorted(order))
        self.assertIn("not in its", rfc_xdr.build_file(
            {"kind": "fragment", "parts": []}, {}, {}).decode())
        self.assertIn("only in its prose", x)

    def test_page_break_is_joined(self):
        x = self.build()
        self.assertIn("struct xargs {\n"
                      "     opaque  verf[X_SIZE];\n"
                      "     u32     n;\n"
                      "     u32     m;\n"
                      "};\n", x)
        self.assertNotIn("Page", x)
        self.assertNotIn("\f", x)
        self.assertIn("/* RFC 9993 lines 14-26 */", x)

    def test_union_program_and_rename(self):
        x = self.build()
        self.assertIn("union xres switch (xstat status) {\n", x)
        self.assertIn("/* RFC 9993 lines 35-37, renamed from XPINGargs */\n"
                      "struct XPING1args {\n", x)
        self.assertIn("program X_PROGRAM {\n", x)
        self.assertTrue(x.rstrip().endswith("} = 0x20000999;"))

    def test_built_and_pinned(self):
        with self.tree() as t:
            x = rfc_xdr.rebuild(t.manifest, t.rfcs)[1]["x.x"]
            (t.dir / "x.x").write_bytes(x)
            text = t.manifest.read_text().replace("0" * 64,
                                                  rfc_xdr.sha256(x))
            t.manifest.write_text(text)
            self.assertEqual(t.run("--verify"), 0)
            self.assertEqual(quiet([str(t.manifest), "--check"]), 0)

    def test_refusals(self):
        for rfc3, body, needle in (
                (RFC3.replace("   X_SIZE 8", "   X_SIZE 8\n   X_SIZE 9"),
                 ASSEMBLE, "`X_SIZE N` occurs 2 times"),
                (RFC3.replace("restated.\n\n         typedef unsigned long",
                              "restated.\n\n         typedef long"),
                 ASSEMBLE, "differently"),
                (RFC3.replace("RFC 9993                     Prose XDR    "
                              "                 October 2026\n\n\n",
                              "\n\n"),
                 ASSEMBLE, "page break that is not whole"),
                (RFC3, ASSEMBLE.replace("copy 9993 union xres",
                                        "copy 9993 union nosuch"),
                 "occurs 0 times")):
            with self.assertRaises(rfc_xdr.SourceError) as cm:
                self.build(rfc3, body)
            self.assertIn(needle, str(cm.exception))

    def test_manifest_refusals(self):
        for extra, needle in (
                ("fragment f.x {}\nconstant 9992 X\n", "in an assemble"),
                ("fragment f.x {}\ncopy 9992 enum flavor as other\n",
                 "copy N KEYWORD NAME"),
                ("assemble f.x {}\ncopy 9992 const X\n", "copy of a const")):
            with Tree(extra=extra.format("0" * 64)) as t:
                with self.assertRaises(rfc_xdr.SourceError) as cm:
                    rfc_xdr.parse_manifest(t.manifest)
            self.assertIn(needle, str(cm.exception))


class Committed(unittest.TestCase):
    def test_nfs4_files_match_their_pins(self):
        self.assertEqual(rfc_xdr.main([str(HERE / "nfs4" / "SOURCES"),
                                       "--check"]), 0)

    def test_nfs3_files_match_their_pins(self):
        self.assertEqual(rfc_xdr.main([str(HERE / "nfs3" / "SOURCES"),
                                       "--check"]), 0)


if __name__ == "__main__":
    unittest.main()
