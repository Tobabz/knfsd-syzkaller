#!/usr/bin/env python3
"""Tests for rfc_xdr.py: pins, the RFC's own extraction rule, the prelude.

Synthetic "RFC" texts stand in for the real ones, so these run offline.
The real RFCs are checked by `rfc_xdr.py nfs4/SOURCES --verify`, which
needs the network.  Run: python3 tools/nfs-proxy/schema/test_rfc_xdr.py
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
        head = rfc_xdr.build_prelude(
            {"prelude": {"parts": []}}, {}, {}).decode()
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
            m = {"prelude": {"parts": [("typedefs", ["a.x", "b.x"])]}}
            with self.assertRaises(rfc_xdr.SourceError) as cm:
                rfc_xdr.build_prelude(m, files, {})
        self.assertIn("b.x states other typedefs", str(cm.exception))


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


class Committed(unittest.TestCase):
    def test_nfs4_files_match_their_pins(self):
        self.assertEqual(rfc_xdr.main([str(HERE / "nfs4" / "SOURCES"),
                                       "--check"]), 0)


if __name__ == "__main__":
    unittest.main()
