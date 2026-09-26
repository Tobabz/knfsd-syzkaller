#!/bin/sh
# tools/fport-design-gate.sh - machine-check the DESIGN contract (design-spec.md)
# against target evidence artifacts. The design "holds" iff every active gate
# passes (R3 throughput-bound retired 2026-09-26: env-dependent, out of scope).
# passes on this target. This is a per-target decidable check, not a
# time-inductive prediction - that is how the natural-language design
# guarantees 100% within its preconditions.
#
# exit: 0 = DESIGN HOLDS, 1 = gate failed, 2 = preconditions unmet (UNSUPPORTED)
VERBOSE=0
test "${1:-}" = "-v" && VERBOSE=1

# derive workspace root from script location; override via env
WORK_ROOT=${KOOV_WORK_ROOT:-$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)}
BUNDLE=${KOOV_BUNDLE:-$WORK_ROOT/bundle/patches}
export WORK_ROOT BUNDLE

python3 - "$VERBOSE" <<'PYEOF'
import json, os, pathlib, subprocess, sys, re

VERBOSE = int(sys.argv[1])
HOME = pathlib.Path(os.environ["WORK_ROOT"])

rows = []          # (id, name, ok, detail)
warn = []

def gate(rid, name, ok, detail):
    rows.append((rid, name, bool(ok), detail))
    return bool(ok)

def read_json(p):
    return json.load(open(p, encoding="utf-8"))

def sh(cmd):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return r.returncode == 0, r.stdout.strip()

# ---------- preconditions Psi ----------
psi = {}
m = read_json(HOME/"env/manifest.json")
_ms = m.get("verify", {}) or {}
_mem_san = _ms.get("mem_sanitizer")
_legacy_ms = _ms.get("target_kasan") is True or _ms.get("target_kcsan") is True
psi["Psi2(mem-sanitizer)"] = _mem_san in ("kasan", "kcsan") or _legacy_ms

# kcov in .config or vmlinux symbols
kcov_ok = False
cfg = HOME/"env/linux/.config"
if cfg.exists():
    kcov_ok = sh("grep -q '^CONFIG_KCOV=y' " + str(cfg))[0]
if not kcov_ok:
    kcov_ok = sh("nm " + str(HOME/"env/linux/vmlinux") + " 2>/dev/null | grep -c -m1 ' T kcov_remote_start\\| t kcov_remote_start' >/dev/null")[0] or \
              sh("nm " + str(HOME/"env/linux/vmlinux") + " 2>/dev/null | grep -q ' kcov_remote'")[0]
psi["Psi1(kcov)"] = kcov_ok

ok_psi = all(psi.values())
for k, v in psi.items():
    print(("  [pre] %-14s %s" % (k, "ok" if v else "MISSING")))

bundle = pathlib.Path(os.environ["BUNDLE"])

# ---------- R1 build integrity ----------
_ms_detail = _mem_san or ("kasan" if _ms.get("target_kasan") else
                          ("kcsan" if _ms.get("target_kcsan") else "none"))
r1 = gate("R1", "build-integrity",
    m.get("status") == "pass" and (_mem_san in ("kasan", "kcsan") or _legacy_ms),
    "status=%s mem_sanitizer=%s" % (m.get("status"), _ms_detail))

# ---------- R2 AB (R3 throughput retired 2026-09-26) ----------
a = read_json(HOME/"evidence/analysis_summary.json")
g = a.get("group_statistics", {})
off_fs, on_fs = g.get("off", {}).get("fs/nfsd", {}).get("mean", -1), \
                g.get("on", {}).get("fs/nfsd", {}).get("mean", -1)
r2 = gate("R2", "remote-contribution",
    off_fs == 0 and on_fs > 0 and a.get("all_trials_converged") is True and
    a.get("controls_equal_except_remote_toggle") is True,
    "off fs/nfsd=%.0f on fs/nfsd=%.0f converged=%s controls_eq=%s" % (
        off_fs, on_fs, a.get("all_trials_converged"), a.get("controls_equal_except_remote_toggle")))

# ---------- R4 coverage depth (general corpus) ----------
sa = a.get("set_analysis", {})
fsd_on_only = sa.get("fs/nfsd", {}).get("on_only", 0)
sunrpc_on_only = sa.get("net/sunrpc", {}).get("on_only", 0)
ranked = HOME/"evidence/coverage_sets/fs_nfsd_on_only_ranked.csv"
rank_rows, has_compound = 0, False
if ranked.exists():
    import csv
    with open(ranked, encoding="utf-8") as f:
        rd = list(csv.DictReader(f))
    rank_rows = len(rd)
    has_compound = any(r.get("function") == "nfsd4_proc_compound" and
                       int(r.get("on_only_unique_pcs", 0) or 0) > 0 for r in rd)
r4 = gate("R4", "coverage-depth-general",
    fsd_on_only >= 100 and sunrpc_on_only > 0 and rank_rows >= 10 and has_compound,
    "fs/nfsd.on_only=%d net/sunrpc.on_only=%d ranked_rows=%d nfsd4_proc_compound=%s" % (
        fsd_on_only, sunrpc_on_only, rank_rows, has_compound))

# ---------- R5 evidence chain (general corpus) ----------
sets_dir = HOME/"evidence/coverage_sets"
need_sets = ("fs_nfsd_on_only.pcs", "fs_nfsd_on_union.pcs", "fs_nfs_on_only.pcs",
             "net_sunrpc_on_only.pcs", "net_sunrpc_off_only.pcs", "fs_nfsd_on_only_ranked.csv")
sets_ok = all((sets_dir / s).exists() for s in need_sets)
share = a.get("primary", {}).get("remote_contribution_share_percent", 0)
r5 = gate("R5", "evidence-chain-general",
    a.get("status") == "PASS" and a.get("integrity_pass") is True and
    share >= 95 and sets_ok,
    "status=%s integrity=%s share=%.0f%% sets=%d/6" % (
        a.get("status"), a.get("integrity_pass"), share, sum(1 for s in need_sets if (sets_dir / s).exists())))

# ---------- R6 audit coupling ----------
sha_ok = 0
for sub in ("kernel", "syzkaller"):
    ok, _ = sh("cd '%s/%s' && sha256sum -c SHA256SUMS >/dev/null 2>&1" % (bundle, sub))
    sha_ok += bool(ok)
def series_shape(sub):
    """Hash the patch series actually on disk, in order."""
    base = bundle/sub
    listing = []
    series = base/"series"
    if not series.exists():
        return listing
    for line in series.read_text(encoding="utf-8").splitlines():
        entry = line.strip()
        if not entry:
            continue
        ok, digest = sh("sha256sum '%s' | cut -d' ' -f1" % (base/entry))
        listing.append(digest if ok else "MISSING:" + entry)
    return listing

ks_on = series_shape("kernel")
ss_on = series_shape("syzkaller")
kp = m.get("pins", {}).get("kernel_series", [])
sp = m.get("pins", {}).get("syz_series", [])
# The pins must describe the series that is actually present.  Counting alone
# let a newly added patch slip through, which is why this compares the hashes
# and the lengths together.
pins_match = (kp == ks_on) and (sp == ss_on)
r6 = gate("R6", "apply-audit",
    sha_ok == 2 and pins_match,
    "sha256 bundles=%d/2 kernel_pins=%d/%d match=%s syz_pins=%d/%d match=%s" % (
        sha_ok, len(kp), len(ks_on), kp == ks_on,
        len(sp), len(ss_on), sp == ss_on))

# ---------- verdict ----------
fails = [r for r in rows if not r[2]]
print()
print("requirement | verdict | evidence")
print("----------- | ------- | --------")
for rid, name, ok, detail in rows:
    print("%-3s %-22s | %-7s | %s" % (rid, name, "PASS" if ok else "FAIL", detail))

print()
if not ok_psi:
    print("PRECONDITIONS UNMET -> veredict: UNSUPPORTED (not a design failure; hardened boundary per design-spec.md §1)")
    sys.exit(2)
elif fails:
    print("DESIGN HOLDS on this target: NO (%d gate(s) failed)" % len(fails))
    sys.exit(1)
else:
    print("DESIGN HOLDS on this target: YES (all active gates pass, machine-checked)")
    sys.exit(0)
PYEOF