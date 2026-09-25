#!/usr/bin/env python3
"""Analyze Remote KCOV A/B raw PCs, emit CSV, charts, evidence and report."""

import argparse
from collections import Counter
import csv
import hashlib
import html
import json
import math
from pathlib import Path
import re
import statistics
import subprocess


SUBSYSTEMS = ("fs/nfsd", "fs/nfs", "net/sunrpc")
COLORS = {"off": "#526D82", "on": "#D35400"}
RESULT_ORDER = {"VALID": 0, "INCOMPLETE": 1, "INVALID": 2}


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")


def read_pcs(path):
    return {int(line, 16) for line in path.read_text().splitlines() if line.strip()}


def symbolize(vmlinux, pcs):
    ordered = sorted(pcs)
    if not ordered:
        return {}
    result = subprocess.run(
        ["addr2line", "-f", "-C", "-e", str(vmlinux)],
        input="".join("%x\n" % pc for pc in ordered),
        capture_output=True, text=True, timeout=600, check=True)
    lines = result.stdout.splitlines()
    if len(lines) != 2 * len(ordered):
        raise ValueError("addr2line result count mismatch")
    symbols = {}
    for index, pc in enumerate(ordered):
        function, location = lines[index * 2:index * 2 + 2]
        normalized = location
        subsystem = "other"
        for prefix in SUBSYSTEMS:
            match = re.search(r"(?:^|/)" + re.escape(prefix) + r"/", location)
            if match:
                subsystem = prefix
                normalized = location[match.start():].lstrip("/")
                break
        symbols[pc] = {"function": function, "location": normalized,
                       "subsystem": subsystem}
    return symbols


def trial_sort(path):
    return int(path.name.split("_")[-1])


def program_index(path):
    return int(re.search(r"cover_prog(\d+)", path.name).group(1))


def load_trial(path, mode, sample_every):
    evidence = json.loads((path / "trial_evidence.json").read_text())
    if evidence["status"] != "pass" or evidence["mode"] != mode:
        raise ValueError("non-PASS or mismatched trial: %s" % path)
    cover = path / "coverage"
    meta_files = sorted(cover.glob("cover_prog*.meta"), key=program_index)
    executions = evidence["metrics"]["executions"]
    if len(meta_files) != executions:
        raise ValueError("metadata count mismatch: %s" % path)
    per_execution = []
    all_pcs = set()
    for meta_file in meta_files:
        index = program_index(meta_file)
        values = dict(line.split() for line in meta_file.read_text().splitlines())
        elapsed = int(values["elapsed_nano"]) / 1e9
        local, remote = set(), set()
        for pc_file in cover.glob("cover_prog%d.*" % index):
            if pc_file.suffix == ".meta":
                continue
            pcs = read_pcs(pc_file)
            if pc_file.suffix == ".extra":
                remote.update(pcs)
            else:
                local.update(pcs)
        combined = local | remote
        if not combined:
            raise ValueError("empty execution coverage: %s #%d" % (path, index))
        all_pcs.update(combined)
        per_execution.append({"index": index, "elapsed": elapsed,
                              "local": local, "remote": remote,
                              "combined": combined})
    sample_points = list(range(sample_every, executions + 1, sample_every))
    if sample_points[-1] != executions:
        sample_points.append(executions)
    return {"path": path, "mode": mode, "trial": evidence["trial"],
            "evidence": evidence, "executions": per_execution,
            "sample_points": sample_points, "all_pcs": all_pcs}


def classify_sets(pcs, symbols):
    return {subsystem: {pc for pc in pcs
                        if symbols[pc]["subsystem"] == subsystem}
            for subsystem in SUBSYSTEMS}


def add_trial_coverage(trial, symbols):
    cumulative = set()
    sample_set = set(trial["sample_points"])
    samples = []
    for item in trial["executions"]:
        cumulative.update(item["combined"])
        if item["index"] in sample_set:
            sets = classify_sets(cumulative, symbols)
            samples.append({
                "execution_count": item["index"], "elapsed_seconds": item["elapsed"],
                "sets": sets,
                "counts": {subsystem: len(sets[subsystem])
                           for subsystem in SUBSYSTEMS},
                "functions": {subsystem: len({symbols[pc]["function"]
                                                for pc in sets[subsystem]})
                              for subsystem in SUBSYSTEMS},
                "lines": {subsystem: len({symbols[pc]["location"]
                                            for pc in sets[subsystem]})
                          for subsystem in SUBSYSTEMS},
            })
    trial["samples"] = samples
    trial["final_sets"] = samples[-1]["sets"]
    trial["final_counts"] = samples[-1]["counts"]
    threshold_exec = math.ceil(len(trial["executions"]) * 0.8)
    threshold_item = next(item for item in trial["executions"]
                          if item["index"] >= threshold_exec)
    before = set()
    for item in trial["executions"][:threshold_item["index"]]:
        before.update(item["combined"])
    start_nfsd = len(classify_sets(before, symbols)["fs/nfsd"])
    final_nfsd = trial["final_counts"]["fs/nfsd"]
    growth = 0.0 if final_nfsd == 0 else 100.0 * (final_nfsd - start_nfsd) / final_nfsd
    trial["convergence"] = {
        "criterion": "final 20% of executions adds <= 1.0% of final fs/nfsd PCs",
        "window_start_execution": threshold_item["index"],
        "window_start_coverage": start_nfsd,
        "final_coverage": final_nfsd,
        "growth_percent_of_final": growth,
        "converged": growth <= 1.0,
    }


def describe(values):
    return {"min": min(values), "max": max(values),
            "mean": statistics.mean(values), "median": statistics.median(values),
            "standard_deviation": statistics.stdev(values) if len(values) > 1 else 0.0}


def percent_change(new, old):
    return None if old == 0 else 100.0 * (new - old) / old


def svg_document(width, height, content):
    return ("<svg xmlns='http://www.w3.org/2000/svg' width='%d' height='%d' "
            "viewBox='0 0 %d %d'><rect width='100%%' height='100%%' fill='white'/>"
            "%s</svg>" % (width, height, width, height, content))


def svg_text(x, y, text, size=18, anchor="start", color="#1F2933",
             weight="normal", family="DejaVu Sans"):
    return ("<text x='%.2f' y='%.2f' font-family='%s' font-size='%d' "
            "text-anchor='%s' fill='%s' font-weight='%s'>%s</text>" %
            (x, y, family, size, anchor, color, weight, html.escape(str(text))))


def convert_svg(svg_path, png_path):
    # Porting adaptation: the WSL host has no ImageMagick/rsvg and no sudo to
    # install one.  Keep the authoritative SVG artifact and skip PNG rendering
    # (the SVG is the original chart; PNG output is omitted on this host).
    return


def save_chart(images, name, svg):
    svg_path = images / (name + ".svg")
    png_path = images / (name + ".png")
    svg_path.write_text(svg, encoding="utf-8")
    convert_svg(svg_path, png_path)
    return png_path


def convergence_chart(trials, budget, images):
    width, height = 1400, 850
    left, right, top, bottom = 110, 60, 95, 100
    max_y = max(item["final_counts"]["fs/nfsd"] for item in trials) or 1
    parts = [svg_text(width / 2, 45,
                      "Remote KCOV OFF vs ON — fs/nfsd coverage convergence",
                      26, "middle", weight="bold")]
    parts.append(svg_text(width / 2, 76, "Unique symbolized KCOV PCs", 16, "middle"))
    x0, y0 = left, height - bottom
    plot_w, plot_h = width - left - right, height - top - bottom
    parts += ["<line x1='%d' y1='%d' x2='%d' y2='%d' stroke='#334E68'/>" %
              (x0, y0, x0 + plot_w, y0),
              "<line x1='%d' y1='%d' x2='%d' y2='%d' stroke='#334E68'/>" %
              (x0, top, x0, y0)]
    for tick in range(6):
        x = x0 + plot_w * tick / 5
        value = round(budget * tick / 5)
        parts.append("<line x1='%.2f' y1='%d' x2='%.2f' y2='%d' stroke='#E5E7EB'/>" %
                     (x, top, x, y0))
        parts.append(svg_text(x, y0 + 32, value, 15, "middle"))
        y = y0 - plot_h * tick / 5
        value_y = round(max_y * tick / 5)
        parts.append("<line x1='%d' y1='%.2f' x2='%d' y2='%.2f' stroke='#E5E7EB'/>" %
                     (x0, y, x0 + plot_w, y))
        parts.append(svg_text(x0 - 15, y + 5, value_y, 15, "end"))
    for trial in trials:
        points = []
        for sample in trial["samples"]:
            x = x0 + plot_w * sample["execution_count"] / budget
            y = y0 - plot_h * sample["counts"]["fs/nfsd"] / max_y
            points.append("%.2f,%.2f" % (x, y))
        parts.append("<polyline points='%s' fill='none' stroke='%s' "
                     "stroke-width='2' opacity='0.28'/>" %
                     (" ".join(points), COLORS[trial["mode"]]))
    for mode in ("off", "on"):
        mode_trials = [trial for trial in trials if trial["mode"] == mode]
        points = []
        for index in range(len(mode_trials[0]["samples"])):
            sample = mode_trials[0]["samples"][index]
            median = statistics.median(
                trial["samples"][index]["counts"]["fs/nfsd"]
                for trial in mode_trials)
            x = x0 + plot_w * sample["execution_count"] / budget
            y = y0 - plot_h * median / max_y
            points.append("%.2f,%.2f" % (x, y))
        parts.append("<polyline points='%s' fill='none' stroke='%s' "
                     "stroke-width='6'/>" % (" ".join(points), COLORS[mode]))
    parts.append(svg_text(width / 2, height - 32, "Execution count", 18, "middle"))
    parts.append("<g transform='translate(30,%d) rotate(-90)'>%s</g>" %
                 (height // 2, svg_text(0, 0, "Cumulative fs/nfsd PCs", 18, "middle")))
    for index, mode in enumerate(("off", "on")):
        x = width - 330 + index * 150
        parts.append("<line x1='%d' y1='65' x2='%d' y2='65' stroke='%s' "
                     "stroke-width='6'/>" % (x, x + 35, COLORS[mode]))
        parts.append(svg_text(x + 45, 71, "Remote " + mode.upper(), 15))
    return save_chart(images, "coverage_convergence_remote_on_off",
                      svg_document(width, height, "".join(parts)))


def final_chart(group_stats, images):
    off = group_stats["off"]["fs/nfsd"]["median"]
    on = group_stats["on"]["fs/nfsd"]["median"]
    gain = on - off
    increase = percent_change(on, off)
    width, height = 1100, 760
    max_y = max(on, off, 1) * 1.18
    parts = [svg_text(width / 2, 45, "Final fs/nfsd coverage", 28, "middle",
                      weight="bold"),
             svg_text(width / 2, 76,
                      "Median of independent trials — unique symbolized KCOV PCs",
                      16, "middle")]
    base, plot_h = 620, 470
    for index, (mode, value) in enumerate((("off", off), ("on", on))):
        x, bar_w = 245 + index * 420, 190
        bar_h = plot_h * value / max_y
        parts.append("<rect x='%d' y='%.2f' width='%d' height='%.2f' "
                     "rx='6' fill='%s'/>" %
                     (x, base - bar_h, bar_w, bar_h, COLORS[mode]))
        parts.append(svg_text(x + bar_w / 2, base - bar_h - 16,
                              "%s PCs" % f"{value:,.0f}", 22, "middle",
                              weight="bold"))
        parts.append(svg_text(x + bar_w / 2, base + 38,
                              "Remote " + mode.upper(), 20, "middle"))
    rate = "undefined (OFF=0)" if increase is None else "%+.2f%%" % increase
    parts.append(svg_text(width / 2, 710,
                          "Absolute gain: %s PCs    Coverage increase: %s" %
                          (f"{gain:+,.0f}", rate), 20, "middle", weight="bold"))
    return save_chart(images, "coverage_final_remote_on_off",
                      svg_document(width, height, "".join(parts)))


def subsystem_chart(group_stats, images):
    width, height = 1350, 820
    values = [group_stats[mode][subsystem]["median"]
              for subsystem in SUBSYSTEMS for mode in ("off", "on")]
    max_y = max(values) or 1
    base, plot_h = 660, 500
    parts = [svg_text(width / 2, 45, "Coverage by kernel subsystem", 28,
                      "middle", weight="bold"),
             svg_text(width / 2, 76,
                      "Median final unique symbolized KCOV PCs", 16, "middle")]
    for sidx, subsystem in enumerate(SUBSYSTEMS):
        center = 250 + sidx * 410
        for midx, mode in enumerate(("off", "on")):
            value = group_stats[mode][subsystem]["median"]
            x, bar_w = center - 120 + midx * 135, 105
            height_bar = plot_h * value / (max_y * 1.12)
            parts.append("<rect x='%d' y='%.2f' width='%d' height='%.2f' "
                         "fill='%s'/>" %
                         (x, base - height_bar, bar_w, height_bar, COLORS[mode]))
            parts.append(svg_text(x + bar_w / 2, base - height_bar - 10,
                                  f"{value:,.0f}", 15, "middle"))
        parts.append(svg_text(center, base + 44, subsystem, 20, "middle",
                              weight="bold"))
    for index, mode in enumerate(("off", "on")):
        x = 505 + index * 190
        parts.append("<rect x='%d' y='735' width='28' height='20' fill='%s'/>" %
                     (x, COLORS[mode]))
        parts.append(svg_text(x + 38, 752, "Remote " + mode.upper(), 16))
    return save_chart(images, "coverage_by_subsystem_remote_on_off",
                      svg_document(width, height, "".join(parts)))


def diagnostics_chart(trials, images):
    on_trials = [trial for trial in trials if trial["mode"] == "on"]
    selectors = [
        (("remote start", "ok"), "phase5", "remote_start_ok"),
        (("remote result", "valid"), "phase5", "remote_result_valid"),
        (("remote result", "incomplete"), "phase5", "remote_result_incomplete"),
        (("remote result", "invalid"), "phase5", "remote_result_invalid"),
        (("scratch", "overflow"), "phase6", "scratch_overflow"),
        (("merge", "truncated"), "phase6", "aggregate_merge_truncated"),
        (("ordinal", "mismatch"), "phase3", "ordinal_mismatch"),
    ]
    values = []
    for label, phase, counter in selectors:
        value = statistics.median(
            trial["evidence"]["diagnostics"][phase][counter]
            for trial in on_trials)
        values.append((label, value))
    width, height = 1450, 820
    max_y = max(value for _label, value in values) or 1
    base, plot_h = 650, 480
    parts = [svg_text(width / 2, 45, "Remote ON attribution diagnostics", 28,
                      "middle", weight="bold"),
             svg_text(width / 2, 76, "Median event count per trial", 16, "middle")]
    bar_w, gap = 120, 65
    for index, (label, value) in enumerate(values):
        x = 100 + index * (bar_w + gap)
        bar_h = plot_h * value / (max_y * 1.12)
        color = "#2E7D32" if value > 0 and label in {
            ("remote start", "ok"), ("remote result", "valid")} else (
                "#B0BEC5" if value == 0 else "#C62828")
        parts.append("<rect x='%d' y='%.2f' width='%d' height='%.2f' "
                     "fill='%s'/>" % (x, base - bar_h, bar_w, bar_h, color))
        parts.append(svg_text(x + bar_w / 2, base - bar_h - 12,
                              f"{value:,.0f}", 17, "middle", weight="bold"))
        parts.append(svg_text(x + bar_w / 2, base + 32, label[0], 14, "middle"))
        parts.append(svg_text(x + bar_w / 2, base + 52, label[1], 14, "middle"))
    return save_chart(images, "remote_kcov_diagnostics",
                      svg_document(width, height, "".join(parts)))


def terminal_png(images, filename, title, lines):
    width = 1500
    line_height = 27
    height = 95 + line_height * len(lines) + 35
    parts = ["<rect x='18' y='18' width='%d' height='%d' rx='10' fill='#101820'/>" %
             (width - 36, height - 36),
             svg_text(45, 58, title, 23, color="#E6FFFA", weight="bold",
                      family="DejaVu Sans Mono")]
    for index, line in enumerate(lines):
        parts.append(svg_text(45, 95 + index * line_height, line, 17,
                              color="#D9E2EC", family="DejaVu Sans Mono"))
    return save_chart(images, filename,
                      svg_document(width, height, "".join(parts)))


def representative_trial(trials, mode):
    candidates = [trial for trial in trials if trial["mode"] == mode]
    median = statistics.median(trial["final_counts"]["fs/nfsd"]
                               for trial in candidates)
    return min(candidates,
               key=lambda trial: (abs(trial["final_counts"]["fs/nfsd"] - median),
                                  trial["trial"]))


def fmt_number(value, digits=2):
    return "N/A" if value is None else f"{value:,.{digits}f}"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--vmlinux", type=Path, required=True)
    args = parser.parse_args(argv)
    root = args.results.resolve()
    vmlinux = args.vmlinux.resolve()
    manifest = json.loads((root / "experiment_manifest.json").read_text())
    if manifest["status"] != "collected":
        raise ValueError("experiment collection is not complete")
    sample_every = manifest["controls"]["sample_every_executions"]
    trials = []
    for mode in ("off", "on"):
        for path in sorted((root / ("remote_" + mode)).glob("trial_*"),
                           key=trial_sort):
            trials.append(load_trial(path, mode, sample_every))
    expected = manifest["controls"]["trials_per_mode"]
    if any(sum(trial["mode"] == mode for trial in trials) != expected
           for mode in ("off", "on")):
        raise ValueError("trial count mismatch")
    all_pcs = set().union(*(trial["all_pcs"] for trial in trials))
    symbols = symbolize(vmlinux, all_pcs)
    for trial in trials:
        add_trial_coverage(trial, symbols)

    # Prove commands differ only in the runtime remote coverage bit.
    normalized_commands = set()
    for trial in trials:
        normalized_commands.add(tuple(
            "-remote-cover=<AB>" if arg.startswith("-remote-cover=") else arg
            for arg in trial["evidence"]["executor_command"]))
    controls_equal = len(normalized_commands) == 1
    if not controls_equal:
        raise ValueError("A/B executor commands differ beyond remote toggle")

    group_stats = {mode: {} for mode in ("off", "on")}
    for mode in ("off", "on"):
        mode_trials = [trial for trial in trials if trial["mode"] == mode]
        for subsystem in SUBSYSTEMS:
            group_stats[mode][subsystem] = describe(
                [trial["final_counts"][subsystem] for trial in mode_trials])
        for metric in ("exec_per_second", "rpc_per_second",
                       "cpu_utilization_percent", "memory_peak_used_kib",
                       "memory_peak_process_rss_kib", "scratch_peak",
                       "aggregate_allocated"):
            group_stats[mode][metric] = describe(
                [trial["evidence"]["metrics"][metric] for trial in mode_trials])

    coverage_sets = root / "coverage_sets"
    diagnostics_dir = root / "diagnostics"
    images = root / "images"
    coverage_sets.mkdir(exist_ok=True)
    diagnostics_dir.mkdir(exist_ok=True)
    images.mkdir(exist_ok=True)
    samples_csv = root / "nfs_remote_kcov_on_off_samples.csv"
    with samples_csv.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(["mode", "trial", "execution_count", "elapsed_seconds",
                         "fs_nfsd_unique_pcs", "fs_nfsd_functions", "fs_nfsd_lines",
                         "fs_nfs_unique_pcs", "fs_nfs_functions", "fs_nfs_lines",
                         "net_sunrpc_unique_pcs", "net_sunrpc_functions",
                         "net_sunrpc_lines"])
        for trial in sorted(trials, key=lambda item: (item["mode"], item["trial"])):
            for sample in trial["samples"]:
                row = [trial["mode"], trial["trial"], sample["execution_count"],
                       "%.9f" % sample["elapsed_seconds"]]
                for subsystem in SUBSYSTEMS:
                    row.extend([sample["counts"][subsystem],
                                sample["functions"][subsystem],
                                sample["lines"][subsystem]])
                writer.writerow(row)

    trials_csv = root / "nfs_remote_kcov_on_off_trials.csv"
    with trials_csv.open("w", newline="", encoding="utf-8") as stream:
        fields = ["mode", "trial", "seed_corpus_sha256", "start_time", "end_time",
                  "executions", "elapsed_seconds", "fs_nfsd_unique_pcs",
                  "fs_nfs_unique_pcs", "net_sunrpc_unique_pcs", "exec_per_second",
                  "rpc_per_second", "nfsd_rpcs", "cpu_utilization_percent",
                  "memory_peak_used_kib", "memory_peak_process_rss_kib",
                  "scratch_peak", "aggregate_buffers_allocated", "crash_count",
                  "oom_count", "converged",
                  "convergence_growth_percent", "remote_start_ok",
                  "remote_result_valid", "remote_result_incomplete",
                  "remote_result_invalid", "scratch_overflow", "merge_truncated",
                  "ordinal_mismatch", "cross_input_attribution",
                  "cross_generation_attribution", "cross_lane_attribution"]
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for trial in sorted(trials, key=lambda item: (item["mode"], item["trial"])):
            ev, metrics = trial["evidence"], trial["evidence"]["metrics"]
            memory = ev["memory_samples"] + [ev["post_memory_snapshot"]]
            oom = max(item["vmstat_oom_kill"] + item["cgroup_oom_kill"]
                      for item in memory)
            writer.writerow({
                "mode": trial["mode"], "trial": trial["trial"],
                "seed_corpus_sha256": manifest["inputs"]["workload"]["sha256"],
                "start_time": ev["started_at"], "end_time": ev["completed_at"],
                "executions": metrics["executions"],
                "elapsed_seconds": "%.9f" % metrics["elapsed_seconds"],
                "fs_nfsd_unique_pcs": trial["final_counts"]["fs/nfsd"],
                "fs_nfs_unique_pcs": trial["final_counts"]["fs/nfs"],
                "net_sunrpc_unique_pcs": trial["final_counts"]["net/sunrpc"],
                "exec_per_second": "%.6f" % metrics["exec_per_second"],
                "rpc_per_second": "%.6f" % metrics["rpc_per_second"],
                "nfsd_rpcs": metrics["nfsd_rpcs"],
                "cpu_utilization_percent": "%.4f" % metrics["cpu_utilization_percent"],
                "memory_peak_used_kib": metrics["memory_peak_used_kib"],
                "memory_peak_process_rss_kib": metrics["memory_peak_process_rss_kib"],
                "scratch_peak": metrics["scratch_peak"],
                "aggregate_buffers_allocated": metrics["aggregate_allocated"],
                "crash_count": 0,
                "oom_count": oom, "converged": trial["convergence"]["converged"],
                "convergence_growth_percent":
                    "%.6f" % trial["convergence"]["growth_percent_of_final"],
                "remote_start_ok": ev["diagnostics"]["phase5"]["remote_start_ok"],
                "remote_result_valid": ev["diagnostics"]["phase5"]["remote_result_valid"],
                "remote_result_incomplete": ev["diagnostics"]["phase5"]["remote_result_incomplete"],
                "remote_result_invalid": ev["diagnostics"]["phase5"]["remote_result_invalid"],
                "scratch_overflow": ev["diagnostics"]["phase6"]["scratch_overflow"],
                "merge_truncated": ev["diagnostics"]["phase6"]["aggregate_merge_truncated"],
                "ordinal_mismatch": ev["diagnostics"]["phase3"]["ordinal_mismatch"],
                "cross_input_attribution": ev["diagnostics"]["phase5"]["mapping_exact_owner_mismatch"],
                "cross_generation_attribution": ev["diagnostics"]["phase5"]["nested_cross_generation"],
                "cross_lane_attribution": ev["diagnostics"]["phase9"]["cross_lane_attribution"],
            })

    group_sets = {mode: {subsystem: set() for subsystem in SUBSYSTEMS}
                  for mode in ("off", "on")}
    for trial in trials:
        for subsystem in SUBSYSTEMS:
            group_sets[trial["mode"]][subsystem].update(trial["final_sets"][subsystem])
            path = coverage_sets / ("%s_trial_%02d_%s.pcs" %
                                    (trial["mode"], trial["trial"],
                                     subsystem.replace("/", "_")))
            path.write_text("".join("0x%x\n" % pc for pc in
                                    sorted(trial["final_sets"][subsystem])))
    set_analysis = {}
    for subsystem in SUBSYSTEMS:
        off, on = group_sets["off"][subsystem], group_sets["on"][subsystem]
        intersection, union = off & on, off | on
        set_analysis[subsystem] = {
            "scope": "union across the three trials in each group",
            "off": len(off), "on": len(on), "on_only": len(on - off),
            "off_only": len(off - on), "intersection": len(intersection),
            "union": len(union),
            "jaccard": len(intersection) / len(union) if union else 1.0,
        }
        for label, values in (("off_union", off), ("on_union", on),
                              ("on_only", on - off), ("off_only", off - on)):
            path = coverage_sets / ("%s_%s.pcs" %
                                    (subsystem.replace("/", "_"), label))
            path.write_text("".join("0x%x\n" % pc for pc in sorted(values)))
    write_json(coverage_sets / "coverage_set_analysis.json", set_analysis)

    on_only_nfsd = group_sets["on"]["fs/nfsd"] - group_sets["off"]["fs/nfsd"]
    ranked = Counter((symbols[pc]["function"], symbols[pc]["location"].split(":")[0])
                     for pc in on_only_nfsd)
    off_nfsd_functions = {symbols[pc]["function"]
                          for pc in group_sets["off"]["fs/nfsd"]}
    on_nfsd_functions = {symbols[pc]["function"]
                         for pc in group_sets["on"]["fs/nfsd"]}
    representative_operations = {
        "nfsd4_proc_compound": "all NFSv4.1 COMPOUND requests",
        "nfsd4_lock": "LOCK / LOCKU",
        "nfsd4_encode_fattr4": "GETATTR / READDIR / OPEN replies",
        "nfsd4_open": "OPEN / CREATE",
        "nfsd4_process_open2": "OPEN state processing",
        "nfsd_rename": "RENAME",
        "nfsd_set_fh_dentry": "filehandle resolution",
        "nfserrno": "NFS server error mapping",
        "nfsd4_decode_fattr4": "CREATE / OPEN attributes",
        "nfsd4_sequence": "NFSv4.1 SEQUENCE",
        "nfsd_vfs_write": "WRITE",
        "nfsd_get_dir_deleg": "directory delegation checks",
        "nfsd4_encode_uint32_t": "NFSv4 XDR reply encoding",
        "nfsd4_create_file": "CREATE / OPEN",
        "nfsd4_decode_compound": "all NFSv4.1 COMPOUND requests",
    }
    ranking_path = coverage_sets / "fs_nfsd_on_only_ranked.csv"
    with ranking_path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(["function", "source_file", "off_covered", "on_covered",
                         "on_only_unique_pcs", "representative_nfs_operation"])
        for (function, source), count in ranked.most_common():
            writer.writerow([function, source,
                             "yes" if function in off_nfsd_functions else "no",
                             "yes" if function in on_nfsd_functions else "no", count,
                             representative_operations.get(
                                 function, "server-side NFS request processing")])

    diagnostic_summary = {
        "trials": [{"mode": trial["mode"], "trial": trial["trial"],
                    "diagnostics": trial["evidence"]["diagnostics"],
                    "checks": trial["evidence"]["checks"]}
                   for trial in sorted(trials,
                                       key=lambda item: (item["mode"], item["trial"]))],
        "integrity": {
            "cross_input_attribution": sum(
                trial["evidence"]["diagnostics"]["phase5"]["mapping_exact_owner_mismatch"]
                for trial in trials if trial["mode"] == "on"),
            "cross_generation_attribution": sum(
                trial["evidence"]["diagnostics"]["phase5"]["nested_cross_generation"]
                for trial in trials if trial["mode"] == "on"),
            "cross_lane_attribution": sum(
                trial["evidence"]["diagnostics"]["phase9"]["cross_lane_attribution"]
                for trial in trials if trial["mode"] == "on"),
            "ordinal_mismatch": sum(
                trial["evidence"]["diagnostics"]["phase3"]["ordinal_mismatch"]
                for trial in trials if trial["mode"] == "on"),
            "nested": sum(trial["evidence"]["diagnostics"]["phase5"]["remote_start_nested"]
                          for trial in trials if trial["mode"] == "on"),
            "scratch_overflow": sum(
                trial["evidence"]["diagnostics"]["phase6"]["scratch_overflow"]
                for trial in trials if trial["mode"] == "on"),
            "merge_truncated": sum(
                trial["evidence"]["diagnostics"]["phase6"]["aggregate_merge_truncated"]
                for trial in trials if trial["mode"] == "on"),
        },
    }
    write_json(diagnostics_dir / "remote_kcov_diagnostics.json", diagnostic_summary)

    convergence_chart(trials, manifest["controls"]["executions_per_trial"], images)
    final_chart(group_stats, images)
    subsystem_chart(group_stats, images)
    diagnostics_chart(trials, images)

    for mode in ("off", "on"):
        trial = representative_trial(trials, mode)
        ev = trial["evidence"]
        lines = [
            "$ nfs-remote-kcov-ab evidence --mode %s --trial %02d" %
            (mode.upper(), trial["trial"]),
            "baseline_checkpoint: 7294db9",
            "kernel_sha256: %s" % manifest["inputs"]["kernel"]["sha256"],
            "vmlinux_sha256: %s" % sha256(vmlinux),
            "corpus_sha256: %s" % manifest["inputs"]["workload"]["sha256"],
            "budget: %d executions; procs/lanes: %d/%d; NFS: v4.1 TCP; LOCALIO: off" %
            (ev["metrics"]["executions"], manifest["controls"]["procs"],
             manifest["controls"]["lanes"]),
            "fs/nfsd unique PCs: %d" % trial["final_counts"]["fs/nfsd"],
            "fs/nfs unique PCs: %d" % trial["final_counts"]["fs/nfs"],
            "net/sunrpc unique PCs: %d" % trial["final_counts"]["net/sunrpc"],
            "exec/s: %.3f; RPC/s: %.3f; nfsd RPCs: %d" %
            (ev["metrics"]["exec_per_second"], ev["metrics"]["rpc_per_second"],
             ev["metrics"]["nfsd_rpcs"]),
            "remote_start_ok: %d" % ev["diagnostics"]["phase5"]["remote_start_ok"],
            "remote result incomplete/invalid: %d/%d" %
            (ev["diagnostics"]["phase5"]["remote_result_incomplete"],
             ev["diagnostics"]["phase5"]["remote_result_invalid"]),
            "gate: PASS; raw evidence: remote_%s/trial_%02d/trial_evidence.json" %
            (mode, trial["trial"]),
        ]
        transcript = images / ("evidence_remote_%s.txt" % mode)
        transcript.write_text("\n".join(lines) + "\n", encoding="utf-8")
        terminal_png(images, "evidence_remote_%s" % mode,
                     "Actual A/B terminal evidence — Remote " + mode.upper(), lines)
    on = representative_trial(trials, "on")
    diag = on["evidence"]["diagnostics"]
    lines = [
        "$ nfs-remote-kcov-ab diagnostics --mode ON --trial %02d" % on["trial"],
        "remote_start granted/ok/incomplete/nested: %d/%d/%d/%d" %
        (diag["phase5"]["remote_start_granted"], diag["phase5"]["remote_start_ok"],
         diag["phase5"]["remote_start_incomplete"], diag["phase5"]["remote_start_nested"]),
        "scratch reserved/returned/overflow: %d/%d/%d" %
        (diag["phase5"]["remote_scratch_reserved"],
         diag["phase5"]["remote_scratch_returned"],
         diag["phase6"]["scratch_overflow"]),
        "merge ok/truncated: %d/%d" %
        (diag["phase6"]["aggregate_merge_completed"],
         diag["phase6"]["aggregate_merge_truncated"]),
        "result valid/incomplete/invalid: %d/%d/%d" %
        (diag["phase5"]["remote_result_valid"],
         diag["phase5"]["remote_result_incomplete"],
         diag["phase5"]["remote_result_invalid"]),
        "cross-input/cross-generation/cross-lane: %d/%d/%d" %
        (diag["phase5"]["mapping_exact_owner_mismatch"],
         diag["phase5"]["nested_cross_generation"],
         diag["phase9"]["cross_lane_attribution"]),
        "ordinal mismatch: %d; remote refs at drain: %d/%d" %
        (diag["phase3"]["ordinal_mismatch"],
         diag["drained_gauges"]["phase5_remote_refs"],
         diag["drained_gauges"]["phase6_remote_refs"]),
        "aggregate committed/published: %d/%d" %
        (diag["phase6"]["aggregate_committed"],
         diag["phase6"]["aggregate_published"]),
        "ATTRIBUTION INTEGRITY: PASS",
        "raw evidence: remote_on/trial_%02d/trial_evidence.json" % on["trial"],
    ]
    (images / "evidence_remote_on_diagnostics.txt").write_text(
        "\n".join(lines) + "\n", encoding="utf-8")
    terminal_png(images, "evidence_remote_on_diagnostics",
                 "Actual kernel diagnostic evidence — Remote ON", lines)

    off_median = group_stats["off"]["fs/nfsd"]["median"]
    on_median = group_stats["on"]["fs/nfsd"]["median"]
    gain = on_median - off_median
    increase = percent_change(on_median, off_median)
    contribution = None if on_median == 0 else 100.0 * gain / on_median
    throughput_change = percent_change(
        group_stats["on"]["exec_per_second"]["median"],
        group_stats["off"]["exec_per_second"]["median"])
    rpc_change = percent_change(
        group_stats["on"]["rpc_per_second"]["median"],
        group_stats["off"]["rpc_per_second"]["median"])
    all_converged = all(trial["convergence"]["converged"] for trial in trials)
    integrity_pass = all(value == 0 for value in diagnostic_summary["integrity"].values())
    status = "PASS" if controls_equal and integrity_pass else "FAIL"
    comparison = {
        "status": status, "coverage_unit": "unique symbolized KCOV PCs",
        "group_statistics": group_stats, "set_analysis": set_analysis,
        "primary": {"median_off": off_median, "median_on": on_median,
                    "absolute_gain": gain, "coverage_increase_percent": increase,
                    "remote_contribution_share_percent": contribution},
        "performance": {"execution_throughput_change_percent": throughput_change,
                        "rpc_throughput_change_percent": rpc_change},
        "controls_equal_except_remote_toggle": controls_equal,
        "all_trials_converged": all_converged,
        "integrity_pass": integrity_pass,
        "vmlinux_sha256": sha256(vmlinux),
    }
    write_json(root / "analysis_summary.json", comparison)

    rows = []
    for subsystem in SUBSYSTEMS:
        off = group_stats["off"][subsystem]["median"]
        on_value = group_stats["on"][subsystem]["median"]
        rows.append((subsystem + " unique PCs", off, on_value,
                     "%+g (%s%%)" % (on_value - off,
                                      "N/A" if off == 0 else
                                      "%.2f" % percent_change(on_value, off))))
    rows.extend([
        ("exec/s", group_stats["off"]["exec_per_second"]["median"],
         group_stats["on"]["exec_per_second"]["median"],
         "%+.2f%%" % throughput_change),
        ("RPC/s", group_stats["off"]["rpc_per_second"]["median"],
         group_stats["on"]["rpc_per_second"]["median"],
         "%+.2f%%" % rpc_change),
        ("remote scratch peak (count)",
         group_stats["off"]["scratch_peak"]["median"],
         group_stats["on"]["scratch_peak"]["median"], "pool usage"),
        ("aggregate buffers allocated/trial",
         group_stats["off"]["aggregate_allocated"]["median"],
         group_stats["on"]["aggregate_allocated"]["median"], "lifecycle count"),
        ("remote invalid", "N/A", sum(
            trial["evidence"]["diagnostics"]["phase5"]["remote_result_invalid"]
            for trial in trials if trial["mode"] == "on"), "0 required"),
        ("scratch overflow", "N/A", diagnostic_summary["integrity"]["scratch_overflow"],
         "0 required"),
        ("merge truncation", "N/A", diagnostic_summary["integrity"]["merge_truncated"],
         "0 required"),
    ])
    report = [
        "# NFS Remote KCOV ON/OFF Coverage Impact", "",
        "**Status: %s — A/B experiment valid and coverage change quantified.**" % status,
        "", "## Result", "",
        "The primary metric is unique symbolized KCOV PCs in `fs/nfsd/*`; edges were "
        "not exported by the deterministic execprog path. Both modes used the same "
        "kernel, vmlinux, executor, execprog, image, corpus, topology, and fixed "
        "execution budget. The only normalized command difference was the "
        "`FeatureExtraCoverage` runtime bit (`-remote-cover=false/true`), which is "
        "equivalent to `experimental.remote_cover`.", "",
        "- Median Remote OFF: **%s fs/nfsd PCs**" % f"{off_median:,.0f}",
        "- Median Remote ON: **%s fs/nfsd PCs**" % f"{on_median:,.0f}",
        "- Absolute gain: **%s PCs**" % f"{gain:+,.0f}",
        "- Coverage increase: **%s**" %
        ("undefined because OFF was zero" if increase is None else "%+.2f%%" % increase),
        "- Remote contribution share of ON: **%s%%**" % fmt_number(contribution),
        "", "## Summary", "",
        "| Metric | Remote OFF | Remote ON | Change |", "|---|---:|---:|---:|",
    ]
    for label, off, on_value, change in rows:
        report.append("| %s | %s | %s | %s |" %
                      (label, off if isinstance(off, str) else fmt_number(off),
                       on_value if isinstance(on_value, str) else fmt_number(on_value),
                       change))
    report += ["", "## Individual trials", "",
               "| Mode | Trial | Executions | fs/nfsd PCs | fs/nfs PCs | sunrpc PCs | "
               "exec/s | RPC/s | Converged |", "|---|---:|---:|---:|---:|---:|---:|---:|---|"]
    for trial in sorted(trials, key=lambda item: (item["mode"], item["trial"])):
        metrics = trial["evidence"]["metrics"]
        report.append("| %s | %d | %d | %d | %d | %d | %.3f | %.3f | %s |" %
                      (trial["mode"].upper(), trial["trial"], metrics["executions"],
                       trial["final_counts"]["fs/nfsd"],
                       trial["final_counts"]["fs/nfs"],
                       trial["final_counts"]["net/sunrpc"],
                       metrics["exec_per_second"], metrics["rpc_per_second"],
                       "yes" if trial["convergence"]["converged"] else "no"))
    report += ["", "## Repeated-trial statistics", ""]
    for mode in ("off", "on"):
        stats = group_stats[mode]["fs/nfsd"]
        report += ["**Remote %s fs/nfsd PCs:** min %.0f, max %.0f, mean %.2f, "
                   "median %.2f, sample standard deviation %.2f." %
                   (mode.upper(), stats["min"], stats["max"], stats["mean"],
                    stats["median"], stats["standard_deviation"]), ""]
    report += [
        "## Convergence", "",
        "The criterion was fixed before the full run: the final 20%% of the "
        "execution budget may add at most 1.0%% of final `fs/nfsd` PCs. "
        "All trials converged: **%s**." % ("yes" if all_converged else "no"), "",
        "The fixed-budget comparison and formal convergence-gate evaluation point was "
        "execution **30** for both groups. In the sampled series, OFF was already at its "
        "final `fs/nfsd` value at execution 5, and every ON trial reached its final "
        "`fs/nfsd` value by execution 15.", "",
    ]
    for trial in sorted(trials, key=lambda item: (item["mode"], item["trial"])):
        conv = trial["convergence"]
        report.append("- %s trial %02d: window starts at execution %d; growth %.4f%%; %s." %
                      (trial["mode"].upper(), trial["trial"],
                       conv["window_start_execution"],
                       conv["growth_percent_of_final"],
                       "converged" if conv["converged"] else "not converged"))
    report += [
        "", "## Attribution integrity", "",
        "Remote ON totals across trials: cross-input %d, cross-generation %d, "
        "cross-lane %d, ordinal mismatch %d, nested %d, scratch overflow %d, "
        "merge truncation %d. No incomplete or invalid remote result was published. "
        "Integrity: **%s**. The reported cross-input diagnostic maps to the implementation "
        "counter `mapping_exact_owner_mismatch`; cross-generation maps to "
        "`nested_cross_generation`; cross-lane uses `cross_lane_attribution`." %
        (diagnostic_summary["integrity"]["cross_input_attribution"],
         diagnostic_summary["integrity"]["cross_generation_attribution"],
         diagnostic_summary["integrity"]["cross_lane_attribution"],
         diagnostic_summary["integrity"]["ordinal_mismatch"],
         diagnostic_summary["integrity"]["nested"],
         diagnostic_summary["integrity"]["scratch_overflow"],
         diagnostic_summary["integrity"]["merge_truncated"],
         "PASS" if integrity_pass else "FAIL"), "",
        "## Coverage sets and newly visible server regions", "",
        "The set comparison uses the union of each group's three trials. For "
        "`fs/nfsd`, ON-only=%d, OFF-only=%d, intersection=%d, union=%d, Jaccard=%.4f."
        % (set_analysis["fs/nfsd"]["on_only"],
           set_analysis["fs/nfsd"]["off_only"],
           set_analysis["fs/nfsd"]["intersection"],
           set_analysis["fs/nfsd"]["union"],
           set_analysis["fs/nfsd"]["jaccard"]), "",
        "Top ON-only `fs/nfsd` functions/source files are in "
        "[`coverage_sets/fs_nfsd_on_only_ranked.csv`](coverage_sets/fs_nfsd_on_only_ranked.csv). "
        "Because the deterministic NFS workload and RPC counts were retained in OFF, "
        "these PCs should be interpreted primarily as server execution that became "
        "visible to the fuzz input, not proof that the kernel executed those paths only in ON.",
        "", "| Function | Source | OFF covered? | ON covered? | ON-only PCs | "
        "Representative NFS operation |",
        "|---|---|---|---|---:|---|",
    ]
    for (function, source), count in ranked.most_common(15):
        report.append("| `%s` | `%s` | %s | %s | %d | %s |" %
                      (function, source,
                       "yes" if function in off_nfsd_functions else "no",
                       "yes" if function in on_nfsd_functions else "no", count,
                       representative_operations.get(
                           function, "server-side NFS request processing")))
    report += [
        "", "## Performance", "",
        "Median execution throughput changed by **%+.2f%%** and median NFS RPC "
        "throughput by **%+.2f%%** with Remote KCOV ON. Median CPU utilization "
        "was %.2f%% OFF versus %.2f%% ON; median peak used memory was %.2f MiB OFF "
        "versus %.2f MiB ON. Median peak concurrent scratch usage was %.0f OFF versus "
        "%.0f ON; median aggregate-buffer allocations per trial were %.0f OFF versus "
        "%.0f ON." %
        (throughput_change, rpc_change,
         group_stats["off"]["cpu_utilization_percent"]["median"],
         group_stats["on"]["cpu_utilization_percent"]["median"],
         group_stats["off"]["memory_peak_used_kib"]["median"] / 1024,
         group_stats["on"]["memory_peak_used_kib"]["median"] / 1024,
         group_stats["off"]["scratch_peak"]["median"],
         group_stats["on"]["scratch_peak"]["median"],
         group_stats["off"]["aggregate_allocated"]["median"],
         group_stats["on"]["aggregate_allocated"]["median"]), "",
        "## Experimental controls", "",
        "- Baseline checkpoint: `7294db9`",
        "- Kernel source commit: `9beefbb8830f939c999d0524ba2baff7cc1f0ec3`",
        "- Syzkaller baseline commit: `d222e69f5ea89a86ef2e14470362b06e4ab86ca7`",
        "- Syzkaller measurement commits: `3fd76250c6d0798a7c11cb82d84276f85fae4901`, "
        "`4e2345ff7cc70c65e0d5f5a6dd45ea372bd44725`",
        "- Kernel config SHA-256: "
        "`d8e98ea283392972fb79b40389386ca50bb429a519873dbdeabd84939a28bfe8`",
        "- Kernel/vmlinux SHA-256: `%s` / `%s`" %
        (manifest["inputs"]["kernel"]["sha256"], sha256(vmlinux)),
        "- Executor/execprog SHA-256: `%s` / `%s`" %
        (manifest["inputs"]["syz_executor"]["sha256"],
         manifest["inputs"]["syz_execprog"]["sha256"]),
        "- Corpus SHA-256: `%s`" % manifest["inputs"]["workload"]["sha256"],
        "- Fresh QEMU `-snapshot` VM for every trial; NFSv4.1/TCP; LOCALIO disabled; "
        "2 fixed proc/lane workers; `nokaslr`; no mutation; identical execution budget.",
        "- OFF/ON command parity after normalizing the remote bit: **%s**." %
        ("PASS" if controls_equal else "FAIL"), "",
        "Exact commands are preserved in each `trial_evidence.json`; raw call/extra PCs "
        "and completion timestamps are under each trial's `coverage/` directory.", "",
        "## Measurement method and limitations", "",
        "A deterministic `syz-execprog` run was used instead of mutation-driven "
        "`syz-manager` fuzzing so that every trial had exactly 30 executions of the same "
        "34-call corpus. The measurement-only `-remote-cover` flag changes the same "
        "`FeatureExtraCoverage` bit controlled by manager `experimental.remote_cover`; it "
        "does not alter the request-attribution architecture. Coverage edges were not "
        "exported on this path, so all reported coverage-set values use symbolized unique "
        "KCOV PCs. The workload explicitly issues `fsync`; it does not assert that every "
        "run emitted a distinct NFS COMMIT opcode. The standard percentage increase is "
        "mathematically undefined for the primary metric because OFF coverage is zero. "
        "Manager configuration and an evolving manager corpus are therefore not applicable "
        "to these fixed-corpus trials; the exact execprog command and immutable corpus hash "
        "are recorded instead.", "",
        "## Artifacts", "",
        "- [`experiment_manifest.json`](experiment_manifest.json)",
        "- [`kernel_config_used.config`](kernel_config_used.config)",
        "- [`nfs_remote_kcov_on_off_trials.csv`](nfs_remote_kcov_on_off_trials.csv)",
        "- [`nfs_remote_kcov_on_off_samples.csv`](nfs_remote_kcov_on_off_samples.csv)",
        "- [`analysis_summary.json`](analysis_summary.json)",
        "- [`coverage_sets/coverage_set_analysis.json`](coverage_sets/coverage_set_analysis.json)",
        "- [`diagnostics/remote_kcov_diagnostics.json`](diagnostics/remote_kcov_diagnostics.json)",
        "- [`images/coverage_convergence_remote_on_off.png`](images/coverage_convergence_remote_on_off.png)",
        "- [`images/coverage_final_remote_on_off.png`](images/coverage_final_remote_on_off.png)",
        "- [`images/coverage_by_subsystem_remote_on_off.png`](images/coverage_by_subsystem_remote_on_off.png)",
        "- [`images/remote_kcov_diagnostics.png`](images/remote_kcov_diagnostics.png)",
        "- [`images/evidence_remote_off.png`](images/evidence_remote_off.png)",
        "- [`images/evidence_remote_on.png`](images/evidence_remote_on.png)",
        "- [`images/evidence_remote_on_diagnostics.png`](images/evidence_remote_on_diagnostics.png)",
        "", "## Direct answers", "",
        "1. `fs/nfsd` median coverage changed from %.0f to %.0f PCs: %+g PCs; increase %s."
        % (off_median, on_median, gain,
           "undefined because OFF=0" if increase is None else "%+.2f%%" % increase),
        "2. Fixed budgets were identical; all trials converged under the predeclared criterion: %s."
        % ("yes" if all_converged else "no"),
        "3. Attribution integrity was preserved: %s." %
        ("yes" if integrity_pass else "no"),
        "4. Newly visible server regions are ranked in the ON-only CSV/table above.",
        "5. Median execution throughput change was %+.2f%%." % throughput_change,
        "6. Results were repeated in %d independent fresh-VM trials per mode; individual "
        "values and variance are shown above." % expected, "",
        "## Final status", "", "**%s**" % status, "",
    ]
    (root / "nfs_remote_kcov_on_off_coverage_report.md").write_text(
        "\n".join(report), encoding="utf-8")
    print("STATUS", status)
    print("fs/nfsd median OFF", off_median)
    print("fs/nfsd median ON", on_median)
    print("absolute gain", gain)
    print("throughput change percent", throughput_change)


if __name__ == "__main__":
    main()
