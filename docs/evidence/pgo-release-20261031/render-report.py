#!/usr/bin/env python3
"""Render the completed 31 October release matrix from adjacent JSON (stdlib only).

Requires capacity-summary.json and integrity.json. Writes the report under
beeper/ and arms.csv beside this script; never starts a benchmark or uses a host.
"""

import csv
import hashlib
import json
import math
from pathlib import Path
from statistics import median

HERE = Path(__file__).resolve().parent
IDENTITIES = {
    "release": "3b1ecbe1b5fd7a32e89547007d00628878b6135dc255b74811688cccca0858ec",
    "candidate": "0ca04dcb8d3b9d07e02ac19658546d7882d6f2719c6937be2f259ca65eef83c5",
    "helper": "1cce1f3ca5837e5d68b9be757438af28a88be789468372392bf6148a3987721d",
}
PROTOCOLS = {"h1": "H1 plaintext", "h1s": "H1 TLS", "h2c": "H2c", "h2": "H2 TLS", "h3": "H3"}
METRICS = {
    "rps": ("RPS", 0, 1), "p99_us": ("Arm p99 ms", 3, .001),
    "server_process_cpu_us_per_response": ("Process CPU µs/R", 3, 1),
    "user_instructions_per_response": ("User instructions/R", 0, 1),
    "user_cycles_per_response": ("User cycles/R", 0, 1),
    "whole_vm_busy_ticks_per_response": ("VM busy ticks/R", 6, 1),
}


def need(condition, message):
    if not condition:
        raise ValueError(message)


def equal(actual, expected, label):
    need(math.isfinite(actual) and math.isclose(actual, expected, rel_tol=1e-10, abs_tol=1e-10),
         f"inconsistent {label}: {actual!r} != {expected!r}")


def option(command, flag):
    for index, value in enumerate(command):
        if value == flag:
            return command[index + 1]
        if value.startswith(flag + "="):
            return value.split("=", 1)[1]
    raise ValueError(f"missing {flag}")


def validate(summary, integrity, digest):
    expected_integrity = {"status": "passed", "completed_cells": 20, "completed_arms": 240,
                          "measured_responses": 48000000, "warmup_responses": 2400000,
                          "all_artifact_hashes_unchanged": True,
                          "no_owned_benchmark_executables_running": True, "summary_sha256": digest}
    need(all(integrity.get(k) == v and type(integrity.get(k)) is type(v)
             for k, v in expected_integrity.items()), "integrity receipt does not seal this complete matrix")
    need(summary["schema"] == 1 and summary["profile"] == "true-lo" and summary["status"] == "complete"
         and summary["matrix_failure"] is None and summary["matrix_completion"]["completed_jobs"] == 20,
         "expected a complete schema-1 true-loopback matrix")
    for name, sha in IDENTITIES.items():
        need(summary["provenance"]["artifacts"][name]["sha256"] == sha, f"wrong {name} SHA256")
    env = summary["provenance"]["environment"]
    need(env["HJ_BENCH_ADDR"] == env["HJ_BENCH_BIND"] == "127.0.0.2", "wrong network profile")
    cells = summary["cells"]
    expected = {(p, size, case) for p in PROTOCOLS for size in (1024, 32768) for case in ("static", "pagecache")}
    need(len(cells) == 20 and {(c["protocol"], c["size"], c["case"]) for c in cells} == expected,
         "expected exactly the 20 release cells")
    totals = [0, 0, 0]
    for cell in cells:
        tag = f"{cell['protocol']}/{cell['case']}/{cell['size']}"
        need(cell["comparison"] == "release" and cell["status"] == "complete" and not cell["issues"], tag)
        job, observer = cell["job_exit"], cell["observer_last_event"]
        need(job["exit_code"] == 0 and not job["aborted"] and not job["forced_observer_kill"]
             and job["failure"] is None and cell["job_failure"] is None, f"failed job: {tag}")
        need(observer["event"] == "finished" and observer["command_exit"] == 0
             and observer["compiler_overlap_observed"] is False, f"unsealed observer: {tag}")
        need(cell["arm_counts"] == {"complete": 12, "failed": 0, "incomplete": 0,
                                    "not_started": 0, "unplanned": 0}, f"wrong arm counts: {tag}")
        args = cell["harness_metadata"]["arguments"]
        need(all(args[k] == v for k, v in {"rounds": 3, "requests": 200000, "warmup": 10000,
                 "connections": 32, "streams": 4, "workers": 1, "server_cpus": "8",
                 "client_cpus": "0,2,4,6,12,14", "client_threads": 6, "rate": None}.items()),
             f"wrong sampling/affinity/load settings: {tag}")
        arms = cell["arms"]
        need(len(arms) == 12 and not cell["kernel_coverage"]["errors"], f"incomplete kernel/arm evidence: {tag}")
        for cycle in (1, 2, 3):
            need([(a["position"], a["role"]) for a in arms if a["cycle"] == cycle] ==
                 [(1, "baseline"), (2, "candidate"), (3, "candidate"), (4, "baseline")], f"wrong ABBA: {tag}")
        for arm in arms:
            need(arm["status"] == "complete" and not arm["issues"] and arm["failure"] is None
                 and not arm["failure_marker_present"], f"failed arm: {tag}")
            need(arm["denominator"] == {"measured_requests": 200000, "warmup_requests": 10000,
                                        "whole_span_responses": 210000}, f"wrong denominator: {tag}")
            candidate = arm["role"] == "candidate"
            recorded = arm["recorded_artifacts"]
            sha = recorded.get("server_binary_sha256", recorded.get("arm", {}).get("sha256"))
            need(sha == IDENTITIES["candidate" if candidate else "release"], f"wrong arm SHA256: {tag}")
            kernel_arm = candidate and cell["protocol"] in ("h1", "h2c")
            if kernel_arm:
                need(recorded["arm"]["launcher"]["sha256"] == IDENTITIES["helper"], f"wrong helper: {tag}")
            validation = arm["validation"]
            pmu = validation["hardware_counters"]
            need(not validation["training_only"] and not validation["diagnostic_only"] and pmu["valid"]
                 and pmu["include_user"] is True and pmu["exclude_kernel"] is True
                 and validation["client_cpu_headroom_gate"]["passed"], f"invalid measurement scope: {tag}")
            server = arm["server_command"]
            need(option(server, "--http-addr").startswith("127.0.0.2:") and
                 option(server, "--https-addr").startswith("127.0.0.2:") and
                 option(arm["client_command"], "--bind") == "127.0.0.2", f"wrong bind: {tag}")
            need("--page-cache" in server, f"page cache disabled: {tag}")
            if candidate:
                need("--page-cache-response-memo" in server, f"candidate memo disabled: {tag}")
                if cell["protocol"] == "h1":
                    need(option(server, "--h1-kernel") == "required" and
                         option(server, "--h1-kernel-wakeup") == "polling", f"wrong H1 mode: {tag}")
                if cell["protocol"] == "h2c":
                    need("--h2-kernel" in server, f"H2 kernel not requested: {tag}")
                if cell["protocol"] == "h3":
                    need(option(server, "--h3-engine") == "accelerated" and
                         option(server, "--h3-gso-segments") == "20" and option(server, "--h3-send-batch") == "1",
                         f"wrong H3 mode: {tag}")
            for metric in METRICS:
                value = arm["metrics"][metric]
                need(isinstance(value, (float, int)) and not isinstance(value, bool)
                     and math.isfinite(value) and value > 0, f"invalid {metric}: {tag}")
            fraction = arm["metrics"]["kernel_success_fraction"]
            if cell["protocol"] != "h3" and candidate:
                count = arm["kernel_successes"]
                need(isinstance(count, (int, float)) and 0 <= count <= 210000, f"invalid kernel count: {tag}")
                equal(fraction, count / 210000, f"kernel fraction {tag}")
                need((count > 0) if kernel_arm and cell["size"] == 1024 else (count == 0), f"wrong kernel coverage: {tag}")
            totals = [totals[0] + 1, totals[1] + 200000, totals[2] + 10000]
        if cell["protocol"] == "h2c" and cell["size"] == 32768:
            coverage = {x["result"]: x for x in cell["kernel_coverage"]["observations"]}
            for arm in arms:
                if arm["role"] == "candidate":
                    need(coverage[arm["sources"]["result.json"]["path"]]["observed_publication_candidates"] == 0,
                         f"oversized H2 body queued publication candidates: {tag}")
        for role in ("baseline", "candidate"):
            for metric in (*METRICS, "kernel_success_fraction"):
                values = [a["metrics"][metric] for a in arms if a["role"] == role]
                if all(x is None for x in values):
                    need(metric == "kernel_success_fraction" and cell["medians"][role][metric] is None,
                         f"missing metric: {tag}/{metric}")
                else:
                    equal(cell["medians"][role][metric], median(values), f"median {tag}/{role}/{metric}")
        need([x["cycle"] for x in cell["within_cycle_abba"]] == [1, 2, 3], f"missing cycle summaries: {tag}")
        for cycle in cell["within_cycle_abba"]:
            for metric in METRICS:
                b, c = ([a["metrics"][metric] for a in arms if a["cycle"] == cycle["cycle"] and a["role"] == role]
                        for role in ("baseline", "candidate"))
                for key, expected_ratio in (("center", median(c) / median(b)), ("min", min(c) / max(b)),
                                             ("max", max(c) / min(b))):
                    equal(cycle["ratios"][metric][key], expected_ratio, f"cycle {tag}/{metric}/{key}")
    need(totals == [240, 48000000, 2400000], "incomplete response totals")
    return sorted(cells, key=lambda c: (c["size"], c["case"] != "static", list(PROTOCOLS).index(c["protocol"])))


def pct(ratio):
    return f"{100 * (ratio - 1):+.2f}%"


def ratio(cell, metric):
    return cell["medians"]["candidate"][metric] / cell["medians"]["baseline"][metric]


def pair(cell, metric):
    _, decimals, scale = METRICS[metric]
    b, c = (cell["medians"][role][metric] * scale for role in ("baseline", "candidate"))
    return f"{b:,.{decimals}f} → {c:,.{decimals}f} ({pct(ratio(cell, metric))})"


def label(cell):
    return f"{cell['size']//1024} KiB {PROTOCOLS[cell['protocol']]} / {cell['case']}"


def kernel(cell):
    if cell["protocol"] == "h3":
        return "n/a (QUIC in userspace)"
    def role_value(role):
        values = [a["metrics"]["kernel_success_fraction"] for a in cell["arms"] if a["role"] == role]
        return "not exposed" if all(v is None for v in values) else \
            f"{100*median(values):.4f}% [{100*min(values):.4f}%, {100*max(values):.4f}%]"
    return role_value("baseline") + " → " + role_value("candidate")


def table(lines, headers, rows):
    lines += ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    lines += ["| " + " | ".join(str(x).replace("|", "\\|") for x in row) + " |" for row in rows]
    lines.append("")


def render(cells, digest):
    higher = lambda metric: sum(ratio(c, metric) > 1 for c in cells)
    lines = ["# PGO Candidate C against the exact release: complete capacity matrix", "",
        "Measured and published **31 October 2026**.", "",
        f"Across-arm median throughput rises in {higher('rps')}/20 cells and falls in "
        f"{sum(ratio(c, 'rps') < 1 for c in cells)}/20. Median arm p99 rises in {higher('p99_us')}/20 cells; "
        f"measured process CPU per response rises in {higher('server_process_cpu_us_per_response')}/20. "
        "These direction counts do not establish an overall winner. Every cell and opposite-sign cycle is retained below.", "",
        "This compares the exact shipped **v0.1.10-11** with the PGO Candidate C binary. Both arms enable and warm "
        "their caches; the release cache is active. Candidate changes include the finished page-response memo, "
        "PGO, H1/H2 kernel paths and the accelerated H3 engine with GSO limit 20/send batch 1. These are combined "
        "build/runtime effects and cannot all be attributed to Beeper. "
        "The [previous C matrix](final-matrix-2026-10-30.md) retains source-control comparisons; "
        "the [same-source PGO pilot](pgo-pilot-2026-10-30.md) isolates PGO on the C runtime. "
        "There is no matched release-source PGO control here, and pilot percentages are not additive components of these deltas.", "",
        "## Artifact identity", ""]
    table(lines, ["Artifact", "SHA256"], [(name, f"`{sha}`") for name, sha in IDENTITIES.items()])
    lines += ["The helper is the PGO-built privileged `httpjet-beeper-h1` launcher for plaintext kernel arms. "
        "The candidate enables H1 polling and H2 kernel serving only on plaintext paths, with the default 16 KiB body cap. "
        "The 32 KiB requested-kernel cases serve natively; oversized H2 publication candidates must remain zero. "
        "TLS retains native ownership. H3 remains Quinn-owned userspace QUIC/TLS, not in-kernel QUIC.", "",
        "## All twenty cells", "",
        "Values are medians of six arms per binary: **release → candidate (Δ)**, with "
        "`Δ = 100 × (candidate/release − 1)`. Positive p99/CPU/count deltas mean higher latency/cost. "
        "The p99 is a median of arm percentiles, not a percentile recomputed from merged requests. "
        "Kernel percentages show the six-arm median [minimum, maximum] over measured plus warm-up responses. "
        "A missing release counter is labeled `not exposed`, not measured zero.", ""]
    for size in (1024, 32768):
        for case in ("static", "pagecache"):
            group = [c for c in cells if c["size"] == size and c["case"] == case]
            lines += [f"### {size//1024} KiB / {case}", ""]
            table(lines, ["Protocol", "RPS (Δ)", "Arm p99 ms (Δ)", "Kernel-hit fraction release → candidate"],
                  [(PROTOCOLS[c["protocol"]], pair(c, "rps"), pair(c, "p99_us"), kernel(c)) for c in group])
            cpu_metrics = list(METRICS)[2:]
            table(lines, ["Protocol", *[METRICS[m][0] + " (Δ)" for m in cpu_metrics]],
                  [(PROTOCOLS[c["protocol"]], *[pair(c, m) for m in cpu_metrics]) for c in group])
    lines += ["## Three ABBA cycles", "",
        "A = release; B = candidate. Each entry is the ratio-of-two-arm-medians RPS delta, followed by "
        "`[min(B)/max(A) − 1, max(B)/min(A) − 1]`. These bounds describe observed arm spread, not confidence intervals.", ""]
    table(lines, ["Cell", "Cycle 1 RPS Δ [range]", "Cycle 2 RPS Δ [range]", "Cycle 3 RPS Δ [range]"],
          [(label(c), *[f"{pct(x['ratios']['rps']['center'])} [{pct(x['ratios']['rps']['min'])}, "
                        f"{pct(x['ratios']['rps']['max'])}]" for x in c["within_cycle_abba"]]) for c in cells])
    reversals = []
    for cell in cells:
        for metric in METRICS:
            cycles = [x["ratios"][metric]["center"] for x in cell["within_cycle_abba"]]
            if any((ratio(cell, metric) - 1) * (x - 1) < 0 for x in cycles):
                reversals.append((label(cell), METRICS[metric][0], pct(ratio(cell, metric)), *map(pct, cycles)))
    lines += ["### Opposite-sign cycles", "",
        "Every metric whose cycle direction opposes its across-arm median direction appears here. "
        "Positive aggregate deltas do not imply that every arm or cycle improved.", ""]
    if reversals:
        table(lines, ["Cell", "Metric", "Across-arm Δ", "Cycle 1 Δ", "Cycle 2 Δ", "Cycle 3 Δ"], reversals)
    else:
        lines += ["No cycle center has the opposite sign to its across-arm median delta; individual arm ranges still matter.", ""]
    lines += ["## Measurement scope and limits", "",
        "The sealed matrix contains **20 cells, 240 arms, 48,000,000 measured responses and 2,400,000 warm-up responses**: "
        "three A–B–B–A cycles, each arm containing 200,000 measured requests after 10,000 warm-up requests. "
        "Both server destination and client source bind are literal `127.0.0.2` on SINGULARITY Linux/WSL2. "
        "One server worker uses CPU 8; six clients use separate physical cores `0,2,4,6,12,14`. There are 32 connections; "
        "H2/H3 use four streams per connection and H1 is sequential per connection. This is per-worker true-loopback capacity.", "",
        "- **RPS/p99:** measured requests only at fixed concurrency. This is saturation/completion latency, not scheduled "
        "offered-load latency. A capacity change can alter the load experienced by each arm.",
        "- **Process CPU:** observed server/descendant user + system CPU over the whole client span, including handshake, "
        "warm-up, output and teardown, divided by 210,000 responses. Kernel/IRQ work charged elsewhere is excluded.",
        "- **PMU instructions/cycles:** server user mode only over that whole span and the same denominator; kernel, "
        "IRQ, softirq and hypervisor work are excluded. These are not total CPU costs.",
        "- **VM busy ticks:** all Linux VM CPUs' user + nice + system + IRQ + softirq ticks per whole-span response, "
        "including clients and unrelated work; idle/iowait/steal are excluded. No tick-to-time conversion is inferred. "
        "Windows-host CPU/scheduling cost is unmeasured. VM busy is not server-owned CPU.",
        "- Both warm static-cache and origin-page-cache fixtures are shown. Page-cache content is generated static "
        "content with PHP disabled; this does not qualify dynamic applications or production-site performance. "
        "Neither throughput, process CPU nor VM busy alone establishes total-server CPU savings.", "",
        "## Evidence and regeneration", "",
        "The [raw summary](../docs/evidence/pgo-release-20261031/capacity-summary.json) retains every arm, "
        "command, scope and cycle ratio. The [integrity receipt](../docs/evidence/pgo-release-20261031/integrity.json) "
        "seals completion, unchanged artifacts and absence of owned benchmark processes. "
        f"Summary SHA256: `{digest}`. The [arm CSV](../docs/evidence/pgo-release-20261031/arms.csv) "
        "retains all 240 rows. The [standalone renderer](../docs/evidence/pgo-release-20261031/render-report.py) "
        "requires the sealed complete matrix, exact binaries/helper and recomputed displayed arithmetic.", "",
        "```sh", "python3 docs/evidence/pgo-release-20261031/render-report.py", "```", "",
        "The H1/H2 research builds on [Beeper](https://github.com/lerboe/beeper) and "
        "[hyper-fast-path](https://github.com/lerboe/hyper-fast-path) by "
        "[Laurin Brandner (@lerboe)](https://github.com/lerboe). H3 execution changes are HTTPJet work around Quinn.", ""]
    return "\n".join(lines)


def write_arms(cells):
    fields = ["protocol", "fixture", "size_bytes", "cycle", "position", "role", "binary_sha256",
              "measured_requests", "warmup_requests", *METRICS, "kernel_success_fraction"]
    with (HERE / "arms.csv").open("w", encoding="utf-8", newline="") as destination:
        writer = csv.DictWriter(destination, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        for cell in cells:
            for arm in cell["arms"]:
                writer.writerow({"protocol": cell["protocol"], "fixture": cell["case"], "size_bytes": cell["size"],
                    **{k: arm[k] for k in ("cycle", "position", "role")},
                    "binary_sha256": IDENTITIES["candidate" if arm["role"] == "candidate" else "release"],
                    "measured_requests": 200000, "warmup_requests": 10000,
                    **{k: arm["metrics"][k] for k in (*METRICS, "kernel_success_fraction")}})


def main():
    try:
        raw = (HERE / "capacity-summary.json").read_bytes()
        integrity = json.loads((HERE / "integrity.json").read_text())
        digest = hashlib.sha256(raw).hexdigest()
        cells = validate(json.loads(raw), integrity, digest)
        report = render(cells, digest)
        (HERE.parents[2] / "beeper" / "pgo-release-2026-10-31.md").write_text(report, encoding="utf-8")
        write_arms(cells)
    except (OSError, ValueError, KeyError, TypeError, IndexError) as error:
        raise SystemExit(f"release report refused: {error}") from error
    print("Rendered 20 sealed release cells / 240 arms; no benchmark executed")


if __name__ == "__main__":
    main()
