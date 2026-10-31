#!/usr/bin/env python3
"""Render the frozen 30 October 2026 same-source PGO pilot (stdlib only).

Run from any directory; defaults resolve relative to this file. This reads the
summary only, does not contact the benchmark host, and starts no benchmark.
Optional --arms-csv writes arms.csv beside this renderer.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
from pathlib import Path
from statistics import median


HERE = Path(__file__).resolve().parent
CONTROL = "f9b441d1810afc842e096222fd279323b174076410c923d713e533b11a79c7e2"
PGO = "0ca04dcb8d3b9d07e02ac19658546d7882d6f2719c6937be2f259ca65eef83c5"
SUMMARY_SHA256 = "34331fc817d9a0f433ef5e796f88389498fae98ace7366692780a74daa209442"
PROTOCOLS = ("h1", "h1s", "h2c", "h2", "h3")
LABELS = {"h1": "H1 plaintext", "h1s": "H1 TLS", "h2c": "H2c", "h2": "H2 TLS", "h3": "H3"}
METRICS = ("rps", "server_process_cpu_us_per_response", "p99_us", "user_instructions_per_response")
EXPECTED_CELLS = {(p, size) for size in (1024, 32768) for p in PROTOCOLS}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def close(actual: float, expected: float, label: str) -> None:
    require(math.isfinite(actual) and math.isclose(actual, expected, rel_tol=1e-10, abs_tol=1e-10),
            f"inconsistent {label}: {actual!r} != {expected!r}")


def argument(command: list[str], option: str) -> str:
    for index, item in enumerate(command):
        if item == option:
            require(index + 1 < len(command), f"missing value for {option}")
            return command[index + 1]
        if item.startswith(option + "="):
            return item.split("=", 1)[1]
    raise ValueError(f"missing option {option}")


def validate(summary: dict, digest: str) -> list[dict]:
    """Fail closed on another artifact, partial run, or changed arithmetic."""
    require(digest == SUMMARY_SHA256, "summary SHA256 differs from the frozen pilot")
    require(summary["schema"] == 1 and summary["profile"] == "true-lo", "unexpected schema/profile")
    require(summary["status"] == "complete" and summary["matrix_failure"] is None, "matrix is not complete")
    require(summary["matrix_completion"]["completed_jobs"] == 10, "expected 10 completed jobs")
    artifacts = summary["provenance"]["artifacts"]
    require(artifacts["candidate"]["sha256"] == PGO, "wrong PGO binary SHA256")
    require(artifacts["native_baseline"]["sha256"] == CONTROL, "wrong control binary SHA256")
    env = summary["provenance"]["environment"]
    require(env["HJ_BENCH_ADDR"] == env["HJ_BENCH_BIND"] == "127.0.0.2", "not the true-loopback pilot")
    cells = summary["cells"]
    require(len(cells) == 10, "expected exactly 10 cells")
    require({(c["protocol"], c["size"]) for c in cells} == EXPECTED_CELLS, "unexpected or duplicate cells")
    total_arms = measured = warmup = 0
    for cell in cells:
        tag = f"{cell['protocol']}/{cell['size']}"
        require(cell["comparison"] == "source" and cell["case"] == "static", f"wrong comparison/fixture: {tag}")
        require(cell["status"] == "complete" and not cell["issues"], f"incomplete/flagged cell: {tag}")
        job = cell["job_exit"]
        require(job["exit_code"] == 0 and not job["aborted"] and not job["forced_observer_kill"]
                and job["failure"] is None and cell["job_failure"] is None, f"failed job: {tag}")
        require(cell["arm_counts"] == {"complete": 12, "failed": 0, "incomplete": 0,
                                        "not_started": 0, "unplanned": 0}, f"unexpected arm counts: {tag}")
        args = cell["harness_metadata"]["arguments"]
        require(args["rounds"] == 3 and args["requests"] == 100000 and args["warmup"] == 5000,
                f"unexpected rounds/request counts: {tag}")
        require(args["workers"] == 1 and args["server_cpus"] == "8", f"unexpected server affinity: {tag}")
        require(args["client_cpus"] == "0,2,4,6,12,14" and args["client_threads"] == 6,
                f"unexpected client affinity: {tag}")
        require(args["connections"] == 32 and args["streams"] == 4 and args["rate"] is None,
                f"unexpected concurrency/load mode: {tag}")
        arms = cell["arms"]
        require(len(arms) == 12, f"expected 12 arms: {tag}")
        for cycle in (1, 2, 3):
            cycle_arms = [a for a in arms if a["cycle"] == cycle]
            require([(a["position"], a["role"]) for a in cycle_arms] ==
                    [(1, "baseline"), (2, "candidate"), (3, "candidate"), (4, "baseline")],
                    f"expected ABBA order: {tag}, cycle {cycle}")
        for arm in arms:
            require(arm["status"] == "complete" and not arm["issues"] and arm["failure"] is None
                    and not arm["failure_marker_present"], f"failed/flagged arm: {tag}")
            require(arm["denominator"] == {"measured_requests": 100000, "warmup_requests": 5000,
                                           "whole_span_responses": 105000}, f"unexpected denominator: {tag}")
            expected_sha = CONTROL if arm["role"] == "baseline" else PGO
            recorded = arm["recorded_artifacts"]
            actual_sha = recorded.get("server_binary_sha256", recorded.get("arm", {}).get("sha256"))
            require(actual_sha == expected_sha, f"wrong arm binary SHA256: {tag}")
            validation = arm["validation"]
            require(not validation["training_only"] and not validation["diagnostic_only"], f"training/diagnostic arm: {tag}")
            counters = validation["hardware_counters"]
            require(counters["valid"] and counters["include_user"] and counters["exclude_kernel"],
                    f"invalid user-mode PMU evidence: {tag}")
            require(validation["client_cpu_headroom_gate"]["passed"], f"client headroom gate failed: {tag}")
            server, client = arm["server_command"], arm["client_command"]
            require(argument(server, "--http-addr").startswith("127.0.0.2:") and
                    argument(server, "--https-addr").startswith("127.0.0.2:") and
                    argument(client, "--bind") == "127.0.0.2", f"unexpected endpoint binding: {tag}")
            require("--page-cache-response-memo" in server and "--page-cache" in server,
                    f"cache/memo settings changed: {tag}")
            if cell["protocol"] == "h3":
                require(argument(server, "--h3-engine") == "accelerated" and
                        argument(server, "--h3-gso-segments") == "20" and
                        argument(server, "--h3-send-batch") == "1", f"H3 settings changed: {tag}")
            else:
                require(arm["kernel_successes"] == 0 and not arm["kernel_expectation"]["requested"],
                        f"H1/H2 kernel serving was active: {tag}")
            for metric in METRICS:
                require(math.isfinite(arm["metrics"][metric]) and arm["metrics"][metric] > 0,
                        f"invalid {metric}: {tag}")
            total_arms += 1
            measured += arm["denominator"]["measured_requests"]
            warmup += arm["denominator"]["warmup_requests"]
        for role in ("baseline", "candidate"):
            for metric in METRICS:
                value = median(a["metrics"][metric] for a in arms if a["role"] == role)
                close(cell["medians"][role][metric], value, f"median {tag}/{role}/{metric}")
        require([x["cycle"] for x in cell["within_cycle_abba"]] == [1, 2, 3], f"expected 3 cycle summaries: {tag}")
        for cycle in cell["within_cycle_abba"]:
            for metric in METRICS:
                values = {role: [a["metrics"][metric] for a in arms
                                 if a["cycle"] == cycle["cycle"] and a["role"] == role]
                          for role in ("baseline", "candidate")}
                b, p = values["baseline"], values["candidate"]
                ratios = cycle["ratios"][metric]
                for key, value in (("center", median(p) / median(b)), ("min", min(p) / max(b)),
                                   ("max", max(p) / min(b))):
                    close(ratios[key], value, f"cycle {tag}/{cycle['cycle']}/{metric}/{key}")
    require((total_arms, measured, warmup) == (120, 12000000, 600000), "incomplete response totals")
    return sorted(cells, key=lambda c: (c["size"], PROTOCOLS.index(c["protocol"])))


def percent(ratio: float) -> str:
    return f"{100 * (ratio - 1):+.2f}%"


def delta(cell: dict, metric: str) -> str:
    return percent(cell["medians"]["candidate"][metric] / cell["medians"]["baseline"][metric])


def label(cell: dict) -> str:
    return f"{cell['size'] // 1024} KiB {LABELS[cell['protocol']]}"


def pair(cell: dict, metric: str, precision: int, divisor: float = 1) -> str:
    b, p = (cell["medians"][role][metric] / divisor for role in ("baseline", "candidate"))
    return f"{b:,.{precision}f} → {p:,.{precision}f} ({delta(cell, metric)})"


def cycle_values(cell: dict, metric: str) -> str:
    return ", ".join(percent(c["ratios"][metric]["center"]) for c in cell["within_cycle_abba"])


def render(cells: list[dict]) -> str:
    lines = [
        "# Same-source PGO pilot: higher median throughput, mixed H2 cycle results",
        "",
        "Measured **30 October 2026**; published **31 October 2026**.",
        "",
        "This pilot compares the corrected Candidate C runtime with and without profile-guided optimization (PGO). "
        "Across-arm median throughput is higher in all ten static-file cells (+4.61% to +49.93%), while measured "
        "server-process CPU per response is lower (−4.45% to −32.81%). Eight cells have a positive throughput "
        "change in every ABBA cycle. The two 32 KiB H2 cells change direction between cycles; H2c also has a "
        "**9.56% worse median arm p99**. These results support a workload-specific PGO benefit, not universal superiority or total-server CPU savings.",
        "",
        "## Matched comparison",
        "",
        "Both binaries use the same frozen source, features (`beeper-h2-serve`, `beeper-observer`, `quic-bpf`), "
        "native CPU target, frame pointers, optimization level 3, thin LTO and one codegen unit. The PGO build "
        "adds the collected profile; the control has no PGO. "
        "The [build receipts and frozen input manifest](../docs/evidence/pgo-c6ac-20261030/pgo-inputs.json) "
        "record the inputs; separate [control](../docs/evidence/pgo-c6ac-20261030/build-control.json) and "
        "[PGO](../docs/evidence/pgo-c6ac-20261030/build-use.json) receipts record the build settings.",
        "",
        f"- No-PGO control SHA256: `{CONTROL}`.",
        f"- PGO candidate SHA256: `{PGO}`.",
        "",
        "H1/H2 kernel serving is off for both binaries, with zero observed kernel-serving successes. "
        "Both H3 arms use the accelerated on-core engine, GSO limit 20 and send batch 1. "
        "Both arms enable and warm the static fixture's cache path and finished-response memo; "
        "the page-cache response-memo setting also matches, but this pilot has no separate page-cache fixture. "
        "There is **no release comparison in this pilot**; the release artifact recorded in the provenance is not a measured arm here.",
        "",
        "## All ten cells",
        "",
        "Each value below is the median of six arms for that binary. Arrows run **no PGO → PGO**; "
        "parentheses show `100 × (PGO / control − 1)`. Higher RPS is favorable; lower CPU, p99 and instruction counts are favorable. "
        "The p99 column is a median of per-arm p99 values, not a percentile recomputed from combined requests.",
        "",
        "| Static body / protocol | RPS | Server-process CPU µs/response | Arm p99 ms | User instructions/response Δ |",
        "|---|---:|---:|---:|---:|",
    ]
    for cell in cells:
        lines.append(f"| {label(cell)} | {pair(cell, 'rps', 0)} | "
                     f"{pair(cell, 'server_process_cpu_us_per_response', 3)} | "
                     f"{pair(cell, 'p99_us', 3, 1000)} | {delta(cell, 'user_instructions_per_response')} |")
    lines += [
        "",
        "## Variation within the three ABBA cycles",
        "",
        "A = no-PGO control; B = PGO. Each cycle runs A–B–B–A. Entries show the throughput delta "
        "of the two-arm medians, followed by `[minimum, maximum]` arm-pair deltas. Bounds are "
        "`min(B)/max(A)` and `max(B)/min(A)` minus one: descriptive observed spread, **not confidence intervals**.",
        "",
        "| Static body / protocol | Cycle 1 RPS Δ [range] | Cycle 2 RPS Δ [range] | Cycle 3 RPS Δ [range] |",
        "|---|---:|---:|---:|",
    ]
    for cell in cells:
        values = []
        for cycle in cell["within_cycle_abba"]:
            ratio = cycle["ratios"]["rps"]
            values.append(f"{percent(ratio['center'])} [{percent(ratio['min'])}, {percent(ratio['max'])}]")
        lines.append(f"| {label(cell)} | " + " | ".join(values) + " |")
    lines += [
        "",
        "The following rows retain every cell with a cycle whose RPS, process-CPU or p99 direction "
        "opposes its across-arm median change. Each list is in cycle 1, 2, 3 order.",
        "",
        "| Static body / protocol | Cycle RPS Δ | Cycle process-CPU Δ | Cycle p99 Δ |",
        "|---|---:|---:|---:|",
    ]
    for cell in cells:
        reverses = any((cell["medians"]["candidate"][metric] / cell["medians"]["baseline"][metric] - 1) *
                       (cycle["ratios"][metric]["center"] - 1) < 0
                       for metric in METRICS for cycle in cell["within_cycle_abba"])
        if reverses:
            lines.append(f"| {label(cell)} | {cycle_values(cell, 'rps')} | "
                         f"{cycle_values(cell, 'server_process_cpu_us_per_response')} | {cycle_values(cell, 'p99_us')} |")
    lines += [
        "",
        "For 32 KiB H2c, the +7.66% median throughput change conceals cycle deltas of +68.26%, +3.29% and "
        "−10.95%; process CPU rises 17.88% in cycle 3. Its p99 improves 77.58% in cycle 1, then worsens "
        "12.60% and 90.01%. This is not a consistent win. The 32 KiB H2 TLS median throughput gain "
        "(+4.61%) also includes a negative first cycle (−0.44%). Lower median p99 in 1 KiB H1 TLS, "
        "1 KiB H2c and 32 KiB H2 TLS does not remove their opposite-sign latency cycles.",
        "",
        "H3 throughput medians rise 21.56% at 1 KiB and 19.51% at 32 KiB, with positive cycle centers "
        "at both sizes. Those are PGO results with the same accelerated H3 engine on both sides; "
        "they are not evidence of in-kernel QUIC processing.",
        "",
        "## Measurement scope and limits",
        "",
        "The complete pilot contains **10 cells, 120 arms, 12,000,000 measured responses and 600,000 warm-up responses**. "
        "Each arm has 100,000 measured requests after 5,000 warm-up requests. "
        "Measurements run on Linux/WSL2 on SINGULARITY using literal `127.0.0.2` for both the server destination "
        "and client source bind: true Linux loopback, without a public origin or CDN. "
        "One server worker is pinned to CPU 8; six client threads use six physical cores (`0,2,4,6,12,14`). "
        "There are 32 connections and, for H2/H3, four streams per connection; H1 uses one request stream per connection.",
        "",
        "- **RPS and p99** cover measured requests only. These are saturation/completion measurements; no scheduled "
        "offered rate is configured, so the p99 values do not describe latency at matched offered load.",
        "- **Server-process CPU** is user plus system CPU for the observed server/descendant tree over the whole "
        "client span, including handshake, warm-up and teardown, divided by 105,000 responses per arm. "
        "It excludes kernel/IRQ work charged elsewhere and is not total-server CPU.",
        "- **PMU instructions** cover server user mode only over that whole span, with the same 105,000-response "
        "denominator. They exclude kernel, IRQ and softirq work. Lower instruction counts do not establish total CPU savings.",
        "- Repeated arms and ABBA order expose substantial drift in some cells. A positive across-arm median or "
        "cycle center does not imply that every individual PGO arm beat every control arm. "
        "This pilot covers warm static-file fixtures on one topology, not page-cache, dynamic-application or production-wide qualification.",
        "",
        "## Evidence and reproduction",
        "",
        "The [raw pilot summary](../docs/evidence/pgo-c6ac-20261030/pilot-summary.json) retains every arm, "
        "metric scope, command, artifact identity and cycle ratio. Its SHA256 is "
        f"`{SUMMARY_SHA256}`. "
        "The [integrity receipt](../docs/evidence/pgo-c6ac-20261030/pilot-integrity.json) records completion and artifact checks. "
        "The [standalone renderer](../docs/evidence/pgo-c6ac-20261030/render-pilot.py) verifies the frozen summary digest, "
        "full binary identities, complete matrix, response denominators, ABBA ordering and displayed arithmetic before writing this report.",
        "",
        "```sh",
        "python3 docs/evidence/pgo-c6ac-20261030/render-pilot.py",
        "```",
        "",
        "This regenerates the Markdown from local evidence only. Optional `--arms-csv` also exports the 120 arms "
        "to `arms.csv` beside the renderer; it does not rerun measurements.",
        "",
        "The H1/H2 research builds on [Beeper](https://github.com/lerboe/beeper) and "
        "[hyper-fast-path](https://github.com/lerboe/hyper-fast-path) by "
        "[Laurin Brandner (@lerboe)](https://github.com/lerboe). H3 execution changes are HTTPJet work around Quinn; "
        "Quinn retains ownership of QUIC and TLS.",
        "",
    ]
    return "\n".join(lines)


def write_csv(cells: list[dict]) -> None:
    fields = ["protocol", "size_bytes", "cycle", "position", "role", "binary_sha256",
              "measured_requests", "warmup_requests", *METRICS]
    with (HERE / "arms.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        for cell in cells:
            for arm in cell["arms"]:
                writer.writerow({"protocol": cell["protocol"], "size_bytes": cell["size"],
                                 "cycle": arm["cycle"], "position": arm["position"], "role": arm["role"],
                                 "binary_sha256": CONTROL if arm["role"] == "baseline" else PGO,
                                 "measured_requests": arm["denominator"]["measured_requests"],
                                 "warmup_requests": arm["denominator"]["warmup_requests"],
                                 **{key: arm["metrics"][key] for key in METRICS}})


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("summary", nargs="?", type=Path, default=HERE / "pilot-summary.json")
    parser.add_argument("--output", type=Path,
                        default=HERE.parents[2] / "beeper" / "pgo-pilot-2026-10-30.md")
    parser.add_argument("--arms-csv", action="store_true", help="write arms.csv beside this renderer")
    options = parser.parse_args()
    try:
        data = options.summary.read_bytes()
        cells = validate(json.loads(data), hashlib.sha256(data).hexdigest())
        report = render(cells)
        options.output.write_text(report, encoding="utf-8")
        if options.arms_csv:
            write_csv(cells)
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(1, f"pilot rendering failed: {error}\n")
    print(f"Rendered {len(cells)} complete cells / 120 arms to {options.output}")


if __name__ == "__main__":
    main()
