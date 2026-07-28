#!/usr/bin/env python3
"""Check the locked Cargo graph and generate its license inventory."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys


BLOCKED_MARKERS = (
    "BUSL",
    "CDDL",
    "COMMONS-CLAUSE",
    "ELASTIC",
    "POLYFORM",
    "SSPL",
)
BLOCKED_PACKAGES = {"inferno"}


def cargo_metadata(repo: Path) -> dict:
    result = subprocess.run(
        [
            "cargo",
            "metadata",
            "--all-features",
            "--locked",
            "--format-version",
            "1",
            "--manifest-path",
            str(repo / "Cargo.toml"),
        ],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    return json.loads(result.stdout)


def source_kind(package: dict, repo: Path) -> str:
    if package["source"]:
        if package["source"].startswith("registry+"):
            return "registry"
        if package["source"].startswith("git+"):
            return "git"
        return "external"
    manifest = Path(package["manifest_path"])
    try:
        relative = manifest.relative_to(repo)
    except ValueError:
        return "path"
    if relative.parts[0] == "vendor":
        return "vendored"
    if relative.parts[0] == "crates":
        return "workspace"
    return "path"


def inventory(metadata: dict, repo: Path) -> tuple[str, list[str]]:
    rows = []
    errors = []
    for package in metadata["packages"]:
        name = package["name"]
        license_expression = package.get("license")
        if not license_expression:
            errors.append(f"{name} {package['version']} has no license metadata")
            license_expression = "NOASSERTION"
        upper = license_expression.upper()
        for marker in BLOCKED_MARKERS:
            if marker in upper:
                errors.append(
                    f"{name} {package['version']} uses blocked license marker {marker}: "
                    f"{license_expression}"
                )
        if name in BLOCKED_PACKAGES:
            errors.append(f"{name} must not appear in the distributed dependency graph")
        rows.append(
            (
                name,
                package["version"],
                source_kind(package, repo),
                license_expression,
            )
        )

    rows.sort(key=lambda row: (row[0].casefold(), row[1], row[2]))
    lines = [
        "# Locked Cargo dependency licenses",
        "",
        "Generated from `Cargo.lock` by `scripts/check-dependency-licenses.py`.",
        "License expressions are upstream metadata, not a substitute for the",
        "component license texts or legal review.",
        "",
        "| Package | Version | Source | License expression |",
        "|---|---:|---|---|",
    ]
    for name, version, source, expression in rows:
        lines.append(f"| `{name}` | {version} | {source} | `{expression}` |")
    lines.append("")
    return "\n".join(lines), errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        metavar="REPORT",
        type=Path,
        help="verify that REPORT exactly matches the locked dependency graph",
    )
    parser.add_argument(
        "--write",
        metavar="REPORT",
        type=Path,
        help="write the generated report after policy checks pass",
    )
    args = parser.parse_args()
    if args.check and args.write:
        parser.error("--check and --write are mutually exclusive")

    repo = Path(__file__).resolve().parent.parent
    report, errors = inventory(cargo_metadata(repo), repo)
    if errors:
        for error in errors:
            print(f"license policy: {error}", file=sys.stderr)
        return 1

    if args.check:
        if not args.check.is_file() or args.check.read_text() != report:
            print(f"{args.check} is stale; regenerate it with --write", file=sys.stderr)
            return 1
        print(f"dependency license report is current: {args.check}")
        return 0
    if args.write:
        args.write.write_text(report)
        print(f"wrote {args.write}")
        return 0

    print(report, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
