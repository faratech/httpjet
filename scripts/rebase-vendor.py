#!/usr/bin/env python3
"""Replay a vendored crate's local changes in a scratch directory."""

import argparse
import difflib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tomllib


ROOT = Path(__file__).resolve().parent.parent
MANUAL = {"Cargo.toml", "Cargo.toml.orig", "Cargo.lock", ".cargo_vcs_info.json"}


def tracked_files(fork):
    prefix = f"vendor/{fork}/"
    paths = subprocess.check_output(
        ["git", "ls-files", "-z", "--", prefix], cwd=ROOT
    ).split(b"\0")
    return {os.fsdecode(path).removeprefix(prefix) for path in paths if path}


def copy(source, target):
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)


def contents(path):
    return path.read_bytes() if path.is_file() else None


def new_source(relative, fork):
    # OpenSSL fixtures are deliberately absent from HTTPJet's export.
    allowed = {"src", "examples", "benches", "proto"}
    if fork != "openssl":
        allowed.add("tests")
    return Path(relative).parts[0] in allowed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    manifest = tomllib.loads((ROOT / "Cargo.toml").read_text())
    patches = manifest["patch"]["crates-io"]
    forks = sorted(
        name for name, patch in patches.items()
        if isinstance(patch, dict) and patch.get("path") == f"vendor/{name}"
    )
    parser.add_argument("fork", choices=forks)
    parser.add_argument("old", type=Path, help="pristine upstream directory at the recorded base")
    parser.add_argument("new", type=Path, help="pristine upstream directory at the new pinned base")
    parser.add_argument("output", type=Path, help="new scratch directory outside the HTTPJet checkout")
    args = parser.parse_args()

    old, new, output = (path.resolve() for path in (args.old, args.new, args.output))
    if not all((path / "Cargo.toml").is_file() for path in (old, new)):
        parser.error("old and new must point to the upstream crate directories")
    if output.exists() or output.is_relative_to(ROOT):
        parser.error("output must be a new directory outside the HTTPJet checkout")

    local = ROOT / "vendor" / args.fork
    local_files = tracked_files(args.fork)
    if "Cargo.toml" not in local_files:
        parser.error("the selected fork must already be tracked")

    staged = output / "crate"
    staged.mkdir(parents=True)
    new_files = {
        path.relative_to(new).as_posix()
        for directory in ("src", "examples", "benches", "proto", "tests")
        for path in (new / directory).rglob("*")
        if path.is_file()
    }

    conflicts = []
    for relative in sorted(local_files | new_files):
        a, o, b = (base / relative for base in (local, old, new))
        dest = staged / relative
        if relative in MANUAL:
            if a.is_file():
                copy(a, dest)
            continue
        if relative not in local_files:
            # Preserve intentional upstream omissions. Only consider new source files.
            if not o.exists() and new_source(relative, args.fork):
                copy(b, dest)
            continue

        local_data, old_data, new_data = map(contents, (a, o, b))
        if local_data == old_data:
            if new_data is not None:
                copy(b, dest)
        elif new_data == old_data or local_data == new_data:
            if local_data is not None:
                copy(a, dest)
        elif all(data is not None and b"\0" not in data for data in (
            local_data, old_data, new_data
        )):
            # Mode is taken from the local fork. Use descriptive merge markers.
            result = subprocess.run(
                ["git", "merge-file", "-p", "--diff3", "-L", "httpjet",
                 "-L", "old upstream", "-L", "new upstream", a, o, b],
                stdout=subprocess.PIPE,
                check=False,
            )
            if 0 <= result.returncode < 128:
                copy(a, dest)
                dest.write_bytes(result.stdout)
                if result.returncode:
                    conflicts.append(f"{relative} (merge markers)")
                continue
            copy(a, dest)
            conflicts.append(f"{relative} (merge tool failed)")
        else:
            if local_data is not None:
                copy(a, dest)
            conflicts.append(f"{relative} (add/delete or binary change)")

    manifest_delta = difflib.unified_diff(
        (old / "Cargo.toml").read_text().splitlines(keepends=True),
        (new / "Cargo.toml").read_text().splitlines(keepends=True),
        fromfile="old-upstream/Cargo.toml",
        tofile="new-upstream/Cargo.toml",
    )
    (output / "Cargo.upstream.diff").write_text("".join(manifest_delta))
    (output / "conflicts.txt").write_text("".join(f"{path}\n" for path in conflicts))
    print(f"Staged {staged}. Review Cargo.upstream.diff and conflicts.txt.", file=sys.stderr)
    return bool(conflicts)


if __name__ == "__main__":
    raise SystemExit(main())
