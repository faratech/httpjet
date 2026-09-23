#!/usr/bin/env python3
"""Materialize reviewed hex seeds for libFuzzer without replacing corpus data."""
import hashlib
from pathlib import Path
import sys

TARGETS = {"h1_chunked_decode", "h1_request_framing"}


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in TARGETS:
        raise SystemExit("usage: fuzz-seeds.py h1_chunked_decode|h1_request_framing")
    target = sys.argv[1]
    root = Path(__file__).resolve().parent.parent / "fuzz"
    corpus = root / "corpus" / target
    corpus.mkdir(parents=True, exist_ok=True)
    count = 0
    for line in (root / "seeds" / f"{target}.hex").read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        data = b"" if line == "-" else bytes.fromhex(line)
        if len(data) > 4096:
            raise ValueError("seed exceeds bounded replay size")
        path = corpus / ("seed-" + hashlib.sha256(data).hexdigest())
        try:
            with path.open("xb") as output:
                output.write(data)
        except FileExistsError:
            if path.read_bytes() != data:
                raise ValueError(f"existing seed has unexpected contents: {path}")
        count += 1
    if not count:
        raise ValueError("empty seed source")
    print(f"materialized {count} reviewed seeds for {target}")


if __name__ == "__main__":
    main()
