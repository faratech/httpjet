#!/usr/bin/env python3
"""Regenerate the embedded page-cache metadata dictionary from synthetic data only.

The corpus below mirrors metablob::encode_raw's byte framing, but every hostname,
path, tag, cookie, and header value is a deterministic fixture using reserved
example domains. The script does not read traffic captures, environment-provided
corpora, or the network.

Zstd dictionary training is deterministic only for a fixed trainer version and
parameters. Keep PINNED_ZSTD_VERSION, DICT_ID, and EXPECTED_SHA256 in sync with an
intentional regeneration. Run with --check in CI or before committing.
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile


PINNED_ZSTD_VERSION = "1.5.7"
DICT_SIZE = 16_384
# Little-endian "HJSM", masked to zstd's positive 31-bit dictionary-ID range.
DICT_ID = int.from_bytes(b"HJSM", "little") & 0x7FFF_FFFF
# Filled after generating the canonical fixture with the pinned trainer.
EXPECTED_SHA256 = "949371feb9b22a5f154c1b3f6fe2e9a6d3f60be3d8da20990c5fe0abe59222c9"

SCRIPT_DIR = Path(__file__).resolve().parent
OUTPUT = SCRIPT_DIR.parent / "src" / "pagecache-meta.dict"
DICT_MAGIC = bytes.fromhex("37 a4 30 ec")

HOSTS = (
    "cache-a.example",
    "cache-b.example",
    "tenant.example.test",
    "origin.invalid",
)
ADJECTIVES = ("amber", "brisk", "calm", "delta", "even", "fresh", "green", "quiet")
NOUNS = ("atlas", "beacon", "comet", "harbor", "meadow", "orbit", "signal", "willow")
TOPICS = ("about", "accounts", "cookies", "privacy", "search", "security", "start", "terms")
LANGUAGES = ("en-US", "en-GB", "de-DE", "fr-FR")


def lp(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return struct.pack("<I", len(encoded)) + encoded


def synthetic_path(index: int) -> str:
    adjective = ADJECTIVES[index % len(ADJECTIVES)]
    noun = NOUNS[(index // len(ADJECTIVES)) % len(NOUNS)]
    number = 10_000 + index
    variants = (
        "/",
        f"/articles/{adjective}-{noun}.{number}/",
        f"/categories/{noun}/{index % 17}/",
        f"/help/{TOPICS[index % len(TOPICS)]}/",
        f"/archive/{2020 + index % 7}/{1 + index % 12}/",
        f"/profiles/sample-user-{index % 97}/",
        f"/search/results/{adjective}-{noun}/",
        f"/api/v1/items/{number}",
    )
    return variants[index % len(variants)]


def synthetic_headers(index: int, host: str, path: str, private: bool) -> list[tuple[str, str]]:
    language = LANGUAGES[index % len(LANGUAGES)]
    if index % 29 == 0:
        return [
            ("location", f"https://{host}{path}"),
            ("cache-control", "public, max-age=300"),
            ("content-type", "text/html; charset=utf-8"),
            ("vary", "Accept-Encoding"),
        ]
    if index % 13 == 0:
        return [
            ("content-type", "application/json; charset=utf-8"),
            ("cache-control", "private, no-store" if private else "public, max-age=60"),
            ("vary", "Accept-Encoding"),
            ("x-content-type-options", "nosniff"),
            ("content-language", language),
        ]
    return [
        ("content-type", "text/html; charset=utf-8"),
        (
            "cache-control",
            "private, max-age=120" if private else f"public, max-age={300 + (index % 4) * 300}",
        ),
        ("vary", "Accept-Encoding"),
        ("x-frame-options", "SAMEORIGIN"),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "strict-origin-when-cross-origin"),
        ("content-language", language),
        ("strict-transport-security", "max-age=31536000; includeSubDomains; preload"),
    ]


def synthetic_metablob(index: int) -> bytes:
    host = HOSTS[index % len(HOSTS)]
    path = synthetic_path(index)
    secure = index % 9 != 0
    scheme = "https" if secure else "http"
    private = index % 11 == 0
    owner = 100_000 + index if private else 0
    query_options = (
        "",
        f"page={1 + index % 12}",
        f"sort=latest&page={1 + index % 12}",
        f"filter=all&cursor={index % 41}",
    )
    query = query_options[index % len(query_options)]
    key_vary = ("", "theme=light", "theme=dark", f"locale={LANGUAGES[index % 4]}")[
        index % 4
    ]
    vary_cookie = "" if index % 4 == 0 else ("theme" if index % 2 == 0 else "locale")
    entry_vary = "" if not vary_cookie else key_vary.partition("=")[2]
    status = 301 if index % 29 == 0 else (404 if index % 31 == 0 else 200)
    scope_owner = owner if private else 0
    tags = [
        "private" if private else "public",
        f"item_{10_000 + index}",
        f"section_{index % 17}",
        "member" if private else "guest",
    ]
    headers = synthetic_headers(index, host, path, private)

    fields = [
        b"HJPM",
        struct.pack("<H", 2),
        struct.pack("<I", 1 + index % len(HOSTS)),
        bytes((int(secure),)),
        lp(host),
        lp(path),
        lp(query),
        lp(key_vary),
        struct.pack("<Q", owner),
        struct.pack("<H", status),
        bytes((int(private),)),
        struct.pack("<Q", scope_owner),
        lp(f"{scheme}\n{host}\n{path}"),
        lp(vary_cookie),
        lp(entry_vary),
        struct.pack("<H", len(tags)),
        *(lp(tag) for tag in tags),
        struct.pack("<H", len(headers)),
        *(part for name, value in headers for part in (lp(name), lp(value))),
    ]
    return b"".join(fields)


def trainer_version(zstd: str) -> str:
    result = subprocess.run(
        [zstd, "--version"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    match = re.search(r"\bv(\d+\.\d+\.\d+)\b", result.stdout)
    if not match:
        raise RuntimeError("could not parse zstd trainer version")
    return match.group(1)


def build_dictionary(zstd: str, workdir: Path) -> bytes:
    corpus = workdir / "corpus"
    corpus.mkdir()
    samples = []
    for index in range(1_024):
        sample = corpus / f"meta-{index:04}.bin"
        sample.write_bytes(synthetic_metablob(index))
        samples.append(sample)

    candidate = workdir / "pagecache-meta.dict"
    command = [
        zstd,
        "--train-cover=k=64,d=8,steps=8,split=100",
        f"--maxdict={DICT_SIZE}",
        f"--dictID={DICT_ID}",
        "-o",
        str(candidate),
        *(str(sample) for sample in samples),
    ]
    subprocess.run(
        command,
        check=True,
        env={"LC_ALL": "C"},
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    generated = candidate.read_bytes()
    if len(generated) != DICT_SIZE:
        raise RuntimeError(f"expected {DICT_SIZE} dictionary bytes, got {len(generated)}")
    if generated[:4] != DICT_MAGIC:
        raise RuntimeError("trainer did not emit a full zstd dictionary")
    actual_id = int.from_bytes(generated[4:8], "little")
    if actual_id != DICT_ID:
        raise RuntimeError(f"expected dictionary ID {DICT_ID}, got {actual_id}")
    return generated


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="regenerate in a temporary directory and verify the checked-in dictionary",
    )
    args = parser.parse_args()

    zstd = shutil.which("zstd")
    if zstd is None:
        parser.error("zstd is required")
    version = trainer_version(zstd)
    if version != PINNED_ZSTD_VERSION:
        parser.error(
            f"zstd {PINNED_ZSTD_VERSION} is required for reproducible output; found {version}"
        )

    with tempfile.TemporaryDirectory(prefix="httpjet-synthetic-meta-dict-") as tmp:
        generated = build_dictionary(zstd, Path(tmp))

    digest = hashlib.sha256(generated).hexdigest()
    if EXPECTED_SHA256 and digest != EXPECTED_SHA256:
        parser.error(
            "generated dictionary checksum differs from EXPECTED_SHA256; "
            "review the corpus/trainer change before updating the checksum"
        )

    if args.check:
        if not OUTPUT.is_file() or OUTPUT.read_bytes() != generated:
            parser.error(f"{OUTPUT} is not the deterministic synthetic dictionary")
        print(f"synthetic metadata dictionary is reproducible ({len(generated)} bytes, sha256 {digest})")
        return 0

    temporary_output = OUTPUT.with_suffix(".dict.tmp")
    temporary_output.write_bytes(generated)
    temporary_output.replace(OUTPUT)
    print(f"wrote {OUTPUT} ({len(generated)} bytes, sha256 {digest})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
