#!/usr/bin/env python3
"""Bounded aioquic HTTP/3 load client for PGO coverage."""

import argparse
import asyncio
from collections import Counter
from dataclasses import dataclass, field
import ssl
import time

from aioquic.asyncio import connect
from aioquic.quic.configuration import QuicConfiguration

from h3get import H3Client


@dataclass
class LoadResult:
    requested: int
    attempted: int = 0
    completed: int = 0
    succeeded: int = 0
    body_bytes: int = 0
    failed: int = 0
    statuses: Counter = field(default_factory=Counter)

    @property
    def skipped(self):
        return self.requested - self.attempted

    @property
    def ok(self):
        return (
            self.attempted == self.requested
            and self.completed == self.requested
            and self.failed == 0
        )


async def run_bounded_load(
    client,
    authority,
    path,
    *,
    requests,
    concurrency,
    headers=(),
    timeout=30.0,
    max_errors=None,
):
    """Issue repeated GETs with a fixed upper bound on in-flight streams."""
    if requests < 1 or concurrency < 1:
        raise ValueError("requests and concurrency must be positive")
    concurrency = min(concurrency, requests)
    max_errors = concurrency if max_errors is None else max_errors
    if max_errors < 1:
        raise ValueError("max_errors must be positive")

    result = LoadResult(requests)
    next_request = 0
    stopped = False

    def take_request():
        nonlocal next_request
        if stopped or next_request >= requests:
            return False
        next_request += 1
        result.attempted += 1
        return True

    async def worker():
        nonlocal stopped
        while take_request():
            try:
                status, length = await client.get_discard(
                    authority, path, headers=headers, timeout=timeout
                )
            except Exception:
                result.failed += 1
                stopped = result.failed >= max_errors
                continue
            result.completed += 1
            result.body_bytes += length
            status_text = status.decode("ascii", "replace") if status else "none"
            result.statuses[status_text] += 1
            try:
                good_status = 200 <= int(status_text) < 400
            except ValueError:
                good_status = False
            if good_status:
                result.succeeded += 1
            else:
                result.failed += 1
                stopped = result.failed >= max_errors

    await asyncio.gather(*(worker() for _ in range(concurrency)))
    return result


def positive_int(value):
    value = int(value)
    if value < 1:
        raise argparse.ArgumentTypeError("must be positive")
    return value


def parse_header(value):
    name, separator, header_value = value.partition(":")
    name = name.strip().lower()
    if not separator or not name or name.startswith(":") or "\r" in value or "\n" in value:
        raise argparse.ArgumentTypeError("header must be NAME: VALUE without CR/LF")
    try:
        return name.encode("ascii"), header_value.strip().encode("ascii")
    except UnicodeEncodeError as exc:
        raise argparse.ArgumentTypeError("header must be ASCII") from exc


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("authority")
    parser.add_argument("path")
    parser.add_argument("host", nargs="?", default="127.0.0.1")
    parser.add_argument("port", nargs="?", type=int, default=443)
    parser.add_argument("-n", "--requests", required=True, type=positive_int)
    parser.add_argument("-c", "--concurrency", default=8, type=positive_int)
    parser.add_argument("--max-errors", type=positive_int)
    parser.add_argument("--timeout", default=30.0, type=float)
    parser.add_argument("-H", "--header", action="append", type=parse_header, default=[])
    args = parser.parse_args(argv)
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    return args


async def run(args):
    config = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    config.verify_mode = ssl.CERT_NONE
    config.server_name = args.authority
    async with connect(
        args.host,
        args.port,
        configuration=config,
        create_protocol=H3Client,
        wait_connected=False,
    ) as client:
        # aioquic's connect(wait_connected=False) also suppresses the initial
        # handshake datagram so callers can send 0-RTT first. We only use the
        # mode to put a deadline around the handshake, therefore kick it off
        # explicitly before waiting for completion.
        client.transmit()
        await asyncio.wait_for(client.wait_connected(), timeout=args.timeout)
        started = time.monotonic()
        result = await run_bounded_load(
            client,
            args.authority,
            args.path,
            requests=args.requests,
            concurrency=args.concurrency,
            headers=tuple(args.header),
            timeout=args.timeout,
            max_errors=args.max_errors,
        )
        elapsed = max(time.monotonic() - started, 1e-9)
        statuses = ",".join(
            f"{status}:{count}" for status, count in sorted(result.statuses.items())
        ) or "none"
        print(
            f"requests={result.requested} attempted={result.attempted} "
            f"completed={result.completed} succeeded={result.succeeded} "
            f"failed={result.failed} skipped={result.skipped} "
            f"bytes={result.body_bytes} statuses={statuses} "
            f"elapsed={elapsed:.3f}s rps={result.completed / elapsed:.1f}"
        )
        return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(run(parse_args())))
