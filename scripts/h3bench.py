#!/usr/bin/env python3
"""Bounded HTTP/3-only load client using pycurl's CurlMulti API.

The URL hostname remains the request authority and TLS SNI name.  CURLOPT_RESOLVE
maps that name to an explicitly supplied loopback address, so benchmark traffic
cannot leave the host or traverse Cloudflare.
"""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass, field
import ipaddress
import math
import re
import sys
import time
from typing import Iterable

try:
    import pycurl
except ImportError:  # Keep the no-network scheduler tests usable without pycurl.
    pycurl = None


_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")


def positive_int(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be positive")
    return number


def port_number(value: str) -> int:
    port = int(value)
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("must be between 1 and 65535")
    return port


def positive_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("must be a finite positive number")
    return number


def loopback_address(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "must be a literal loopback address (for example 127.0.0.1 or ::1)"
        ) from exc
    if not address.is_loopback:
        raise argparse.ArgumentTypeError("must be a loopback address")
    return address.compressed


def authority_name(value: str) -> str:
    if not value or value != value.strip() or any(c in value for c in "/?#@\r\n\t "):
        raise argparse.ArgumentTypeError("must be a bare hostname or IPv4 address")
    if ":" in value:
        raise argparse.ArgumentTypeError(
            "must not include a port or IPv6 literal (the port is a separate argument)"
        )
    return value


def request_path(value: str) -> str:
    if not value.startswith("/") or "\r" in value or "\n" in value:
        raise argparse.ArgumentTypeError("must start with '/' and contain no CR/LF")
    return value


def request_header(value: str) -> str:
    name, separator, header_value = value.partition(":")
    name = name.strip()
    if (
        not separator
        or not _HEADER_NAME.fullmatch(name)
        or "\r" in header_value
        or "\n" in header_value
    ):
        raise argparse.ArgumentTypeError("must be an HTTP NAME: VALUE without CR/LF")
    if name.lower() == "host":
        raise argparse.ArgumentTypeError(
            "Host cannot be overridden; the authority argument supplies :authority and SNI"
        )
    try:
        value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise argparse.ArgumentTypeError("must contain ASCII only") from exc
    return f"{name}: {header_value.strip()}"


def _url_host(authority: str) -> str:
    return f"[{authority}]" if ":" in authority else authority


def build_url(authority: str, port: int, path: str) -> str:
    return f"https://{_url_host(authority)}:{port}{path}"


def build_resolve_entry(authority: str, port: int, connect_host: str) -> str:
    address = f"[{connect_host}]" if ":" in connect_host else connect_host
    return f"{authority}:{port}:{address}"


class RequestScheduler:
    """Small, deterministic admission controller independent of the network."""

    def __init__(self, requests: int, concurrency: int, max_errors: int):
        if requests < 1 or concurrency < 1 or max_errors < 1:
            raise ValueError("requests, concurrency, and max_errors must be positive")
        self.requests = requests
        self.concurrency = min(concurrency, requests)
        self.max_errors = max_errors
        self.next_request = 0
        self.in_flight = 0
        self.failures = 0

    @property
    def stopped(self) -> bool:
        return self.failures >= self.max_errors

    @property
    def attempted(self) -> int:
        return self.next_request

    @property
    def skipped(self) -> int:
        return self.requests - self.attempted

    def take(self) -> int | None:
        if (
            self.stopped
            or self.next_request >= self.requests
            or self.in_flight >= self.concurrency
        ):
            return None
        request_id = self.next_request
        self.next_request += 1
        self.in_flight += 1
        return request_id

    def finish(self, *, failed: bool) -> None:
        if self.in_flight < 1:
            raise RuntimeError("finished a request that was not in flight")
        self.in_flight -= 1
        if failed:
            self.failures += 1


@dataclass
class LoadStats:
    requested: int
    attempted: int = 0
    completed: int = 0
    succeeded: int = 0
    body_bytes: int = 0
    status_failures: int = 0
    transport_failures: int = 0
    statuses: Counter[int] = field(default_factory=Counter)
    transport_errors: Counter[str] = field(default_factory=Counter)
    latencies: list[float] = field(default_factory=list)

    def started(self) -> None:
        self.attempted += 1

    def response(self, status: int, body_bytes: int, elapsed: float) -> bool:
        """Record a response and return whether it is a failed request."""
        self.completed += 1
        self.body_bytes += body_bytes
        self.statuses[status] += 1
        self.latencies.append(max(0.0, elapsed))
        if 200 <= status < 300:
            self.succeeded += 1
            return False
        self.status_failures += 1
        return True

    def transport_failure(
        self, error_key: str, body_bytes: int = 0, elapsed: float | None = None
    ) -> None:
        self.completed += 1
        self.body_bytes += body_bytes
        self.transport_failures += 1
        self.transport_errors[error_key] += 1
        if elapsed is not None and elapsed > 0:
            self.latencies.append(elapsed)

    @property
    def failed(self) -> int:
        return self.status_failures + self.transport_failures

    @property
    def skipped(self) -> int:
        return self.requested - self.attempted

    @property
    def incomplete(self) -> int:
        return self.requested - self.completed

    @property
    def ok(self) -> bool:
        return (
            self.attempted == self.requested
            and self.completed == self.requested
            and self.succeeded == self.requested
            and self.failed == 0
        )


@dataclass
class Transfer:
    request_id: int
    started_at: float
    body_bytes: int = 0

    def discard(self, chunk: bytes) -> int:
        length = len(chunk)
        self.body_bytes += length
        return length


def percentile(values: Iterable[float], percent: int) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    index = round((percent / 100) * (len(ordered) - 1))
    return ordered[index]


def _counter_text(counter: Counter) -> str:
    return ",".join(f"{key}:{counter[key]}" for key in sorted(counter, key=str)) or "none"


def format_summary(stats: LoadStats, elapsed: float) -> str:
    elapsed = max(elapsed, 1e-9)
    p50 = percentile(stats.latencies, 50) * 1000
    p90 = percentile(stats.latencies, 90) * 1000
    p99 = percentile(stats.latencies, 99) * 1000
    maximum = (max(stats.latencies) if stats.latencies else 0.0) * 1000
    return (
        f"requests={stats.requested} attempted={stats.attempted} "
        f"completed={stats.completed} succeeded={stats.succeeded} "
        f"failed={stats.failed} skipped={stats.skipped} incomplete={stats.incomplete} "
        f"status_failures={stats.status_failures} "
        f"transport_failures={stats.transport_failures} bytes={stats.body_bytes} "
        f"statuses={_counter_text(stats.statuses)} "
        f"transport_errors={_counter_text(stats.transport_errors)} "
        f"elapsed={elapsed:.6f}s rps={stats.completed / elapsed:.2f} "
        f"p50={p50:.3f}ms p90={p90:.3f}ms p99={p99:.3f}ms "
        f"max={maximum:.3f}ms latency_samples={len(stats.latencies)}"
    )


def _http3_available() -> bool:
    return bool(
        pycurl is not None
        and hasattr(pycurl, "CURL_HTTP_VERSION_3ONLY")
        and pycurl.version_info()[4] & pycurl.VERSION_HTTP3
    )


def _safe_total_time(handle, state: Transfer) -> float:
    try:
        elapsed = float(handle.getinfo(pycurl.TOTAL_TIME))
    except pycurl.error:
        elapsed = 0.0
    return elapsed if elapsed > 0 else max(0.0, time.monotonic() - state.started_at)


def run_load(args) -> tuple[LoadStats, float]:
    if not _http3_available():
        detail = "pycurl is not installed" if pycurl is None else pycurl.version
        raise RuntimeError(f"pycurl/libcurl has no HTTP/3 support ({detail})")

    max_errors = args.max_errors or min(args.concurrency, args.requests)
    scheduler = RequestScheduler(args.requests, args.concurrency, max_errors)
    stats = LoadStats(args.requests)
    transfers = {}
    url = build_url(args.authority, args.port, args.path)
    resolve = build_resolve_entry(args.authority, args.port, args.connect_host)
    timeout_ms = max(1, round(args.timeout * 1000))

    multi = pycurl.CurlMulti()
    multi.setopt(pycurl.M_PIPELINING, pycurl.PIPE_MULTIPLEX)
    multi.setopt(pycurl.M_MAX_TOTAL_CONNECTIONS, args.connections)
    multi.setopt(pycurl.M_MAX_HOST_CONNECTIONS, args.connections)
    streams_per_connection = math.ceil(args.concurrency / args.connections)
    if hasattr(pycurl, "M_MAX_CONCURRENT_STREAMS"):
        multi.setopt(pycurl.M_MAX_CONCURRENT_STREAMS, streams_per_connection)

    def add_transfer() -> bool:
        request_id = scheduler.take()
        if request_id is None:
            return False
        stats.started()
        state = Transfer(request_id=request_id, started_at=time.monotonic())
        handle = pycurl.Curl()
        handle.setopt(pycurl.URL, url)
        handle.setopt(pycurl.RESOLVE, [resolve])
        handle.setopt(pycurl.HTTP_VERSION, pycurl.CURL_HTTP_VERSION_3ONLY)
        handle.setopt(pycurl.PROXY, "")
        handle.setopt(pycurl.NOPROXY, "*")
        handle.setopt(pycurl.CONNECTTIMEOUT_MS, timeout_ms)
        handle.setopt(pycurl.TIMEOUT_MS, timeout_ms)
        handle.setopt(pycurl.FOLLOWLOCATION, 0)
        handle.setopt(pycurl.NOSIGNAL, 1)
        # Establish the requested initial connection fanout.  Later transfers
        # reuse and multiplex over this bounded pool.
        if request_id < args.connections:
            handle.setopt(pycurl.FRESH_CONNECT, 1)
        handle.setopt(pycurl.SSL_VERIFYPEER, 0 if args.insecure else 1)
        handle.setopt(pycurl.SSL_VERIFYHOST, 0 if args.insecure else 2)
        handle.setopt(pycurl.WRITEFUNCTION, state.discard)
        handle.setopt(pycurl.USERAGENT, "httpjet-h3bench/1")
        if args.header:
            handle.setopt(pycurl.HTTPHEADER, args.header)
        transfers[handle] = state
        multi.add_handle(handle)
        return True

    def fill() -> None:
        while len(transfers) < scheduler.concurrency and add_transfer():
            pass

    def finish_handle(handle, *, error: tuple[int, str] | None = None) -> None:
        state = transfers.pop(handle)
        elapsed = _safe_total_time(handle, state)
        if error is not None:
            errno, _message = error
            stats.transport_failure(str(errno), state.body_bytes, elapsed)
            failed = True
        else:
            try:
                version = int(handle.getinfo(pycurl.INFO_HTTP_VERSION))
                status = int(handle.getinfo(pycurl.RESPONSE_CODE))
            except pycurl.error as exc:
                stats.transport_failure(str(exc.args[0]), state.body_bytes, elapsed)
                failed = True
            else:
                if version != pycurl.CURL_HTTP_VERSION_3:
                    stats.transport_failure(
                        f"http_version_{version}", state.body_bytes, elapsed
                    )
                    failed = True
                else:
                    failed = stats.response(status, state.body_bytes, elapsed)
        scheduler.finish(failed=failed)
        multi.remove_handle(handle)
        handle.close()

    started_at = time.monotonic()
    try:
        fill()
        while transfers:
            while True:
                result, _active = multi.perform()
                if result != pycurl.E_CALL_MULTI_PERFORM:
                    break

            processed = 0
            while True:
                queued, successful, errors = multi.info_read()
                for handle in successful:
                    finish_handle(handle)
                    processed += 1
                for handle, errno, message in errors:
                    finish_handle(handle, error=(errno, message))
                    processed += 1
                if queued == 0:
                    break

            fill()
            if transfers and processed == 0:
                ready = multi.select(1.0)
                if ready == -1:
                    time.sleep(0.001)
    finally:
        for handle in list(transfers):
            try:
                multi.remove_handle(handle)
            finally:
                handle.close()
        multi.close()

    return stats, max(time.monotonic() - started_at, 1e-9)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("authority", type=authority_name)
    parser.add_argument("path", type=request_path)
    parser.add_argument(
        "connect_host",
        nargs="?",
        default="127.0.0.1",
        type=loopback_address,
        help="literal loopback destination (default: 127.0.0.1)",
    )
    parser.add_argument("port", nargs="?", default=443, type=port_number)
    parser.add_argument("-n", "--requests", required=True, type=positive_int)
    parser.add_argument("-c", "--concurrency", default=32, type=positive_int)
    parser.add_argument(
        "--connections",
        type=positive_int,
        help="maximum QUIC connections (default: min(16, concurrency))",
    )
    parser.add_argument(
        "--max-errors",
        type=positive_int,
        help="stop admitting requests after this many failures (default: concurrency)",
    )
    parser.add_argument("--timeout", default=30.0, type=positive_float)
    parser.add_argument("--insecure", action="store_true", help="disable TLS verification")
    parser.add_argument("-H", "--header", action="append", type=request_header, default=[])
    args = parser.parse_args(argv)
    args.concurrency = min(args.concurrency, args.requests)
    if args.connections is None:
        args.connections = min(16, args.concurrency)
    if args.connections > args.concurrency:
        parser.error("--connections cannot exceed --concurrency")
    return args


def main(argv=None) -> int:
    args = parse_args(argv)
    try:
        stats, elapsed = run_load(args)
    except RuntimeError as exc:
        print(f"h3bench: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("h3bench: interrupted", file=sys.stderr)
        return 130
    print(format_summary(stats, elapsed))
    return 0 if stats.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
