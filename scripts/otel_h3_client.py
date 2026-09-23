#!/usr/bin/env python3
"""Synthetic-only client for the ignored Rust OTel QUIC interoperability test."""
import asyncio
import ssl
import sys

from aioquic.asyncio import connect
from aioquic.quic.configuration import QuicConfiguration
from h3get import H3Client


async def main():
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    # Ephemeral self-signed certificate; this helper only connects to loopback.
    cfg.verify_mode = ssl.CERT_NONE
    cfg.server_name = "canon.test"
    async with connect("127.0.0.1", int(sys.argv[1]), configuration=cfg,
                       create_protocol=H3Client) as client:
        await client.wait_connected()
        for path, expected in [("/index.html", b"synthetic QUIC response"),
                               ("/large.txt", b"x" * (2 * 1024 * 1024))]:
            status, body = await asyncio.wait_for(client.get("canon.test", path), 5)
            assert status == b"200", status
            assert body == expected, (path, len(body))
    print("PASS: H3 small and 2 MiB bodies are byte-identical")


if __name__ == "__main__":
    asyncio.run(asyncio.wait_for(main(), 12))
