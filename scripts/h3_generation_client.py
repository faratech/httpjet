#!/usr/bin/env python3
"""Exercise one established and one new H3 connection across a test reload."""
import asyncio
import ssl
import sys

from aioquic.asyncio import connect
from aioquic.quic.configuration import QuicConfiguration
from h3get import H3Client


def configuration():
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    cfg.verify_mode = ssl.CERT_NONE
    cfg.server_name = "canon.test"
    return cfg


async def fetch(client):
    status, body = await asyncio.wait_for(
        client.get("canon.test", "/index.html"), 5
    )
    assert status == b"200", status
    return body


async def main():
    port = int(sys.argv[1])
    async with connect(
        "127.0.0.1", port, configuration=configuration(), create_protocol=H3Client
    ) as established:
        await established.wait_connected()
        assert await fetch(established) == b"before publication"
        print("READY", flush=True)
        await asyncio.to_thread(sys.stdin.readline)
        assert await fetch(established) == b"before publication"

    async with connect(
        "127.0.0.1", port, configuration=configuration(), create_protocol=H3Client
    ) as fresh:
        await fresh.wait_connected()
        assert await fetch(fresh) == b"after publication"

    print("PASS: established H3 stayed pinned and fresh H3 used replacement")


if __name__ == "__main__":
    asyncio.run(asyncio.wait_for(main(), 15))
