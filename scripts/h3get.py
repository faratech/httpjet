#!/usr/bin/env python3
# Minimal HTTP/3 GET client (aioquic) to validate httpjet's io_uring-H3 streaming
# path against the live deployed binary on loopback (mTLS-exempt). The historical
# four-position CLI and H3Client.get(authority, path) API are intentionally stable.
import asyncio
import hashlib
import ssl
import sys

from aioquic.asyncio import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated, StreamReset


class H3Client(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._h3 = H3Connection(self._quic)
        self._buf = {}
        self._length = {}
        self._status = {}
        self._done = {}

    def quic_event_received(self, event):
        if isinstance(event, ConnectionTerminated):
            message = (
                "HTTP/3 connection terminated "
                f"(error={event.error_code}, reason={event.reason_phrase!r})"
            )
            for future in self._done.values():
                if not future.done():
                    future.set_exception(ConnectionError(message))
            return
        if isinstance(event, StreamReset):
            future = self._done.get(event.stream_id)
            if future is not None and not future.done():
                future.set_exception(
                    ConnectionError(
                        f"HTTP/3 stream reset (error={event.error_code})"
                    )
                )
            return

        for http_event in self._h3.handle_event(event):
            stream_id = http_event.stream_id
            if stream_id not in self._done:
                continue
            if isinstance(http_event, HeadersReceived):
                status = dict(http_event.headers).get(b":status")
                if status is not None:  # trailers must not erase the response status
                    self._status[stream_id] = status
                if http_event.stream_ended:
                    self._finish(stream_id)
            elif isinstance(http_event, DataReceived):
                self._length[stream_id] += len(http_event.data)
                if self._buf[stream_id] is not None:
                    self._buf[stream_id].extend(http_event.data)
                if http_event.stream_ended:
                    self._finish(stream_id)

    def _finish(self, stream_id):
        future = self._done.get(stream_id)
        if future is not None and not future.done():
            future.set_result(None)

    async def _get(
        self,
        authority,
        path,
        *,
        headers=(),
        capture_body=True,
        timeout=30.0,
    ):
        stream_id = self._quic.get_next_available_stream_id()
        self._buf[stream_id] = bytearray() if capture_body else None
        self._length[stream_id] = 0
        self._done[stream_id] = asyncio.get_running_loop().create_future()
        try:
            request_headers = [
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", authority.encode()),
                (b":path", path.encode()),
                *headers,
            ]
            self._h3.send_headers(stream_id, request_headers, end_stream=True)
            self.transmit()
            await asyncio.wait_for(self._done[stream_id], timeout=timeout)
            body = self._buf[stream_id]
            return (
                self._status.get(stream_id),
                bytes(body) if body is not None else None,
                self._length[stream_id],
            )
        finally:
            self._buf.pop(stream_id, None)
            self._length.pop(stream_id, None)
            self._status.pop(stream_id, None)
            self._done.pop(stream_id, None)

    async def get(self, authority, path):
        status, body, _ = await self._get(authority, path)
        return status, body

    async def get_discard(self, authority, path, *, headers=(), timeout=30.0):
        status, _, length = await self._get(
            authority,
            path,
            headers=headers,
            capture_body=False,
            timeout=timeout,
        )
        return status, length


def format_single_response(status, body):
    return (
        f"status={status.decode() if status else None} "
        f"len={len(body)} md5={hashlib.md5(body).hexdigest()}"
    )


async def main():
    authority, path = sys.argv[1], sys.argv[2]
    config = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    config.verify_mode = ssl.CERT_NONE
    config.server_name = authority
    host = sys.argv[3] if len(sys.argv) > 3 else "127.0.0.1"
    port = int(sys.argv[4]) if len(sys.argv) > 4 else 443
    async with connect(
        host, port, configuration=config, create_protocol=H3Client
    ) as client:
        await client.wait_connected()
        status, body = await client.get(authority, path)
        print(format_single_response(status, body))


if __name__ == "__main__":
    asyncio.run(main())
