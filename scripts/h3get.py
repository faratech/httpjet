#!/usr/bin/env python3
# Minimal HTTP/3 GET client (aioquic) to validate httpjet's io_uring-H3 streaming
# path against the live deployed binary on loopback (mTLS-exempt). Prints status,
# byte length, and md5 of the body so we can compare to the on-disk file / an H2 fetch.
import asyncio, ssl, sys, hashlib
from aioquic.asyncio import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived, DataReceived
from aioquic.quic.configuration import QuicConfiguration


class H3Client(QuicConnectionProtocol):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self._h3 = H3Connection(self._quic)
        self._buf = {}
        self._status = {}
        self._done = {}

    def quic_event_received(self, event):
        for e in self._h3.handle_event(event):
            if isinstance(e, HeadersReceived):
                self._status[e.stream_id] = dict(e.headers).get(b":status")
                self._buf.setdefault(e.stream_id, bytearray())
                if getattr(e, "stream_ended", False):
                    self._finish(e.stream_id)
            elif isinstance(e, DataReceived):
                self._buf.setdefault(e.stream_id, bytearray()).extend(e.data)
                if getattr(e, "stream_ended", False):
                    self._finish(e.stream_id)

    def _finish(self, sid):
        fut = self._done.get(sid)
        if fut and not fut.done():
            fut.set_result(True)

    async def get(self, authority, path):
        sid = self._quic.get_next_available_stream_id()
        self._buf[sid] = bytearray()
        self._done[sid] = asyncio.get_event_loop().create_future()
        self._h3.send_headers(sid, [
            (b":method", b"GET"), (b":scheme", b"https"),
            (b":authority", authority.encode()), (b":path", path.encode()),
        ], end_stream=True)
        self.transmit()
        await asyncio.wait_for(self._done[sid], timeout=30)
        return self._status.get(sid), bytes(self._buf[sid])


async def main():
    authority, path = sys.argv[1], sys.argv[2]
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    cfg.verify_mode = ssl.CERT_NONE
    cfg.server_name = authority
    host = sys.argv[3] if len(sys.argv) > 3 else "127.0.0.1"
    port = int(sys.argv[4]) if len(sys.argv) > 4 else 443
    async with connect(host, port, configuration=cfg, create_protocol=H3Client) as client:
        await client.wait_connected()
        status, body = await client.get(authority, path)
        print(f"status={status.decode() if status else None} len={len(body)} md5={hashlib.md5(body).hexdigest()}")


if __name__ == "__main__":
    asyncio.run(main())
