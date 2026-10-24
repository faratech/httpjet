# lsphp hardening patch

`lsapilib-hardening.patch` applies to `sapi/litespeed/lsapilib.c` in the PHP source
tree that builds prod lsphp (`/web/install_php.py`, `php-<version>/`):
`patch -p1 < lsapilib-hardening.patch` before `./configure`.

It fixes three lsapilib defects found during the 2026-10-23 audit (#1117):

1. `LSAPI_Finish_r` reused a connection whose request body the script left
   partly unread, so lsphp parsed the unread bytes as the next BEGIN_REQUEST and
   executed it. It now ends such a connection with RESP_END + CONN_CLOSE, like
   `LSAPI_End_Response_r`.
2. `readReq` re-read the packet header into the start of its buffer on every
   pass, so a header that arrived in two reads was overwritten instead of
   appended to.
3. `parseEnv` bounded the env count only from above; a negative count walked the
   env list past its allocation (a NULL or heap write) before the frame was
   refused.

httpjet already refuses any request body that embeds a frame lsphp would accept,
including negative counts, so none of these is reachable through httpjet; the
patch is defense in depth for the worker itself.

`verify/run.sh <stock lsapilib.c>` builds a 20-line LSAPI app against the stock
and patched files and replays all three cases. Expected output:

    orig     T1 forged tail executed=True ...
    orig     T2 negative count: asan_error=True ...
    orig     T3 header split across writes: served=False ...
    patched  T1 forged tail executed=False ...
    patched  T2 negative count: asan_error=False ...
    patched  T3 header split across writes: served=True ...
