# Architecture

A navigation map of the public httpjet workspace: how the crates layer, where
responsibilities live, and how a request flows. Deployment policy is deliberately
outside this document; start with the staged example in the README.

## Crate dependency DAG

One binary crate (`httpjet`) over fourteen `hj-*` libraries. The graph is acyclic
with `hj-config` at the root and `hj-core` as the seam every handler programs
against. Edges are *internal* deps only (third-party crates omitted).

```
                         hj-config ──────────────┐  (parsed LiteSpeed XML model)
                            │                     │
                            ▼                     ▼
        ┌──────────────── hj-core ───────────┐  hj-cache   (shared cache primitive)
        │        │      │     │     │     │   │
        ▼        ▼      ▼     ▼     ▼     ▼   ▼
     hj-tls   hj-h2  hj-lsapi hj-static hj-compress hj-proxy hj-acl
        │
        ▼
     hj-http                         hj-pagecache   hj-rewrite   hj-log
        │                          (transport-agnostic; uses hj-cache)
        └──────────────── all of the above ──────────────┐
                                                          ▼
                                                       httpjet
                                          (binding, accept loops, request pipeline)
```

- **Roots with no `hj-*` deps:** `hj-config` (XML → normalized model),
  `hj-rewrite` (Apache `.htaccess` engine), and `hj-log`. `hj-pagecache`
  remains transport-agnostic but reuses the sharded cache primitive from
  `hj-cache`; its `ReqCtx`-aware glue lives in the binary's `lscache/`.
- **`hj-core`** re-exports `hj_core::config::*`, so every downstream crate imports the
  config model *through* core — one import surface. Do not invert this layering.
- **`httpjet`** is the only crate that sees everything; it owns the orchestration
  (`pipeline/`, `state.rs`, `lscache/`, `server.rs`, `main.rs`).

## The frozen contract — `hj-core`

The seam that lets handlers compose without knowing the transport. Changing these
signatures means updating every dependent, so treat them as frozen:

- `Body { Empty, Full(Bytes), Stream(BoxBody), File(FileBody) }`, `Request`, `Response`; a `FileBody`
  may carry an open descriptor that pins the selected inode across a concurrent cache version swap.
- `#[async_trait] trait Handler { async fn handle(&self, &mut ReqCtx, Request) -> Result<Response, HandlerError> }`
  — the terminal handlers (`StaticFiles`, `Lsapi`, `ProxyHandler`).
- `#[async_trait] trait ResponseTransform { async fn transform(&self, &ReqCtx, &mut Response) }`
  — the post-handler pipeline (cache-small-static → expires → compress →
  deny-CDN-cache → Alt-Svc), assembled once into `ServerState::transforms`.
- `ReqCtx` — per-request state (server/vhost Arcs, peer/client IP, TLS, protocol,
  `env` for rewrite `[E=]` + CGI overrides).
- `Router::resolve(listener, key)` — SNI/Host → vhost.

New terminal handlers impl `Handler` and register in `pipeline/mod.rs::dispatch()`;
new response munging impls `ResponseTransform` and is pushed into the transform Vec
(see `state.rs::build_transforms`). Neither requires touching `handle()`.

## Module organization (post-reorg)

The two former god-files are split into cohesive submodules (verbatim moves; no API
change). Names map 1:1 to responsibility:

- `crates/httpjet/src/pipeline/` — `mod.rs` keeps `handle`/`dispatch`/`finalize_response`;
  `rewrite_glue`, `proxy_glue` (incl. `ProxyHandler`), `htaccess_apply`,
  `suffix_routing`, `response_util` hold the stages.
- `crates/httpjet/src/lscache/` — `mod.rs` (`CacheCtx`, `cache_lookup`/`cache_store`),
  `hit` (hit-response construction + precompress), `singleflight` (miss-stampede
  collapse).
- `crates/hj-h2/src/server/` — `state`/`recv`/`send` + `serve()`; HPACK is
  the folded-in `hpack` submodule (was the standalone `hj-hpack` crate).
- `hj-rewrite` `rules`→`{parse,eval}`, `hj-config` `parse`→`{raw,scalar,vhost}`,
  `hj-lsapi` `supervisor` + the security-critical `jail`, `proto`→`{frame,builder}`.

## Request pipeline

`pipeline::handle()` → vhost resolution → mTLS trust-boundary → ACL/real-IP →
`dispatch()` → response transforms → access log. `dispatch()` mirrors OpenLiteSpeed
ordering, with the page-cache seams inserted after rewrite/access state has been
resolved:

```
.htaccess chain → SetEnvIf → pre-rewrite ACL → rewrite (inline then .htaccess)
  → destination-chain reload when needed → access enforcement
  → PATH_INFO script deny check → page-cache lookup / single-flight
  → WebSocket upgrade → proxy <context> → suffix routing (php/html → LSAPI, else static)
```

Each terminal finishes with `finalize_response` (`.htaccess` header ops + error
documents) then `cache_store`. The terminals are intentionally **not** a uniform
matcher registry: their predicates (request headers vs path vs script-path split),
fall-through rules (a proxy context that can't resolve its ext-processor falls
through to static; a script with no PHP pool hard-fails 503 and must *never* fall
through — a source-disclosure guard), and post-processing all differ, so the
explicit `if/return` chain keeps that security-relevant ordering legible.

The page-cache seams are inert unless `--page-cache` is set: `cache_lookup` runs
after rewrite/ACL but before any backend; `cache_store` runs after each terminal.
Both key off the **original** request URI (never the rewrite-resolved path) via a
single `CacheCtx` built once in `dispatch()`. The identity guard in
`hj-pagecache` makes any accidental key collision fail closed to a miss.

## Transport paths

The **pure-io_uring (monoio) transport is the only transport** — it is unconditional (there is no
longer a feature flag, and the tokio/epoll + tokio/quinn adapters were removed). `crates/httpjet/src/uring/`
runs one monoio io_uring runtime per inherited (or self-bound) `SO_REUSEPORT` listener:

- **H1** is a custom monoio + `httparse` codec; **H2/h2c** is the native `hj-h2` stack (via its `monoio`
  `serve_local` path); **TLS** terminates with `monoio-rustls`; **H3** is `uring/h3.rs`, a quinn-proto
  driver on a monoio io_uring UDP loop.
- The bridge (`uring/bridge.rs`) hands each request to the ambient tokio runtime, runs `pipeline::handle`
  (so LSAPI, proxy, rewrite, page-cache, SIGHUP reloads, and metrics are all shared), then returns the
  response to the monoio core for framing/writes — streaming large bodies (>256 KiB) on H1, H2, and H3
  alike, buffering small ones.
- `crates/httpjet/src/server.rs` is reduced to adopting the systemd socket-activation fds; `hj-http` is
  reduced to the shared `ServeConfig` connection-tuning struct (its hyper-H1 + quinn-H3 adapters were removed).
- Reverting off io_uring is a `git` operation (rebuild), not a runtime flag or a `URING=0` build.
