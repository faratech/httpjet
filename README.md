# httpjet

An experimental Linux web server written in Rust: it reads LiteSpeed-compatible
XML, speaks LSAPI to `lsphp`, and serves HTTP/1.1, HTTP/2, and HTTP/3 with TLS,
static files, proxying, rewrites, compression, and an opt-in page cache.

> **Production note.** httpjet is early-stage software built around one
> production configuration. It powers
> [WindowsForum.com](https://windowsforum.com) in production. Test on alternate
> ports before using it elsewhere. Visit **[httpjet.net](https://httpjet.net)**
> and read the full documentation at **[httpjet.net/docs/](https://httpjet.net/docs/)**.

## Contents

- [Documentation](#documentation)
- [Features at a glance](#features-at-a-glance)
- [Build and try it](#build-and-try-it)
- [Configuration](#configuration)
- [Capability limits](#capability-limits)
- [Operations](#operations)
- [Development](#development)
- [Security and contributing](#security-and-contributing)
- [License](#license)

## Documentation

Complete technical documentation, architecture diagrams, interactive `.htaccess` / cache-key / build-by-build benchmark explorers, and configuration references are hosted at **[httpjet.net/docs/](https://httpjet.net/docs/)**:

- **[Quickstart](https://httpjet.net/docs/quickstart)** — Build from source, validate a LiteSpeed config tree with `check --strict`, and serve on loopback.
- **[Architecture](https://httpjet.net/docs/architecture)** — The 19 `hj-*` workspace crates, the frozen `hj-core` contract, the `io_uring` transport bridge, and the request pipeline.
- **[Protocol stacks](https://httpjet.net/docs/protocols)** — HTTP/1.1, native HTTP/2 (zero-allocation HPACK), HTTP/3 over QUIC, `sendfile(2)`, and `kTLS` on one `io_uring` transport.
- **[LSAPI & PHP](https://httpjet.net/docs/lsapi)** — Native LSAPI wire codec, persistent `lsphp` external pool, generation tracking, and process jail.
- **[Rewrite & `.htaccess`](https://httpjet.net/docs/rewrite)** — Apache `mod_rewrite` engine, dense-DFA prefilter, `fast_memo` eligibility, and interactive `.htaccess` inspector.
- **[Origin Page Cache](https://httpjet.net/docs/page-cache)** — LSCache-compatible public/private tiers, W-TinyLFU admission, `jetcache` tmpfs file tier, and per-vhost zstd dictionaries.
- **[Configuration Reference](https://httpjet.net/docs/configuration)** & **[CLI Reference](https://httpjet.net/docs/cli)** — Filterable LiteSpeed XML directive and `httpjet` flag references.
- **[Performance Benchmarks](https://httpjet.net/docs/performance)** & **[Migrating from LiteSpeed](https://httpjet.net/docs/migration)** — Loopback 3-way benchmarks, production attribution, and validation-first cutover guide.
- **[LLM Documentation Corpus (`llms-full.txt`)](https://httpjet.net/llms-full.txt)** — Single-file Markdown reference of all 21 documentation pages.

## Features at a glance

Verified against the crate layout and the `httpjet` binary's argument
definitions in `crates/httpjet/src/main.rs`:

| Area | What is implemented |
|---|---|
| Protocols | HTTP/1.1, native HTTP/2, HTTP/3 (QUIC), TLS/mTLS |
| PHP | LSAPI to `lsphp`, with an optional standalone supervised pool (`httpjet lsphp`, `httpjet lsphp-reload`) |
| Content | Static files, reverse proxy with WebSocket and SSE forwarding |
| Rewrites | Apache `mod_rewrite` / `.htaccess` subset, including a limited `mod_headers` subset |
| Compression | Response zstd, Brotli, and gzip; gzip request decompression by default, Brotli/zstd opt-in via `--request-decompression-extra` |
| Caching | Opt-in LSCache-equivalent full-page cache (`--page-cache`, off by default); short-TTL origin (microcache) caching |
| Access control | LiteSpeed-compatible IP allow/deny, plus GeoIP/ASN sources loaded offline |
| Operations | Loopback Prometheus metrics (`--metrics-addr`, default `127.0.0.1:9090`), optional loopback admin and WAF-sidecar endpoints, access/error logging |

The `httpjet` binary is under `crates/httpjet`; reusable components are the
`hj-*` crates (`hj-config`, `hj-lsapi`, `hj-h2`, `hj-pagecache`, `hj-proxy`,
`hj-rewrite`, `hj-tls`, and others). Optional Cargo features are off by
default: `acme`, `ocsp`, `otel`, `profiling`, `allocount`, and the staged
`ktls`.

## Build and try it

Requires Linux with io_uring and Rust 1.99.1 or newer (the workspace
`rust-version`).

```bash
git clone https://github.com/faratech/httpjet.git
cd httpjet
cargo build --release -p httpjet
target/release/httpjet --root "$PWD/examples/litespeed" check --strict
target/release/httpjet --root "$PWD/examples/litespeed" serve \
  --http-addr 127.0.0.1:8080 --https-addr "" --workers 1 --no-php
curl -H 'Host: example.test' http://127.0.0.1:8080/
```

Use `--root` with an existing LiteSpeed configuration tree (default
`/usr/local/lsws`). With no subcommand, `httpjet` runs `check`. Run
`httpjet serve --help` for runtime options.

## Configuration

httpjet reads a LiteSpeed configuration tree: `conf/httpd_config.xml` under
the server root, plus one XML file per virtual host. Start from the bundled,
synthetic quick-start fixture:

- [`examples/litespeed/conf/httpd_config.xml`](examples/litespeed/conf/httpd_config.xml) — server, tuning, listener, and vhost map
- [`examples/litespeed/conf/vhosts/example.test.xml`](examples/litespeed/conf/vhosts/example.test.xml) — per-vhost document root and rewrite settings
- [`examples/litespeed/example/public/index.html`](examples/litespeed/example/public/index.html) — the page the quick start serves

Validate any tree before serving it:

```bash
target/release/httpjet --root /path/to/litespeed check --strict
```

Treat `check --strict` warnings as review items, not as proof of LiteSpeed
parity (see [Capability limits](#capability-limits)).

## Capability limits

Compatibility covers only the implemented and tested directive and protocol
surface:

- LiteSpeed XML is the configuration format; directives outside the
  implemented subset do not behave as they would under LiteSpeed.
- `.htaccess` response-header operations are intentionally a subset of
  Apache `mod_headers`; unsupported forms are ignored rather than emulated.
- Request decompression is bounded: gzip keeps its existing default
  behavior, while Brotli and zstd uploads are opt-in
  (`--request-decompression-extra`) under a transport-independent policy.
- Short-TTL origin caching works today; reusable route-policy controls for
  microcache are not yet exposed.
- The page cache is opt-in and additionally gated per vhost and per
  response; it is inert unless enabled.
- FastCGI primitives exist (`hj-fastcgi`) but are deliberately not wired
  into request routing yet.

## Operations

- **OCI / containers:** a hardened, non-root
  [OCI example](packaging/oci/README.md) documents the required writable
  mounts, separate TCP/UDP publication for HTTP/3, io_uring runtime
  requirements, and its non-privileged smoke gate. It is an adoption
  example, not the production deployment model.
- **systemd:** unit examples and install steps are in
  [`packaging/systemd/README.md`](packaging/systemd/README.md).
- **ACME (optional):** certificate automation is available with
  `--features acme` and explicit runtime opt-in (HTTP-01 and
  DNS-01/wildcard). It is disabled by default and does not replace
  existing certbot configuration automatically.
- **OCSP stapling (optional):** available with `--features ocsp` and an
  explicit responder URL. It is for compatible certificate authorities,
  not current Let's Encrypt certificates (whose issuer retired OCSP).
- **Fuzzing:** targets and the continuous corpus checks are described in
  [`fuzz/README.md`](fuzz/README.md).

## Development

```bash
cargo fmt --all --check
cargo check -p httpjet --bin httpjet
cargo test --workspace
```

## Security and contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) (focused changes, regression tests,
signed commits), [SECURITY.md](SECURITY.md) (private vulnerability
reporting and the production trust boundary), and
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

Donations support maintenance only; they do not buy features or influence.
Funding links will appear in GitHub's Sponsor button when enabled.

## License

httpjet is [GPL-3.0-only](LICENSE), with no paid edition or license key. It
is independent of and not endorsed by LiteSpeed Technologies.
