# httpjet

httpjet is an experimental Linux web server written in Rust. It reads
LiteSpeed-compatible XML, speaks LSAPI to `lsphp`, and supports H1/H2/H3, TLS,
static files, proxying, rewrites, compression, and an opt-in page cache.

It is early-stage software. Test on alternate ports before using it in a
production environment.

Learn more—or at least enjoy the animation—at [httpjet.net](https://httpjet.net).

## Build and try it

Requires Linux with io_uring and Rust 1.97+.

```bash
git clone https://github.com/faratech/httpjet.git
cd httpjet
cargo build --release -p httpjet
target/release/httpjet --root "$PWD/examples/litespeed" check --strict
target/release/httpjet --root "$PWD/examples/litespeed" serve \
  --http-addr 127.0.0.1:8080 --https-addr "" --workers 1 --no-php
curl -H 'Host: example.test' http://127.0.0.1:8080/
```

Use `--root` with an existing LiteSpeed configuration tree. Run
`httpjet serve --help` for runtime options.

Before adopting it, review the current [capability matrix and operational
limits](docs/capability-matrix.md), [configuration
examples](docs/configuration-examples.md), and [LiteSpeed migration
guide](docs/migrating-from-litespeed.md). Compatibility is limited to the
implemented/tested directive and protocol surface; `check --strict` warnings
must be reviewed rather than treated as parity.

Optional Brotli/zstd uploads use the bounded, transport-independent
[request decompression policy](docs/request-decompression.md); gzip retains its
existing default behavior.

Short-TTL origin caching is supported today. The missing reusable route-policy
controls and their isolated executable proof are documented in the
[microcache policy requirements](docs/microcache-policy.md).

`.htaccess` response-header operations are intentionally a subset of Apache
`mod_headers`; the exact supported and ignored forms are pinned in the
[header-directive compatibility inventory](docs/header-directive-compatibility.md).

A hardened, non-root [OCI example](packaging/oci/README.md) documents the
required writable mounts, separate TCP/UDP publication for HTTP/3, io_uring
runtime requirements, and its non-privileged smoke gate.

Optional certificate automation is available with `--features acme` and
explicit runtime opt-in. See
[HTTP-01](docs/acme-http01.md) and [DNS-01/wildcard configuration](docs/acme-dns01.md); it is disabled by
default and does not replace existing certbot configuration automatically.

Optional [OCSP stapling](docs/ocsp-stapling.md) uses `--features ocsp` and an
explicit responder URL. It is for compatible certificate authorities, not
current Let's Encrypt certificates (whose issuer retired OCSP).

## Development

The `httpjet` binary is under `crates/httpjet`; reusable components are the
`hj-*` crates.

```bash
cargo fmt --all --check
cargo check -p httpjet --bin httpjet
cargo test --workspace
```

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

Donations support maintenance only; they do not buy features or influence.
Funding links will appear in GitHub's Sponsor button when enabled.

httpjet is [GPL-3.0-only](LICENSE), with no paid edition or license key. It is
independent of and not endorsed by LiteSpeed Technologies.
