# httpjet

httpjet is an experimental, high-performance Rust web server for Linux. It is
designed as a drop-in replacement for the parts of LiteSpeed Web Server used by
an existing deployment: it reads the same XML configuration, speaks LSAPI to
`lsphp`, and implements HTTP/1.1, HTTP/2, HTTP/3, TLS, rewrite rules, reverse
proxying, static files, and an opt-in origin page cache.

> **Status: 0.1.0, early-stage.** FaraTech runs httpjet in production, but the
> project has been developed against a specific configuration and is not a
> claim of complete LiteSpeed compatibility. Stage it on alternate ports,
> review the security model, and test every required directive before a
> cutover.

httpjet is completely open source under
[GPL-3.0-only](LICENSE). There is no paid edition, license key, or
sponsor-only feature set. Sponsorship supports maintenance but does not change
the software license or feature access.

## Current scope

- **LiteSpeed XML compatibility** — reads `conf/httpd_config.xml`,
  `conf/vhosts/*.xml`, `mime.properties`, and supported `.htaccess` directives.
- **Linux io_uring transport** — per-core monoio runtimes serve H1, native
  H2/h2c, TLS H1/H2, and quinn-proto-backed H3.
- **Native LSAPI** — LSAPI codec, owned `lsphp` supervision, and an optional
  independently supervised external pool.
- **TLS with rustls** — SNI certificates and optional client-certificate
  verification from the imported listener configuration.
- **Static, proxy, rewrite, and compression** — ranges and conditionals,
  HTTP/WebSocket/SSE proxying, Apache-style rewrite rules, gzip, Brotli, and
  zstd.
- **Origin page cache** — opt-in, sharded cache with private variants,
  stale handling, tag purge, optional tmpfs persistence, and dictionary
  compression.

The current release does **not** have a native TOML configuration format or
automatic configuration migration command. `--root` always names a
LiteSpeed-compatible configuration tree.

## Requirements

- Linux with io_uring support
- Rust 1.97 or newer
- A LiteSpeed-compatible XML configuration tree
- Optional: an LSAPI-compatible `lsphp` binary for PHP sites

The workspace crates are source components of the application and currently
set `publish = false`; they are not published independently to crates.io.

## Build

```bash
git clone https://github.com/faratech/httpjet.git
cd httpjet
cargo build --release -p httpjet
```

The binary is `target/release/httpjet`.

## Try the static example

The repository includes a self-contained, HTTP-only example on
`127.0.0.1:8080`:

```bash
target/release/httpjet --root "$(pwd)/examples/litespeed" check --strict
target/release/httpjet --root "$(pwd)/examples/litespeed" serve \
  --http-addr 127.0.0.1:8080 \
  --https-addr "" \
  --workers 1 \
  --no-php
```

Then request it with:

```bash
curl -H 'Host: example.test' http://127.0.0.1:8080/
```

`--no-php` is appropriate only for a configuration that cannot expose PHP
source files. Do not add PHP content to this static example.

For an existing installation, validate its configuration before serving:

```bash
httpjet --root /path/to/litespeed check --strict
httpjet --root /path/to/litespeed serve \
  --http-addr 127.0.0.1:8080 \
  --https-addr 127.0.0.1:4443 \
  --workers 1 \
  --no-mtls \
  --php-socket /tmp/httpjet-test-lsphp.sock \
  --php-children 2
```

Use alternate ports and a non-production PHP socket until application,
protocol, cache, and rollback testing is complete. `--no-mtls` is for explicit
local testing only.

## Test

```bash
cargo fmt --all --check
cargo check -p httpjet --bin httpjet
cargo check -p httpjet --bin httpjet --features profiling
cargo test --workspace
```

Ignored tests can depend on local software or configuration and must be invoked
separately. The profiling feature exposes raw pprof data for external tools; it
does not bundle a flamegraph renderer.

## Architecture

The workspace contains one binary crate and fourteen `hj-*` libraries. See
[ARCHITECTURE.md](ARCHITECTURE.md) for the dependency map and request
pipeline.

## Installation

[packaging/systemd](packaging/systemd) contains an unprivileged, static-only
example service for the bundled configuration. It deliberately listens on
port 8080 and enables neither TLS, PHP, nor the page cache. Production policy
belongs in a reviewed local unit or drop-in.

## Contributing and security

Contributions use DCO sign-offs and are accepted under GPL-3.0-only; FaraTech
does not require a proprietary-relicensing CLA. See
[CONTRIBUTING.md](CONTRIBUTING.md).

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).
Third-party attributions are in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md), with development provenance
summarized in [PROVENANCE.md](PROVENANCE.md).

## Sponsorship

Sponsorship is optional recognition and support for maintenance. It does not
buy private features, change support obligations, or restrict anyone's GPL
rights. Available funding links appear in GitHub's **Sponsor** button when
enabled. See [SPONSORSHIP.md](SPONSORSHIP.md) for the recognition-only policy
and current enrollment status.

## License and names

Copyright © FaraTech.

FaraTech-owned code and documentation are licensed under
[GNU GPL version 3 only](LICENSE). Third-party components retain their own
licenses. See [TRADEMARKS.md](TRADEMARKS.md) for use of the httpjet name.

LiteSpeed and OpenLiteSpeed are names of their respective owners. httpjet is
an independent project and is not affiliated with or endorsed by LiteSpeed
Technologies.
