# httpjet

httpjet is an experimental Linux web server written in Rust. It reads
LiteSpeed-compatible XML, speaks LSAPI to `lsphp`, and supports H1/H2/H3, TLS,
static files, proxying, rewrites, compression, and an opt-in page cache.

It is early-stage software built around one production configuration. Test on
alternate ports before using it elsewhere.

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
