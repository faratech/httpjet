# Changelog

All notable public changes to httpjet are documented here.

## Unreleased

Prepared for the initial public source release.

- Linux io_uring HTTP/1.1, native HTTP/2, and HTTP/3 serving paths.
- LiteSpeed-compatible XML configuration and `.htaccess` rewrite support.
- Static serving, reverse proxying, TLS, LSAPI/PHP, compression, and an
  opt-in origin page cache.
- GPL-3.0-only licensing, DCO contribution policy, security reporting, CI,
  synthetic embedded dictionary, and generic static example.
- Profiling output is raw pprof protobuf; no CDDL flamegraph renderer is
  linked into the application.

This early release is not a claim of complete LiteSpeed compatibility. There
is no native TOML configuration format or automatic migration command.
