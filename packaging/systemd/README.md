# systemd example

This directory contains a deliberately conservative demonstration service for
the bundled static configuration. It:

- listens only on `127.0.0.1:8080`;
- disables TLS and PHP;
- does not enable the origin page cache;
- runs under a transient unprivileged account; and
- writes logs to the journal.

Build and install it:

```bash
cargo build --release -p httpjet
install -m0755 target/release/httpjet /usr/bin/httpjet
install -d -m0755 /etc/httpjet
cp -a examples/litespeed /etc/httpjet/litespeed
install -m0644 packaging/systemd/httpjet-example.service \
  /etc/systemd/system/httpjet-example.service
systemctl daemon-reload
systemctl enable --now httpjet-example.service
curl -H 'Host: example.test' http://127.0.0.1:8080/
```

The unit is an installation smoke test, not a production policy. A real
deployment must supply a reviewed configuration tree, listener addresses,
TLS key permissions, PHP supervision, cache limits, writable paths, logging,
and rollback procedure. Keep first runs on alternate ports and use a separate
LSAPI socket from any existing server.

The current application takes listener and runtime settings from command-line
arguments while importing virtual-host policy from LiteSpeed-compatible XML.
Use a local systemd drop-in to replace `ExecStart` rather than editing this
example in place.

`httpjet-lsphp.service` is a separate template for a persistent LSAPI pool.
Review its user, paths, child count, and PHP configuration before enabling it,
then point the web service at `/run/httpjet/lsphp.sock` with
`--lsphp-external`.
