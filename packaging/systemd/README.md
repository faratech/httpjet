# systemd examples

`httpjet-example.service` runs the bundled static example on loopback port
8080 with TLS, PHP, and caching disabled.

```bash
cargo build --release -p httpjet
install -m0755 target/release/httpjet /usr/bin/httpjet
install -d /etc/httpjet
cp -a examples/litespeed /etc/httpjet/litespeed
install -m0644 packaging/systemd/httpjet-example.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now httpjet-example
```

`httpjet-lsphp.service` is a persistent LSAPI-pool template. Review all users,
paths, ports, limits, permissions, and rollback procedures before deployment.
