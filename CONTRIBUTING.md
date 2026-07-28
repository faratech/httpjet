# Contributing

Keep changes focused, add regression tests, and never include secrets,
production data, or private configuration.

```bash
cargo fmt --all --check
cargo check -p httpjet --bin httpjet
cargo test --workspace
```

Sign every commit under the [Developer Certificate of Origin](DCO):

```bash
git commit -s
```

Contributions are GPL-3.0-only; there is no proprietary-relicensing CLA.
Disclose material AI assistance in the pull request and remain responsible for
the submitted code and its provenance.
