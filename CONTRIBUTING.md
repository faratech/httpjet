# Contributing to httpjet

Thank you for helping improve httpjet. Bug reports, documentation fixes,
tests, and focused code changes are welcome.

## Before opening a change

- Search existing issues and pull requests.
- Keep changes narrowly scoped. Security-sensitive behavior, protocol
  compatibility, and cache correctness need regression tests.
- Do not include credentials, production data, private configuration,
  customer content, or generated artifacts derived from them.
- Discuss large architectural changes in an issue before investing in an
  implementation.

## Development checks

httpjet currently targets Linux and Rust 1.97 or newer.

```bash
cargo fmt --all --check
cargo check -p httpjet --bin httpjet
cargo check -p httpjet --bin httpjet --features profiling
cargo test --workspace
```

Tests marked `ignored` can depend on local software or configuration. Do not
run them against a production installation.

## Developer Certificate of Origin

Contributions use the [Developer Certificate of Origin](DCO), not a
copyright-assignment or commercial-relicensing CLA. Sign every commit:

```bash
git commit -s
```

The sign-off certifies the statements in [DCO](DCO). It must use a name and
email address you are authorized to submit publicly. Pull requests with
unsigned commits will be asked to add sign-offs.

Contributions are licensed under `GPL-3.0-only`. FaraTech does not receive a
special right to relicense community contributions under proprietary terms.

## AI-assisted contributions

You remain responsible for every line you submit. Disclose material use of a
generative tool in the pull request, review the output, and confirm that you
have the right to contribute it. Never send private repository content,
credentials, production data, or third-party confidential material to a tool
that is not approved to receive it.

## Pull requests

Explain the problem, the intended behavior, operational impact, and checks
run. Avoid drive-by formatting or dependency changes unrelated to the fix.
Preserve third-party license notices and add provenance for newly vendored
code.
