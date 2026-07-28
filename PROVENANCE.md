# Provenance notes

httpjet is a Rust implementation of behavior needed to read
LiteSpeed-compatible configuration and serve an existing deployment.

Compatibility work used public protocol and configuration information,
black-box behavior, local configuration, and review of OpenLiteSpeed's
GPL-licensed implementation. The resulting FaraTech-owned implementation is
released under GPL-3.0-only, a compatible license. No OpenLiteSpeed source tree
is vendored in this repository.

The LSAPI constants and reference C material under
`crates/hj-lsapi/vendor/` come from their identified BSD-3-Clause sources and
retain the original notices. Locally patched Rust crates retain their upstream
licenses and are documented in `vendor/PATCHES.md`.

AI coding assistants were used during development. FaraTech reviewed and
accepted the resulting changes and is responsible for the code it publishes.
Future contributors must follow the provenance and disclosure requirements in
`CONTRIBUTING.md`.

Compatibility does not imply sponsorship or endorsement by LiteSpeed,
OpenLiteSpeed, PHP, or any other upstream project. Please report a missing
notice or suspected provenance problem through an issue, or privately under
`SECURITY.md` when public disclosure would create risk.
