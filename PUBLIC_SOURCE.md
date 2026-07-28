# Public source boundary

The public repository is created as a clean source snapshot rather than by
changing the visibility of FaraTech's historical operations repository.

The snapshot includes all source required to build httpjet, its tests and fuzz
targets, vendored patches, the synthetic embedded dictionary, public
documentation, CI, and generic packaging examples. It excludes only private
deployment automation, production runbooks and telemetry, incident notes,
historical benchmark artifacts, screenshots, local agent instructions, and
the old private Git history. There is no separate proprietary server edition.

Future community work should happen in the public repository. Contributors
receive the same GPL-licensed source as sponsors and maintainers.

Maintainers can reproduce the boundary from a committed revision:

```bash
scripts/export-public-source.sh /absolute/path/to/empty-output HEAD
```

The exporter uses an explicit allowlist, checks that private top-level
materials are absent, verifies the synthetic dictionary, and scans for common
credential formats. A dedicated secret scanner must still be run against the
result before publication.
