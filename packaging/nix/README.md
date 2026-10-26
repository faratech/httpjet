# NixOS integration

Use the native module and hash-pinned package; do not run the imperative installer
on NixOS. Linux io_uring remains required. The definitions support x86_64-linux
and aarch64-linux and default to single-shot io_uring accept. No epoll fallback or
global kernel-policy change is made.

## Authenticate the release first

Obtain a published schema-2 `manifest.json` and its detached `.asc` signature for
a specific `X.Y.Z-N`. Verify them with GPG using the approved archive public key
and independently checked complete fingerprint. `package.nix` deliberately
expects this locally authenticated manifest: a fixed output hash cannot establish
who approved a manifest obtained from an untrusted source.

Keep that manifest at `/etc/nixos/httpjet-release/manifest.json` and this source
checkout at `/etc/nixos/httpjet`. The package fetches the immutable universal tar
URL and its exact manifest SHA256; it neither rebuilds nor patches/strips the ELF.
The default release origin is `https://httpjet-packages.pages.dev/releases`.
The qualification recipe's pinned nixpkgs revision is recorded in `pins.nix`.
Your own NixOS configuration supplies its `pkgs`; qualify a different nixpkgs
revision before treating it as supported.

## Enable in configuration.nix

```nix
{ lib, pkgs, ... }:
let
  httpjetPackage = pkgs.callPackage ./httpjet/packaging/nix/package.nix {
    releaseManifest = ./httpjet-release/manifest.json;
  };
in {
  imports = [ ./httpjet/packaging/nix/module.nix ];
  services.httpjet = {
    enable = true;
    package = httpjetPackage;
    # extraGroups = [ "an-existing-io-uring-policy-group" ];
  };
}
```

The module creates the dedicated account, root-managed XML configuration link,
state/log/runtime directories and systemd service with only low-port capability.
It seeds `/var/www/httpjet/index.html` once when the document root is absent;
existing content and intentional deletions after initialization are retained.

```sh
sudo nixos-rebuild test
systemctl status httpjet
curl --fail http://127.0.0.1/
sudo nixos-rebuild switch
```

The supplied default is HTTP-only on port 80, without PHP, page caching or a
management listener. Configuration is a Nix-store-backed tree, not an imperative
file to edit. To supply your own tree, add this to the configuration, where
`httpjet-conf/` contains `httpd_config.xml`, `mime.properties`, and `vhosts/`:

```nix
environment.etc."httpjet/conf".source = lib.mkForce ./httpjet-conf;
```

`services.httpjet` also exposes `configRoot`, `httpAddress`, `httpsAddress`,
`extraArgs`, `extraGroups` and `noMultishotAccept`. A custom configRoot requires
you to provide that full XML tree. Extra groups must match an existing deliberate
host policy; this module does not relax io_uring policy automatically.

## Update, rollback and disable

Authenticate a new manifest, change `releaseManifest`, and rebuild the system.
Use NixOS generations for rollback, for example `sudo nixos-rebuild switch --rollback`. Set `services.httpjet.enable = false` and rebuild to disable/remove
the service. Website data and logs remain outside the Nix store. The imperative
httpjetctl update/rollback/uninstall interface does not manage this integration.

`qualification.nix` builds a disposable VM with candidate/baseline/disabled
specialisations. A first-release baseline is labelled a same-ELF fixture. Local
parse/evaluation and package-byte checks do not prove a complete NixOS boot,
generation transition or ARM64 runtime; the release matrix requires those real
results before claiming the route qualified.
