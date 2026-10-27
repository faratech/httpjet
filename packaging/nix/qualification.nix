# Build a real NixOS VM with native declarative service generations.
{ releaseManifest, sshPublicKey, releaseBase ? "https://httpjet-packages.pages.dev/releases"
, previousManifest ? null, system ? builtins.currentSystem, sshPort ? 2222
, httpPort ? 18080, tlsPort ? 18443, quicPort ? 18443, certificate ? null }:
let
  pins = import ./pins.nix;
  source = builtins.fetchGit { url = "https://github.com/NixOS/nixpkgs"; rev = pins.nixpkgs; shallow = true; };
  pkgs = import source { inherit system; };
  candidate = pkgs.callPackage ./package.nix { inherit releaseManifest releaseBase certificate; };
  baseline = if previousManifest == null then candidate.overrideAttrs (_: {
    pname = "httpjet-first-release-fixture";
    __intentionallyOverridingVersion = true;
    version = "${candidate.manifest.upstream_version}-fixture";
  }) else pkgs.callPackage ./package.nix { releaseManifest = previousManifest; inherit releaseBase certificate; };
  evaluated = import (source + "/nixos/lib/eval-config.nix") {
    inherit system;
    modules = [
      ./module.nix
      (source + "/nixos/modules/virtualisation/qemu-vm.nix")
      ({ lib, ... }: {
        networking.hostName = "httpjet-qualification";
        networking.extraHosts = "10.0.2.2 httpjet-qualification.local";
        system.stateVersion = "26.05";
        users.users.qualifier = {
          isNormalUser = true; extraGroups = [ "wheel" ];
          openssh.authorizedKeys.keys = [ (builtins.readFile sshPublicKey) ];
        };
        security.sudo.wheelNeedsPassword = false;
        services.openssh.enable = true;
        services.openssh.settings = { PasswordAuthentication = false; PermitRootLogin = "no"; };
        networking.firewall.enable = false;
        environment.systemPackages = with pkgs; [ python3 curl gnupg util-linux openssl binutils ];
        security.pki.certificateFiles = lib.optional (certificate != null) certificate;
        services.httpjet = { enable = true; package = candidate; };
        specialisation.httpjet-baseline.configuration.services.httpjet.package = lib.mkForce baseline;
        specialisation.httpjet-disabled.configuration.services.httpjet.enable = lib.mkForce false;
        virtualisation = {
          memorySize = 2048; cores = 2; diskSize = 8192; graphics = false;
          writableStore = true;
          forwardPorts = [
            { from = "host"; host.address = "127.0.0.1"; host.port = sshPort; guest.port = 22; }
            { from = "host"; host.address = "127.0.0.1"; host.port = httpPort; guest.port = 18080; }
            { from = "host"; host.address = "127.0.0.1"; host.port = tlsPort; guest.port = 18443; }
            { from = "host"; proto = "udp"; host.address = "127.0.0.1"; host.port = quicPort; guest.port = 18443; }
          ];
          # The pinned wrapper already uses -machine accel=kvm:tcg.
          # The isolated builder rejects /dev/kvm, selecting its TCG fallback.
          qemu.forceAccel = false;
        };
      })
    ];
  };
in {
  vm = evaluated.config.system.build.vm;
  package = candidate;
  systemClosure = evaluated.config.system.build.toplevel;
}
