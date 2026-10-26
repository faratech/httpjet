# releaseManifest must be a locally authenticated schema-2 manifest. Its payload
# is fetched by an immutable URL and the exact SHA256, with no binary rewriting.
{ lib, stdenvNoCC, fetchurl, releaseManifest
, releaseBase ? "https://packages.httpjet.net/releases", certificate ? null }:
let
  manifest = builtins.fromJSON (builtins.readFile releaseManifest);
  architecture = { x86_64-linux = "amd64"; aarch64-linux = "arm64"; }.${stdenvNoCC.hostPlatform.system}
    or (throw "httpjet supports x86_64-linux and aarch64-linux");
  binary = manifest.binaries.${architecture};
  artifact = manifest.artifacts.${binary.artifact};
in
assert manifest.schema == 2;
assert binary.libc == "musl" && artifact.libc == "musl";
assert artifact.architecture == architecture;
assert builtins.match "[0-9a-f]{64}" artifact.sha256 != null;
stdenvNoCC.mkDerivation {
  pname = "httpjet-bin";
  version = manifest.release_id;
  src = fetchurl {
    url = "${releaseBase}/${manifest.release_id}/${binary.artifact}";
    sha256 = artifact.sha256;
    curlOpts = lib.optionalString (certificate != null)
      "--cacert ${toString (builtins.path { path = certificate; name = "httpjet-qualification-ca.crt"; })}";
  };
  sourceRoot = "httpjet-${manifest.release_id}";
  dontConfigure = true;
  dontBuild = true;
  dontFixup = true;
  dontStrip = true;
  installPhase = ''
    runHook preInstall
    mkdir -p "$out/bin" "$out/share"
    cp -p bin/httpjet "$out/bin/httpjet"
    cp -a share/httpjet "$out/share/httpjet"
    runHook postInstall
  '';
  passthru = { inherit manifest architecture; binarySha256 = binary.binary_sha256; };
  meta = {
    description = "Static httpjet server from an authenticated release manifest";
    homepage = "https://httpjet.net";
    license = lib.licenses.gpl3Only;
    platforms = [ "x86_64-linux" "aarch64-linux" ];
    mainProgram = "httpjet";
  };
}
