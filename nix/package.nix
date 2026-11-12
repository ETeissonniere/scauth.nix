{ lib, rustPlatform }:
let
  cargoToml = lib.importTOML ../Cargo.toml;
in
rustPlatform.buildRustPackage {
  pname = cargoToml.package.name;
  inherit (cargoToml.package) version;
  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../Cargo.toml
      ../Cargo.lock
      ../src
    ];
  };
  cargoLock.lockFile = ../Cargo.lock;
  meta = {
    description = "Provision macOS CryptoTokenKit SSH identities";
    platforms = [ "aarch64-darwin" ];
    mainProgram = "scauth";
  };
}
