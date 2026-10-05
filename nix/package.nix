{ lib, rustPlatform }:
rustPlatform.buildRustPackage {
  pname = "scauth";
  version = "0.1.0";
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
