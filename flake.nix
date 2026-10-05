{
  description = "Declarative macOS CryptoTokenKit SSH identities";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    nix-darwin = {
      url = "github:nix-darwin/nix-darwin";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    home-manager = {
      url = "github:nix-community/home-manager";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      nix-darwin,
      home-manager,
    }:
    let
      system = "aarch64-darwin";
      pkgs = nixpkgs.legacyPackages.${system};
    in
    {
      homeManagerModules.default = import ./nix/home-manager.nix;
      packages.${system}.default = pkgs.callPackage ./nix/package.nix { };
      formatter.${system} = pkgs.nixfmt;
      checks.${system} = {
        package = self.packages.${system}.default;
        home-manager = import ./tests/home-manager.nix {
          inherit
            self
            nixpkgs
            nix-darwin
            home-manager
            system
            ;
        };
      };
      devShells.${system}.default = pkgs.mkShell {
        packages = [
          pkgs.cargo
          pkgs.rustc
          pkgs.rustfmt
          pkgs.clippy
          pkgs.nixfmt
        ];
      };
    };
}
