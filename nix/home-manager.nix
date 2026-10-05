{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib)
    mkEnableOption
    mkIf
    mkOption
    types
    ;
  cfg = config.programs.scauth;
  runtimeConfig = builtins.toJSON {
    user = config.home.username;
    identities = lib.mapAttrs (_: identity: {
      protection = if identity.touchId then "bio" else "none";
    }) cfg.identities;
  };
  configFile = pkgs.writeText "scauth.json" runtimeConfig;
  identityType = types.submodule (
    { name, ... }: {
      config = {
        inherit name;
        identityFile = "${config.home.homeDirectory}/.ssh/scauth/${name}/id_ecdsa_sk";
        publicKeyFile = "${config.home.homeDirectory}/.ssh/scauth/${name}/id_ecdsa_sk.pub";
      };
      options = {
        name = mkOption {
          type = types.str;
          readOnly = true;
          description = "CTK label, generated from this identity's attribute name.";
        };
        identityFile = mkOption {
          type = types.str;
          readOnly = true;
          description = "Absolute path to the SSH reference file, created during provisioning.";
        };
        publicKeyFile = mkOption {
          type = types.str;
          readOnly = true;
          description = "Absolute path to the public key file, created during provisioning.";
        };
        touchId = mkOption {
          type = types.bool;
          default = true;
          description = "Whether use of this identity requires Touch ID authentication.";
        };
      };
    }
  );
in
{
  options.programs.scauth = {
    enable = mkEnableOption "CryptoTokenKit SSH identity provisioning";
    securityKeyProvider = mkOption {
      type = types.str;
      readOnly = true;
      default = "/usr/lib/ssh-keychain.dylib";
      description = "Apple's CryptoTokenKit provider for SSH and ssh-keygen.";
    };
    package = mkOption {
      type = types.package;
      default = pkgs.callPackage ./package.nix { };
      description = "The scauth reconciler package.";
    };
    identities = mkOption {
      type = types.attrsOf identityType;
      default = { };
      example = {
        personal = { };
        work = {
          touchId = true;
        };
        deploy = {
          touchId = false;
        };
      };
      description = ''
        Non-exportable P-256 identities, keyed by CTK label. Names must contain
        only letters, digits, underscores or hyphens. Existing matching labels
        are adopted only when their key type and Touch ID setting agree. Changes
        to touchId fail rather than replace a key. Removing an entry permanently
        deletes its managed key and SSH files on the next activation. Rollbacks
        cannot restore deleted keys. Keep the module enabled to perform cleanup.

        Provisioning runs during Home Manager activation and may request
        Touch ID. Run activation from the user's macOS login session.
        Run `darwin-rebuild switch` again after a cancellation.
        Stubs and public keys are written
        under ~/.ssh/scauth/NAME/id_ecdsa_sk and id_ecdsa_sk.pub. Retrieve a key
        with `scauth pubkey NAME`. Public keys are runtime data, not Nix values.
        Use the stub as SSH IdentityFile. Requires macOS with CTK identity
        support and Apple's /usr/lib/ssh-keychain.dylib provider.
      '';
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = pkgs.stdenv.hostPlatform.system == "aarch64-darwin";
        message = "programs.scauth requires an Apple Silicon Mac";
      }
      {
        assertion = lib.all (name: builtins.match "[A-Za-z0-9_-]+" name != null) (
          builtins.attrNames cfg.identities
        );
        message = "programs.scauth identity names must match [A-Za-z0-9_-]+";
      }
    ];
    home.packages = [ cfg.package ];
    xdg.configFile."scauth/config.json".text = runtimeConfig;

    home.activation.scauth = lib.hm.dag.entryAfter [ "linkGeneration" ] ''
      run ${lib.getExe cfg.package} reconcile ${configFile}
    '';
  };
}
