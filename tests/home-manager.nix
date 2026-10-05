{
  self,
  nixpkgs,
  nix-darwin,
  home-manager,
  system,
}:
let
  pkgs = nixpkgs.legacyPackages.${system};
  evaluate =
    username: settings:
    (nix-darwin.lib.darwinSystem {
      modules = [
        home-manager.darwinModules.home-manager
        {
          nixpkgs.hostPlatform = system;
          system.stateVersion = 6;
          users.users.${username}.home = "/Users/${username}";
          home-manager = {
            useGlobalPkgs = true;
            useUserPackages = true;
            sharedModules = [ self.homeManagerModules.default ];
            users.${username} = {
              imports = [ settings ];
              home.stateVersion = "25.11";
            };
          };
        }
      ];
    }).config;
  settings = { config, ... }: {
    programs.scauth = {
      enable = true;
      identities = {
        work.touchId = false;
        personal = { };
      };
    };
    programs.ssh = {
      enable = true;
      enableDefaultConfig = false;
      settings."*" = {
        IdentityFile = config.programs.scauth.identities.work.identityFile;
        IdentitiesOnly = true;
        SecurityKeyProvider = config.programs.scauth.securityKeyProvider;
        AddKeysToAgent = "yes";
      };
      settings.github = {
        HostName = "github.com";
        User = "git";
        Port = 2222;
        ServerAliveInterval = 47;
      };
    };
    home.sessionVariables.SSH_SK_PROVIDER = config.programs.scauth.securityKeyProvider;
    programs.git = {
      enable = true;
      signing = {
        format = "ssh";
        key = config.programs.scauth.identities.personal.publicKeyFile;
      };
    };
  };
  systemConfig = evaluate "alice" settings;
  alice = systemConfig.home-manager.users.alice;
  bob = (evaluate "bob" settings).home-manager.users.bob;
  disabled = (evaluate "alice" { }).home-manager.users.alice;
  provisioningOnly = (evaluate "alice" { programs.scauth.enable = true; }).home-manager.users.alice;
  existingSsh =
    enabled:
    (evaluate "alice" {
      programs.scauth.enable = enabled;
      programs.ssh = {
        enable = true;
        enableDefaultConfig = false;
        settings."*".IdentityFile = "~/.ssh/id_ed25519";
      };
    }).home-manager.users.alice.home.file.".ssh/config".text;
  invalidName =
    (evaluate "alice" {
      programs.scauth.enable = true;
      programs.scauth.identities."../escape" = { };
    }).home-manager.users.alice;
  runtime = user: builtins.fromJSON user.xdg.configFile."scauth/config.json".text;
  activationUser =
    (evaluate "alice" {
      imports = [ settings ];
      programs.scauth.package = pkgs.writeShellScriptBin "scauth" ''
        set -eu
        test "$#" = 2
        test "$1" = reconcile
        if [[ -v SCAUTH_TEST_FAIL ]]; then exit 7; fi
        cp "$2" "$SCAUTH_TEST_CONFIG"
      '';
    }).home-manager.users.alice;
in
assert builtins.all (entry: entry.assertion) systemConfig.assertions;
assert builtins.all (entry: entry.assertion) alice.assertions;
assert (runtime alice).user == "alice";
assert (runtime bob).user == "bob";
assert (runtime alice).identities.work == { protection = "none"; };
assert (runtime alice).identities.personal == { protection = "bio"; };
assert !(alice.launchd.agents ? scauth);
assert !(disabled.xdg.configFile ? "scauth/config.json");
assert !(disabled.home.activation ? scauth);
assert !provisioningOnly.programs.ssh.enable;
assert !(provisioningOnly.home.sessionVariables ? SSH_SK_PROVIDER);
assert alice.home.sessionVariables.SSH_SK_PROVIDER == "/usr/lib/ssh-keychain.dylib";
assert !(provisioningOnly.home.file ? ".ssh/config");
assert existingSsh true == existingSsh false;
assert
  alice.programs.scauth.identities.work.identityFile == "/Users/alice/.ssh/scauth/work/id_ecdsa_sk";
assert
  bob.programs.scauth.identities.work.identityFile == "/Users/bob/.ssh/scauth/work/id_ecdsa_sk";
assert
  alice.programs.git.iniContent.user.signingKey
  == "/Users/alice/.ssh/scauth/personal/id_ecdsa_sk.pub";
assert builtins.any (entry: !entry.assertion) invalidName.assertions;
pkgs.runCommand "scauth-home-manager-check"
  {
    nativeBuildInputs = [ pkgs.openssh ];
    sshConfig = pkgs.writeText "ssh_config" alice.home.file.".ssh/config".text;
    expectedConfig =
      pkgs.writeText "expected-scauth.json"
        alice.xdg.configFile."scauth/config.json".text;
    activationScript = pkgs.writeShellScript "scauth-activation-test" ''
      source ${home-manager}/lib/bash/home-manager.sh
      ${activationUser.home.activation.scauth.data}
    '';
  }
  ''
    ssh -G -F "$sshConfig" github > effective
    grep -Fx 'hostname github.com' effective
    grep -Fx 'user git' effective
    grep -Fx 'port 2222' effective
    grep -Fx 'identityfile /Users/alice/.ssh/scauth/work/id_ecdsa_sk' effective
    grep -Fx 'identitiesonly yes' effective
    grep -Fx 'securitykeyprovider /usr/lib/ssh-keychain.dylib' effective
    grep -Fx 'serveraliveinterval 47' effective
    test "$(grep -c '^identityfile ' effective)" = 1
    ssh -G -F "$sshConfig" unrelated.invalid > unrelated
    grep -Fx 'identityfile /Users/alice/.ssh/scauth/work/id_ecdsa_sk' unrelated
    test "$(grep -c '^identityfile ' unrelated)" = 1
    export SCAUTH_TEST_CONFIG="$PWD/activation.json"
    DRY_RUN=1 "$activationScript"
    test ! -e "$SCAUTH_TEST_CONFIG"
    "$activationScript"
    cmp "$expectedConfig" "$SCAUTH_TEST_CONFIG"
    if SCAUTH_TEST_FAIL=1 "$activationScript"; then
      echo "Reconciliation failure was not propagated" >&2
      exit 1
    fi
    cp "$SCAUTH_TEST_CONFIG" "$out"
  ''
