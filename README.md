# scauth.nix

A Home Manager module for named macOS CryptoTokenKit SSH identities, based on
[this sc_auth example](https://gist.github.com/arianvp/5f59f1783e3eaf1a2d4cd8e952bb4acf).
It provisions non-exportable P-256 keys with biometric protection by default.
Requires running a recent macOS release with `sc_auth create-ctk-identity` support and Apple's
`/usr/lib/ssh-keychain.dylib` provider.

## Configure

Add this flake as an input:

```nix
inputs.scauth.url = "github:ETeissonniere/scauth.nix";
```

If you already use Home Manager inside `nix-darwin`, add this to your `nix-darwin`
configuration:

```nix
home-manager.sharedModules = [ inputs.scauth.homeManagerModules.default ];
```

Then configure identities in your **Home Manager user module**. It uses
`home.username` and `home.homeDirectory`. The supported setup is Home Manager
integrated with nix-darwin on Apple Silicon.

```nix
{ config, ... }:
{
  programs.scauth = {
    enable = true;

    identities = {
      work = {
        # `true` by default
        touchId = true;
      };
      personal = {
        # technically `touchId` is also `true` here
      };
      deploy = {
        touchId = false;
      };
    };
  };

  programs.ssh = {
    enable = true;
    enableDefaultConfig = false;
    settings."*" = {
      IdentityFile = config.programs.scauth.identities.personal.identityFile;
      IdentitiesOnly = true;
      SecurityKeyProvider = "/usr/lib/ssh-keychain.dylib";
    };
  };
}
```

Identity names are arbitrary: use letters, digits, underscores and hyphens.
Set `touchId = false` to request a key without Touch ID authentication.
The default is `true`, so `personal = {}` also requires Touch ID.

Each identity exposes read-only `name`, `identityFile` and `publicKeyFile`
values. The file paths are absolute paths under the configured user's home;
the files are created at runtime during provisioning.

`scauth` only provisions identities. You will need to configure SSH settings
in your own `programs.ssh.settings`, as above.

## Use

When running `darwin-rebuild switch`, you may see a Touch ID prompt from
macOS CryptoTokenKit. This is expected: `scauth` is creating your new identities
with keys protected by the Secure Enclave. Approve the prompt to finish provisioning.

```fish
# Copy this output to GitHub.
scauth pubkey personal

# Install the public key on a server.
ssh-copy-id -i ~/.ssh/scauth/personal/id_ecdsa_sk.pub user@server.example.com

ssh user@server.example.com
```

Each identity creates two files under `~/.ssh/scauth/NAME/`:

- `id_ecdsa_sk` tells SSH which key to use through macOS. It does not contain
  the private key itself; that remains protected by the Secure Enclave.
- `id_ecdsa_sk.pub` contains the public key you share with GitHub or servers
  to let them recognize you.

These files are created during provisioning, not while Nix evaluates your
configuration, because creating the keys may require your Touch ID approval.

For Git signing, add this to your Home Manager configuration:

```nix
home.sessionVariables.SSH_SK_PROVIDER = "/usr/lib/ssh-keychain.dylib";
```

## Provisioning and retries

On rebuild, `scauth` creates missing keys and prepares their SSH files. Existing
keys are reused. Removing a managed identity deletes its key and SSH files.
Changing its Touch ID setting reports an error rather than replacing the key.

> [!WARNING]
> Removing an identity permanently deletes its key on the next rebuild.
> A Nix rollback cannot restore it. Recreating the identity generates a new
> key that you must register with GitHub and your servers again.

scauth records the identities it creates or adopts in
`~/.ssh/scauth/managed.json` and only cleans up those identities. Keep the module
enabled when removing identities; disabling it also disables cleanup.

If you cancel the Touch ID prompt, run `darwin-rebuild switch` again to retry.
