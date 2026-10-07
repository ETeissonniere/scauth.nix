use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    env, fs,
    io::{self, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const PROVIDER: &str = "/usr/lib/ssh-keychain.dylib";
const KEY_TYPE: &str = "sk-ecdsa-sha2-nistp256@openssh.com";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    user: String,
    identities: BTreeMap<String, Identity>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    protection: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ManagedIdentity {
    hash: String,
    fingerprint: String,
}

type ManagedIdentities = BTreeMap<String, ManagedIdentity>;

fn valid_hash(hash: &str) -> bool {
    hash.len() == 40 && hash.bytes().all(|c| c.is_ascii_hexdigit())
}

fn save_managed(root: &Path, identities: &ManagedIdentities) -> Result<()> {
    let mut file = tempfile::NamedTempFile::new_in(root)?;
    serde_json::to_writer(&mut file, identities)?;
    file.as_file().sync_all()?;
    file.persist(root.join("managed.json"))?;
    Ok(())
}

#[derive(Debug)]
struct ListedIdentity {
    label: String,
    hash: String,
    key_type: String,
    protection: String,
    valid: bool,
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}

fn parse_identities(output: &str) -> Result<Vec<ListedIdentity>> {
    let mut lines = output.lines().filter(|line| !line.trim().is_empty());
    let header = lines.next().ok_or("sc_auth returned no identity table")?;
    if !header.starts_with("Key Type Public Key Hash") {
        return Err(format!("unexpected sc_auth output: {output}").into());
    }
    let label_start = header.find("Label ").ok_or("missing Label column")?;
    let label_end = header
        .find("Common Name")
        .ok_or("missing Common Name column")?;
    lines
        .map(|line| {
            let columns: Vec<_> = line.split_whitespace().collect();
            let label = line
                .get(label_start..label_end)
                .ok_or("malformed identity label column")?
                .trim();
            if columns.len() < 5 || label.is_empty() {
                return Err(format!("malformed identity row: {line}").into());
            }
            Ok(ListedIdentity {
                label: label.to_owned(),
                key_type: columns[0].to_owned(),
                hash: columns[1].to_owned(),
                protection: columns[2].to_owned(),
                valid: columns.last() == Some(&"YES"),
            })
        })
        .collect()
}

fn select_identity<'a>(
    rows: &'a [ListedIdentity],
    label: &str,
    desired: &Identity,
) -> Result<Option<&'a ListedIdentity>> {
    let matches: Vec<_> = rows.iter().filter(|row| row.label == label).collect();
    match matches.as_slice() {
        [] => Ok(None),
        [row] => {
            if row.key_type != "p-256-ne" || row.protection != desired.protection {
                return Err(format!(
                    "{label}: existing key type or protection differs; refusing to replace identity"
                )
                .into());
            }
            if !row.valid {
                return Err(format!(
                    "{label}: CTK certificate is not valid; renew it explicitly before exporting"
                )
                .into());
            }
            Ok(Some(row))
        }
        _ => Err(format!("{label}: multiple CTK identities share this label").into()),
    }
}

fn run(command: &mut Command) -> Result<String> {
    let output = command.output()?;
    if !output.status.success() {
        return Err(format!(
            "{command:?} failed ({}): {}{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    // Apple's CTK tool can report errors while returning exit status zero.
    if String::from_utf8_lossy(&output.stderr).contains("Error:") {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned().into());
    }
    Ok(String::from_utf8(output.stdout)?)
}

trait Keychain {
    fn list(&self, ssh: bool) -> Result<Vec<ListedIdentity>>;
    fn create(&self, label: &str, identity: &Identity) -> Result<()>;
    fn delete(&self, hash: &str) -> Result<()>;
    fn export(&self, hash: &str, directory: &Path) -> Result<()>;
    fn public_key(&self, stub: &Path) -> Result<String>;
}

struct MacKeychain;

impl Keychain for MacKeychain {
    fn list(&self, ssh: bool) -> Result<Vec<ListedIdentity>> {
        let output = run(Command::new("/usr/sbin/sc_auth").args([
            "list-ctk-identities",
            "-t",
            if ssh { "ssh" } else { "sha1" },
        ]))?;
        parse_identities(&output)
    }

    fn create(&self, label: &str, identity: &Identity) -> Result<()> {
        run(Command::new("/usr/sbin/sc_auth").args([
            "create-ctk-identity",
            "-l",
            label,
            "-k",
            "p-256-ne",
            "-t",
            &identity.protection,
        ]))?;
        Ok(())
    }

    fn export(&self, hash: &str, directory: &Path) -> Result<()> {
        // Filtering also avoids Apple's resident-key filename collision.
        run(Command::new("/usr/bin/ssh-keygen")
            .args(["-w", PROVIDER, "-K", "-N", ""])
            .env("KEYCHAIN_CERTIFICATES", hash)
            // OpenSSH asks for a PIN even though CTK uses its own biometric UI.
            // A failed askpass yields an empty PIN without opening a terminal.
            .env("SSH_ASKPASS", "/usr/bin/false")
            .env("SSH_ASKPASS_REQUIRE", "force")
            .stdin(Stdio::null())
            .current_dir(directory))?;
        Ok(())
    }

    fn delete(&self, hash: &str) -> Result<()> {
        run(Command::new("/usr/sbin/sc_auth").args(["delete-ctk-identity", "-h", hash]))?;
        Ok(())
    }

    fn public_key(&self, stub: &Path) -> Result<String> {
        run(Command::new("/usr/bin/ssh-keygen")
            .args(["-y", "-P", "", "-f"])
            .arg(stub))
    }
}

fn fingerprint(public_key: &str) -> Result<String> {
    let fields: Vec<_> = public_key.split_whitespace().collect();
    if fields.len() < 2 || fields[0] != KEY_TYPE {
        return Err("expected an OpenSSH P-256 security-key public key".into());
    }
    let blob = STANDARD_NO_PAD.decode(fields[1].trim_end_matches('='))?;
    Ok(format!(
        "SHA256:{}",
        STANDARD_NO_PAD.encode(Sha256::digest(blob))
    ))
}

fn check_fingerprint(public_key: &str, expected: &str) -> Result<()> {
    if fingerprint(public_key)? != expected {
        return Err("SSH public key does not match the managed CTK identity".into());
    }
    Ok(())
}

fn write_public_key(directory: &Path, public_key: &str, label: &str) -> Result<()> {
    let fields: Vec<_> = public_key.split_whitespace().take(2).collect();
    let mut file = tempfile::NamedTempFile::new_in(directory)?;
    writeln!(file, "{} {} {label}", fields[0], fields[1])?;
    file.persist(directory.join("id_ecdsa_sk.pub"))?;
    Ok(())
}

fn cleanup(
    keychain: &impl Keychain,
    config: &Config,
    root: &Path,
    managed: &mut ManagedIdentities,
) -> Result<()> {
    let removed: Vec<_> = managed
        .keys()
        .filter(|label| !config.identities.contains_key(*label))
        .cloned()
        .collect();
    for label in removed {
        let identity = &managed[&label];
        let directory = root.join(&label);
        match fs::symlink_metadata(&directory) {
            Ok(metadata) if !metadata.is_dir() => {
                return Err(format!("{label}: expected a managed directory").into());
            }
            Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error.into()),
            _ => {}
        }
        // Refuse cleanup if someone has replaced the managed SSH files.
        for name in ["id_ecdsa_sk", "id_ecdsa_sk.pub"] {
            let path = directory.join(name);
            match fs::symlink_metadata(&path) {
                Ok(metadata) => {
                    if !metadata.is_file() {
                        return Err(
                            format!("{} is not a regular managed file", path.display()).into()
                        );
                    }
                    let public_key = if name.ends_with(".pub") {
                        fs::read_to_string(&path)?
                    } else {
                        keychain.public_key(&path)?
                    };
                    check_fingerprint(&public_key, &identity.fingerprint)?;
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        if keychain
            .list(false)?
            .iter()
            .any(|row| row.hash == identity.hash)
        {
            eprintln!("Deleting managed CTK identity {label}");
            keychain.delete(&identity.hash)?;
            if keychain
                .list(false)?
                .iter()
                .any(|row| row.hash == identity.hash)
            {
                return Err(
                    format!("{label}: CTK identity is still present after deletion").into(),
                );
            }
        }
        for name in ["id_ecdsa_sk", "id_ecdsa_sk.pub"] {
            match fs::remove_file(directory.join(name)) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        match fs::remove_dir(directory) {
            Ok(()) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::DirectoryNotEmpty
                ) => {}
            Err(error) => return Err(error.into()),
        }
        managed.remove(&label);
        save_managed(root, managed)?;
    }
    Ok(())
}

fn export_identity(
    keychain: &impl Keychain,
    root: &Path,
    label: &str,
    hash: &str,
    fingerprint: &str,
) -> Result<()> {
    let directory = root.join(label);
    if directory.exists() {
        let public_key = keychain.public_key(&directory.join("id_ecdsa_sk"))?;
        check_fingerprint(&public_key, fingerprint)?;
        write_public_key(&directory, &public_key, label)?;
        return Ok(());
    }

    // Publish the pair together, and never leave a half-written identity.
    let staging = tempfile::tempdir_in(root)?;
    keychain.export(hash, staging.path())?;
    let stubs: Vec<_> = fs::read_dir(staging.path())?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<io::Result<Vec<_>>>()?
        .into_iter()
        .filter(|path| path.extension().is_none())
        .collect();
    if stubs.len() != 1 {
        return Err("expected exactly one exported SSH stub".into());
    }
    let public_key = keychain.public_key(&stubs[0])?;
    check_fingerprint(&public_key, fingerprint)?;
    let stub = staging.path().join("id_ecdsa_sk");
    fs::rename(&stubs[0], &stub)?;
    for entry in fs::read_dir(staging.path())? {
        let path = entry?.path();
        if path != stub {
            fs::remove_file(path)?;
        }
    }
    write_public_key(staging.path(), &public_key, label)?;
    fs::rename(staging.path(), directory)?;
    Ok(())
}

fn reconcile(keychain: &impl Keychain, config: &Config, root: &Path) -> Result<()> {
    for (label, identity) in &config.identities {
        if !valid_name(label) || !matches!(identity.protection.as_str(), "bio" | "none") {
            return Err(format!("invalid identity configuration: {label}").into());
        }
    }
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(root)?;
    let lock = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(root.join(".lock"))?;
    match lock.try_lock() {
        Ok(()) => {}
        Err(fs::TryLockError::WouldBlock) => {
            return Err("another scauth reconciliation is running".into());
        }
        Err(fs::TryLockError::Error(error)) => return Err(error.into()),
    }
    let mut managed: ManagedIdentities = match fs::read(root.join("managed.json")) {
        Ok(bytes) => serde_json::from_slice(&bytes)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => BTreeMap::new(),
        Err(error) => return Err(error.into()),
    };
    if managed.iter().any(|(label, identity)| {
        !valid_name(label)
            || !valid_hash(&identity.hash)
            || !identity.fingerprint.starts_with("SHA256:")
    }) {
        return Err("invalid managed identity state".into());
    }

    for (label, desired) in &config.identities {
        let mut rows = keychain.list(false)?;
        if select_identity(&rows, label, desired)?.is_none() {
            if managed.contains_key(label) {
                return Err(format!("{label}: managed key is missing; remove its declaration and reconcile before recreating it").into());
            }
            eprintln!("Creating CTK identity {label}; macOS may request Touch ID");
            keychain.create(label, desired)?;
            rows = keychain.list(false)?;
        }
        let identity =
            select_identity(&rows, label, desired)?.ok_or("created identity not found")?;
        if !valid_hash(&identity.hash) {
            return Err("invalid CTK SHA-1 hash".into());
        }
        let ssh_rows = keychain.list(true)?;
        let ssh_identity =
            select_identity(&ssh_rows, label, desired)?.ok_or("SSH identity not found")?;
        if let Some(previous) = managed.get(label) {
            if previous.hash != identity.hash || previous.fingerprint != ssh_identity.hash {
                return Err(format!(
                    "{label}: managed key has changed; refusing to adopt a replacement"
                )
                .into());
            }
        } else {
            // Record ownership before exporting, so a cancelled export can be cleaned up.
            managed.insert(
                label.clone(),
                ManagedIdentity {
                    hash: identity.hash.clone(),
                    fingerprint: ssh_identity.hash.clone(),
                },
            );
            save_managed(root, &managed)?;
        }
        export_identity(keychain, root, label, &identity.hash, &ssh_identity.hash)?;
    }
    cleanup(keychain, config, root, &mut managed)
}

fn main() {
    if let Err(error) = cli() {
        eprintln!("scauth: {error}");
        std::process::exit(1);
    }
}

fn public_keys(root: &Path) -> Result<String> {
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(String::new()),
        Err(error) => return Err(error.into()),
    };
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry?;
        if entry.file_type()?.is_dir() && entry.file_name().to_str().is_some_and(valid_name) {
            paths.push(entry.path().join("id_ecdsa_sk.pub"));
        }
    }
    paths.sort();
    let mut output = String::new();
    for path in paths {
        let key = match fs::read_to_string(&path) {
            Ok(key) => key,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(format!("{}: {error}", path.display()).into()),
        };
        output.push_str(&key);
        if !output.ends_with('\n') {
            output.push('\n');
        }
    }
    Ok(output)
}

fn cli() -> Result<()> {
    let args: Vec<_> = env::args().skip(1).collect();
    if args == ["--help"] || args == ["-h"] {
        println!(
            "Usage: scauth reconcile [CONFIG.json]\n       scauth pubkey [NAME]\n\nOmit NAME to show all exported public keys.\nConfig: $XDG_CONFIG_HOME/scauth/config.json (default ~/.config/scauth/config.json)\nFiles: ~/.ssh/scauth/NAME/id_ecdsa_sk[.pub]\nRun as the configured user in their macOS login session."
        );
        return Ok(());
    }
    let home = PathBuf::from(env::var("HOME")?);
    let root = home.join(".ssh/scauth");
    match args.as_slice() {
        [command] if command == "pubkey" => {
            let keys = public_keys(&root)?;
            if keys.is_empty() {
                eprintln!(
                    "No public keys found. Run `scauth reconcile` to provision your configured identities."
                );
            } else {
                print!("{keys}");
            }
        }
        [command, name] if command == "pubkey" && valid_name(name) => {
            print!(
                "{}",
                fs::read_to_string(root.join(name).join("id_ecdsa_sk.pub"))?
            );
        }
        [command, rest @ ..] if command == "reconcile" && rest.len() <= 1 => {
            let path = match rest.first() {
                Some(path) => PathBuf::from(path),
                None => env::var_os("XDG_CONFIG_HOME")
                    .filter(|value| !value.is_empty())
                    .map(PathBuf::from)
                    .unwrap_or_else(|| home.join(".config"))
                    .join("scauth/config.json"),
            };
            let config: Config = serde_json::from_slice(&fs::read(path)?)?;
            let user = run(Command::new("/usr/bin/id").arg("-un"))?;
            if user.trim() == "root" || user.trim() != config.user {
                return Err("run reconciliation as the configured user, without sudo".into());
            }
            reconcile(&MacKeychain, &config, &root)?;
        }
        _ => return Err("usage: scauth reconcile [CONFIG.json] | scauth pubkey [NAME]".into()),
    }
    Ok(())
}

#[cfg(test)]
mod tests;
