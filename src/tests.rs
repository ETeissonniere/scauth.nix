use super::*;
use std::cell::{Cell, RefCell};

const PUBLIC_KEY: &str = "sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAAAIbmlzdHAyNTYAAABBBKiHAiAZhcsZ95n85dkNGs9GnbDt0aNOia2gnuknYV2wKL3y0u+d3QrE9cFkmWXIymHZMglL+uJA+6mShY8SeykAAAAEc3NoOg== ssh:";
const HASH: &str = "A71277F0BC5825A7B3576D014F31282A866EF3BC";

fn config(names: &[&str]) -> Config {
    Config {
        user: "test".into(),
        identities: names
            .iter()
            .map(|name| {
                (
                    name.to_string(),
                    Identity {
                        protection: "bio".into(),
                    },
                )
            })
            .collect(),
    }
}

#[derive(Default)]
struct FakeKeychain {
    labels: RefCell<Vec<String>>,
    hash_overrides: RefCell<BTreeMap<String, String>>,
    deletes: RefCell<Vec<String>>,
    creates: Cell<usize>,
    exports: Cell<usize>,
    fail_export: Cell<bool>,
    fail_delete: Cell<bool>,
    ignore_delete: Cell<bool>,
}

impl FakeKeychain {
    fn hash(&self, label: &str) -> String {
        self.hash_overrides
            .borrow()
            .get(label)
            .cloned()
            .unwrap_or_else(|| format!("{:x}", Sha256::digest(label.as_bytes()))[..40].to_owned())
    }
}

impl Keychain for FakeKeychain {
    fn list(&self, ssh: bool) -> Result<Vec<ListedIdentity>> {
        Ok(self
            .labels
            .borrow()
            .iter()
            .map(|label| ListedIdentity {
                label: label.clone(),
                hash: if ssh {
                    fingerprint(PUBLIC_KEY).unwrap()
                } else {
                    self.hash(label)
                },
                key_type: "p-256-ne".into(),
                protection: "bio".into(),
                valid: true,
            })
            .collect())
    }

    fn create(&self, label: &str, _: &Identity) -> Result<()> {
        self.creates.set(self.creates.get() + 1);
        self.labels.borrow_mut().push(label.into());
        Ok(())
    }

    fn export(&self, hash: &str, directory: &Path) -> Result<()> {
        assert!(
            self.labels
                .borrow()
                .iter()
                .any(|label| self.hash(label) == hash)
        );
        self.exports.set(self.exports.get() + 1);
        fs::write(directory.join("id_ecdsa_sk_rk"), PUBLIC_KEY)?;
        fs::write(directory.join("id_ecdsa_sk_rk.pub"), PUBLIC_KEY)?;
        if self.fail_export.get() {
            return Err("cancelled".into());
        }
        Ok(())
    }

    fn public_key(&self, stub: &Path) -> Result<String> {
        Ok(fs::read_to_string(stub)?)
    }

    fn delete(&self, hash: &str) -> Result<()> {
        if self.fail_delete.get() {
            return Err("deletion failed".into());
        }
        if !self.ignore_delete.get() {
            self.labels
                .borrow_mut()
                .retain(|label| self.hash(label) != hash);
            self.deletes.borrow_mut().push(hash.into());
        }
        Ok(())
    }
}

#[test]
fn concurrent_reconciliation_is_rejected_until_the_lock_is_released() {
    let root = tempfile::tempdir().unwrap();
    let backend = FakeKeychain::default();
    let lock = fs::File::create(root.path().join(".lock")).unwrap();
    lock.lock().unwrap();

    let error = reconcile(&backend, &config(&["work"]), root.path()).unwrap_err();
    assert_eq!(
        error.to_string(),
        "another scauth reconciliation is running"
    );
    assert_eq!(backend.creates.get(), 0);
    assert!(!root.path().join("managed.json").exists());

    drop(lock);
    reconcile(&backend, &config(&["work"]), root.path()).unwrap();
    assert_eq!(backend.creates.get(), 1);
}

#[test]
fn parses_fixed_width_labels_without_adopting_prefix_matches() {
    let output = format!(
        "{:<9}{:<41}{:<5}{:<20}Common Name Email Address Valid To Valid\n{:<9}{:<41}{:<5}{:<20}a common name 11/24/26, 3:26 PM YES\n",
        "Key Type", "Public Key Hash", "Prot", "Label", "p-256-ne", HASH, "bio", "work laptop"
    );
    let rows = parse_identities(&output).unwrap();
    assert_eq!(rows[0].label, "work laptop");
    assert!(
        select_identity(
            &rows,
            "work",
            &Identity {
                protection: "bio".into()
            }
        )
        .unwrap()
        .is_none()
    );
    assert_eq!(rows[0].hash, HASH);
    assert!(
        parse_identities(
            "Key Type Public Key Hash Prot Label Common Name Email Address Valid To Valid \n"
        )
        .unwrap()
        .is_empty()
    );
    for malformed in [
        "",
        "Error: Failed to get TKTokenDriver configuration",
        "unknown format",
    ] {
        assert!(parse_identities(malformed).is_err());
    }
}

#[test]
fn rejects_duplicate_labels_policy_changes_and_expired_certificates() {
    let backend = FakeKeychain::default();
    backend.labels.borrow_mut().push("work".into());
    let desired = Identity {
        protection: "bio".into(),
    };
    let mut rows = backend.list(false).unwrap();
    rows[0].key_type = "p-256".into();
    assert!(select_identity(&rows, "work", &desired).is_err());
    rows[0].key_type = "p-256-ne".into();
    rows[0].protection = "none".into();
    assert!(select_identity(&rows, "work", &desired).is_err());
    rows[0].protection = "bio".into();
    rows[0].valid = false;
    assert!(select_identity(&rows, "work", &desired).is_err());
    backend.labels.borrow_mut().push("work".into());
    assert!(select_identity(&backend.list(false).unwrap(), "work", &desired).is_err());
}

#[test]
fn reconciles_multiple_identities_once_and_restores_missing_public_key() {
    let directory = tempfile::tempdir().unwrap();
    let backend = FakeKeychain::default();
    let desired = config(&["work", "personal"]);
    reconcile(&backend, &desired, directory.path()).unwrap();
    let public_path = directory.path().join("work/id_ecdsa_sk.pub");
    let original = fs::read_to_string(&public_path).unwrap();
    assert!(original.ends_with(" work\n"));
    fs::remove_file(&public_path).unwrap();
    reconcile(&backend, &desired, directory.path()).unwrap();
    assert_eq!(fs::read_to_string(public_path).unwrap(), original);
    assert_eq!(backend.creates.get(), 2);
    assert_eq!(backend.exports.get(), 2);
    assert_eq!(backend.labels.borrow().len(), 2);
}

#[test]
fn removes_only_retired_managed_keys_and_generated_files() {
    let directory = tempfile::tempdir().unwrap();
    let backend = FakeKeychain::default();
    backend.labels.borrow_mut().push("unmanaged".into());
    reconcile(&backend, &config(&["work", "personal"]), directory.path()).unwrap();
    fs::write(directory.path().join("work/notes"), "keep me").unwrap();
    reconcile(&backend, &config(&["personal"]), directory.path()).unwrap();
    assert_eq!(*backend.deletes.borrow(), vec![backend.hash("work")]);
    assert_eq!(*backend.labels.borrow(), vec!["unmanaged", "personal"]);
    assert!(!directory.path().join("work/id_ecdsa_sk").exists());
    assert!(!directory.path().join("work/id_ecdsa_sk.pub").exists());
    assert!(directory.path().join("work/notes").exists());
    assert!(directory.path().join("personal/id_ecdsa_sk").exists());
    reconcile(&backend, &config(&[]), directory.path()).unwrap();
    assert!(!directory.path().join("personal").exists());
    assert_eq!(*backend.labels.borrow(), vec!["unmanaged"]);
    let state: ManagedIdentities =
        serde_json::from_slice(&fs::read(directory.path().join("managed.json")).unwrap()).unwrap();
    assert!(state.is_empty());
}

#[test]
fn missing_state_does_not_infer_ownership_from_labels_or_files() {
    let directory = tempfile::tempdir().unwrap();
    let backend = FakeKeychain::default();
    backend.labels.borrow_mut().push("work".into());
    fs::create_dir(directory.path().join("work")).unwrap();
    fs::write(directory.path().join("work/id_ecdsa_sk"), PUBLIC_KEY).unwrap();
    reconcile(&backend, &config(&[]), directory.path()).unwrap();
    assert!(backend.deletes.borrow().is_empty());
    assert!(directory.path().join("work/id_ecdsa_sk").exists());
}

#[test]
fn adopted_identity_is_tracked_for_cleanup() {
    let directory = tempfile::tempdir().unwrap();
    let backend = FakeKeychain::default();
    backend.labels.borrow_mut().push("work".into());
    reconcile(&backend, &config(&["work"]), directory.path()).unwrap();
    assert_eq!(backend.creates.get(), 0);
    reconcile(&backend, &config(&[]), directory.path()).unwrap();
    assert_eq!(*backend.deletes.borrow(), vec![backend.hash("work")]);
}

#[test]
fn cancelled_export_can_be_cleaned_up() {
    let directory = tempfile::tempdir().unwrap();
    let backend = FakeKeychain::default();
    backend.fail_export.set(true);
    assert!(reconcile(&backend, &config(&["work"]), directory.path()).is_err());
    reconcile(&backend, &config(&[]), directory.path()).unwrap();
    assert_eq!(*backend.deletes.borrow(), vec![backend.hash("work")]);
}

#[test]
fn failed_or_ineffective_delete_preserves_state_and_files_for_retry() {
    for silent_failure in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let backend = FakeKeychain::default();
        reconcile(&backend, &config(&["work"]), directory.path()).unwrap();
        let before = fs::read(directory.path().join("managed.json")).unwrap();
        backend.fail_delete.set(!silent_failure);
        backend.ignore_delete.set(silent_failure);
        assert!(reconcile(&backend, &config(&[]), directory.path()).is_err());
        assert_eq!(
            fs::read(directory.path().join("managed.json")).unwrap(),
            before
        );
        assert!(directory.path().join("work/id_ecdsa_sk").exists());
        backend.fail_delete.set(false);
        backend.ignore_delete.set(false);
        reconcile(&backend, &config(&[]), directory.path()).unwrap();
        assert!(!directory.path().join("work").exists());
    }
}

#[test]
fn replacement_key_with_same_label_is_not_deleted() {
    let directory = tempfile::tempdir().unwrap();
    let backend = FakeKeychain::default();
    reconcile(&backend, &config(&["work"]), directory.path()).unwrap();
    backend
        .hash_overrides
        .borrow_mut()
        .insert("work".into(), "F".repeat(40));
    assert!(reconcile(&backend, &config(&["work"]), directory.path()).is_err());
    reconcile(&backend, &config(&[]), directory.path()).unwrap();
    assert_eq!(*backend.labels.borrow(), vec!["work"]);
    assert!(backend.deletes.borrow().is_empty());
}

#[test]
fn replaced_files_prevent_key_deletion() {
    let directory = tempfile::tempdir().unwrap();
    let backend = FakeKeychain::default();
    reconcile(&backend, &config(&["work"]), directory.path()).unwrap();
    fs::write(
        directory.path().join("work/id_ecdsa_sk.pub"),
        format!("{KEY_TYPE} YWJj"),
    )
    .unwrap();
    assert!(reconcile(&backend, &config(&[]), directory.path()).is_err());
    assert!(backend.deletes.borrow().is_empty());
}

#[test]
fn malformed_state_stops_reconciliation_before_key_changes() {
    for state in [
        "not json".to_owned(),
        format!(r#"{{"../escape":{{"hash":"{HASH}","fingerprint":"SHA256:test"}}}}"#),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let backend = FakeKeychain::default();
        fs::write(directory.path().join("managed.json"), state).unwrap();
        assert!(reconcile(&backend, &config(&["work"]), directory.path()).is_err());
        assert_eq!(backend.creates.get(), 0);
        assert!(backend.deletes.borrow().is_empty());
    }
}

#[test]
fn failed_export_can_retry_without_creating_another_identity() {
    let directory = tempfile::tempdir().unwrap();
    let backend = FakeKeychain::default();
    backend.fail_export.set(true);
    assert!(reconcile(&backend, &config(&["work"]), directory.path()).is_err());
    assert!(!directory.path().join("work").exists());
    backend.fail_export.set(false);
    reconcile(&backend, &config(&["work"]), directory.path()).unwrap();
    assert_eq!(backend.creates.get(), 1);
}

#[test]
fn mismatched_existing_stub_is_preserved() {
    let directory = tempfile::tempdir().unwrap();
    let backend = FakeKeychain::default();
    reconcile(&backend, &config(&["work"]), directory.path()).unwrap();
    let path = directory.path().join("work/id_ecdsa_sk");
    let different = format!("{KEY_TYPE} YWJj");
    fs::write(&path, &different).unwrap();
    assert!(reconcile(&backend, &config(&["work"]), directory.path()).is_err());
    assert_eq!(fs::read_to_string(path).unwrap(), different);
    assert_eq!(backend.exports.get(), 1);
}

#[test]
fn invalid_names_fail_before_creating_keys_or_directories() {
    for name in ["", "../escape", "a/b", "a b", "x\n"] {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("state");
        let backend = FakeKeychain::default();
        assert!(reconcile(&backend, &config(&[name]), &root).is_err());
        assert!(!root.exists());
        assert_eq!(backend.creates.get(), 0);
    }
}

#[test]
fn fingerprint_matches_published_openssh_example() {
    assert_eq!(
        fingerprint(PUBLIC_KEY).unwrap(),
        "SHA256:vs4ByYo+T9M3V8iiDYONMSvx2k5Fj2ujVBWt1j6yzis"
    );
}
