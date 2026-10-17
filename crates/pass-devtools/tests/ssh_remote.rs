//! 2.0 rc2: clone, push and pull over SSH with a key handed over from
//! memory, plus the host-key and authentication refusals the apps show.
//!
//! No-op unless PASSPONY_SSH_URL is set: CI's ssh-bare leg runs an OpenSSH
//! server with an empty bare repo and sets
//!
//! - `PASSPONY_SSH_URL`: e.g. `ssh://gitci@127.0.0.1:2222/home/gitci/store.git`
//! - `PASSPONY_SSH_KEY`: path to the client's OpenSSH private key
//! - `PASSPONY_SSH_KEY_PASSPHRASE`: its passphrase, if it has one
//! - `PASSPONY_SSH_HOST_KEY`: path to the server's host public key (.pub)
//!
//! The key goes through `ssh::import_private_key` exactly as an app import
//! does, so a passphrase-protected key is decrypted in memory first.

use std::fs;
use std::path::PathBuf;

use pass_core::git::{messages, ConflictChoice, GitError, GitStore, SshConfig};
use pass_core::ssh::{self, HostKey};
use zeroize::Zeroizing;

struct Env {
    url: String,
    key: Zeroizing<String>,
    host_key: HostKey,
}

fn env() -> Option<Env> {
    let url = std::env::var("PASSPONY_SSH_URL").ok()?;
    let key_file = fs::read(std::env::var("PASSPONY_SSH_KEY").expect("PASSPONY_SSH_KEY")).unwrap();
    let passphrase = std::env::var("PASSPONY_SSH_KEY_PASSPHRASE").ok();
    let key = ssh::import_private_key(&key_file, passphrase.as_deref()).unwrap();
    let host_pub =
        fs::read_to_string(std::env::var("PASSPONY_SSH_HOST_KEY").expect("PASSPONY_SSH_HOST_KEY"))
            .unwrap();
    let b64 = host_pub.split_whitespace().nth(1).unwrap();
    let host_key = HostKey::from_blob(&decode(b64)).unwrap();
    Some(Env {
        url,
        key: key.private_openssh,
        host_key,
    })
}

fn decode(b64: &str) -> Vec<u8> {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0);
    for c in b64.trim_end_matches('=').bytes() {
        acc = (acc << 6) | A.iter().position(|&x| x == c).unwrap() as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    out
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("passpony-ssh-{name}"));
    let _ = fs::remove_dir_all(&dir);
    dir
}

fn no_conflict(path: &str) -> ConflictChoice {
    panic!("unexpected conflict on {path}")
}

#[test]
fn ssh_remote_end_to_end() {
    let Some(env) = env() else {
        eprintln!("PASSPONY_SSH_URL not set; skipping the SSH remote test");
        return;
    };
    let host = ssh::ssh_endpoint(&env.url).unwrap().known_hosts_name();

    // First contact: the host is unknown, and the error carries the key the
    // app shows and pins.
    let fresh = SshConfig {
        private_key: Some(env.key.clone()),
        known_hosts: String::new(),
    };
    let Err(err) = GitStore::clone_with_ssh(&env.url, scratch("first"), None, fresh) else {
        panic!("cloned without pinning the host");
    };
    let GitError::UnknownHostKey { host: seen, key } = err else {
        panic!("expected UnknownHostKey, got {err:?}");
    };
    assert_eq!(seen, host);
    assert_eq!(key, env.host_key);
    assert!(key.fingerprint.starts_with("SHA256:"));

    let pinned = SshConfig {
        private_key: Some(env.key.clone()),
        known_hosts: ssh::known_hosts_add("", &host, &key),
    };

    // Clone, commit, push.
    let phone_path = scratch("phone");
    let mut phone = GitStore::clone_with_ssh(&env.url, &phone_path, None, pinned.clone()).unwrap();
    let name = format!("ssh-{}", std::process::id());
    fs::write(phone_path.join(format!("{name}.age")), b"not really age").unwrap();
    phone
        .commit_paths(&[&format!("{name}.age")], &messages::add(&name))
        .unwrap();
    if phone.status().unwrap().has_remote && phone.sync(&mut no_conflict).is_err() {
        // An empty remote has no branch to pull yet; pushing creates it.
    }
    phone.set_ssh(pinned.clone());
    phone.push().unwrap();

    // A second clone sees it, and a later push from it syncs back.
    let laptop_path = scratch("laptop");
    let laptop = GitStore::clone_with_ssh(&env.url, &laptop_path, None, pinned.clone()).unwrap();
    assert!(laptop_path.join(format!("{name}.age")).exists());
    fs::write(laptop_path.join(format!("{name}-2.age")), b"second").unwrap();
    laptop
        .commit_paths(
            &[&format!("{name}-2.age")],
            &messages::add(&format!("{name}-2")),
        )
        .unwrap();
    laptop.push().unwrap();
    phone.sync(&mut no_conflict).unwrap();
    assert!(phone_path.join(format!("{name}-2.age")).exists());

    // A different key pinned for the same host: hard failure, nothing fetched.
    let impostor = ssh::generate_ed25519("").unwrap();
    let impostor_key = HostKey::from_blob(&decode(
        impostor.public_openssh.split_whitespace().nth(1).unwrap(),
    ))
    .unwrap();
    phone.set_ssh(SshConfig {
        private_key: Some(env.key.clone()),
        known_hosts: ssh::known_hosts_add("", &host, &impostor_key),
    });
    match phone.sync(&mut no_conflict).unwrap_err() {
        GitError::HostKeyChanged {
            host: h,
            fingerprint,
            pinned_fingerprint,
        } => {
            assert_eq!(h, host);
            assert_eq!(fingerprint, env.host_key.fingerprint);
            assert_eq!(pinned_fingerprint, impostor_key.fingerprint);
        }
        other => panic!("expected HostKeyChanged, got {other:?}"),
    }

    // No key at all, then a key the server doesn't know.
    phone.set_ssh(SshConfig {
        private_key: None,
        known_hosts: pinned.known_hosts.clone(),
    });
    assert!(matches!(phone.push(), Err(GitError::SshKeyMissing)));
    phone.set_ssh(SshConfig {
        private_key: Some(impostor.private_openssh.clone()),
        known_hosts: pinned.known_hosts.clone(),
    });
    let err = phone.sync(&mut no_conflict).unwrap_err();
    assert!(matches!(err, GitError::SshAuthFailed), "got {err:?}");
}
