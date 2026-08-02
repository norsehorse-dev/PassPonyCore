//! The P1 gate: everything pass-core writes must be readable by the real
//! CLIs, byte-for-byte; re-encrypt honors recipient-file changes; moves
//! follow each format's re-encryption semantics.
//!
//! Requires: age, gpg, pass; the passage script (PASSAGE_SCRIPT env, the
//! fixtures/.tools clone, or `passage` on PATH).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use pass_core::entry::Entry;
use pass_core::store::{Store, StoreFormat};
use pass_devtools::{AgeCliBackend, GpgCliBackend};

fn fixtures_root() -> PathBuf {
    match std::env::var_os("PASSPONY_FIXTURES") {
        Some(p) => PathBuf::from(p),
        None => Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures"),
    }
}

/// Locate a way to run the passage CLI.
fn passage_invocation() -> (String, Vec<String>) {
    if let Some(script) = std::env::var_os("PASSAGE_SCRIPT") {
        return ("bash".into(), vec![script.to_string_lossy().into_owned()]);
    }
    let tools = fixtures_root().join(".tools/passage-src/src/password-store.sh");
    if tools.is_file() {
        return ("bash".into(), vec![tools.to_string_lossy().into_owned()]);
    }
    ("passage".into(), vec![]) // hope it's on PATH; error out loudly if not
}

fn passage_show(store: &Path, identities: &Path, entry: &str) -> Vec<u8> {
    let (prog, base_args) = passage_invocation();
    let out = Command::new(&prog)
        .args(&base_args)
        .arg("show")
        .arg(entry)
        .env("PASSAGE_DIR", store)
        .env("PASSAGE_IDENTITIES_FILE", identities)
        .output()
        .expect("passage CLI not runnable (set PASSAGE_SCRIPT or run gen-fixtures.sh)");
    assert!(
        out.status.success(),
        "passage show {entry} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

fn pass_show(store: &Path, gnupghome: &Path, entry: &str) -> Vec<u8> {
    let out = Command::new("pass")
        .arg("show")
        .arg(entry)
        .env("PASSWORD_STORE_DIR", store)
        .env("GNUPGHOME", gnupghome)
        .output()
        .expect("pass CLI not runnable");
    assert!(
        out.status.success(),
        "pass show {entry} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

fn test_gnupghome() -> PathBuf {
    let home = std::env::temp_dir().join("passpony-roundtrip-gnupghome");
    let marker = home.join(".imported");
    if !marker.exists() {
        fs::create_dir_all(&home).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let keys = fixtures_root().join("keys");
        let status = Command::new("gpg")
            .env("GNUPGHOME", &home)
            .args(["--quiet", "--batch", "--import"])
            .arg(keys.join("gpg-key-a.sec.asc"))
            .arg(keys.join("gpg-key-b.sec.asc"))
            .status()
            .expect("gpg not runnable");
        assert!(status.success());
        // pass runs plain `gpg -d`; mark the fixture keys ultimately trusted
        // so decryption/encryption is prompt-free.
        for k in ["gpg-key-a.fpr", "gpg-key-b.fpr"] {
            let fpr = fs::read_to_string(keys.join(k)).unwrap().trim().to_owned();
            let mut child = Command::new("gpg")
                .env("GNUPGHOME", &home)
                .args(["--import-ownertrust"])
                .stdin(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            use std::io::Write;
            child
                .stdin
                .take()
                .unwrap()
                .write_all(format!("{fpr}:6:\n").as_bytes())
                .unwrap();
            assert!(child.wait().unwrap().success());
        }
        fs::write(&marker, b"").unwrap();
    }
    home
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("passpony-p1-{name}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

const TRICKY_CONTENTS: &[(&str, &[u8])] = &[
    ("simple", b"pw-simple\n"),
    ("fields", b"pw\nusername: kevin\nurl: example.com\n"),
    (
        "gnarly/deep/no-newline",
        b"pw\nline two\n\ntrailing spaces  \nno trailing newline",
    ),
    ("unicode/caf\u{e9}", "pw\nnote: naïve ✓\n".as_bytes()),
    (
        "otp",
        b"pw\notpauth://totp/X?secret=JBSWY3DPEHPK3PXP&digits=8\n",
    ),
];

#[test]
fn passage_reads_what_we_write_recipients_file() {
    let dir = scratch("passage-recipients");
    let store_dir = dir.join("store");
    fs::create_dir_all(&store_dir).unwrap();
    let identities = dir.join("identities");
    fs::copy(fixtures_root().join("keys/age-key-a.txt"), &identities).unwrap();
    let pub_a = fs::read_to_string(fixtures_root().join("keys/age-key-a.pub")).unwrap();
    fs::write(
        store_dir.join(".age-recipients"),
        format!("# test\n\n{pub_a}"),
    )
    .unwrap();

    let store = Store::open(&store_dir, StoreFormat::Passage).unwrap();
    let backend = AgeCliBackend {
        identities_file: identities.clone(),
        recipients_file: None,
    };
    for (name, content) in TRICKY_CONTENTS {
        store
            .write_entry(name, &Entry::from_bytes(content.to_vec()), &backend)
            .unwrap();
        let cli = passage_show(&store_dir, &identities, name);
        assert_eq!(&cli, content, "CLI read-back mismatch for {name}");
    }
}

#[test]
fn passage_reads_what_we_write_identities_fallback() {
    let dir = scratch("passage-fallback");
    let store_dir = dir.join("store");
    fs::create_dir_all(&store_dir).unwrap();
    let identities = dir.join("identities");
    fs::copy(fixtures_root().join("keys/age-key-a.txt"), &identities).unwrap();

    let store = Store::open(&store_dir, StoreFormat::Passage).unwrap();
    let backend = AgeCliBackend {
        identities_file: identities.clone(),
        recipients_file: None,
    };
    let content: &[u8] = b"fallback-pw\nusername: kevin\n";
    store
        .write_entry("solo", &Entry::from_bytes(content.to_vec()), &backend)
        .unwrap();
    assert_eq!(passage_show(&store_dir, &identities, "solo"), content);
}

#[test]
fn pass_reads_what_we_write() {
    let home = test_gnupghome();
    let dir = scratch("pass-write");
    let store_dir = dir.join("store");
    fs::create_dir_all(&store_dir).unwrap();
    let fpr_a = fs::read_to_string(fixtures_root().join("keys/gpg-key-a.fpr")).unwrap();
    fs::write(store_dir.join(".gpg-id"), format!("{}\n", fpr_a.trim())).unwrap();

    let store = Store::open(&store_dir, StoreFormat::Pass).unwrap();
    let backend = GpgCliBackend {
        gnupghome: Some(home.clone()),
    };
    for (name, content) in TRICKY_CONTENTS {
        store
            .write_entry(name, &Entry::from_bytes(content.to_vec()), &backend)
            .unwrap();
        let cli = pass_show(&store_dir, &home, name);
        assert_eq!(&cli, content, "CLI read-back mismatch for {name}");
    }
}

#[test]
fn reencrypt_subtree_follows_recipient_change() {
    let dir = scratch("passage-reencrypt");
    let store_dir = dir.join("store");
    fs::create_dir_all(store_dir.join("work")).unwrap();
    let identities_ab = dir.join("identities-ab");
    let a = fs::read_to_string(fixtures_root().join("keys/age-key-a.txt")).unwrap();
    let b = fs::read_to_string(fixtures_root().join("keys/age-key-b.txt")).unwrap();
    fs::write(&identities_ab, format!("{a}{b}")).unwrap();
    let identities_b = dir.join("identities-b");
    fs::write(&identities_b, &b).unwrap();
    let pub_a = fs::read_to_string(fixtures_root().join("keys/age-key-a.pub")).unwrap();
    let pub_b = fs::read_to_string(fixtures_root().join("keys/age-key-b.pub")).unwrap();
    fs::write(store_dir.join(".age-recipients"), &pub_a).unwrap();
    fs::write(store_dir.join("work/.age-recipients"), &pub_a).unwrap();

    let store = Store::open(&store_dir, StoreFormat::Passage).unwrap();
    let backend = AgeCliBackend {
        identities_file: identities_ab.clone(),
        recipients_file: None,
    };
    let root_content: &[u8] = b"root-pw\n";
    let work_content: &[u8] = b"work-pw\nnote: rekey me\n";
    store
        .write_entry(
            "rootentry",
            &Entry::from_bytes(root_content.to_vec()),
            &backend,
        )
        .unwrap();
    store
        .write_entry(
            "work/jira",
            &Entry::from_bytes(work_content.to_vec()),
            &backend,
        )
        .unwrap();
    let root_bytes_before = fs::read(store_dir.join("rootentry.age")).unwrap();

    // Re-key work/ to B and re-encrypt the subtree.
    fs::write(store_dir.join("work/.age-recipients"), &pub_b).unwrap();
    let preview = store.reencrypt_targets("work").unwrap();
    assert_eq!(preview, vec!["work/jira".to_string()]);
    let rewritten = store.reencrypt_subtree("work", &backend).unwrap();
    assert_eq!(rewritten, preview);

    // Entry outside the subtree is untouched byte-for-byte.
    assert_eq!(
        fs::read(store_dir.join("rootentry.age")).unwrap(),
        root_bytes_before
    );
    // The real CLI, holding ONLY identity B, now reads the re-keyed entry.
    assert_eq!(
        passage_show(&store_dir, &identities_b, "work/jira"),
        work_content
    );
}

#[test]
fn pass_move_same_keys_is_plain_rename() {
    let home = test_gnupghome();
    let dir = scratch("pass-move-same");
    let store_dir = dir.join("store");
    fs::create_dir_all(&store_dir).unwrap();
    let fpr_a = fs::read_to_string(fixtures_root().join("keys/gpg-key-a.fpr")).unwrap();
    fs::write(store_dir.join(".gpg-id"), format!("{}\n", fpr_a.trim())).unwrap();

    let store = Store::open(&store_dir, StoreFormat::Pass).unwrap();
    let backend = GpgCliBackend {
        gnupghome: Some(home.clone()),
    };
    store
        .write_entry("old", &Entry::from_bytes(b"pw\n".to_vec()), &backend)
        .unwrap();
    let bytes_before = fs::read(store_dir.join("old.gpg")).unwrap();
    store.move_entry("old", "sub/new", &backend).unwrap();
    assert!(!store_dir.join("old.gpg").exists());
    // Same resolved key set: ciphertext must be byte-identical (no re-encrypt).
    assert_eq!(
        fs::read(store_dir.join("sub/new.gpg")).unwrap(),
        bytes_before
    );
    assert_eq!(pass_show(&store_dir, &home, "sub/new"), b"pw\n");
}

#[test]
fn pass_move_different_keys_reencrypts() {
    let home = test_gnupghome();
    let dir = scratch("pass-move-rekey");
    let store_dir = dir.join("store");
    fs::create_dir_all(store_dir.join("bkeyed")).unwrap();
    let fpr_a = fs::read_to_string(fixtures_root().join("keys/gpg-key-a.fpr")).unwrap();
    let fpr_b = fs::read_to_string(fixtures_root().join("keys/gpg-key-b.fpr")).unwrap();
    fs::write(store_dir.join(".gpg-id"), format!("{}\n", fpr_a.trim())).unwrap();
    fs::write(
        store_dir.join("bkeyed/.gpg-id"),
        format!("{}\n", fpr_b.trim()),
    )
    .unwrap();

    let store = Store::open(&store_dir, StoreFormat::Pass).unwrap();
    let backend = GpgCliBackend {
        gnupghome: Some(home.clone()),
    };
    store
        .write_entry("old", &Entry::from_bytes(b"pw\n".to_vec()), &backend)
        .unwrap();
    let bytes_before = fs::read(store_dir.join("old.gpg")).unwrap();
    store.move_entry("old", "bkeyed/new", &backend).unwrap();
    let bytes_after = fs::read(store_dir.join("bkeyed/new.gpg")).unwrap();
    assert_ne!(bytes_after, bytes_before, "should have re-encrypted");
    assert_eq!(pass_show(&store_dir, &home, "bkeyed/new"), b"pw\n");
}

#[test]
fn remove_prunes_empty_parents_but_not_keyed_dirs() {
    let dir = scratch("passage-rm");
    let store_dir = dir.join("store");
    fs::create_dir_all(&store_dir).unwrap();
    let identities = dir.join("identities");
    fs::copy(fixtures_root().join("keys/age-key-a.txt"), &identities).unwrap();
    let store = Store::open(&store_dir, StoreFormat::Passage).unwrap();
    let backend = AgeCliBackend {
        identities_file: identities,
        recipients_file: None,
    };
    store
        .write_entry(
            "a/b/c/entry",
            &Entry::from_bytes(b"pw\n".to_vec()),
            &backend,
        )
        .unwrap();
    store.remove_entry("a/b/c/entry").unwrap();
    assert!(!store_dir.join("a").exists(), "empty parents pruned");
    assert!(store_dir.exists(), "store root never pruned");

    // A directory holding a recipients file survives.
    fs::create_dir_all(store_dir.join("keyed")).unwrap();
    let pub_a = fs::read_to_string(fixtures_root().join("keys/age-key-a.pub")).unwrap();
    fs::write(store_dir.join("keyed/.age-recipients"), pub_a).unwrap();
    store
        .write_entry(
            "keyed/entry",
            &Entry::from_bytes(b"pw\n".to_vec()),
            &backend,
        )
        .unwrap();
    store.remove_entry("keyed/entry").unwrap();
    assert!(store_dir.join("keyed/.age-recipients").is_file());
}

/// Fidelity through a full encrypt→decrypt cycle: edit one field of a real
/// fixture entry, write, CLI-read, and confirm everything but that field is
/// byte-identical.
#[test]
fn field_edit_fidelity_through_cli() {
    let dir = scratch("passage-fidelity");
    let store_dir = dir.join("store");
    fs::create_dir_all(&store_dir).unwrap();
    let identities = dir.join("identities");
    fs::copy(fixtures_root().join("keys/age-key-a.txt"), &identities).unwrap();
    let store = Store::open(&store_dir, StoreFormat::Passage).unwrap();
    let backend = AgeCliBackend {
        identities_file: identities.clone(),
        recipients_file: None,
    };

    let original: &[u8] = b"pw\nusername: kevin\nurl: old.example\nnote: precious   spacing\n";
    store
        .write_entry("e", &Entry::from_bytes(original.to_vec()), &backend)
        .unwrap();

    let mut entry = store.read_entry("e", &backend).unwrap();
    entry.set_field("url", "new.example");
    store.write_entry("e", &entry, &backend).unwrap();

    let read_back = passage_show(&store_dir, &identities, "e");
    assert_eq!(
        read_back,
        b"pw\nusername: kevin\nurl: new.example\nnote: precious   spacing\n"
    );
}
