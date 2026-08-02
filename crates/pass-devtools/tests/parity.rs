//! The P0 gate: pass-core's read path against the fixture corpus generated
//! by the real CLIs. `ls` output must match tree-for-tree; `show` must match
//! byte-for-byte.
//!
//! Corpus location: ../../fixtures (or PASSPONY_FIXTURES). Regenerate with
//! fixtures/gen-fixtures.sh; requires pass, passage, age, gpg, tree.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use pass_core::store::{render_ls, RecipientSource, Store, StoreFormat};
use pass_devtools::{AgeCliBackend, GpgCliBackend};

fn fixtures_root() -> PathBuf {
    match std::env::var_os("PASSPONY_FIXTURES") {
        Some(p) => PathBuf::from(p),
        None => Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures"),
    }
}

fn store_dirs(format_dir: &str) -> Vec<PathBuf> {
    let root = fixtures_root().join(format_dir);
    let mut out: Vec<PathBuf> = fs::read_dir(&root)
        .unwrap_or_else(|_| panic!("fixture corpus missing at {root:?}; run fixtures/gen-fixtures.sh"))
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.join("store").is_dir() && p.join("goldens").is_dir())
        .collect();
    out.sort();
    assert!(!out.is_empty(), "no fixture stores under {root:?}");
    out
}

/// Golden `ls.plain` = header + tree body from the real CLI, ANSI-stripped.
fn assert_ls_parity(fixture: &Path, format: StoreFormat) {
    let golden_path = fixture.join("goldens/ls.plain");
    let Ok(rc_text) = fs::read_to_string(fixture.join("goldens/ls.rc")) else {
        return; // invocation-only fixture (e.g. sneaky) with no ls golden
    };
    let rc: i32 = rc_text.trim().parse().unwrap();
    if rc != 0 {
        return; // error-case goldens (e.g. no-store) are covered in unit tests
    }
    let golden = fs::read_to_string(&golden_path).unwrap();
    let store = Store::open(fixture.join("store"), format).unwrap();
    let ours = render_ls(&store).unwrap();
    assert_eq!(
        ours, golden,
        "ls mismatch for {fixture:?}\n--- ours ---\n{ours}\n--- golden ---\n{golden}"
    );
}

/// Every goldens/show/<name>.out with rc 0 must equal our decrypted bytes.
fn assert_show_parity(fixture: &Path, format: StoreFormat) {
    let show_dir = fixture.join("goldens/show");
    if !show_dir.is_dir() {
        return;
    }
    let store = Store::open(fixture.join("store"), format).unwrap();
    for e in fs::read_dir(&show_dir).unwrap().filter_map(|e| e.ok()) {
        let path = e.path();
        if path.extension().and_then(|s| s.to_str()) != Some("out") {
            continue;
        }
        let stem = path.file_stem().unwrap().to_str().unwrap();
        let rc: i32 = fs::read_to_string(path.with_extension("rc"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        if rc != 0 {
            continue;
        }
        let entry_name = stem.replace("__", "/");
        let golden = fs::read(&path).unwrap();
        let ours = match format {
            StoreFormat::Passage => {
                let backend = AgeCliBackend {
                    identities_file: fixture.join("identities"),
                    recipients_file: None,
                };
                store.read_entry(&entry_name, &backend).unwrap()
            }
            StoreFormat::Pass => {
                let backend = GpgCliBackend {
                    gnupghome: Some(test_gnupghome()),
                };
                store.read_entry(&entry_name, &backend).unwrap()
            }
        };
        assert_eq!(
            ours.to_bytes(),
            golden.as_slice(),
            "show mismatch for {fixture:?} entry {entry_name}"
        );
    }
}

/// Import the committed fixture secret keys into a scratch GNUPGHOME once.
fn test_gnupghome() -> PathBuf {
    let home = std::env::temp_dir().join("passpony-parity-gnupghome");
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
        assert!(status.success(), "importing fixture gpg keys failed");
        fs::write(&marker, b"").unwrap();
    }
    home
}

#[test]
fn passage_ls_parity() {
    for fixture in store_dirs("passage") {
        assert_ls_parity(&fixture, StoreFormat::Passage);
    }
}

#[test]
fn passage_show_parity() {
    for fixture in store_dirs("passage") {
        assert_show_parity(&fixture, StoreFormat::Passage);
    }
}

#[test]
fn pass_ls_parity() {
    for fixture in store_dirs("pass") {
        assert_ls_parity(&fixture, StoreFormat::Pass);
    }
}

#[test]
fn pass_show_parity() {
    for fixture in store_dirs("pass") {
        assert_show_parity(&fixture, StoreFormat::Pass);
    }
}

#[test]
fn recipient_resolution_semantics() {
    let fx = fixtures_root();

    // passage nested: work/deep/sub inherits work/.age-recipients (nearest
    // ancestor), root entries use the root file.
    let store = Store::open(fx.join("passage/recipients-nested/store"), StoreFormat::Passage).unwrap();
    match store.resolve_recipients("work/deep/sub/vault").unwrap() {
        RecipientSource::RecipientsFile(p) => {
            assert!(p.ends_with("work/.age-recipients"), "got {p:?}")
        }
        other => panic!("expected work/.age-recipients, got {other:?}"),
    }
    match store.resolve_recipients("rootentry").unwrap() {
        RecipientSource::RecipientsFile(p) => {
            assert!(p.parent().unwrap().ends_with("store"), "got {p:?}")
        }
        other => panic!("expected root .age-recipients, got {other:?}"),
    }

    // passage minimal: no recipients file anywhere -> identities fallback.
    let store = Store::open(fx.join("passage/minimal/store"), StoreFormat::Passage).unwrap();
    assert_eq!(
        store.resolve_recipients("alpha").unwrap(),
        RecipientSource::IdentitiesFallback
    );

    // pass nested: work/ re-keyed to two IDs; root has one.
    let store = Store::open(fx.join("pass/nested/store"), StoreFormat::Pass).unwrap();
    match store.resolve_recipients("work/jira").unwrap() {
        RecipientSource::Ids(ids) => assert_eq!(ids.len(), 2, "work should have 2 ids: {ids:?}"),
        other => panic!("expected Ids, got {other:?}"),
    }
    match store.resolve_recipients("rootentry").unwrap() {
        RecipientSource::Ids(ids) => assert_eq!(ids.len(), 1, "root should have 1 id: {ids:?}"),
        other => panic!("expected Ids, got {other:?}"),
    }
}

#[test]
fn hidden_entries_indexed_but_not_listed() {
    let fx = fixtures_root().join("passage/dotfiles");
    let store = Store::open(fx.join("store"), StoreFormat::Passage).unwrap();
    let entries = store.entries().unwrap();
    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    assert!(names.contains(&".hidden"));
    assert!(names.contains(&"dir/.secret"));
    assert!(names.contains(&"visible"));
    assert!(entries.iter().find(|e| e.name == ".hidden").unwrap().hidden);
    assert!(!entries.iter().find(|e| e.name == "visible").unwrap().hidden);
    // But ls (the golden, already checked for tree parity) hides them:
    let rendered = render_ls(&store).unwrap();
    assert!(!rendered.contains("hidden"));
    assert!(!rendered.contains(".secret"));
}

#[test]
fn file_beats_directory_on_show() {
    let fx = fixtures_root().join("passage/collision");
    let store = Store::open(fx.join("store"), StoreFormat::Passage).unwrap();
    let backend = AgeCliBackend {
        identities_file: fx.join("identities"),
        recipients_file: None,
    };
    // `web` is both an entry and a directory; the entry wins, as in the CLI.
    let entry = store.read_entry("web", &backend).unwrap();
    let golden = fs::read(fx.join("goldens/show/web.out")).unwrap();
    assert_eq!(entry.to_bytes(), golden.as_slice());
}
