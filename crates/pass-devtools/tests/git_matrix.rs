//! P2 gate, local slice: the sync scenarios that must never be improvised —
//! fast-forward, clean rebase, per-file conflict with each resolution choice,
//! keep-both producing a real `.conflict` entry, and non-fast-forward push
//! rejection. Two working clones ("phone" and "laptop") share a bare remote,
//! all on the local filesystem; CI runs the same scenarios against
//! SSH-bare-repo and Forgejo containers (.github/workflows/ci.yml).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use pass_core::entry::Entry;
use pass_core::git::{messages, ConflictChoice, GitStore, SyncOutcome};
use pass_core::store::{Store, StoreFormat};
use pass_devtools::AgeCliBackend;

fn fixtures_root() -> PathBuf {
    match std::env::var_os("PASSPONY_FIXTURES") {
        Some(p) => PathBuf::from(p),
        None => Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures"),
    }
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("passpony-p2-{name}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn git_config_identity(root: &Path) {
    for (k, v) in [
        ("user.name", "PassPony Test"),
        ("user.email", "test@passpony.test"),
    ] {
        assert!(Command::new("git")
            .args(["config", k, v])
            .current_dir(root)
            .status()
            .unwrap()
            .success());
    }
}

struct Device {
    store: Store,
    git: GitStore,
    backend: AgeCliBackend,
}

impl Device {
    fn write(&self, name: &str, content: &[u8]) {
        self.store
            .write_entry(name, &Entry::from_bytes(content.to_vec()), &self.backend)
            .unwrap();
        self.git
            .commit_paths(&[&format!("{name}.age")], &messages::add(name))
            .unwrap();
    }

    fn read(&self, name: &str) -> Vec<u8> {
        self.store
            .read_entry(name, &self.backend)
            .unwrap()
            .to_bytes()
            .to_vec()
    }
}

/// Bare remote + two clones, both age-backed with fixture key A.
fn setup(name: &str) -> (PathBuf, Device, Device) {
    let dir = scratch(name);
    let remote = dir.join("remote.git");
    Repositoryish::init_bare(&remote);

    // Seed the remote from a founding device.
    let seed = dir.join("seed");
    fs::create_dir_all(&seed).unwrap();
    let identities = dir.join("identities");
    fs::copy(fixtures_root().join("keys/age-key-a.txt"), &identities).unwrap();
    GitStore::init(&seed, StoreFormat::Passage).expect("init failed");
    git_config_identity(&seed);
    // Re-open so the signature picks up the identity we just configured.
    let git = GitStore::open(&seed).unwrap();
    let store = Store::open(&seed, StoreFormat::Passage).unwrap();
    let backend = AgeCliBackend {
        identities_file: identities.clone(),
        recipients_file: None,
    };
    let seed_dev = Device {
        store,
        git,
        backend,
    };
    seed_dev.write("shared", b"seed-pw\n");
    assert!(Command::new("git")
        .args(["remote", "add", "origin", remote.to_str().unwrap()])
        .current_dir(&seed)
        .status()
        .unwrap()
        .success());
    seed_dev.git.push().unwrap();

    // Two devices clone it.
    let base = dir.clone();
    let mk = move |label: &str| -> Device {
        let path = base.join(label);
        GitStore::clone_from(remote.to_str().unwrap(), &path, None).unwrap();
        git_config_identity(&path);
        Device {
            store: Store::open(&path, StoreFormat::Passage).unwrap(),
            git: GitStore::open(&path).unwrap(),
            backend: AgeCliBackend {
                identities_file: identities.clone(),
                recipients_file: None,
            },
        }
    };
    let phone = mk("phone");
    let laptop = mk("laptop");
    (dir, phone, laptop)
}

struct Repositoryish;
impl Repositoryish {
    fn init_bare(path: &Path) {
        git2::Repository::init_opts(
            path,
            git2::RepositoryInitOptions::new()
                .bare(true)
                .initial_head("main"),
        )
        .unwrap();
    }
}

fn no_conflict_expected(path: &str) -> ConflictChoice {
    panic!("unexpected conflict on {path}");
}

/// Smoke test against a real server (CI matrix: Forgejo over HTTP; the
/// SSH-bare leg joins once the credentials callback + TOFU work lands).
/// No-op unless PASSPONY_REMOTE_URL is set. The remote persists across
/// runs, so the entry name is unique per run and prior content is synced in.
#[test]
fn remote_smoke_against_configured_server() {
    let Ok(url) = std::env::var("PASSPONY_REMOTE_URL") else {
        return;
    };
    let dir = scratch("remote-smoke");
    let identities = dir.join("identities");
    fs::copy(fixtures_root().join("keys/age-key-a.txt"), &identities).unwrap();

    let pub_path = dir.join("publisher");
    GitStore::clone_from(&url, &pub_path, None).unwrap();
    // An empty remote leaves HEAD unborn on a default branch that may not
    // match the server's; pin it to main before the first commit.
    let _ = Command::new("git")
        .args(["symbolic-ref", "HEAD", "refs/heads/main"])
        .current_dir(&pub_path)
        .status();
    git_config_identity(&pub_path);
    let publisher = Device {
        store: Store::open(&pub_path, StoreFormat::Passage).unwrap(),
        git: GitStore::open(&pub_path).unwrap(),
        backend: AgeCliBackend {
            identities_file: identities.clone(),
            recipients_file: None,
        },
    };
    let unique = format!(
        "smoke/run-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    publisher.write(&unique, b"smoke-pw\n");
    publisher.git.sync(&mut no_conflict_expected).unwrap();
    publisher.git.push().unwrap();

    let rd_path = dir.join("reader");
    GitStore::clone_from(&url, &rd_path, None).unwrap();
    let reader_store = Store::open(&rd_path, StoreFormat::Passage).unwrap();
    let backend = AgeCliBackend {
        identities_file: identities,
        recipients_file: None,
    };
    assert_eq!(
        reader_store
            .read_entry(&unique, &backend)
            .unwrap()
            .to_bytes(),
        b"smoke-pw\n"
    );
}

#[test]
fn fast_forward_when_only_remote_moved() {
    let (_dir, phone, laptop) = setup("ff");
    phone.write("from-phone", b"phone-pw\n");
    phone.git.push().unwrap();

    let outcome = laptop.git.sync(&mut no_conflict_expected).unwrap();
    assert_eq!(outcome, SyncOutcome::FastForwarded);
    assert_eq!(laptop.read("from-phone"), b"phone-pw\n");
}

#[test]
fn clean_rebase_when_both_moved_different_files() {
    let (_dir, phone, laptop) = setup("rebase");
    phone.write("from-phone", b"phone-pw\n");
    phone.git.push().unwrap();
    laptop.write("from-laptop", b"laptop-pw\n");

    let outcome = laptop.git.sync(&mut no_conflict_expected).unwrap();
    assert_eq!(outcome, SyncOutcome::Rebased { replayed: 1 });
    assert_eq!(laptop.read("from-phone"), b"phone-pw\n");
    assert_eq!(laptop.read("from-laptop"), b"laptop-pw\n");
    laptop.git.push().unwrap();

    let outcome = phone.git.sync(&mut no_conflict_expected).unwrap();
    assert_eq!(outcome, SyncOutcome::FastForwarded);
    assert_eq!(phone.read("from-laptop"), b"laptop-pw\n");
}

#[test]
fn same_file_conflict_keep_local() {
    let (_dir, phone, laptop) = setup("keep-local");
    phone.write("shared", b"phone-version\n");
    phone.git.push().unwrap();
    laptop.write("shared", b"laptop-version\n");

    let mut asked = Vec::new();
    let outcome = laptop
        .git
        .sync(&mut |path| {
            asked.push(path.to_owned());
            ConflictChoice::KeepLocal
        })
        .unwrap();
    assert_eq!(asked, vec!["shared.age".to_string()]);
    match outcome {
        SyncOutcome::ResolvedConflicts {
            resolved,
            kept_both,
        } => {
            assert_eq!(resolved, vec!["shared.age".to_string()]);
            assert!(kept_both.is_empty());
        }
        other => panic!("expected ResolvedConflicts, got {other:?}"),
    }
    assert_eq!(laptop.read("shared"), b"laptop-version\n");
}

#[test]
fn same_file_conflict_keep_remote() {
    let (_dir, phone, laptop) = setup("keep-remote");
    phone.write("shared", b"phone-version\n");
    phone.git.push().unwrap();
    laptop.write("shared", b"laptop-version\n");

    laptop
        .git
        .sync(&mut |_| ConflictChoice::KeepRemote)
        .unwrap();
    assert_eq!(laptop.read("shared"), b"phone-version\n");
    // The discarded local commit must not resurface on push + re-sync.
    laptop.git.push().unwrap();
    let outcome = phone.git.sync(&mut no_conflict_expected).unwrap();
    assert!(
        matches!(outcome, SyncOutcome::UpToDate | SyncOutcome::FastForwarded),
        "got {outcome:?}"
    );
    assert_eq!(phone.read("shared"), b"phone-version\n");
}

#[test]
fn same_file_conflict_keep_both_creates_conflict_entry() {
    let (_dir, phone, laptop) = setup("keep-both");
    phone.write("shared", b"phone-version\n");
    phone.git.push().unwrap();
    laptop.write("shared", b"laptop-version\n");

    let outcome = laptop.git.sync(&mut |_| ConflictChoice::KeepBoth).unwrap();
    match outcome {
        SyncOutcome::ResolvedConflicts { kept_both, .. } => {
            assert_eq!(kept_both, vec!["shared.conflict.age".to_string()]);
        }
        other => panic!("expected ResolvedConflicts, got {other:?}"),
    }
    // Remote version holds the name; local version is a normal entry beside it.
    assert_eq!(laptop.read("shared"), b"phone-version\n");
    assert_eq!(laptop.read("shared.conflict"), b"laptop-version\n");
    // And it is visible in the listing like any entry.
    let names: Vec<String> = laptop
        .store
        .entries()
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert!(names.contains(&"shared.conflict".to_string()), "{names:?}");
    // After push, the other device sees both, no conflict.
    laptop.git.push().unwrap();
    phone.git.sync(&mut no_conflict_expected).unwrap();
    assert_eq!(phone.read("shared.conflict"), b"laptop-version\n");
}

#[test]
fn push_rejected_when_stale_maps_to_non_fast_forward() {
    let (_dir, phone, laptop) = setup("non-ff");
    phone.write("a", b"pw\n");
    phone.git.push().unwrap();
    laptop.write("b", b"pw\n");
    let err = laptop.git.push().unwrap_err();
    assert!(
        matches!(err, pass_core::git::GitError::NonFastForward),
        "got {err:?}"
    );
    // Recovery is sync-then-push, as the UX prescribes.
    laptop.git.sync(&mut no_conflict_expected).unwrap();
    laptop.git.push().unwrap();
}

#[test]
fn status_counts_unpushed_commits_for_badge() {
    let (_dir, phone, _laptop) = setup("badge");
    let st = phone.git.status().unwrap();
    assert_eq!((st.ahead, st.behind), (0, 0));
    phone.write("one", b"pw\n");
    phone.write("two", b"pw\n");
    let st = phone.git.status().unwrap();
    assert_eq!(st.ahead, 2, "offline commit queue badge");
    assert!(!st.dirty);
    phone.git.push().unwrap();
    let st = phone.git.status().unwrap();
    assert_eq!(st.ahead, 0);
}

#[test]
fn history_reads_like_the_clis() {
    let (dir, phone, _laptop) = setup("log");
    phone.write("web/github", b"pw\n");
    phone.store.remove_entry("web/github").unwrap();
    phone
        .git
        .commit_paths(&["web/github.age"], &messages::remove("web/github"))
        .unwrap();
    let out = Command::new("git")
        .args(["log", "--format=%s"])
        .current_dir(dir.join("phone"))
        .output()
        .unwrap();
    let log = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = log.lines().collect();
    assert_eq!(
        lines[0], "Remove web/github from store.",
        "full log:\n{log}"
    );
    assert_eq!(lines[1], "Add given password for web/github to store.");
    assert!(lines.contains(&"Add current contents of password store."));
    assert!(lines.contains(&"Configure git repository for age file diff."));
}
