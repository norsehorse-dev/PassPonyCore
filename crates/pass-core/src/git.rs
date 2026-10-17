//! Git engine over git2-rs (libgit2). Sync model per the plan:
//! pull is fetch + rebase (never merge commits), conflicts are per-file and
//! explicit — keep local, keep remote, or keep both (remote wins the name,
//! the local version becomes `<name>.conflict`) — never a silent merge of
//! encrypted blobs. Offline commits accumulate locally; `status()` exposes
//! the unpushed count for the badge.
//!
//! Commit messages mirror the CLIs (see docs/passage-store-semantics.md §5)
//! so a store managed by PassPony reads naturally in `pass git log`.

use std::cell::RefCell;
use std::fs;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use git2::{
    build::CheckoutBuilder, AnnotatedCommit, ErrorCode, FetchOptions, IndexEntry, Oid, Rebase,
    RebaseOptions, Repository, Signature,
};

use crate::ssh::{self, HostCheck, HostKey, RemoteScheme};
use crate::store::StoreFormat;
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum GitError {
    #[error("git: {0}")]
    Git(#[from] git2::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("store has no git repository")]
    NoRepository,
    #[error("no remote configured")]
    NoRemote,
    #[error("push rejected: remote has commits you don't have (pull first)")]
    NonFastForward,
    #[error("remote history was rewritten (force-push upstream); explicit recovery required")]
    UpstreamRewritten,
    #[error("working tree has uncommitted changes")]
    DirtyWorkdir,
    /// First connection to an SSH host: show the fingerprint, and pin the
    /// key with `ssh::known_hosts_add` if the user trusts it.
    #[error("unknown SSH host {host} ({fingerprint})", fingerprint = key.fingerprint)]
    UnknownHostKey { host: String, key: HostKey },
    /// A pinned SSH host presented a different key. No way past this but
    /// forgetting the host on purpose.
    #[error("SSH host key for {host} changed: now {fingerprint}, pinned {pinned_fingerprint}")]
    HostKeyChanged {
        host: String,
        fingerprint: String,
        pinned_fingerprint: String,
    },
    #[error("the SSH host didn't send a usable host key")]
    NoHostKey,
    #[error("this remote needs an SSH key and none is set up")]
    SshKeyMissing,
    #[error("the SSH host didn't accept this app's key")]
    SshAuthFailed,
}

/// What SSH remotes need from the app: its private key (unencrypted
/// OpenSSH text, handed to libssh2 from memory) and the hosts it trusts
/// (OpenSSH known_hosts text). HTTPS remotes ignore both.
#[derive(Clone, Default)]
pub struct SshConfig {
    pub private_key: Option<Zeroizing<String>>,
    pub known_hosts: String,
}

impl std::fmt::Debug for SshConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshConfig")
            .field("has_key", &self.private_key.is_some())
            .finish_non_exhaustive()
    }
}

/// Pass-style commit messages, one place so every caller matches the CLIs.
pub mod messages {
    pub fn add(name: &str) -> String {
        format!("Add given password for {name} to store.")
    }
    pub fn add_generated(name: &str) -> String {
        format!("Add generated password for {name}.")
    }
    pub fn replace_generated(name: &str) -> String {
        format!("Replace generated password for {name}.")
    }
    pub fn edit(name: &str) -> String {
        format!("Edit password for {name} using PassPony.")
    }
    pub fn remove(name: &str) -> String {
        format!("Remove {name} from store.")
    }
    pub fn rename(from: &str, to: &str) -> String {
        format!("Rename {from} to {to}.")
    }
    pub fn copy(from: &str, to: &str) -> String {
        format!("Copy {from} to {to}.")
    }
    pub fn reencrypt(path: &str) -> String {
        let path = if path.is_empty() { "." } else { path };
        format!("Reencrypted {path}.")
    }
    pub fn initial() -> String {
        "Add current contents of password store.".to_string()
    }
    pub fn configure() -> String {
        "Configure git repository for age file diff.".to_string()
    }
    /// `pass otp code` on an HOTP entry.
    pub fn hotp_increment(name: &str) -> String {
        format!("Increment HOTP counter for {name}.")
    }
    /// `pass otp insert` on a new entry.
    pub fn passkey_add(name: &str) -> String {
        format!("Add passkey to {name}.")
    }
    pub fn passkey_remove(name: &str) -> String {
        format!("Remove passkey from {name}.")
    }
    pub fn otp_add(name: &str) -> String {
        format!("Add OTP secret for {name} to store.")
    }
    pub fn resolve_keep_both(name: &str) -> String {
        format!("Keep both versions of {name} after sync conflict.")
    }
}

/// What `sync` did, or what it needs from the user.
#[derive(Debug, PartialEq, Eq)]
pub enum SyncOutcome {
    /// Nothing to do in either direction.
    UpToDate,
    /// Remote was ahead only; local branch fast-forwarded.
    FastForwarded,
    /// Histories had diverged; local commits were replayed cleanly on top.
    Rebased { replayed: usize },
    /// Histories had diverged and files conflicted; the resolver was
    /// consulted for each named path and the rebase completed with those
    /// choices applied. `kept_both` lists entries duplicated as
    /// `<name>.conflict`.
    ResolvedConflicts {
        resolved: Vec<String>,
        kept_both: Vec<String>,
    },
}

/// Per-file conflict decision. Never made implicitly — the resolver is the
/// UX asking the user (or a policy the user explicitly configured).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictChoice {
    /// Local version wins the path.
    KeepLocal,
    /// Remote version wins the path; local edits are discarded.
    KeepRemote,
    /// Remote wins the path; the local version is preserved beside it as
    /// `<name>.conflict` (a normal entry, listed and decryptable).
    KeepBoth,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SyncStatus {
    /// Local commits not on the remote tracking branch (the badge count).
    pub ahead: usize,
    /// Remote commits not yet integrated.
    pub behind: usize,
    /// Uncommitted changes in the working tree.
    pub dirty: bool,
    /// Whether a remote named `origin` exists.
    pub has_remote: bool,
}

pub struct GitStore {
    repo: Repository,
    root: PathBuf,
    ssh: SshConfig,
}

impl GitStore {
    /// Initialize a repository at the store root, mirroring `passage git init`
    /// / `pass git init`: commit current contents, write `.gitattributes`
    /// marking encrypted files binary-diffed, set `diff.<ext>.binary`.
    /// (The CLIs also set `diff.<ext>.textconv` to their own decrypt command;
    /// that references binaries on the user's machine, so PassPony leaves
    /// textconv to the CLI — running `pass git init` later adds it and is
    /// harmless.)
    pub fn init(root: impl Into<PathBuf>, format: StoreFormat) -> Result<Self, GitError> {
        let root = root.into();
        let repo = Repository::init_opts(
            &root,
            git2::RepositoryInitOptions::new().initial_head("main"),
        )?;
        let ext = format.entry_extension();
        {
            let mut config = repo.config()?;
            config.set_bool(&format!("diff.{ext}.binary"), true)?;
        }
        // A store repo needs an identity before its first commit. Use any
        // already-configured one; otherwise set a repo-local placeholder the
        // app's settings later overwrite (mirrors APS behavior).
        if repo.signature().is_err() {
            let mut config = repo.config()?;
            config.set_str("user.name", "PassPony")?;
            config.set_str("user.email", "passpony@localhost")?;
        }
        let s = GitStore {
            repo,
            root,
            ssh: SshConfig::default(),
        };
        s.commit_all(&messages::initial())?;
        let attributes = format!("*.{ext} diff={ext}\n");
        fs::write(s.root.join(".gitattributes"), attributes)?;
        s.commit_paths(&[".gitattributes"], &messages::configure())?;
        Ok(s)
    }

    pub fn open(root: impl Into<PathBuf>) -> Result<Self, GitError> {
        let root = root.into();
        let repo = Repository::open(&root).map_err(|e| {
            if e.code() == ErrorCode::NotFound {
                GitError::NoRepository
            } else {
                GitError::Git(e)
            }
        })?;
        Ok(GitStore {
            repo,
            root,
            ssh: SshConfig::default(),
        })
    }

    /// The key and known hosts used by fetch, sync and push from now on.
    pub fn set_ssh(&mut self, ssh: SshConfig) {
        self.ssh = ssh;
    }

    /// Clone a store. `depth` enables shallow clone for huge stores.
    pub fn clone_from(
        url: &str,
        dest: impl Into<PathBuf>,
        depth: Option<i32>,
    ) -> Result<Self, GitError> {
        Self::clone_with_ssh(url, dest, depth, SshConfig::default())
    }

    /// Clone over any transport; SSH remotes use `ssh`, which the returned
    /// store keeps for later fetches and pushes.
    pub fn clone_with_ssh(
        url: &str,
        dest: impl Into<PathBuf>,
        depth: Option<i32>,
        ssh: SshConfig,
    ) -> Result<Self, GitError> {
        let dest = dest.into();
        let mut fo = FetchOptions::new();
        if let Some(d) = depth {
            fo.depth(d);
        }
        let (callbacks, problem) = transport_callbacks(url, &ssh);
        fo.remote_callbacks(callbacks);
        let repo = git2::build::RepoBuilder::new()
            .fetch_options(fo)
            .clone(url, &dest);
        let repo = transport_result(repo, &problem)?;
        // An empty remote leaves HEAD on libgit2's default `master`, while
        // init() and the bare repos git hosts create use `main`; the first
        // push would then create a branch nobody's HEAD points at.
        if repo.is_empty()? {
            repo.set_head("refs/heads/main")?;
        }
        // A cloned repo has no local identity until something sets one --
        // a fresh device's very first commit (the first edit made after
        // setting up from an existing remote) would otherwise fail with
        // "signature not found". Same placeholder init() falls back to.
        if repo.signature().is_err() {
            let mut config = repo.config()?;
            config.set_str("user.name", "PassPony")?;
            config.set_str("user.email", "passpony@localhost")?;
        }
        Ok(GitStore {
            repo,
            root: dest,
            ssh,
        })
    }

    /// The `origin` remote's URL, if configured. May contain embedded
    /// credentials — callers displaying it must redact userinfo.
    pub fn remote_url(&self) -> Option<String> {
        self.repo
            .find_remote("origin")
            .ok()
            .and_then(|r| r.url().map(str::to_owned))
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn signature(&self) -> Result<Signature<'static>, GitError> {
        Ok(self.repo.signature()?)
    }

    /// Stage the given store-relative paths (adds and deletions both) and
    /// commit. Paths must be relative to the store root.
    pub fn commit_paths(&self, paths: &[&str], message: &str) -> Result<Oid, GitError> {
        let mut index = self.repo.index()?;
        for p in paths {
            let abs = self.root.join(p);
            if abs.exists() {
                index.add_path(Path::new(p))?;
            } else {
                index.remove_path(Path::new(p))?;
            }
        }
        index.write()?;
        self.commit_index(message)
    }

    /// Stage everything (like the CLIs' `git add .` on init) and commit.
    pub fn commit_all(&self, message: &str) -> Result<Oid, GitError> {
        let mut index = self.repo.index()?;
        index.add_all(["*"].iter(), git2::IndexAddOption::DEFAULT, None)?;
        index.write()?;
        self.commit_index(message)
    }

    fn commit_index(&self, message: &str) -> Result<Oid, GitError> {
        let mut index = self.repo.index()?;
        let tree_oid = index.write_tree()?;
        let tree = self.repo.find_tree(tree_oid)?;
        let sig = self.signature()?;
        let parents: Vec<git2::Commit> = match self.repo.head() {
            Ok(head) => vec![head.peel_to_commit()?],
            Err(_) => vec![],
        };
        let parent_refs: Vec<&git2::Commit> = parents.iter().collect();
        let oid = self
            .repo
            .commit(Some("HEAD"), &sig, &sig, message, &tree, &parent_refs)?;
        Ok(oid)
    }

    fn head_branch(&self) -> Result<String, GitError> {
        let head = self.repo.head()?;
        Ok(head.shorthand().unwrap_or("main").to_string())
    }

    fn remote_tracking_oid(&self) -> Result<Option<Oid>, GitError> {
        let branch = self.head_branch()?;
        match self
            .repo
            .find_reference(&format!("refs/remotes/origin/{branch}"))
        {
            Ok(r) => Ok(r.target()),
            Err(e) if e.code() == ErrorCode::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn status(&self) -> Result<SyncStatus, GitError> {
        let mut st = SyncStatus {
            has_remote: self.repo.find_remote("origin").is_ok(),
            ..Default::default()
        };
        let statuses = self.repo.statuses(None)?;
        st.dirty = statuses.iter().any(|s| {
            let f = s.status();
            !f.is_ignored() && f != git2::Status::CURRENT
        });
        if let (Ok(head), Ok(Some(remote_oid))) = (self.repo.head(), self.remote_tracking_oid()) {
            if let Some(local_oid) = head.target() {
                let (ahead, behind) = self.repo.graph_ahead_behind(local_oid, remote_oid)?;
                st.ahead = ahead;
                st.behind = behind;
            }
        } else if self.repo.head().is_ok() && st.has_remote {
            // Remote exists but no tracking ref yet: everything is unpushed.
            let mut walk = self.repo.revwalk()?;
            walk.push_head()?;
            st.ahead = walk.count();
        }
        Ok(st)
    }

    /// Point `origin` at `url`, creating or updating it. The app's
    /// publish-existing-store flow: init → set_remote → push.
    pub fn set_remote(&self, url: &str) -> Result<(), GitError> {
        if self.repo.find_remote("origin").is_ok() {
            self.repo.remote_set_url("origin", url)?;
        } else {
            self.repo.remote("origin", url)?;
        }
        Ok(())
    }

    pub fn fetch(&self) -> Result<(), GitError> {
        let url = self.remote_url();
        let mut remote = self
            .repo
            .find_remote("origin")
            .map_err(|_| GitError::NoRemote)?;
        let branch = self.head_branch()?;
        let mut fo = FetchOptions::new();
        let (callbacks, problem) = transport_callbacks(url.as_deref().unwrap_or(""), &self.ssh);
        fo.remote_callbacks(callbacks);
        let fetched = remote.fetch(&[branch.as_str()], Some(&mut fo), None);
        transport_result(fetched, &problem)?;
        Ok(())
    }

    /// Pull with rebase semantics. `resolver` is consulted once per
    /// conflicted store path; it is only called when a real conflict exists.
    pub fn sync(
        &self,
        resolver: &mut dyn FnMut(&str) -> ConflictChoice,
    ) -> Result<SyncOutcome, GitError> {
        let pre = self.status()?;
        if pre.dirty {
            return Err(GitError::DirtyWorkdir);
        }
        self.fetch()?;
        let Some(remote_oid) = self.remote_tracking_oid()? else {
            return Ok(SyncOutcome::UpToDate);
        };
        let head = self.repo.head()?;
        let local_oid = head.target().expect("HEAD has a target");
        if local_oid == remote_oid {
            return Ok(SyncOutcome::UpToDate);
        }
        let (ahead, behind) = self.repo.graph_ahead_behind(local_oid, remote_oid)?;
        if behind == 0 {
            return Ok(SyncOutcome::UpToDate); // ahead only; push pending
        }
        if ahead == 0 {
            // Fast-forward.
            let remote_commit = self.repo.find_commit(remote_oid)?;
            let branch = self.head_branch()?;
            let mut reference = self.repo.find_reference(&format!("refs/heads/{branch}"))?;
            reference.set_target(remote_oid, "passpony: fast-forward")?;
            self.repo.set_head(&format!("refs/heads/{branch}"))?;
            self.repo.checkout_tree(
                remote_commit.as_object(),
                Some(CheckoutBuilder::new().force()),
            )?;
            return Ok(SyncOutcome::FastForwarded);
        }
        // Diverged: rebase local commits onto the remote head.
        self.rebase_onto(remote_oid, resolver)
    }

    fn rebase_onto(
        &self,
        upstream_oid: Oid,
        resolver: &mut dyn FnMut(&str) -> ConflictChoice,
    ) -> Result<SyncOutcome, GitError> {
        let upstream: AnnotatedCommit = self.repo.find_annotated_commit(upstream_oid)?;
        let mut opts = RebaseOptions::new();
        let mut rebase: Rebase = self
            .repo
            .rebase(None, Some(&upstream), None, Some(&mut opts))?;
        let sig = self.signature()?;
        let mut replayed = 0usize;
        let mut resolved: Vec<String> = Vec::new();
        let mut kept_both: Vec<String> = Vec::new();

        while let Some(op) = rebase.next() {
            op?;
            {
                let mut index = self.repo.index()?;
                if index.has_conflicts() {
                    let conflicts: Vec<(Option<IndexEntry>, Option<IndexEntry>)> = index
                        .conflicts()?
                        .filter_map(|c| c.ok())
                        .map(|c| (c.our, c.their))
                        .collect();
                    for (our, their) in conflicts {
                        // In a rebase, "our" is the upstream/remote side and
                        // "their" is the local commit being replayed.
                        let path_bytes = our
                            .as_ref()
                            .or(their.as_ref())
                            .map(|e| e.path.clone())
                            .unwrap_or_default();
                        let path = String::from_utf8_lossy(&path_bytes).into_owned();
                        let choice = resolver(&path);
                        resolved.push(path.clone());
                        let remote_blob = our.as_ref().map(|e| e.id);
                        let local_blob = their.as_ref().map(|e| e.id);
                        index.remove_path(Path::new(&path)).ok();
                        match choice {
                            ConflictChoice::KeepLocal => {
                                self.write_blob_to_workdir(&path, local_blob)?;
                                index.add_path(Path::new(&path))?;
                            }
                            ConflictChoice::KeepRemote => {
                                self.write_blob_to_workdir(&path, remote_blob)?;
                                index.add_path(Path::new(&path))?;
                            }
                            ConflictChoice::KeepBoth => {
                                self.write_blob_to_workdir(&path, remote_blob)?;
                                index.add_path(Path::new(&path))?;
                                let conflict_name = conflict_sibling(&path);
                                self.write_blob_to_workdir(&conflict_name, local_blob)?;
                                index.add_path(Path::new(&conflict_name))?;
                                kept_both.push(conflict_name);
                            }
                        }
                    }
                    index.write()?;
                }
            }
            match rebase.commit(None, &sig, None) {
                Ok(_) => replayed += 1,
                Err(e) if e.code() == ErrorCode::Applied => {
                    // Local commit became empty (e.g. KeepRemote discarded
                    // its only change) — skip it.
                }
                Err(e) => return Err(e.into()),
            }
        }
        rebase.finish(Some(&sig))?;
        // Make the working tree match the rebased HEAD.
        let head = self.repo.head()?.peel_to_commit()?;
        self.repo
            .checkout_tree(head.as_object(), Some(CheckoutBuilder::new().force()))?;
        if resolved.is_empty() {
            Ok(SyncOutcome::Rebased { replayed })
        } else {
            Ok(SyncOutcome::ResolvedConflicts {
                resolved,
                kept_both,
            })
        }
    }

    fn write_blob_to_workdir(&self, dest: &str, blob: Option<Oid>) -> Result<(), GitError> {
        if let Some(oid) = blob {
            let blob = self.repo.find_blob(oid)?;
            let abs = self.root.join(dest);
            if let Some(parent) = abs.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&abs, blob.content())?;
        }
        Ok(())
    }

    /// Push the current branch to origin. A non-fast-forward rejection maps
    /// to [`GitError::NonFastForward`] so the UX can prompt a sync first.
    pub fn push(&self) -> Result<(), GitError> {
        let url = self.remote_url();
        let mut remote = self
            .repo
            .find_remote("origin")
            .map_err(|_| GitError::NoRemote)?;
        let branch = self.head_branch()?;
        let refspec = format!("refs/heads/{branch}:refs/heads/{branch}");
        let mut po = git2::PushOptions::new();
        let (callbacks, problem) = transport_callbacks(url.as_deref().unwrap_or(""), &self.ssh);
        po.remote_callbacks(callbacks);
        let pushed = remote.push(&[refspec.as_str()], Some(&mut po));
        if let Some(p) = problem.borrow_mut().take() {
            return Err(p);
        }
        pushed.map_err(|e| {
            if e.code() == ErrorCode::NotFastForward
                || e.message().contains("non-fast-forward")
                || e.message().contains("failed to update ref")
            {
                GitError::NonFastForward
            } else {
                GitError::Git(e)
            }
        })?;
        // Update the tracking ref so ahead/behind stays accurate even where
        // the transport doesn't report it back.
        if let Ok(Some(oid)) = self.repo.head().map(|h| h.target()) {
            let _ = self.repo.reference(
                &format!("refs/remotes/origin/{branch}"),
                oid,
                true,
                "passpony: update tracking after push",
            );
        }
        Ok(())
    }
}

/// Load a CA bundle into libgit2's TLS verify store.
///
/// libgit2 links a vendored OpenSSL with no system trust store on Android,
/// so HTTPS clone/fetch/push fail certificate verification (class=Ssl (16),
/// code GIT_ECERTIFICATE -17) against an empty set of trust anchors. On
/// desktop, handing libgit2 the CA file path loads it into the verify store.
/// On Android the vendored OpenSSL cannot open a file through its own BIO, so
/// the file path is useless there; instead each root is parsed in Rust and
/// added to the trust store from memory (see `add_ca_bundle_from_memory`).
/// Call once at startup before any network op.
pub fn init_tls(ca_file: &str) {
    // Also initializes libgit2 and its OpenSSL cert store. On desktop this
    // loads the CA file directly; on Android the vendored OpenSSL cannot open
    // a cert file via its own BIO, so this is a no-op there and the memory add
    // below provides the trust anchors instead.
    let _ = unsafe { git2::opts::set_ssl_cert_file(ca_file) };

    #[cfg(target_os = "android")]
    add_ca_bundle_from_memory(ca_file);
}

/// Read a PEM CA bundle with Rust std (Android's OpenSSL cannot open it via its
/// own file BIO) and add each root to libgit2's OpenSSL trust store from memory
/// through GIT_OPT_ADD_SSL_X509_CERT. libgit2 up-refs each cert, so dropping our
/// copies after is fine.
#[cfg(target_os = "android")]
fn add_ca_bundle_from_memory(ca_file: &str) {
    use foreign_types_shared::ForeignType;
    let Ok(bytes) = std::fs::read(ca_file) else {
        return;
    };
    let Ok(certs) = openssl::x509::X509::stack_from_pem(&bytes) else {
        return;
    };
    for cert in &certs {
        // SAFETY: variadic libgit2 option; cert.as_ptr() is a live X509* from the
        // same openssl-sys libgit2 links, valid for the duration of the call.
        unsafe {
            libgit2_sys::git_libgit2_opts(
                libgit2_sys::GIT_OPT_ADD_SSL_X509_CERT as std::os::raw::c_int,
                cert.as_ptr(),
            );
        }
    }
}

/// Set by a transport callback when it refuses something the user should
/// hear about in plain words; checked before libgit2's generic error.
type TransportProblem = Rc<RefCell<Option<GitError>>>;

/// Credentials and host-key checks for one network operation.
///
/// HTTPS: libgit2 treats URL userinfo only as a hint and still demands a
/// callback, so `user:token@` is parsed out of the remote URL and supplied
/// as plaintext credentials.
///
/// SSH: the username comes from the URL (`git` when there is none), the key
/// is the app's, handed over from memory, and the host key must be pinned
/// in `ssh.known_hosts`. An unknown or changed host key stops the
/// connection before authentication and is reported as its own error.
fn transport_callbacks(
    url: &str,
    ssh: &SshConfig,
) -> (git2::RemoteCallbacks<'static>, TransportProblem) {
    let problem: TransportProblem = Rc::new(RefCell::new(None));
    let creds = parse_userinfo(url);
    let endpoint = ssh::ssh_endpoint(url);
    let key = ssh.private_key.clone();
    let url_user = endpoint.as_ref().and_then(|e| e.user.clone());
    let mut key_offered = false;
    let mut cbs = git2::RemoteCallbacks::new();
    let cred_problem = problem.clone();
    cbs.credentials(move |_url, username_from_url, allowed| {
        if allowed.contains(git2::CredentialType::USER_PASS_PLAINTEXT) {
            if let Some((user, pass)) = &creds {
                return git2::Cred::userpass_plaintext(user, pass);
            }
        }
        let user = username_from_url
            .map(str::to_owned)
            .or_else(|| url_user.clone())
            .unwrap_or_else(|| "git".to_owned());
        if allowed.contains(git2::CredentialType::USERNAME) {
            return git2::Cred::username(&user);
        }
        if allowed.intersects(git2::CredentialType::SSH_KEY | git2::CredentialType::SSH_MEMORY) {
            let Some(key) = &key else {
                *cred_problem.borrow_mut() = Some(GitError::SshKeyMissing);
                return Err(git2::Error::from_str("no SSH key"));
            };
            if key_offered {
                // libgit2 asks again after a rejected key; once is enough.
                *cred_problem.borrow_mut() = Some(GitError::SshAuthFailed);
                return Err(git2::Error::from_str("SSH key rejected"));
            }
            key_offered = true;
            return git2::Cred::ssh_key_from_memory(&user, None, key, None);
        }
        if allowed.contains(git2::CredentialType::DEFAULT) {
            return git2::Cred::default();
        }
        Err(git2::Error::from_str(&format!(
            "no usable credentials for {user} (HTTPS: embed user:token in the URL)"
        )))
    });
    if let Some(endpoint) = endpoint {
        let host_name = endpoint.known_hosts_name();
        let known_hosts = ssh.known_hosts.clone();
        let cert_problem = problem.clone();
        cbs.certificate_check(move |cert, _hostname| {
            let Some(hostkey) = cert.as_hostkey() else {
                return Ok(git2::CertificateCheckStatus::CertificatePassthrough);
            };
            let Some(presented) = hostkey.hostkey().and_then(HostKey::from_blob) else {
                *cert_problem.borrow_mut() = Some(GitError::NoHostKey);
                return Err(git2::Error::from_str("no host key"));
            };
            match ssh::known_hosts_check(&known_hosts, &host_name, &presented) {
                HostCheck::Trusted => Ok(git2::CertificateCheckStatus::CertificateOk),
                HostCheck::Unknown => {
                    *cert_problem.borrow_mut() = Some(GitError::UnknownHostKey {
                        host: host_name.clone(),
                        key: presented,
                    });
                    Err(git2::Error::from_str("unknown host key"))
                }
                HostCheck::Changed { pinned_fingerprint } => {
                    *cert_problem.borrow_mut() = Some(GitError::HostKeyChanged {
                        host: host_name.clone(),
                        fingerprint: presented.fingerprint,
                        pinned_fingerprint,
                    });
                    Err(git2::Error::from_str("host key changed"))
                }
            }
        });
    }
    (cbs, problem)
}

/// A network result, with a refusal from the callbacks taking precedence
/// over libgit2's generic message for it.
fn transport_result<T>(
    result: Result<T, git2::Error>,
    problem: &TransportProblem,
) -> Result<T, GitError> {
    match result {
        Ok(v) => Ok(v),
        Err(e) => Err(problem.borrow_mut().take().unwrap_or(GitError::Git(e))),
    }
}

/// Which transport a remote URL uses; for Diagnostics and the URL fields.
pub fn remote_scheme(url: &str) -> RemoteScheme {
    ssh::remote_scheme(url)
}

/// Extract percent-decoded `user:password` from a URL's userinfo section.
fn parse_userinfo(url: &str) -> Option<(String, String)> {
    let rest = url.split("://").nth(1)?;
    let (userinfo, _) = rest.split_once('@')?;
    let (user, pass) = userinfo.split_once(':')?;
    Some((percent_decode(user), percent_decode(pass)))
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = |b: u8| match b {
                b'0'..=b'9' => Some(b - b'0'),
                b'a'..=b'f' => Some(b - b'a' + 10),
                b'A'..=b'F' => Some(b - b'A' + 10),
                _ => None,
            };
            if let (Some(h), Some(l)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `web/github` → `web/github.conflict`; extension handling happens at the
/// store layer (the path here is the on-disk file path, e.g. `a.age` →
/// `a.conflict.age` so the copy remains a normal entry).
fn conflict_sibling(path: &str) -> String {
    for ext in [".age", ".gpg"] {
        if let Some(stem) = path.strip_suffix(ext) {
            return format!("{stem}.conflict{ext}");
        }
    }
    format!("{path}.conflict")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conflict_sibling_keeps_entry_extension() {
        assert_eq!(
            conflict_sibling("web/github.age"),
            "web/github.conflict.age"
        );
        assert_eq!(conflict_sibling("a.gpg"), "a.conflict.gpg");
        assert_eq!(conflict_sibling("odd"), "odd.conflict");
    }

    #[test]
    fn message_templates_match_clis() {
        assert_eq!(messages::add("x"), "Add given password for x to store.");
        assert_eq!(messages::remove("x"), "Remove x from store.");
        assert_eq!(messages::rename("a", "b"), "Rename a to b.");
        assert_eq!(messages::copy("b", "c"), "Copy b to c.");
        assert_eq!(messages::reencrypt(""), "Reencrypted ..");
        assert_eq!(
            messages::initial(),
            "Add current contents of password store."
        );
    }
}

#[cfg(test)]
mod auth_tests {
    use super::parse_userinfo;

    #[test]
    fn userinfo_parsing() {
        assert_eq!(
            parse_userinfo("https://kevin:ghp_abc123@github.com/x/y.git"),
            Some(("kevin".into(), "ghp_abc123".into()))
        );
        assert_eq!(
            parse_userinfo("https://kevin:p%40ss@host/x.git"),
            Some(("kevin".into(), "p@ss".into()))
        );
        assert_eq!(parse_userinfo("https://github.com/x/y.git"), None);
        assert_eq!(parse_userinfo("/local/path"), None);
    }
}
