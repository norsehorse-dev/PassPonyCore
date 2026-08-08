//! Git engine over git2-rs (libgit2). Sync model per the plan:
//! pull is fetch + rebase (never merge commits), conflicts are per-file and
//! explicit — keep local, keep remote, or keep both (remote wins the name,
//! the local version becomes `<name>.conflict`) — never a silent merge of
//! encrypted blobs. Offline commits accumulate locally; `status()` exposes
//! the unpushed count for the badge.
//!
//! Commit messages mirror the CLIs (see docs/passage-store-semantics.md §5)
//! so a store managed by PassPony reads naturally in `pass git log`.

use std::fs;
use std::path::{Path, PathBuf};

use git2::{
    build::CheckoutBuilder, AnnotatedCommit, ErrorCode, FetchOptions, IndexEntry, Oid, Rebase,
    RebaseOptions, Repository, Signature,
};

use crate::store::StoreFormat;

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
        let s = GitStore { repo, root };
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
        Ok(GitStore { repo, root })
    }

    /// Clone a store. `depth` enables shallow clone for huge stores.
    pub fn clone_from(
        url: &str,
        dest: impl Into<PathBuf>,
        depth: Option<i32>,
    ) -> Result<Self, GitError> {
        let dest = dest.into();
        let mut fo = FetchOptions::new();
        if let Some(d) = depth {
            fo.depth(d);
        }
        fo.remote_callbacks(auth_callbacks(url));
        let repo = git2::build::RepoBuilder::new()
            .fetch_options(fo)
            .clone(url, &dest)?;
        // A cloned repo has no local identity until something sets one --
        // a fresh device's very first commit (the first edit made after
        // setting up from an existing remote) would otherwise fail with
        // "signature not found". Same placeholder init() falls back to.
        if repo.signature().is_err() {
            let mut config = repo.config()?;
            config.set_str("user.name", "PassPony")?;
            config.set_str("user.email", "passpony@localhost")?;
        }
        Ok(GitStore { repo, root: dest })
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
        fo.remote_callbacks(auth_callbacks(url.as_deref().unwrap_or("")));
        remote.fetch(&[branch.as_str()], Some(&mut fo), None)?;
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
        po.remote_callbacks(auth_callbacks(url.as_deref().unwrap_or("")));
        remote
            .push(&[refspec.as_str()], Some(&mut po))
            .map_err(|e| {
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

/// Credentials for the transport layer. libgit2 treats URL userinfo only as
/// a hint and still demands a callback, so this parses `user:token@` out of
/// the remote URL and supplies it as plaintext credentials — the HTTPS+token
/// path. SSH credentials land with the P2.5 auth work (keygen, TOFU).
fn auth_callbacks(url: &str) -> git2::RemoteCallbacks<'static> {
    let creds = parse_userinfo(url);
    let mut cbs = git2::RemoteCallbacks::new();
    cbs.credentials(move |_url, username_from_url, allowed| {
        if allowed.contains(git2::CredentialType::USER_PASS_PLAINTEXT) {
            if let Some((user, pass)) = &creds {
                return git2::Cred::userpass_plaintext(user, pass);
            }
        }
        if allowed.contains(git2::CredentialType::DEFAULT) {
            return git2::Cred::default();
        }
        let hint = username_from_url.unwrap_or("");
        Err(git2::Error::from_str(&format!(
            "no usable credentials for {hint} (HTTPS: embed user:token in the URL; SSH support pending)"
        )))
    });
    cbs
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
