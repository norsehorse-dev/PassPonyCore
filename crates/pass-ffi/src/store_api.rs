//! The app-facing FFI surface: store, git sync, TOTP. Thin translation over
//! pass-core; no logic lives here.

use std::sync::{Arc, Mutex};

use crate::{CryptoBackend, ForeignBackendAdapter};

#[derive(Debug, Clone, Copy, uniffi::Enum)]
pub enum StoreFormat {
    Pass,
    Passage,
}

impl From<StoreFormat> for pass_core::store::StoreFormat {
    fn from(f: StoreFormat) -> Self {
        match f {
            StoreFormat::Pass => pass_core::store::StoreFormat::Pass,
            StoreFormat::Passage => pass_core::store::StoreFormat::Passage,
        }
    }
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum StoreError {
    #[error("store not found")]
    NoStore,
    #[error("entry is not in the password store")]
    NotInStore,
    #[error("invalid path")]
    SneakyPath,
    #[error("crypto: {reason}")]
    Crypto { reason: String },
    #[error("io: {reason}")]
    Io { reason: String },
}

impl From<pass_core::store::StoreError> for StoreError {
    fn from(e: pass_core::store::StoreError) -> Self {
        use pass_core::store::StoreError as E;
        match e {
            E::NoStore => StoreError::NoStore,
            E::NotInStore => StoreError::NotInStore,
            E::SneakyPath => StoreError::SneakyPath,
            E::Crypto(c) => StoreError::Crypto {
                reason: c.to_string(),
            },
            E::Io(io) => StoreError::Io {
                reason: io.to_string(),
            },
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct EntryRef {
    pub name: String,
    pub hidden: bool,
}

/// A store handle. Cheap to open; holds no decrypted data, ever.
#[derive(uniffi::Object)]
pub struct PassStore {
    inner: pass_core::store::Store,
}

#[uniffi::export]
impl PassStore {
    #[uniffi::constructor]
    pub fn open(root: String, format: StoreFormat) -> Result<Arc<Self>, StoreError> {
        Ok(Arc::new(PassStore {
            inner: pass_core::store::Store::open(root, format.into())?,
        }))
    }

    /// Full index including hidden entries, byte-sorted — feeds browse,
    /// search, and the autofill identity store (names only, no secrets).
    pub fn entries(&self) -> Result<Vec<EntryRef>, StoreError> {
        Ok(self
            .inner
            .entries()?
            .into_iter()
            .map(|e| EntryRef {
                name: e.name,
                hidden: e.hidden,
            })
            .collect())
    }

    pub fn has_entry(&self, name: String) -> bool {
        self.inner.has_entry(&name)
    }

    /// Decrypt an entry. The returned bytes are the exact plaintext; the
    /// caller (Swift) is responsible for holding them briefly and clearing.
    pub fn read_entry(
        &self,
        name: String,
        backend: Arc<dyn CryptoBackend>,
    ) -> Result<Vec<u8>, StoreError> {
        let adapter = ForeignBackendAdapter(backend);
        let entry = self.inner.read_entry(&name, &adapter)?;
        Ok(entry.to_bytes().to_vec())
    }

    /// Encrypt and write entry content (full plaintext) to `name`.
    pub fn write_entry(
        &self,
        name: String,
        content: Vec<u8>,
        backend: Arc<dyn CryptoBackend>,
    ) -> Result<(), StoreError> {
        let adapter = ForeignBackendAdapter(backend);
        self.inner.write_entry(
            &name,
            &pass_core::entry::Entry::from_bytes(content),
            &adapter,
        )?;
        Ok(())
    }

    pub fn remove_entry(&self, name: String) -> Result<(), StoreError> {
        Ok(self.inner.remove_entry(&name)?)
    }

    pub fn move_entry(
        &self,
        from: String,
        to: String,
        backend: Arc<dyn CryptoBackend>,
    ) -> Result<(), StoreError> {
        let adapter = ForeignBackendAdapter(backend);
        Ok(self.inner.move_entry(&from, &to, &adapter)?)
    }

    /// Preview of what a subtree re-encrypt would rewrite.
    pub fn reencrypt_targets(&self, subpath: String) -> Result<Vec<String>, StoreError> {
        Ok(self.inner.reencrypt_targets(&subpath)?)
    }

    pub fn reencrypt_subtree(
        &self,
        subpath: String,
        backend: Arc<dyn CryptoBackend>,
    ) -> Result<Vec<String>, StoreError> {
        let adapter = ForeignBackendAdapter(backend);
        Ok(self.inner.reencrypt_subtree(&subpath, &adapter)?)
    }
}

// --- entry content helpers (pure functions over plaintext bytes) -------------

/// First line of the plaintext — the password.
#[uniffi::export]
pub fn entry_password(content: Vec<u8>) -> Vec<u8> {
    pass_core::entry::Entry::from_bytes(content)
        .password()
        .to_vec()
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct EntryField {
    pub key: String,
    pub value: String,
}

/// `key: value` lines after the first.
#[uniffi::export]
pub fn entry_fields(content: Vec<u8>) -> Vec<EntryField> {
    let entry = pass_core::entry::Entry::from_bytes(content);
    entry
        .fields()
        .into_iter()
        .map(|f| EntryField {
            key: f.key.to_owned(),
            value: f.value.to_owned(),
        })
        .collect()
}

/// Byte-faithful single-field edit; returns the new full plaintext.
#[uniffi::export]
pub fn entry_set_field(content: Vec<u8>, key: String, value: String) -> Vec<u8> {
    let mut entry = pass_core::entry::Entry::from_bytes(content);
    entry.set_field(&key, &value);
    entry.to_bytes().to_vec()
}

/// Byte-faithful password replacement; returns the new full plaintext.
#[uniffi::export]
pub fn entry_set_password(content: Vec<u8>, password: Vec<u8>) -> Vec<u8> {
    let mut entry = pass_core::entry::Entry::from_bytes(content);
    entry.set_password(&password);
    entry.to_bytes().to_vec()
}

// --- TOTP --------------------------------------------------------------------

#[derive(Debug, Clone, uniffi::Record)]
pub struct TotpCode {
    pub code: String,
    pub seconds_remaining: u64,
    pub period: u64,
    pub label: String,
}

/// Current TOTP code for an entry's plaintext, if it carries an
/// `otpauth://totp/` line. `unix_time` is passed in so the view layer owns
/// the clock (and the ring can tick without re-decrypting).
#[uniffi::export]
pub fn entry_totp(content: Vec<u8>, unix_time: u64) -> Option<TotpCode> {
    let entry = pass_core::entry::Entry::from_bytes(content);
    let uri = entry.otpauth()?;
    let totp = pass_core::totp::Totp::from_uri(uri).ok()?;
    Some(TotpCode {
        code: totp.code_at(unix_time),
        seconds_remaining: totp.seconds_remaining(unix_time),
        period: totp.period,
        label: totp.label.clone(),
    })
}

// --- git sync ----------------------------------------------------------------

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum GitError {
    #[error("no git repository")]
    NoRepository,
    #[error("no remote configured")]
    NoRemote,
    #[error("push rejected; sync first")]
    NonFastForward,
    #[error("remote history rewritten; recovery required")]
    UpstreamRewritten,
    #[error("uncommitted changes present")]
    DirtyWorkdir,
    #[error("git: {reason}")]
    Other { reason: String },
}

impl From<pass_core::git::GitError> for GitError {
    fn from(e: pass_core::git::GitError) -> Self {
        use pass_core::git::GitError as E;
        match e {
            E::NoRepository => GitError::NoRepository,
            E::NoRemote => GitError::NoRemote,
            E::NonFastForward => GitError::NonFastForward,
            E::UpstreamRewritten => GitError::UpstreamRewritten,
            E::DirtyWorkdir => GitError::DirtyWorkdir,
            other => GitError::Other {
                reason: other.to_string(),
            },
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct SyncStatus {
    pub ahead: u32,
    pub behind: u32,
    pub dirty: bool,
    pub has_remote: bool,
}

#[derive(Debug, Clone, Copy, uniffi::Enum)]
pub enum ConflictChoice {
    KeepLocal,
    KeepRemote,
    KeepBoth,
}

/// Implemented by the app: asked once per conflicted file during sync.
/// Called on the sync thread — present UI and block until the user chooses.
#[uniffi::export(with_foreign)]
pub trait ConflictResolver: Send + Sync {
    fn choose(&self, entry_path: String) -> ConflictChoice;
}

#[derive(Debug, Clone, uniffi::Enum)]
pub enum SyncOutcome {
    UpToDate,
    FastForwarded,
    Rebased {
        replayed: u32,
    },
    ResolvedConflicts {
        resolved: Vec<String>,
        kept_both: Vec<String>,
    },
}

/// Git handle for a store. Interior mutex: safe to hold alongside PassStore.
#[derive(uniffi::Object)]
pub struct GitSync {
    inner: Mutex<pass_core::git::GitStore>,
}

#[uniffi::export]
impl GitSync {
    #[uniffi::constructor]
    pub fn open(root: String) -> Result<Arc<Self>, GitError> {
        Ok(Arc::new(GitSync {
            inner: Mutex::new(pass_core::git::GitStore::open(root)?),
        }))
    }

    #[uniffi::constructor]
    pub fn init(root: String, format: StoreFormat) -> Result<Arc<Self>, GitError> {
        Ok(Arc::new(GitSync {
            inner: Mutex::new(pass_core::git::GitStore::init(root, format.into())?),
        }))
    }

    #[uniffi::constructor]
    pub fn clone_from(
        url: String,
        dest: String,
        depth: Option<i32>,
    ) -> Result<Arc<Self>, GitError> {
        Ok(Arc::new(GitSync {
            inner: Mutex::new(pass_core::git::GitStore::clone_from(&url, dest, depth)?),
        }))
    }

    pub fn status(&self) -> Result<SyncStatus, GitError> {
        let st = self.inner.lock().unwrap().status()?;
        Ok(SyncStatus {
            ahead: st.ahead as u32,
            behind: st.behind as u32,
            dirty: st.dirty,
            has_remote: st.has_remote,
        })
    }

    /// Stage the given store-relative file paths and commit.
    pub fn commit_paths(&self, paths: Vec<String>, message: String) -> Result<(), GitError> {
        let refs: Vec<&str> = paths.iter().map(String::as_str).collect();
        self.inner.lock().unwrap().commit_paths(&refs, &message)?;
        Ok(())
    }

    pub fn sync(&self, resolver: Arc<dyn ConflictResolver>) -> Result<SyncOutcome, GitError> {
        let mut cb = |path: &str| match resolver.choose(path.to_owned()) {
            ConflictChoice::KeepLocal => pass_core::git::ConflictChoice::KeepLocal,
            ConflictChoice::KeepRemote => pass_core::git::ConflictChoice::KeepRemote,
            ConflictChoice::KeepBoth => pass_core::git::ConflictChoice::KeepBoth,
        };
        let outcome = self.inner.lock().unwrap().sync(&mut cb)?;
        Ok(match outcome {
            pass_core::git::SyncOutcome::UpToDate => SyncOutcome::UpToDate,
            pass_core::git::SyncOutcome::FastForwarded => SyncOutcome::FastForwarded,
            pass_core::git::SyncOutcome::Rebased { replayed } => SyncOutcome::Rebased {
                replayed: replayed as u32,
            },
            pass_core::git::SyncOutcome::ResolvedConflicts {
                resolved,
                kept_both,
            } => SyncOutcome::ResolvedConflicts {
                resolved,
                kept_both,
            },
        })
    }

    pub fn push(&self) -> Result<(), GitError> {
        self.inner.lock().unwrap().push()?;
        Ok(())
    }

    /// Create or repoint the `origin` remote — the publish-existing-store
    /// flow is init → set_remote → push.
    pub fn set_remote(&self, url: String) -> Result<(), GitError> {
        self.inner.lock().unwrap().set_remote(&url)?;
        Ok(())
    }

    /// The `origin` remote's URL, if configured. May contain embedded
    /// credentials — redact userinfo before displaying.
    pub fn remote_url(&self) -> Option<String> {
        self.inner.lock().unwrap().remote_url()
    }
}

/// CLI-style commit messages so PassPony stores read naturally in `git log`.
#[uniffi::export]
pub fn commit_message_add(name: String) -> String {
    pass_core::git::messages::add(&name)
}

#[uniffi::export]
pub fn commit_message_edit(name: String) -> String {
    pass_core::git::messages::edit(&name)
}

#[uniffi::export]
pub fn commit_message_remove(name: String) -> String {
    pass_core::git::messages::remove(&name)
}

#[uniffi::export]
pub fn commit_message_rename(from: String, to: String) -> String {
    pass_core::git::messages::rename(&from, &to)
}

#[uniffi::export]
pub fn commit_message_reencrypt(path: String) -> String {
    pass_core::git::messages::reencrypt(&path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CryptoError;

    struct FlipEngine;
    impl CryptoBackend for FlipEngine {
        fn encrypt(
            &self,
            plaintext: Vec<u8>,
            _recipients: Vec<String>,
        ) -> Result<Vec<u8>, CryptoError> {
            Ok(plaintext.iter().map(|b| !b).collect())
        }
        fn decrypt(&self, ciphertext: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
            Ok(ciphertext.iter().map(|b| !b).collect())
        }
    }

    #[test]
    fn store_object_round_trips_through_ffi_surface() {
        let dir = std::env::temp_dir().join("passpony-ffi-store");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let store =
            PassStore::open(dir.to_string_lossy().into_owned(), StoreFormat::Passage).unwrap();
        let backend: Arc<dyn CryptoBackend> = Arc::new(FlipEngine);
        let content = b"pw\nusername: kevin\notpauth://totp/X?secret=JBSWY3DPEHPK3PXP\n".to_vec();
        store
            .write_entry("web/example".into(), content.clone(), backend.clone())
            .unwrap();
        let read = store.read_entry("web/example".into(), backend).unwrap();
        assert_eq!(read, content);
        assert_eq!(entry_password(read.clone()), b"pw");
        assert_eq!(entry_fields(read.clone()).len(), 1);
        let totp = entry_totp(read, 59).unwrap();
        assert_eq!(totp.code.len(), 6);
        assert_eq!(totp.seconds_remaining, 1);
        let names: Vec<String> = store
            .entries()
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert_eq!(names, vec!["web/example".to_string()]);
    }
}
