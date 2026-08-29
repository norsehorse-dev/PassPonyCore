//! The app-facing FFI surface: store, git sync, TOTP, password generator.
//! Thin translation over pass-core; no logic lives here.

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

    /// Full index including hidden entries, byte-sorted; feeds browse,
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

/// First line of the plaintext: the password.
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

/// Byte-faithful `otpauth://` line set (replace the first URI line's text, or
/// append one); returns the new full plaintext. `uri` should come from
/// [`totp_build_uri`] or have passed [`totp_describe`].
#[uniffi::export]
pub fn entry_set_otpauth(content: Vec<u8>, uri: String) -> Vec<u8> {
    let mut entry = pass_core::entry::Entry::from_bytes(content);
    entry.set_otpauth(&uri);
    entry.to_bytes().to_vec()
}

/// Remove the first `otpauth://` line with its line ending; returns the new
/// full plaintext. The bytes come back unchanged when there is no URI or the
/// URI is line 1 (an OTP-only entry is deleted whole, never edited; see
/// [`entry_is_otp_only`]).
#[uniffi::export]
pub fn entry_remove_otpauth(content: Vec<u8>) -> Vec<u8> {
    let mut entry = pass_core::entry::Entry::from_bytes(content);
    entry.remove_otpauth();
    entry.to_bytes().to_vec()
}

/// True when line 1 is the `otpauth://` URI (what `pass otp insert` writes),
/// so the UI shows the code and no password row.
#[uniffi::export]
pub fn entry_is_otp_only(content: Vec<u8>) -> bool {
    pass_core::entry::Entry::from_bytes(content).is_otp_only()
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
/// `otpauth://totp/` line (any line, line 1 included, first match wins).
/// `unix_time` is passed in so the view layer owns the clock (and the ring
/// can tick without re-decrypting).
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum TotpAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl From<TotpAlgorithm> for pass_core::totp::TotpAlgorithm {
    fn from(a: TotpAlgorithm) -> Self {
        match a {
            TotpAlgorithm::Sha1 => pass_core::totp::TotpAlgorithm::Sha1,
            TotpAlgorithm::Sha256 => pass_core::totp::TotpAlgorithm::Sha256,
            TotpAlgorithm::Sha512 => pass_core::totp::TotpAlgorithm::Sha512,
        }
    }
}

impl From<pass_core::totp::TotpAlgorithm> for TotpAlgorithm {
    fn from(a: pass_core::totp::TotpAlgorithm) -> Self {
        match a {
            pass_core::totp::TotpAlgorithm::Sha1 => TotpAlgorithm::Sha1,
            pass_core::totp::TotpAlgorithm::Sha256 => TotpAlgorithm::Sha256,
            pass_core::totp::TotpAlgorithm::Sha512 => TotpAlgorithm::Sha512,
        }
    }
}

/// Everything about a code except its secret, for the edit screen's
/// "GitHub (kevin), 6 digits, 30 s" line and for validating a pasted or
/// scanned URI before it is written.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct TotpSummary {
    pub label: String,
    pub issuer: Option<String>,
    pub algorithm: TotpAlgorithm,
    pub digits: u32,
    pub period: u64,
}

impl From<&pass_core::totp::Totp> for TotpSummary {
    fn from(t: &pass_core::totp::Totp) -> Self {
        TotpSummary {
            label: t.label.clone(),
            issuer: t.issuer.clone(),
            algorithm: t.algorithm.into(),
            digits: t.digits,
            period: t.period,
        }
    }
}

/// Why a URI or a typed key was rejected. Variants carry no secret material.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum TotpError {
    #[error("not an otpauth:// totp URI")]
    NotTotpUri,
    #[error("missing secret")]
    MissingSecret,
    #[error("secret is not valid base32")]
    BadSecret,
    #[error("unsupported algorithm: {name}")]
    BadAlgorithm { name: String },
    #[error("invalid number: {detail}")]
    BadNumber { detail: String },
}

impl From<pass_core::totp::TotpError> for TotpError {
    fn from(e: pass_core::totp::TotpError) -> Self {
        use pass_core::totp::TotpError as E;
        match e {
            E::NotTotpUri => TotpError::NotTotpUri,
            E::MissingSecret => TotpError::MissingSecret,
            E::BadSecret => TotpError::BadSecret,
            E::BadAlgorithm(name) => TotpError::BadAlgorithm { name },
            E::BadNumber(detail) => TotpError::BadNumber { detail },
        }
    }
}

/// The entry's code configuration without its secret, if the entry carries
/// a parsable `otpauth://totp/` line.
#[uniffi::export]
pub fn entry_totp_summary(content: Vec<u8>) -> Option<TotpSummary> {
    let entry = pass_core::entry::Entry::from_bytes(content);
    let uri = entry.otpauth()?;
    let totp = pass_core::totp::Totp::from_uri(uri).ok()?;
    Some((&totp).into())
}

/// Validate a pasted or scanned URI and describe it. HOTP and
/// `otpauth-migration://` URIs fail with `NotTotpUri`.
#[uniffi::export]
pub fn totp_describe(uri: String) -> Result<TotpSummary, TotpError> {
    let totp = pass_core::totp::Totp::from_uri(uri.trim())?;
    Ok((&totp).into())
}

/// Check a typed base32 secret as the user goes; returns its decoded length
/// in bytes.
#[uniffi::export]
pub fn totp_validate_secret(secret: String) -> Result<u32, TotpError> {
    let len = pass_core::totp::validate_secret(&secret)?;
    Ok(u32::try_from(len).unwrap_or(u32::MAX))
}

/// Build the canonical `otpauth://totp/` URI from the manual form. Digits
/// must be 6 to 8; period at least 1. Defaults (SHA1, 6, 30) are omitted
/// from the URI, so the same inputs give the same line on every platform.
#[uniffi::export]
pub fn totp_build_uri(
    secret: String,
    account: String,
    issuer: Option<String>,
    algorithm: TotpAlgorithm,
    digits: u32,
    period: u64,
) -> Result<String, TotpError> {
    let totp = pass_core::totp::Totp::new(
        &secret,
        &account,
        issuer.as_deref(),
        algorithm.into(),
        digits,
        period,
    )?;
    Ok(totp.to_uri())
}

// --- password generator ------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum SymbolSet {
    /// Letters and digits only (`pass generate --no-symbols`).
    NoSymbols,
    /// The portal-safe punctuation subset.
    Basic,
    /// All 32 printable ASCII punctuation characters, the pass default.
    Full,
}

impl From<SymbolSet> for pass_core::generate::SymbolSet {
    fn from(s: SymbolSet) -> Self {
        match s {
            SymbolSet::NoSymbols => pass_core::generate::SymbolSet::None,
            SymbolSet::Basic => pass_core::generate::SymbolSet::Basic,
            SymbolSet::Full => pass_core::generate::SymbolSet::Full,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct GeneratorSpec {
    pub length: u32,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: SymbolSet,
}

impl From<GeneratorSpec> for pass_core::generate::GeneratorSpec {
    fn from(s: GeneratorSpec) -> Self {
        pass_core::generate::GeneratorSpec {
            length: s.length,
            lowercase: s.lowercase,
            uppercase: s.uppercase,
            digits: s.digits,
            symbols: s.symbols.into(),
        }
    }
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum GenerateError {
    #[error("length must be between {min} and {max}")]
    BadLength { min: u32, max: u32 },
    #[error("at least one character class must be enabled")]
    NoClasses,
    #[error("no entropy source: {reason}")]
    Entropy { reason: String },
}

impl From<pass_core::generate::GenerateError> for GenerateError {
    fn from(e: pass_core::generate::GenerateError) -> Self {
        use pass_core::generate::GenerateError as E;
        match e {
            E::BadLength => GenerateError::BadLength {
                min: pass_core::generate::MIN_LENGTH,
                max: pass_core::generate::MAX_LENGTH,
            },
            E::NoClasses => GenerateError::NoClasses,
            E::Entropy(reason) => GenerateError::Entropy { reason },
        }
    }
}

/// pass's `generate` defaults: 25 characters, every class, full symbols.
/// What a fresh install uses until the user changes something.
#[uniffi::export]
pub fn generator_pass_default() -> GeneratorSpec {
    GeneratorSpec {
        length: pass_core::generate::DEFAULT_LENGTH,
        lowercase: true,
        uppercase: true,
        digits: true,
        symbols: SymbolSet::Full,
    }
}

/// The punctuation a symbol set contributes, for showing under the picker.
#[uniffi::export]
pub fn generator_symbols(set: SymbolSet) -> String {
    match set {
        SymbolSet::NoSymbols => String::new(),
        SymbolSet::Basic => pass_core::generate::SYMBOLS_BASIC.to_owned(),
        SymbolSet::Full => pass_core::generate::SYMBOLS_FULL.to_owned(),
    }
}

/// The full alphabet a spec draws from (for previews and parity tests).
#[uniffi::export]
pub fn generator_charset(spec: GeneratorSpec) -> Result<String, GenerateError> {
    Ok(pass_core::generate::charset(&spec.into())?)
}

/// A new password from OS entropy, every enabled class present at least once.
#[uniffi::export]
pub fn generate_password(spec: GeneratorSpec) -> Result<String, GenerateError> {
    Ok(pass_core::generate::generate(&spec.into())?)
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
/// Called on the sync thread: present UI and block until the user chooses.
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

    /// Create or repoint the `origin` remote; the publish-existing-store
    /// flow is init → set_remote → push.
    pub fn set_remote(&self, url: String) -> Result<(), GitError> {
        self.inner.lock().unwrap().set_remote(&url)?;
        Ok(())
    }

    /// The `origin` remote's URL, if configured. May contain embedded
    /// credentials; redact userinfo before displaying.
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

    #[test]
    fn otp_helpers_over_the_ffi_surface() {
        let uri = totp_build_uri(
            "jbsw y3dp ehpk 3pxp".into(),
            "kevin".into(),
            Some("Example".into()),
            TotpAlgorithm::Sha1,
            6,
            30,
        )
        .unwrap();
        assert_eq!(
            uri,
            "otpauth://totp/Example:kevin?secret=JBSWY3DPEHPK3PXP&issuer=Example"
        );
        let summary = totp_describe(format!("  {uri}\n")).unwrap();
        assert_eq!(summary.label, "Example:kevin");
        assert_eq!(summary.issuer.as_deref(), Some("Example"));
        assert_eq!(summary.algorithm, TotpAlgorithm::Sha1);
        assert_eq!((summary.digits, summary.period), (6, 30));
        assert!(matches!(
            totp_describe("otpauth://hotp/X?secret=JBSWY3DP".into()),
            Err(TotpError::NotTotpUri)
        ));
        assert!(matches!(
            totp_build_uri("".into(), "k".into(), None, TotpAlgorithm::Sha1, 6, 30),
            Err(TotpError::MissingSecret)
        ));
        assert_eq!(totp_validate_secret("JBSWY3DPEHPK3PXP".into()).unwrap(), 10);

        // Append to a plain entry, read it back, replace, remove.
        let plain = b"pw\nusername: kevin\n".to_vec();
        assert!(entry_totp_summary(plain.clone()).is_none());
        assert!(!entry_is_otp_only(plain.clone()));
        let with_otp = entry_set_otpauth(plain.clone(), uri.clone());
        assert_eq!(
            with_otp,
            format!("pw\nusername: kevin\n{uri}\n").into_bytes()
        );
        assert_eq!(entry_totp_summary(with_otp.clone()).unwrap(), summary);
        assert!(entry_totp(with_otp.clone(), 59).is_some());
        let uri2 = "otpauth://totp/Other?secret=MZXW6YTBOI".to_string();
        let replaced = entry_set_otpauth(with_otp.clone(), uri2.clone());
        assert_eq!(
            replaced,
            format!("pw\nusername: kevin\n{uri2}\n").into_bytes()
        );
        assert_eq!(entry_remove_otpauth(replaced), plain);

        // An OTP-only entry (line 1 is the URI) reads as a code and refuses
        // removal.
        let otp_only = format!("{uri}\n").into_bytes();
        assert!(entry_is_otp_only(otp_only.clone()));
        assert!(entry_totp(otp_only.clone(), 59).is_some());
        assert_eq!(entry_remove_otpauth(otp_only.clone()), otp_only);
    }

    #[test]
    fn generator_over_the_ffi_surface() {
        let spec = generator_pass_default();
        assert_eq!(spec.length, 25);
        assert_eq!(
            generator_charset(spec.clone()).unwrap(),
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
        );
        let pw = generate_password(spec).unwrap();
        assert_eq!(pw.len(), 25);
        let portal = GeneratorSpec {
            length: 19,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: SymbolSet::Basic,
        };
        let pw = generate_password(portal).unwrap();
        assert_eq!(pw.len(), 19);
        assert_eq!(generator_symbols(SymbolSet::Basic), "!#$%&()*+,-.=?@_");
        assert_eq!(generator_symbols(SymbolSet::NoSymbols), "");
        assert!(matches!(
            generate_password(GeneratorSpec {
                length: 4,
                lowercase: true,
                uppercase: true,
                digits: true,
                symbols: SymbolSet::Full,
            }),
            Err(GenerateError::BadLength { min: 8, max: 128 })
        ));
        assert!(matches!(
            generate_password(GeneratorSpec {
                length: 20,
                lowercase: false,
                uppercase: false,
                digits: false,
                symbols: SymbolSet::NoSymbols,
            }),
            Err(GenerateError::NoClasses)
        ));
    }
}
