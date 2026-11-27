//! Store model: formats, tree walk, entry index, recipient resolution, and
//! the read path.
//!
//! Behavioral references: pass 1.7.x and the passage script (v1.7.4 fork,
//! pinned commit in fixtures/gen-fixtures.sh). See
//! docs/passage-store-semantics.md; the fixture corpus is ground truth.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::crypto::CryptoBackend;
use crate::entry::Entry;
use crate::fs::{self, FsError, StdFs, StoreFs};

/// Which flavor of store this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreFormat {
    /// Classic pass: OpenPGP, `.gpg` files, per-directory `.gpg-id`.
    Pass,
    /// passage: age, `.age` files, per-directory `.age-recipients`.
    Passage,
}

impl StoreFormat {
    /// File extension for encrypted entries, without the leading dot.
    pub fn entry_extension(self) -> &'static str {
        match self {
            StoreFormat::Pass => "gpg",
            StoreFormat::Passage => "age",
        }
    }

    /// Name of the per-directory recipients file, resolved nearest-ancestor.
    pub fn recipients_file_name(self) -> &'static str {
        match self {
            StoreFormat::Pass => ".gpg-id",
            StoreFormat::Passage => ".age-recipients",
        }
    }

    /// Default store location relative to `$HOME`.
    pub fn default_store_dir(self) -> &'static str {
        match self {
            StoreFormat::Pass => ".password-store",
            StoreFormat::Passage => ".passage/store",
        }
    }

    /// Header line the CLI prints for a root listing.
    pub fn ls_header(self) -> &'static str {
        match self {
            StoreFormat::Pass => "Password Store",
            StoreFormat::Passage => "Passage",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("store root does not exist or is not a directory")]
    NoStore,
    #[error("entry is not in the password store")]
    NotInStore,
    #[error("sneaky path rejected")]
    SneakyPath,
    /// `add_entry` found an entry already saved under that name (3.0).
    /// Nothing was written.
    #[error("an entry with this name already exists")]
    EntryExists,
    /// The store's folder is gone or the permission to use it was taken
    /// away (3.0, folder stores). Not an ordinary I/O failure: the app asks
    /// for the folder again instead of showing an empty store.
    #[error("the store's folder is no longer available")]
    FolderUnavailable,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Crypto(#[from] crate::crypto::CryptoError),
}

impl From<FsError> for StoreError {
    fn from(e: FsError) -> Self {
        match e {
            FsError::NotFound => StoreError::Io(std::io::ErrorKind::NotFound.into()),
            FsError::AccessLost => StoreError::FolderUnavailable,
            FsError::Other(message) => StoreError::Io(std::io::Error::other(message)),
        }
    }
}

/// Reject path arguments containing `..` components, mirroring the CLIs'
/// `check_sneaky_paths` (which blocks only `..` — leading dots and `.`
/// components are allowed, and that leniency is part of the compat surface).
pub fn is_sneaky_path(path: &str) -> bool {
    path == ".." || path.starts_with("../") || path.ends_with("/..") || path.contains("/../")
}

/// An entry in the index: relative name without extension, `/`-separated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryRef {
    pub name: String,
    /// True if any path component starts with `.` — such entries exist and
    /// decrypt fine, but `ls`/`find` hide them (tree runs without `-a`).
    pub hidden: bool,
}

/// One directory level of the store tree, mirroring what `tree` sees.
#[derive(Debug, Default)]
pub struct DirNode {
    /// Visible child directories, byte-sorted.
    pub dirs: Vec<(String, DirNode)>,
    /// Visible entry names at this level (extension stripped), byte-sorted.
    pub entries: Vec<String>,
}

/// How to encrypt for a given path — resolved but not interpreted; recipient
/// strings and files are opaque to pass-core (crypto is the backend's job).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecipientSource {
    /// pass: parsed IDs from the nearest `.gpg-id` (comments and blank lines
    /// stripped, as the CLI does).
    Ids(Vec<String>),
    /// passage: store-relative path of the nearest `.age-recipients` (the
    /// CLI passes the file to `age -R` unparsed).
    /// `Store::encryption_recipients` reads it.
    RecipientsFile(String),
    /// passage with no `.age-recipients` anywhere up the tree: recipients are
    /// derived from the identities file (`age -e -i identities`).
    IdentitiesFallback,
    /// pass with no `.gpg-id` up the tree: the CLI refuses to operate.
    Uninitialized,
}

/// What `Store::reencrypt_readable` did: the entries rewritten, and how
/// many it could not open and left alone.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReencryptReport {
    pub rewritten: Vec<String>,
    pub skipped: u32,
}

pub struct Store {
    fs: Arc<dyn StoreFs>,
    /// The directory of a store opened by path; empty for `with_fs`.
    root: PathBuf,
    format: StoreFormat,
}

impl Store {
    /// A store in an ordinary directory.
    pub fn open(root: impl Into<PathBuf>, format: StoreFormat) -> Result<Self, StoreError> {
        let root = root.into();
        if !root.is_dir() {
            return Err(StoreError::NoStore);
        }
        Ok(Store {
            fs: Arc::new(StdFs::new(root.clone())),
            root,
            format,
        })
    }

    /// 3.0: a store reached through a file layer the platform supplies, for
    /// a folder a plain path cannot reach. Such a store has no git.
    pub fn with_fs(fs: Arc<dyn StoreFs>, format: StoreFormat) -> Result<Self, StoreError> {
        match fs.list("") {
            Ok(_) => {}
            Err(FsError::NotFound) => return Err(StoreError::NoStore),
            Err(e) => return Err(e.into()),
        }
        Ok(Store {
            fs,
            root: PathBuf::new(),
            format,
        })
    }

    /// The store's directory. Empty for a store opened with `with_fs`,
    /// which has no path.
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn format(&self) -> StoreFormat {
        self.format
    }

    /// Make the directory a file goes in, unless that is the store root.
    fn ensure_parent(&self, file: &str) -> Result<(), StoreError> {
        match fs::parent(file) {
            "" => Ok(()),
            dir => Ok(self.fs.create_dir_all(dir)?),
        }
    }

    /// Store-relative path of the entry's file.
    fn entry_file(&self, name: &str) -> Result<String, StoreError> {
        if is_sneaky_path(name) {
            return Err(StoreError::SneakyPath);
        }
        Ok(format!("{name}.{}", self.format.entry_extension()))
    }

    pub fn has_entry(&self, name: &str) -> bool {
        matches!(self.entry_file(name), Ok(p) if self.fs.is_file(&p).unwrap_or(false))
    }

    /// Walk the store, building the visible tree (what `ls` shows): dot-named
    /// files and directories excluded, `.git` excluded, extensions stripped.
    pub fn tree(&self) -> Result<DirNode, StoreError> {
        self.walk_dir("")
    }

    fn walk_dir(&self, dir: &str) -> Result<DirNode, StoreError> {
        let ext = format!(".{}", self.format.entry_extension());
        let mut node = DirNode::default();
        for child in self.fs.list(dir)? {
            if child.name.starts_with('.') {
                continue; // includes .git, .gpg-id, .age-recipients, dot entries
            }
            if child.is_dir {
                let sub = self.walk_dir(&fs::join(dir, &child.name))?;
                node.dirs.push((child.name, sub));
            } else if let Some(stripped) = child.name.strip_suffix(&ext) {
                node.entries.push(stripped.to_owned());
            }
        }
        node.dirs.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
        node.entries.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        Ok(node)
    }

    /// Every entry including hidden ones — the index autofill and search use.
    /// Names byte-sorted.
    pub fn entries(&self) -> Result<Vec<EntryRef>, StoreError> {
        let ext = format!(".{}", self.format.entry_extension());
        let mut out = Vec::new();
        self.collect_entries("", &ext, &mut out)?;
        out.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
        Ok(out)
    }

    fn collect_entries(
        &self,
        dir: &str,
        ext: &str,
        out: &mut Vec<EntryRef>,
    ) -> Result<(), StoreError> {
        for child in self.fs.list(dir)? {
            if child.name == ".git" {
                continue;
            }
            let rel = fs::join(dir, &child.name);
            if child.is_dir {
                self.collect_entries(&rel, ext, out)?;
            } else if let Some(stripped) = rel.strip_suffix(ext) {
                let hidden = stripped.split('/').any(|c| c.starts_with('.'));
                out.push(EntryRef {
                    name: stripped.to_owned(),
                    hidden,
                });
            }
        }
        Ok(())
    }

    /// Decrypt an entry through the backend. File beats directory, as in the
    /// CLIs: `show foo` finds `foo.gpg` even when directory `foo/` exists.
    pub fn read_entry(&self, name: &str, backend: &dyn CryptoBackend) -> Result<Entry, StoreError> {
        let file = self.entry_file(name)?;
        if !self.fs.is_file(&file)? {
            return Err(StoreError::NotInStore);
        }
        let ciphertext = self.fs.read(&file)?;
        let plaintext = backend.decrypt(&ciphertext)?;
        Ok(Entry::from_bytes(plaintext.to_vec()))
    }

    /// Encrypt `entry` to the recipients resolved for `name` and write it
    /// atomically, creating parent directories as needed. Mirrors
    /// `pass insert -f` / `passage insert -f`: an entry already saved under
    /// `name` is replaced. Use [`Store::add_entry`] for a new entry.
    pub fn write_entry(
        &self,
        name: &str,
        entry: &Entry,
        backend: &dyn CryptoBackend,
    ) -> Result<(), StoreError> {
        let recipients = self.recipients_for(name)?;
        let ciphertext = backend.encrypt(entry.to_bytes(), &recipients)?;
        let file = self.entry_file(name)?;
        self.ensure_parent(&file)?;
        Ok(self.fs.write(&file, &ciphertext)?)
    }

    /// 3.0: write a new entry, refusing with [`StoreError::EntryExists`]
    /// when one is already saved under `name`, so adding can never replace
    /// an entry by accident. The check and the write are one call on
    /// purpose: a caller cannot do one and forget the other. On a file
    /// system that ignores case, a name that differs only by case counts as
    /// taken, because it is the same file. A directory with the same name
    /// is not in the way; `web` and `web/site` live side by side, as in the
    /// CLIs.
    pub fn add_entry(
        &self,
        name: &str,
        entry: &Entry,
        backend: &dyn CryptoBackend,
    ) -> Result<(), StoreError> {
        if self.fs.is_file(&self.entry_file(name)?)? {
            return Err(StoreError::EntryExists);
        }
        self.write_entry(name, entry, backend)
    }

    /// Remove an entry and prune newly-empty parent directories up to the
    /// store root (the CLIs run `rmdir -p`). Recipients files keep a
    /// directory alive, matching the CLIs.
    pub fn remove_entry(&self, name: &str) -> Result<(), StoreError> {
        let file = self.entry_file(name)?;
        if !self.fs.is_file(&file)? {
            return Err(StoreError::NotInStore);
        }
        self.fs.remove_file(&file)?;
        let mut dir = fs::parent(&file);
        while !dir.is_empty() {
            // Looked at here as well as in `remove_dir`, because a file
            // layer whose delete is recursive would take the entries along.
            match self.fs.list(dir) {
                Ok(children) if children.is_empty() => {}
                _ => break, // not empty (or gone) — stop pruning
            }
            if self.fs.remove_dir(dir).is_err() {
                break;
            }
            dir = fs::parent(dir);
        }
        Ok(())
    }

    /// Move an entry. passage semantics: the destination is always
    /// re-encrypted. pass semantics: re-encrypt only when the resolved
    /// recipient set differs between source and destination (otherwise a
    /// plain rename, ciphertext bytes untouched).
    pub fn move_entry(
        &self,
        from: &str,
        to: &str,
        backend: &dyn CryptoBackend,
    ) -> Result<(), StoreError> {
        self.transfer_entry(from, to, backend, true)
    }

    /// Copy an entry; re-encryption rules as in [`Store::move_entry`].
    pub fn copy_entry(
        &self,
        from: &str,
        to: &str,
        backend: &dyn CryptoBackend,
    ) -> Result<(), StoreError> {
        self.transfer_entry(from, to, backend, false)
    }

    fn transfer_entry(
        &self,
        from: &str,
        to: &str,
        backend: &dyn CryptoBackend,
        remove_source: bool,
    ) -> Result<(), StoreError> {
        let src = self.entry_file(from)?;
        if !self.fs.is_file(&src)? {
            return Err(StoreError::NotInStore);
        }
        let dst = self.entry_file(to)?;
        self.ensure_parent(&dst)?;
        let must_reencrypt = match self.format {
            StoreFormat::Passage => true,
            StoreFormat::Pass => self.resolve_recipients(from)? != self.resolve_recipients(to)?,
        };
        let ciphertext = self.fs.read(&src)?;
        if must_reencrypt {
            let plaintext = backend.decrypt(&ciphertext)?;
            let recipients = self.recipients_for(to)?;
            self.fs
                .write(&dst, &backend.encrypt(&plaintext, &recipients)?)?;
        } else {
            self.fs.write(&dst, &ciphertext)?;
        }
        if remove_source {
            self.remove_entry(from)?;
        }
        Ok(())
    }

    /// Entries that a re-encrypt of `subpath` ("" for the whole store) would
    /// rewrite — the preview the UX shows before mirroring `pass init -p` /
    /// `passage reencrypt -p`.
    pub fn reencrypt_targets(&self, subpath: &str) -> Result<Vec<String>, StoreError> {
        if is_sneaky_path(subpath) {
            return Err(StoreError::SneakyPath);
        }
        let prefix = if subpath.is_empty() {
            String::new()
        } else {
            format!("{}/", subpath.trim_end_matches('/'))
        };
        Ok(self
            .entries()?
            .into_iter()
            .map(|e| e.name)
            .filter(|n| prefix.is_empty() || n.starts_with(&prefix))
            .collect())
    }

    /// Decrypt and re-encrypt every entry under `subpath` to its currently
    /// resolved recipient set. Unconditional, like passage (pass skips
    /// entries whose key set is already current; rewriting them anyway is
    /// compatible — the CLIs read the result either way).
    pub fn reencrypt_subtree(
        &self,
        subpath: &str,
        backend: &dyn CryptoBackend,
    ) -> Result<Vec<String>, StoreError> {
        let targets = self.reencrypt_targets(subpath)?;
        for name in &targets {
            let file = self.entry_file(name)?;
            let plaintext = backend.decrypt(&self.fs.read(&file)?)?;
            let recipients = self.recipients_for(name)?;
            let ciphertext = backend.encrypt(&plaintext, &recipients)?;
            self.fs.write(&file, &ciphertext)?;
        }
        Ok(targets)
    }

    /// 2.0 rc4: like `reencrypt_subtree`, but an entry this device's keys
    /// cannot open is left exactly as it is and counted, instead of
    /// stopping the run. A phone that just joined a store can then
    /// re-encrypt what it wrote itself, and a phone that can read
    /// everything still rewrites everything. Any other failure stops it.
    pub fn reencrypt_readable(
        &self,
        subpath: &str,
        backend: &dyn CryptoBackend,
    ) -> Result<ReencryptReport, StoreError> {
        use crate::crypto::CryptoError;
        let mut report = ReencryptReport::default();
        for name in self.reencrypt_targets(subpath)? {
            let file = self.entry_file(&name)?;
            let plaintext = match backend.decrypt(&self.fs.read(&file)?) {
                Ok(p) => p,
                Err(CryptoError::DecryptionFailed) | Err(CryptoError::NoUsableKey) => {
                    report.skipped += 1;
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            let recipients = self.recipients_for(&name)?;
            let ciphertext = backend.encrypt(&plaintext, &recipients)?;
            self.fs.write(&file, &ciphertext)?;
            report.rewritten.push(name);
        }
        Ok(report)
    }

    fn read_text(&self, path: &str) -> Result<String, StoreError> {
        String::from_utf8(self.fs.read(path)?)
            .map_err(|e| StoreError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))
    }

    /// The root recipients file's text (`.age-recipients` or `.gpg-id`),
    /// or `None` when the store has none.
    pub fn root_recipients(&self) -> Result<Option<String>, StoreError> {
        let path = self.format.recipients_file_name();
        if !self.fs.is_file(path)? {
            return Ok(None);
        }
        Ok(Some(self.read_text(path)?))
    }

    /// Replace the root recipients file, atomically.
    pub fn set_root_recipients(&self, text: &str) -> Result<(), StoreError> {
        Ok(self
            .fs
            .write(self.format.recipients_file_name(), text.as_bytes())?)
    }

    /// Resolve the recipient source for (the directory containing) `name`,
    /// walking nearest-ancestor from the entry's directory to the store root.
    /// Env overrides (`PASSWORD_STORE_KEY`, `PASSAGE_RECIPIENTS*`) are the
    /// caller's concern; this resolves the on-disk state only.
    pub fn resolve_recipients(&self, name: &str) -> Result<RecipientSource, StoreError> {
        if is_sneaky_path(name) {
            return Err(StoreError::SneakyPath);
        }
        let mut dir = fs::parent(name);
        loop {
            let candidate = fs::join(dir, self.format.recipients_file_name());
            if self.fs.is_file(&candidate)? {
                return Ok(match self.format {
                    StoreFormat::Passage => RecipientSource::RecipientsFile(candidate),
                    StoreFormat::Pass => {
                        RecipientSource::Ids(parse_gpg_id(&self.read_text(&candidate)?))
                    }
                });
            }
            if dir.is_empty() {
                break;
            }
            dir = fs::parent(dir);
        }
        Ok(match self.format {
            StoreFormat::Passage => RecipientSource::IdentitiesFallback,
            StoreFormat::Pass => RecipientSource::Uninitialized,
        })
    }

    /// The recipient strings to hand a backend's `encrypt` for a resolved
    /// source. `Some(vec![])` means "no explicit recipients — encrypt to
    /// your own identities" (passage's identities-fallback branch); `None`
    /// means encryption is impossible (pass without any `.gpg-id`).
    ///
    /// An `.age-recipients` file is parsed the way age itself reads `-R`
    /// files: one recipient per line, blank lines and `#` comments skipped.
    pub fn encryption_recipients(
        &self,
        source: &RecipientSource,
    ) -> Result<Option<Vec<String>>, StoreError> {
        Ok(match source {
            RecipientSource::Ids(ids) => Some(ids.clone()),
            RecipientSource::RecipientsFile(path) => Some(
                self.read_text(path)?
                    .lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                    .map(str::to_owned)
                    .collect(),
            ),
            RecipientSource::IdentitiesFallback => Some(Vec::new()),
            RecipientSource::Uninitialized => None,
        })
    }

    /// The recipients an entry saved as `name` is encrypted to.
    fn recipients_for(&self, name: &str) -> Result<Vec<String>, StoreError> {
        let source = self.resolve_recipients(name)?;
        Ok(self
            .encryption_recipients(&source)?
            .ok_or(crate::crypto::CryptoError::NoUsableKey)?)
    }
}

/// Parse a `.gpg-id` file the way pass does: per line, strip everything from
/// the first `#`, then skip lines that end up empty. pass uses a shell
/// `read -r` loop, so a final line without a trailing newline is *dropped* —
/// we preserve that quirk deliberately.
fn parse_gpg_id(raw: &str) -> Vec<String> {
    let mut ids = Vec::new();
    let mut rest = raw;
    while let Some(idx) = rest.find('\n') {
        let line = &rest[..idx];
        rest = &rest[idx + 1..];
        let line = line.split('#').next().unwrap_or("").trim();
        if !line.is_empty() {
            ids.push(line.to_owned());
        }
    }
    // `rest` now holds any final unterminated line — dropped, as in the CLI.
    ids
}

/// Render the visible tree the way `pass ls` / `passage` do: the format's
/// header line, then tree(1)-style connectors. Byte-order sorting, dirs and
/// entries interleaved.
pub fn render_ls(store: &Store) -> Result<String, StoreError> {
    let tree = store.tree()?;
    let mut out = String::new();
    out.push_str(store.format().ls_header());
    out.push('\n');
    render_node(&tree, "", &mut out);
    Ok(out)
}

fn render_node(node: &DirNode, indent: &str, out: &mut String) {
    enum Item<'a> {
        Dir(&'a str, &'a DirNode),
        Entry(&'a str),
    }
    let mut items: Vec<Item> = node
        .dirs
        .iter()
        .map(|(n, d)| Item::Dir(n, d))
        .chain(node.entries.iter().map(|n| Item::Entry(n)))
        .collect();
    items.sort_by(|a, b| {
        let ka = match a {
            Item::Dir(n, _) | Item::Entry(n) => n.as_bytes(),
        };
        let kb = match b {
            Item::Dir(n, _) | Item::Entry(n) => n.as_bytes(),
        };
        ka.cmp(kb)
    });
    let last = items.len().saturating_sub(1);
    for (i, item) in items.iter().enumerate() {
        // Matches the canonicalized corpus: tree(1) versions disagree
        // on whether the continuation indent uses non-breaking spaces,
        // so gen-fixtures.sh normalizes them to regular spaces and this
        // renderer emits regular spaces to match.
        let (connector, child_indent) = if i == last {
            ("\u{2514}\u{2500}\u{2500} ", format!("{indent}    "))
        } else {
            ("\u{251c}\u{2500}\u{2500} ", format!("{indent}\u{2502}   "))
        };
        match item {
            Item::Entry(name) => {
                out.push_str(indent);
                out.push_str(connector);
                out.push_str(name);
                out.push('\n');
            }
            Item::Dir(name, child) => {
                out.push_str(indent);
                out.push_str(connector);
                out.push_str(name);
                out.push('\n');
                render_node(child, &child_indent, out);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_conventions() {
        assert_eq!(StoreFormat::Pass.entry_extension(), "gpg");
        assert_eq!(StoreFormat::Passage.entry_extension(), "age");
        assert_eq!(StoreFormat::Pass.recipients_file_name(), ".gpg-id");
        assert_eq!(
            StoreFormat::Passage.recipients_file_name(),
            ".age-recipients"
        );
    }

    #[test]
    fn sneaky_paths_match_cli_rules() {
        for bad in ["..", "../x", "a/../b", "a/.."] {
            assert!(is_sneaky_path(bad), "{bad} should be rejected");
        }
        for ok in [".", "./a", ".hidden", "a/.hidden", "a..b", "web/site"] {
            assert!(!is_sneaky_path(ok), "{ok} should be allowed");
        }
    }

    /// "Encrypts" by writing the recipient list in front of the plaintext;
    /// decrypts only what lists `me`, like a device with one identity.
    struct ListedBackend;
    impl CryptoBackend for ListedBackend {
        fn encrypt(
            &self,
            plaintext: &[u8],
            recipients: &[crate::crypto::Recipient],
        ) -> Result<Vec<u8>, crate::crypto::CryptoError> {
            let mut out = format!("{}\n", recipients.join(",")).into_bytes();
            out.extend_from_slice(plaintext);
            Ok(out)
        }
        fn decrypt(
            &self,
            ciphertext: &[u8],
        ) -> Result<zeroize::Zeroizing<Vec<u8>>, crate::crypto::CryptoError> {
            let split = ciphertext.iter().position(|b| *b == b'\n').unwrap();
            let listed = std::str::from_utf8(&ciphertext[..split]).unwrap();
            if !listed.split(',').any(|r| r == "me") {
                return Err(crate::crypto::CryptoError::DecryptionFailed);
            }
            Ok(zeroize::Zeroizing::new(ciphertext[split + 1..].to_vec()))
        }
    }

    #[test]
    fn reencrypt_readable_skips_what_this_device_cannot_open() {
        let dir = std::env::temp_dir().join(format!("passpony-rc4-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let store = Store::open(&dir, StoreFormat::Passage).unwrap();
        assert_eq!(store.root_recipients().unwrap(), None);

        store.set_root_recipients("me\n").unwrap();
        store
            .write_entry(
                "mine",
                &crate::entry::Entry::from_bytes(b"pw1\n".to_vec()),
                &ListedBackend,
            )
            .unwrap();
        store.set_root_recipients("other\n").unwrap();
        store
            .write_entry(
                "theirs",
                &crate::entry::Entry::from_bytes(b"pw2\n".to_vec()),
                &ListedBackend,
            )
            .unwrap();

        store.set_root_recipients("me\nother\n").unwrap();
        assert_eq!(
            store.root_recipients().unwrap().as_deref(),
            Some("me\nother\n")
        );
        let report = store.reencrypt_readable("", &ListedBackend).unwrap();
        assert_eq!(report.rewritten, vec!["mine".to_string()]);
        assert_eq!(report.skipped, 1);
        let mine = std::fs::read(dir.join("mine.age")).unwrap();
        assert!(mine.starts_with(b"me,other\n"));
        let theirs = std::fs::read(dir.join("theirs.age")).unwrap();
        assert!(
            theirs.starts_with(b"other\n"),
            "an unreadable entry is left as it was"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn gpg_id_parsing_matches_pass() {
        let ids = parse_gpg_id("AAAA # kevin\n# full comment line\n\nBBBB\nDROPPED-NO-NEWLINE");
        assert_eq!(ids, vec!["AAAA".to_string(), "BBBB".to_string()]);
    }

    // --- 3.0: the same behaviour over every file layer ---------------------

    fn entry(text: &str) -> Entry {
        Entry::from_bytes(text.as_bytes().to_vec())
    }

    fn names(store: &Store) -> Vec<String> {
        store
            .entries()
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect()
    }

    /// Runs `check` on a passage store over `std::fs` and over memory.
    fn on_each_fs(tag: &str, check: impl Fn(&Store)) {
        let dir = std::env::temp_dir().join(format!("passpony-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        check(&Store::open(&dir, StoreFormat::Passage).unwrap());
        std::fs::remove_dir_all(&dir).unwrap();

        let mem: Arc<dyn StoreFs> = Arc::new(crate::fs::MemFs::new());
        check(&Store::with_fs(mem, StoreFormat::Passage).unwrap());
    }

    #[test]
    fn entries_tree_and_pruning_on_each_fs() {
        on_each_fs("walk", |store| {
            store.set_root_recipients("me\n").unwrap();
            for name in ["web/github", "web/deep/site", "bank", ".hidden/x"] {
                store
                    .write_entry(name, &entry("pw\n"), &ListedBackend)
                    .unwrap();
            }
            assert_eq!(
                names(store),
                [".hidden/x", "bank", "web/deep/site", "web/github"]
            );
            assert!(store.entries().unwrap()[0].hidden);
            let tree = store.tree().unwrap();
            assert_eq!(tree.entries, ["bank"]);
            assert_eq!(tree.dirs.len(), 1, "the dot directory is not shown");
            assert_eq!(tree.dirs[0].0, "web");
            assert_eq!(tree.dirs[0].1.entries, ["github"]);
            assert!(store.has_entry("web/github"));
            assert!(!store.has_entry("web"));
            assert!(!store.has_entry("../web/github"));

            // Removing the last entry of a directory removes the directory,
            // and stops at the first one that still holds something.
            store.remove_entry("web/deep/site").unwrap();
            assert_eq!(store.tree().unwrap().dirs[0].1.dirs.len(), 0);
            assert!(store.has_entry("web/github"));
            store.remove_entry("web/github").unwrap();
            assert!(store.tree().unwrap().dirs.is_empty());
            assert!(matches!(
                store.remove_entry("web/github"),
                Err(StoreError::NotInStore)
            ));
            assert!(matches!(
                store.read_entry("nope", &ListedBackend),
                Err(StoreError::NotInStore)
            ));
        });
    }

    #[test]
    fn a_recipients_file_keeps_its_directory_and_wins_for_entries_below() {
        on_each_fs("recipients", |store| {
            store.set_root_recipients("me\n").unwrap();
            store
                .write_entry("work/vpn", &entry("pw\n"), &ListedBackend)
                .unwrap();
            store
                .fs
                .write("work/.age-recipients", b"# team\nme\nother\n\n")
                .unwrap();
            assert_eq!(
                store.resolve_recipients("work/deep/x").unwrap(),
                RecipientSource::RecipientsFile("work/.age-recipients".into())
            );
            assert_eq!(
                store.resolve_recipients("bank").unwrap(),
                RecipientSource::RecipientsFile(".age-recipients".into())
            );
            store
                .write_entry("work/deep/x", &entry("pw\n"), &ListedBackend)
                .unwrap();
            assert!(store
                .fs
                .read("work/deep/x.age")
                .unwrap()
                .starts_with(b"me,other\n"));

            store.remove_entry("work/deep/x").unwrap();
            store.remove_entry("work/vpn").unwrap();
            assert!(
                store.fs.is_file("work/.age-recipients").unwrap(),
                "pruning never deletes a recipients file"
            );
        });
    }

    #[test]
    fn move_copy_and_reencrypt_on_each_fs() {
        on_each_fs("move", |store| {
            store.set_root_recipients("me\n").unwrap();
            store
                .write_entry("a", &entry("one\n"), &ListedBackend)
                .unwrap();
            store.copy_entry("a", "copies/a", &ListedBackend).unwrap();
            store.move_entry("a", "moved/a", &ListedBackend).unwrap();
            assert_eq!(names(store), ["copies/a", "moved/a"]);
            assert_eq!(
                store
                    .read_entry("moved/a", &ListedBackend)
                    .unwrap()
                    .to_bytes(),
                b"one\n"
            );

            store.set_root_recipients("me\nother\n").unwrap();
            assert_eq!(
                store.reencrypt_subtree("copies", &ListedBackend).unwrap(),
                ["copies/a"]
            );
            assert!(store
                .fs
                .read("copies/a.age")
                .unwrap()
                .starts_with(b"me,other\n"));
            assert!(store.fs.read("moved/a.age").unwrap().starts_with(b"me\n"));
        });
    }

    #[test]
    fn add_entry_never_replaces() {
        on_each_fs("add", |store| {
            store.set_root_recipients("me\n").unwrap();
            store
                .add_entry("web/github", &entry("first\n"), &ListedBackend)
                .unwrap();
            assert!(matches!(
                store.add_entry("web/github", &entry("second\n"), &ListedBackend),
                Err(StoreError::EntryExists)
            ));
            assert_eq!(
                store
                    .read_entry("web/github", &ListedBackend)
                    .unwrap()
                    .to_bytes(),
                b"first\n"
            );

            // A directory of the same name is not an entry of that name.
            store
                .add_entry("web", &entry("top\n"), &ListedBackend)
                .unwrap();
            assert_eq!(names(store), ["web", "web/github"]);

            // Replacing on purpose still goes through write_entry.
            store
                .write_entry("web/github", &entry("second\n"), &ListedBackend)
                .unwrap();
            assert_eq!(
                store
                    .read_entry("web/github", &ListedBackend)
                    .unwrap()
                    .to_bytes(),
                b"second\n"
            );
            assert!(matches!(
                store.add_entry("../escape", &entry("x\n"), &ListedBackend),
                Err(StoreError::SneakyPath)
            ));
        });
    }

    #[test]
    fn add_entry_on_a_case_blind_folder_treats_other_case_as_taken() {
        /// A file layer that ignores case, like FAT and most phones' shared
        /// storage.
        struct CaseBlind(crate::fs::MemFs);
        impl StoreFs for CaseBlind {
            fn list(&self, dir: &str) -> Result<Vec<crate::fs::FsEntry>, FsError> {
                self.0.list(&dir.to_lowercase())
            }
            fn read(&self, path: &str) -> Result<Vec<u8>, FsError> {
                self.0.read(&path.to_lowercase())
            }
            fn write(&self, path: &str, data: &[u8]) -> Result<(), FsError> {
                self.0.write(&path.to_lowercase(), data)
            }
            fn create_dir_all(&self, dir: &str) -> Result<(), FsError> {
                self.0.create_dir_all(&dir.to_lowercase())
            }
            fn remove_file(&self, path: &str) -> Result<(), FsError> {
                self.0.remove_file(&path.to_lowercase())
            }
            fn remove_dir(&self, dir: &str) -> Result<(), FsError> {
                self.0.remove_dir(&dir.to_lowercase())
            }
            fn is_file(&self, path: &str) -> Result<bool, FsError> {
                self.0.is_file(&path.to_lowercase())
            }
        }
        let fs: Arc<dyn StoreFs> = Arc::new(CaseBlind(crate::fs::MemFs::new()));
        let store = Store::with_fs(fs, StoreFormat::Passage).unwrap();
        store.set_root_recipients("me\n").unwrap();
        store
            .add_entry("GitHub", &entry("first\n"), &ListedBackend)
            .unwrap();
        assert!(matches!(
            store.add_entry("github", &entry("second\n"), &ListedBackend),
            Err(StoreError::EntryExists)
        ));
    }

    #[test]
    fn a_failed_write_leaves_the_old_entry_readable() {
        let mem = Arc::new(crate::fs::MemFs::new());
        let store = Store::with_fs(mem.clone(), StoreFormat::Passage).unwrap();
        store.set_root_recipients("me\n").unwrap();
        store
            .write_entry("bank", &entry("old\n"), &ListedBackend)
            .unwrap();
        mem.fail_writes(true);
        assert!(matches!(
            store.write_entry("bank", &entry("new\n"), &ListedBackend),
            Err(StoreError::Io(_))
        ));
        assert!(store.reencrypt_subtree("", &ListedBackend).is_err());
        mem.fail_writes(false);
        assert_eq!(
            store.read_entry("bank", &ListedBackend).unwrap().to_bytes(),
            b"old\n"
        );
    }

    #[test]
    fn a_lost_folder_is_its_own_error_not_an_empty_store() {
        let mem = Arc::new(crate::fs::MemFs::new());
        let store = Store::with_fs(mem.clone(), StoreFormat::Passage).unwrap();
        store.set_root_recipients("me\n").unwrap();
        store
            .write_entry("bank", &entry("pw\n"), &ListedBackend)
            .unwrap();
        mem.lose_access(true);
        assert!(matches!(
            store.entries(),
            Err(StoreError::FolderUnavailable)
        ));
        assert!(matches!(
            store.read_entry("bank", &ListedBackend),
            Err(StoreError::FolderUnavailable)
        ));
        assert!(matches!(
            store.add_entry("new", &entry("pw\n"), &ListedBackend),
            Err(StoreError::FolderUnavailable)
        ));
        assert!(matches!(
            Store::with_fs(mem.clone(), StoreFormat::Passage),
            Err(StoreError::FolderUnavailable)
        ));
        assert!(
            !store.has_entry("bank"),
            "has_entry stays a plain yes or no"
        );
    }

    #[test]
    fn pass_store_reads_gpg_id_through_the_file_layer() {
        let mem = Arc::new(crate::fs::MemFs::new());
        let store = Store::with_fs(mem.clone(), StoreFormat::Pass).unwrap();
        assert_eq!(
            store.resolve_recipients("a").unwrap(),
            RecipientSource::Uninitialized
        );
        assert!(matches!(
            store.write_entry("a", &entry("pw\n"), &ListedBackend),
            Err(StoreError::Crypto(crate::crypto::CryptoError::NoUsableKey))
        ));
        store.set_root_recipients("me # mine\n").unwrap();
        assert_eq!(
            store.resolve_recipients("deep/a").unwrap(),
            RecipientSource::Ids(vec!["me".into()])
        );
        // Same recipients on both sides: a pass move keeps the bytes.
        store
            .write_entry("a", &entry("pw\n"), &ListedBackend)
            .unwrap();
        let before = mem.file("a.gpg").unwrap();
        store.move_entry("a", "deep/a", &ListedBackend).unwrap();
        assert_eq!(mem.file("deep/a.gpg").unwrap(), before);
        assert!(mem.file("a.gpg").is_none());
    }
}
