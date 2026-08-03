//! Store model: formats, tree walk, entry index, recipient resolution, and
//! the read path.
//!
//! Behavioral references: pass 1.7.x and the passage script (v1.7.4 fork,
//! pinned commit in fixtures/gen-fixtures.sh). See
//! docs/passage-store-semantics.md; the fixture corpus is ground truth.

use std::fs;
use std::path::{Path, PathBuf};

use crate::crypto::CryptoBackend;
use crate::entry::Entry;

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
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Crypto(#[from] crate::crypto::CryptoError),
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
    /// passage: path to the nearest `.age-recipients`, handed to the backend
    /// verbatim (the CLI passes it to `age -R` unparsed).
    RecipientsFile(PathBuf),
    /// passage with no `.age-recipients` anywhere up the tree: recipients are
    /// derived from the identities file (`age -e -i identities`).
    IdentitiesFallback,
    /// pass with no `.gpg-id` up the tree: the CLI refuses to operate.
    Uninitialized,
}

impl RecipientSource {
    /// The recipient strings to hand a backend's `encrypt`. `Some(vec![])`
    /// means "no explicit recipients — encrypt to your own identities"
    /// (passage's identities-fallback branch); `None` means encryption is
    /// impossible (pass without any `.gpg-id`).
    ///
    /// For `.age-recipients` files this parses the way age itself reads
    /// `-R` files: one recipient per line, blank lines and `#` comments
    /// skipped.
    pub fn encryption_recipients(&self) -> Result<Option<Vec<String>>, StoreError> {
        Ok(match self {
            RecipientSource::Ids(ids) => Some(ids.clone()),
            RecipientSource::RecipientsFile(path) => {
                let raw = fs::read_to_string(path)?;
                Some(
                    raw.lines()
                        .map(str::trim)
                        .filter(|l| !l.is_empty() && !l.starts_with('#'))
                        .map(str::to_owned)
                        .collect(),
                )
            }
            RecipientSource::IdentitiesFallback => Some(Vec::new()),
            RecipientSource::Uninitialized => None,
        })
    }
}

/// Write `data` to `path` atomically: temp file in the same directory, then
/// rename over the target. Decrypted content never hits this path — only
/// ciphertext does.
fn atomic_write(path: &Path, data: &[u8]) -> Result<(), StoreError> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = dir.join(format!(
        ".passpony-tmp-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    fs::write(&tmp, data)?;
    match fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            Err(e.into())
        }
    }
}

pub struct Store {
    root: PathBuf,
    format: StoreFormat,
}

impl Store {
    pub fn open(root: impl Into<PathBuf>, format: StoreFormat) -> Result<Self, StoreError> {
        let root = root.into();
        if !root.is_dir() {
            return Err(StoreError::NoStore);
        }
        Ok(Store { root, format })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn format(&self) -> StoreFormat {
        self.format
    }

    fn entry_file(&self, name: &str) -> Result<PathBuf, StoreError> {
        if is_sneaky_path(name) {
            return Err(StoreError::SneakyPath);
        }
        Ok(self
            .root
            .join(format!("{name}.{}", self.format.entry_extension())))
    }

    pub fn has_entry(&self, name: &str) -> bool {
        matches!(self.entry_file(name), Ok(p) if p.is_file())
    }

    /// Walk the store, building the visible tree (what `ls` shows): dot-named
    /// files and directories excluded, `.git` excluded, extensions stripped.
    pub fn tree(&self) -> Result<DirNode, StoreError> {
        self.walk_dir(&self.root)
    }

    fn walk_dir(&self, dir: &Path) -> Result<DirNode, StoreError> {
        let ext = format!(".{}", self.format.entry_extension());
        let mut node = DirNode::default();
        for res in fs::read_dir(dir)? {
            let de = res?;
            let file_name = de.file_name();
            let name = match file_name.to_str() {
                Some(s) => s.to_owned(),
                None => continue, // non-UTF-8 names: passthrough-only, unlisted
            };
            if name.starts_with('.') {
                continue; // includes .git, .gpg-id, .age-recipients, dot entries
            }
            let ftype = de.file_type()?;
            if ftype.is_dir() {
                let child = self.walk_dir(&de.path())?;
                node.dirs.push((name, child));
            } else if ftype.is_file() {
                if let Some(stripped) = name.strip_suffix(&ext) {
                    node.entries.push(stripped.to_owned());
                }
            }
            // Symlinks deliberately unhandled in P0; the CLIs are internally
            // inconsistent about them (see semantics notes §7).
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
        self.collect_entries(&self.root, "", &ext, &mut out)?;
        out.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
        Ok(out)
    }

    fn collect_entries(
        &self,
        dir: &Path,
        prefix: &str,
        ext: &str,
        out: &mut Vec<EntryRef>,
    ) -> Result<(), StoreError> {
        for res in fs::read_dir(dir)? {
            let de = res?;
            let name = match de.file_name().to_str() {
                Some(s) => s.to_owned(),
                None => continue,
            };
            if name == ".git" {
                continue;
            }
            let ftype = de.file_type()?;
            let rel = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            if ftype.is_dir() {
                self.collect_entries(&de.path(), &rel, ext, out)?;
            } else if ftype.is_file() {
                if let Some(stripped) = rel.strip_suffix(ext) {
                    let hidden = stripped.split('/').any(|c| c.starts_with('.'));
                    out.push(EntryRef {
                        name: stripped.to_owned(),
                        hidden,
                    });
                }
            }
        }
        Ok(())
    }

    /// Decrypt an entry through the backend. File beats directory, as in the
    /// CLIs: `show foo` finds `foo.gpg` even when directory `foo/` exists.
    pub fn read_entry(&self, name: &str, backend: &dyn CryptoBackend) -> Result<Entry, StoreError> {
        let file = self.entry_file(name)?;
        if !file.is_file() {
            return Err(StoreError::NotInStore);
        }
        let ciphertext = fs::read(&file)?;
        let plaintext = backend.decrypt(&ciphertext)?;
        Ok(Entry::from_bytes(plaintext.to_vec()))
    }

    /// Encrypt `entry` to the recipients resolved for `name` and write it
    /// atomically (temp file in the same directory, then rename), creating
    /// parent directories as needed. Mirrors `pass insert` / `passage insert`.
    pub fn write_entry(
        &self,
        name: &str,
        entry: &Entry,
        backend: &dyn CryptoBackend,
    ) -> Result<(), StoreError> {
        let recipients = self
            .resolve_recipients(name)?
            .encryption_recipients()?
            .ok_or(crate::crypto::CryptoError::NoUsableKey)?;
        let ciphertext = backend.encrypt(entry.to_bytes(), &recipients)?;
        let file = self.entry_file(name)?;
        if let Some(parent) = file.parent() {
            fs::create_dir_all(parent)?;
        }
        atomic_write(&file, &ciphertext)
    }

    /// Remove an entry and prune newly-empty parent directories up to the
    /// store root (the CLIs run `rmdir -p`). Recipients files keep a
    /// directory alive, matching the CLIs.
    pub fn remove_entry(&self, name: &str) -> Result<(), StoreError> {
        let file = self.entry_file(name)?;
        if !file.is_file() {
            return Err(StoreError::NotInStore);
        }
        fs::remove_file(&file)?;
        let mut dir = file.parent().map(Path::to_path_buf);
        while let Some(d) = dir {
            if d == self.root || !d.starts_with(&self.root) {
                break;
            }
            if fs::remove_dir(&d).is_err() {
                break; // not empty (or gone) — stop pruning
            }
            dir = d.parent().map(Path::to_path_buf);
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
        if !src.is_file() {
            return Err(StoreError::NotInStore);
        }
        let dst = self.entry_file(to)?;
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent)?;
        }
        let must_reencrypt = match self.format {
            StoreFormat::Passage => true,
            StoreFormat::Pass => self.resolve_recipients(from)? != self.resolve_recipients(to)?,
        };
        if must_reencrypt {
            let plaintext = backend.decrypt(&fs::read(&src)?)?;
            let recipients = self
                .resolve_recipients(to)?
                .encryption_recipients()?
                .ok_or(crate::crypto::CryptoError::NoUsableKey)?;
            let ciphertext = backend.encrypt(&plaintext, &recipients)?;
            atomic_write(&dst, &ciphertext)?;
        } else {
            fs::copy(&src, &dst)?;
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
            let plaintext = backend.decrypt(&fs::read(&file)?)?;
            let recipients = self
                .resolve_recipients(name)?
                .encryption_recipients()?
                .ok_or(crate::crypto::CryptoError::NoUsableKey)?;
            let ciphertext = backend.encrypt(&plaintext, &recipients)?;
            atomic_write(&file, &ciphertext)?;
        }
        Ok(targets)
    }

    /// Resolve the recipient source for (the directory containing) `name`,
    /// walking nearest-ancestor from the entry's directory to the store root.
    /// Env overrides (`PASSWORD_STORE_KEY`, `PASSAGE_RECIPIENTS*`) are the
    /// caller's concern; this resolves the on-disk state only.
    pub fn resolve_recipients(&self, name: &str) -> Result<RecipientSource, StoreError> {
        if is_sneaky_path(name) {
            return Err(StoreError::SneakyPath);
        }
        let rel_dir = match name.rsplit_once('/') {
            Some((dir, _)) => dir,
            None => "",
        };
        let mut current = self.root.join(rel_dir);
        loop {
            let candidate = current.join(self.format.recipients_file_name());
            if candidate.is_file() {
                return Ok(match self.format {
                    StoreFormat::Passage => RecipientSource::RecipientsFile(candidate),
                    StoreFormat::Pass => RecipientSource::Ids(parse_gpg_id_file(&candidate)?),
                });
            }
            if current == self.root {
                break;
            }
            match current.parent() {
                Some(p) if p.starts_with(&self.root) => current = p.to_path_buf(),
                _ => break,
            }
        }
        Ok(match self.format {
            StoreFormat::Passage => RecipientSource::IdentitiesFallback,
            StoreFormat::Pass => RecipientSource::Uninitialized,
        })
    }
}

/// Parse a `.gpg-id` file the way pass does: per line, strip everything from
/// the first `#`, then skip lines that end up empty. pass uses a shell
/// `read -r` loop, so a final line without a trailing newline is *dropped* —
/// we preserve that quirk deliberately.
fn parse_gpg_id_file(path: &Path) -> Result<Vec<String>, StoreError> {
    let raw = fs::read_to_string(path)?;
    let mut ids = Vec::new();
    let mut rest = raw.as_str();
    while let Some(idx) = rest.find('\n') {
        let line = &rest[..idx];
        rest = &rest[idx + 1..];
        let line = line.split('#').next().unwrap_or("").trim();
        if !line.is_empty() {
            ids.push(line.to_owned());
        }
    }
    // `rest` now holds any final unterminated line — dropped, as in the CLI.
    Ok(ids)
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
        // Byte-faithful to tree(1) in UTF-8 mode, which the ls goldens
        // are captured from: the continuation indent is a box-drawing
        // pipe followed by two non-breaking spaces and one regular
        // space. Regular spaces would render the same and fail parity.
        let (connector, child_indent) = if i == last {
            ("\u{2514}\u{2500}\u{2500} ", format!("{indent}    "))
        } else {
            ("\u{251c}\u{2500}\u{2500} ", format!("{indent}\u{2502}\u{a0}\u{a0} "))
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

    #[test]
    fn gpg_id_parsing_matches_pass() {
        let dir = std::env::temp_dir().join("passpony-gpgid-test");
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join(".gpg-id");
        std::fs::write(
            &f,
            "AAAA # kevin\n# full comment line\n\nBBBB\nDROPPED-NO-NEWLINE",
        )
        .unwrap();
        let ids = parse_gpg_id_file(&f).unwrap();
        assert_eq!(ids, vec!["AAAA".to_string(), "BBBB".to_string()]);
    }
}
