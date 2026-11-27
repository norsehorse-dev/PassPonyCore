//! The store's file layer (3.0).
//!
//! Everything `store.rs` does to disk goes through [`StoreFs`], so a store
//! can live somewhere a plain path cannot reach: a folder the person picked
//! through Android's Storage Access Framework, which the app can only touch
//! through a content provider. [`StdFs`] is the ordinary implementation over
//! `std::fs` and is what `Store::open` uses; [`MemFs`] is an in-memory one
//! for tests on any platform.
//!
//! Paths are store-relative with `/` separators, and `""` is the store root.
//! An implementation never sees an absolute path from the core, and
//! `is_sneaky_path` has already run on anything derived from an entry name.
//! Implementations still refuse `..` and absolute paths on their own.
//!
//! git does not use this layer. libgit2 needs a real directory, so a store
//! opened through a foreign `StoreFs` has no git.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

/// One child of a directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsEntry {
    pub name: String,
    pub is_dir: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FsError {
    #[error("not found")]
    NotFound,
    /// The store's location can no longer be reached at all: the folder was
    /// deleted or moved, or the permission to use it was taken away. Not an
    /// ordinary I/O failure; the app has to ask for the folder again.
    #[error("the store's folder is no longer available")]
    AccessLost,
    #[error("{0}")]
    Other(String),
}

/// File operations a store needs. See the module comment for the path rules.
pub trait StoreFs: Send + Sync {
    /// The files and directories directly inside `dir`, in any order.
    /// Anything that is neither (a symlink, a device) is left out, as is a
    /// name that is not valid UTF-8.
    fn list(&self, dir: &str) -> Result<Vec<FsEntry>, FsError>;

    fn read(&self, path: &str) -> Result<Vec<u8>, FsError>;

    /// Replace the whole file, creating it if needed. The parent directory
    /// exists. A reader must never see a half-written file, and a failed
    /// write must leave the previous content in place.
    fn write(&self, path: &str, data: &[u8]) -> Result<(), FsError>;

    fn create_dir_all(&self, dir: &str) -> Result<(), FsError>;

    fn remove_file(&self, path: &str) -> Result<(), FsError>;

    /// Remove `dir` only if it is empty; fail otherwise. Never recursive.
    /// The core checks that the directory is empty before it calls this,
    /// but an implementation over an API whose delete is recursive must
    /// check again itself.
    fn remove_dir(&self, dir: &str) -> Result<(), FsError>;

    /// True when `path` is a regular file.
    fn is_file(&self, path: &str) -> Result<bool, FsError>;
}

/// The parent directory of a store-relative path; `""` for a top-level one.
pub(crate) fn parent(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(dir, _)| dir)
}

pub(crate) fn join(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        name.to_owned()
    } else {
        format!("{dir}/{name}")
    }
}

/// True for a path no implementation should follow: absolute, or with a
/// `..` component.
fn escapes(path: &str) -> bool {
    path.starts_with('/') || path.split('/').any(|c| c == "..")
}

// --- std::fs -----------------------------------------------------------------

/// A store in an ordinary directory.
pub struct StdFs {
    root: PathBuf,
}

impl StdFs {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        StdFs { root: root.into() }
    }

    fn at(&self, path: &str) -> Result<PathBuf, FsError> {
        // The CLIs build "$PREFIX/$path", so a leading slash stays inside
        // the store there. `Path::join` would instead replace the root.
        let path = path.trim_start_matches('/');
        if escapes(path) {
            return Err(FsError::Other("path leaves the store".into()));
        }
        Ok(if path.is_empty() {
            self.root.clone()
        } else {
            self.root.join(path)
        })
    }
}

fn io_error(e: io::Error) -> FsError {
    if e.kind() == io::ErrorKind::NotFound {
        FsError::NotFound
    } else {
        FsError::Other(e.to_string())
    }
}

impl StoreFs for StdFs {
    fn list(&self, dir: &str) -> Result<Vec<FsEntry>, FsError> {
        let mut out = Vec::new();
        for res in fs::read_dir(self.at(dir)?).map_err(io_error)? {
            let de = res.map_err(io_error)?;
            let Some(name) = de.file_name().to_str().map(str::to_owned) else {
                continue; // non-UTF-8 names: passthrough-only, unlisted
            };
            let ftype = de.file_type().map_err(io_error)?;
            // Symlinks deliberately unhandled; the CLIs are internally
            // inconsistent about them (see semantics notes §7).
            if ftype.is_dir() {
                out.push(FsEntry { name, is_dir: true });
            } else if ftype.is_file() {
                out.push(FsEntry {
                    name,
                    is_dir: false,
                });
            }
        }
        Ok(out)
    }

    fn read(&self, path: &str) -> Result<Vec<u8>, FsError> {
        fs::read(self.at(path)?).map_err(io_error)
    }

    /// Temp file in the same directory, then rename over the target.
    /// Decrypted content never comes through here, only ciphertext.
    fn write(&self, path: &str, data: &[u8]) -> Result<(), FsError> {
        let target = self.at(path)?;
        let dir = target.parent().unwrap_or(&self.root);
        let tmp = dir.join(format!(
            ".passpony-tmp-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        fs::write(&tmp, data).map_err(io_error)?;
        fs::rename(&tmp, &target).map_err(|e| {
            let _ = fs::remove_file(&tmp);
            io_error(e)
        })
    }

    fn create_dir_all(&self, dir: &str) -> Result<(), FsError> {
        fs::create_dir_all(self.at(dir)?).map_err(io_error)
    }

    fn remove_file(&self, path: &str) -> Result<(), FsError> {
        fs::remove_file(self.at(path)?).map_err(io_error)
    }

    fn remove_dir(&self, dir: &str) -> Result<(), FsError> {
        // std's remove_dir already refuses a directory that is not empty.
        fs::remove_dir(self.at(dir)?).map_err(io_error)
    }

    fn is_file(&self, path: &str) -> Result<bool, FsError> {
        Ok(self.at(path)?.is_file())
    }
}

// --- in memory ---------------------------------------------------------------

/// A store held in memory. For tests: the core's own, and a platform's
/// tests of code that takes a `StoreFs`. It can be told to fail writes or
/// to lose access, to exercise those paths.
#[derive(Default)]
pub struct MemFs {
    state: Mutex<MemState>,
    fail_writes: AtomicBool,
    access_lost: AtomicBool,
}

#[derive(Default)]
struct MemState {
    files: BTreeMap<String, Vec<u8>>,
    dirs: BTreeSet<String>,
}

impl MemFs {
    pub fn new() -> Self {
        Self::default()
    }

    /// While set, every `write` fails and changes nothing.
    pub fn fail_writes(&self, on: bool) {
        self.fail_writes.store(on, Ordering::SeqCst);
    }

    /// While set, every call fails with [`FsError::AccessLost`].
    pub fn lose_access(&self, on: bool) {
        self.access_lost.store(on, Ordering::SeqCst);
    }

    /// The bytes of a file, without going through the trait.
    pub fn file(&self, path: &str) -> Option<Vec<u8>> {
        self.state.lock().unwrap().files.get(path).cloned()
    }

    fn check(&self, path: &str) -> Result<(), FsError> {
        if self.access_lost.load(Ordering::SeqCst) {
            return Err(FsError::AccessLost);
        }
        if escapes(path) {
            return Err(FsError::Other("path leaves the store".into()));
        }
        Ok(())
    }
}

impl MemState {
    fn has_dir(&self, dir: &str) -> bool {
        dir.is_empty() || self.dirs.contains(dir)
    }

    fn children(&self, dir: &str) -> Vec<FsEntry> {
        let child = |path: &str| -> Option<String> {
            let rest = if dir.is_empty() {
                path
            } else {
                path.strip_prefix(dir)?.strip_prefix('/')?
            };
            (!rest.is_empty() && !rest.contains('/')).then(|| rest.to_owned())
        };
        let dirs = self
            .dirs
            .iter()
            .filter_map(|d| child(d).map(|name| FsEntry { name, is_dir: true }));
        let files = self.files.keys().filter_map(|f| {
            child(f).map(|name| FsEntry {
                name,
                is_dir: false,
            })
        });
        dirs.chain(files).collect()
    }
}

impl StoreFs for MemFs {
    fn list(&self, dir: &str) -> Result<Vec<FsEntry>, FsError> {
        self.check(dir)?;
        let state = self.state.lock().unwrap();
        if !state.has_dir(dir) {
            return Err(FsError::NotFound);
        }
        Ok(state.children(dir))
    }

    fn read(&self, path: &str) -> Result<Vec<u8>, FsError> {
        self.check(path)?;
        self.file(path).ok_or(FsError::NotFound)
    }

    fn write(&self, path: &str, data: &[u8]) -> Result<(), FsError> {
        self.check(path)?;
        if self.fail_writes.load(Ordering::SeqCst) {
            return Err(FsError::Other("write failed".into()));
        }
        let mut state = self.state.lock().unwrap();
        if !state.has_dir(parent(path)) {
            return Err(FsError::NotFound);
        }
        if state.dirs.contains(path) {
            return Err(FsError::Other("is a directory".into()));
        }
        state.files.insert(path.to_owned(), data.to_vec());
        Ok(())
    }

    fn create_dir_all(&self, dir: &str) -> Result<(), FsError> {
        self.check(dir)?;
        let mut state = self.state.lock().unwrap();
        let mut current = String::new();
        for part in dir.split('/').filter(|p| !p.is_empty()) {
            current = join(&current, part);
            if state.files.contains_key(&current) {
                return Err(FsError::Other("a file is in the way".into()));
            }
            state.dirs.insert(current.clone());
        }
        Ok(())
    }

    fn remove_file(&self, path: &str) -> Result<(), FsError> {
        self.check(path)?;
        let mut state = self.state.lock().unwrap();
        state
            .files
            .remove(path)
            .map(|_| ())
            .ok_or(FsError::NotFound)
    }

    fn remove_dir(&self, dir: &str) -> Result<(), FsError> {
        self.check(dir)?;
        let mut state = self.state.lock().unwrap();
        if dir.is_empty() || !state.dirs.contains(dir) {
            return Err(FsError::NotFound);
        }
        if !state.children(dir).is_empty() {
            return Err(FsError::Other("directory not empty".into()));
        }
        state.dirs.remove(dir);
        Ok(())
    }

    fn is_file(&self, path: &str) -> Result<bool, FsError> {
        self.check(path)?;
        Ok(self.state.lock().unwrap().files.contains_key(path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exercise(fs: &dyn StoreFs) {
        assert!(fs.list("").unwrap().is_empty());
        assert_eq!(fs.list("nope"), Err(FsError::NotFound));
        assert_eq!(fs.read("a.age"), Err(FsError::NotFound));
        assert!(!fs.is_file("a.age").unwrap());

        fs.write("a.age", b"one").unwrap();
        fs.write("a.age", b"two").unwrap();
        assert_eq!(fs.read("a.age").unwrap(), b"two");
        assert!(fs.is_file("a.age").unwrap());

        assert!(fs.write("web/b.age", b"x").is_err(), "no parent yet");
        fs.create_dir_all("web/deep").unwrap();
        fs.create_dir_all("web/deep").unwrap();
        fs.write("web/deep/b.age", b"x").unwrap();
        assert!(!fs.is_file("web").unwrap(), "a directory is not a file");

        let mut root = fs.list("").unwrap();
        root.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(
            root.iter()
                .filter(|e| !e.name.starts_with('.'))
                .cloned()
                .collect::<Vec<_>>(),
            vec![
                FsEntry {
                    name: "a.age".into(),
                    is_dir: false
                },
                FsEntry {
                    name: "web".into(),
                    is_dir: true
                },
            ]
        );
        assert_eq!(
            fs.list("web").unwrap(),
            vec![FsEntry {
                name: "deep".into(),
                is_dir: true
            }]
        );

        assert!(fs.remove_dir("web/deep").is_err(), "not empty");
        assert!(fs.is_file("web/deep/b.age").unwrap());
        fs.remove_file("web/deep/b.age").unwrap();
        assert_eq!(fs.remove_file("web/deep/b.age"), Err(FsError::NotFound));
        fs.remove_dir("web/deep").unwrap();
        fs.remove_dir("web").unwrap();

        for bad in ["../x", "a/../../x", "web/.."] {
            assert!(fs.read(bad).is_err(), "{bad}");
            assert!(fs.write(bad, b"x").is_err(), "{bad}");
        }
    }

    #[test]
    fn std_and_mem_behave_the_same() {
        let dir = std::env::temp_dir().join(format!("passpony-fs-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        exercise(&StdFs::new(&dir));
        fs::remove_dir_all(&dir).unwrap();

        exercise(&MemFs::new());
    }

    #[test]
    fn std_keeps_a_leading_slash_inside_the_store() {
        let dir = std::env::temp_dir().join(format!("passpony-fs-abs-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let std_fs = StdFs::new(&dir);
        std_fs.write("/etc-passwd.age", b"x").unwrap();
        assert!(dir.join("etc-passwd.age").is_file());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn mem_can_fail_writes_and_lose_access() {
        let mem = MemFs::new();
        mem.write("a.age", b"old").unwrap();
        mem.fail_writes(true);
        assert!(mem.write("a.age", b"new").is_err());
        assert_eq!(mem.read("a.age").unwrap(), b"old");
        mem.fail_writes(false);
        mem.lose_access(true);
        assert_eq!(mem.read("a.age"), Err(FsError::AccessLost));
        assert_eq!(mem.list(""), Err(FsError::AccessLost));
    }
}
