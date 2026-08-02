//! Store formats and their on-disk conventions.
//!
//! Behavioral references: pass 1.7.x and the passage script (v1.7.4 fork).
//! See docs/passage-store-semantics.md for the source read-through; the
//! fixture corpus is ground truth over both.

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
    ///
    /// Divergence to preserve: pass parses `.gpg-id` itself (comments
    /// stripped, one ID per line); passage hands `.age-recipients` verbatim
    /// to `age -R`, which handles blank lines and `#` comments.
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
}

/// Reject path arguments containing `..` components, mirroring the CLIs'
/// `check_sneaky_paths` (which blocks only `..` — leading dots and `.`
/// components are allowed, and that leniency is part of the compat surface).
pub fn is_sneaky_path(path: &str) -> bool {
    path == ".."
        || path.starts_with("../")
        || path.ends_with("/..")
        || path.contains("/../")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_conventions() {
        assert_eq!(StoreFormat::Pass.entry_extension(), "gpg");
        assert_eq!(StoreFormat::Passage.entry_extension(), "age");
        assert_eq!(StoreFormat::Pass.recipients_file_name(), ".gpg-id");
        assert_eq!(StoreFormat::Passage.recipients_file_name(), ".age-recipients");
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
}
