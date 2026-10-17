//! age identities files as text: detection of a passphrase-protected file,
//! and merging an imported file into the one the app already has.
//!
//! Crypto-free like the rest of pass-core. Deciding whether a file is
//! age-encrypted is a prefix check; decrypting it is the platform engine's
//! job (the `age-engine` feature on Android, AgePonyCore on iOS).
//!
//! Merging is append-only. An imported identity is added after the existing
//! ones together with the comment lines that precede it in the imported file
//! (`# created:`, `# public key:`), so the app can still show its public key.
//! Identities already present are skipped. Nothing already in the file is
//! removed or reordered, so entries encrypted to an existing identity stay
//! readable after any import.

const AGE_BINARY_MAGIC: &[u8] = b"age-encryption.org/v1";
const AGE_ARMOR_MAGIC: &[u8] = b"-----BEGIN AGE ENCRYPTED FILE-----";
const SECRET_PREFIX: &str = "AGE-SECRET-KEY-1";

/// True when `data`, after any leading whitespace, starts with an age header
/// (binary or ASCII armor): a passphrase-protected identities file rather
/// than a plaintext one. Decides whether to ask for a passphrase; it does
/// not prove the file decrypts.
pub fn is_age_encrypted(data: &[u8]) -> bool {
    let data = data.trim_ascii_start();
    data.starts_with(AGE_BINARY_MAGIC) || data.starts_with(AGE_ARMOR_MAGIC)
}

/// One identity from an identities file, with the comment lines directly
/// above it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityBlock {
    pub comments: Vec<String>,
    pub secret: String,
}

impl IdentityBlock {
    /// The `# public key: age1...` comment, when the file carries one.
    pub fn public_key_hint(&self) -> Option<&str> {
        self.comments
            .iter()
            .find_map(|c| c.strip_prefix("# public key:").map(str::trim))
            .filter(|k| !k.is_empty())
    }
}

/// Split an identities file into identity blocks. Comment lines attach to
/// the next identity; a blank line ends a run of comments. Lines that are
/// neither comments nor `AGE-SECRET-KEY-1` identities (plugin identities,
/// garbage) are ignored here, as the engines ignore them.
pub fn parse_identities(text: &str) -> Vec<IdentityBlock> {
    let mut blocks = Vec::new();
    let mut pending: Vec<String> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            pending.clear();
        } else if line.starts_with('#') {
            pending.push(line.to_owned());
        } else if line.to_ascii_uppercase().starts_with(SECRET_PREFIX) {
            blocks.push(IdentityBlock {
                comments: std::mem::take(&mut pending),
                secret: line.to_owned(),
            });
        } else {
            pending.clear();
        }
    }
    blocks
}

/// Result of merging an imported identities file into the existing one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergedIdentities {
    /// The new identities file: the existing text unchanged, then each new
    /// identity block, separated by blank lines, ending in a newline.
    pub text: String,
    /// Identities appended.
    pub added: u32,
    /// Identities in the import that the existing file already had.
    pub already_present: u32,
}

/// Append the identities in `imported` that `existing` does not already
/// have. Identity comparison is case-insensitive (bech32 is), so the same
/// key in either case counts as present.
pub fn merge_identities(existing: &str, imported: &str) -> MergedIdentities {
    let have: std::collections::HashSet<String> = parse_identities(existing)
        .into_iter()
        .map(|b| b.secret.to_ascii_uppercase())
        .collect();
    let mut seen = have.clone();
    let mut text = existing.to_owned();
    let mut added = 0u32;
    let mut already_present = 0u32;
    for block in parse_identities(imported) {
        let key = block.secret.to_ascii_uppercase();
        if have.contains(&key) {
            already_present += 1;
            continue;
        }
        if !seen.insert(key) {
            continue; // duplicated inside the import itself
        }
        if !text.is_empty() {
            if !text.ends_with('\n') {
                text.push('\n');
            }
            if !text.ends_with("\n\n") {
                text.push('\n');
            }
        }
        for c in &block.comments {
            text.push_str(c);
            text.push('\n');
        }
        text.push_str(&block.secret);
        text.push('\n');
        added += 1;
    }
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    MergedIdentities {
        text,
        added,
        already_present,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str =
        "# created: 2026-01-01T00:00:00Z\n# public key: age1aaa\nAGE-SECRET-KEY-1AAAA\n";
    const B: &str =
        "# created: 2026-02-02T00:00:00Z\n# public key: age1bbb\nAGE-SECRET-KEY-1BBBB\n";

    #[test]
    fn detection() {
        assert!(is_age_encrypted(b"age-encryption.org/v1\n-> scrypt"));
        assert!(is_age_encrypted(
            b"\n  -----BEGIN AGE ENCRYPTED FILE-----\n"
        ));
        assert!(!is_age_encrypted(A.as_bytes()));
        assert!(!is_age_encrypted(b""));
    }

    #[test]
    fn parse_keeps_comments_with_their_identity() {
        let blocks = parse_identities(&format!("{A}\n# stray\n\n{B}"));
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].public_key_hint(), Some("age1aaa"));
        assert_eq!(blocks[1].comments.len(), 2);
        assert_eq!(blocks[1].public_key_hint(), Some("age1bbb"));
    }

    #[test]
    fn merge_appends_and_never_drops() {
        let m = merge_identities(A, B);
        assert_eq!((m.added, m.already_present), (1, 0));
        assert_eq!(m.text, format!("{A}\n{B}"));
        assert!(m.text.starts_with(A));

        // Importing the same file again changes nothing.
        let again = merge_identities(&m.text, B);
        assert_eq!((again.added, again.already_present), (0, 1));
        assert_eq!(again.text, m.text);

        // Case-insensitive match, and duplicates within the import collapse.
        let lower = "AGE-SECRET-KEY-1aaaa\nAGE-SECRET-KEY-1CCCC\nAGE-SECRET-KEY-1CCCC\n";
        let m2 = merge_identities(A, lower);
        assert_eq!((m2.added, m2.already_present), (1, 1));
        assert_eq!(m2.text, format!("{A}\nAGE-SECRET-KEY-1CCCC\n"));
    }

    #[test]
    fn merge_into_empty_or_unterminated() {
        assert_eq!(merge_identities("", A).text, A);
        let m = merge_identities("AGE-SECRET-KEY-1ZZZZ", B);
        assert_eq!(m.text, format!("AGE-SECRET-KEY-1ZZZZ\n\n{B}"));
        assert_eq!(merge_identities(A, "garbage\n").added, 0);
    }
}
