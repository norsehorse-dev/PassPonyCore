//! A store's root `.age-recipients` file as text (2.0 rc4): which keys it
//! lists, adding this device's keys, and removing one.
//!
//! Every phone keeps its own identity and lists its public key here, so
//! whatever any of them saves is readable by all of them; no secret key
//! ever leaves a device. The file is read exactly the way age reads `-R`
//! files and `RecipientSource::encryption_recipients` does: one recipient
//! per line, blank lines and `#` comments skipped.
//!
//! Edits keep everything already in the file (comments, order, other
//! recipients, unknown lines) and only append or drop whole lines, so the
//! result stays byte-for-byte what a person would write by hand.

/// The recipients a `.age-recipients` text lists, trimmed, in order, with
/// duplicates removed.
pub fn recipients_in(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if !out.iter().any(|k| k == line) {
            out.push(line.to_owned());
        }
    }
    out
}

/// The result of adding keys: the new text and how many were added.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Added {
    pub text: String,
    pub added: u32,
}

/// Append each key in `keys` that `existing` does not already list. A file
/// that did not end in a newline gets one first; nothing else changes.
pub fn add_recipients(existing: &str, keys: &[String]) -> Added {
    let mut present = recipients_in(existing);
    let mut text = existing.to_owned();
    let mut added = 0;
    for key in keys {
        let key = key.trim();
        if key.is_empty() || key.starts_with('#') || present.iter().any(|k| k == key) {
            continue;
        }
        present.push(key.to_owned());
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str(key);
        text.push('\n');
        added += 1;
    }
    Added { text, added }
}

/// The result of removing a key: the new text and whether it was there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Removed {
    pub text: String,
    pub removed: bool,
}

/// Drop every line that is exactly `key` (after trimming). Comments and
/// every other line stay.
pub fn remove_recipient(existing: &str, key: &str) -> Removed {
    let key = key.trim();
    let mut removed = false;
    let mut text = String::with_capacity(existing.len());
    for line in existing.split_inclusive('\n') {
        if !key.is_empty() && line.trim() == key {
            removed = true;
            continue;
        }
        text.push_str(line);
    }
    Removed { text, removed }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "age1aaaa";
    const B: &str = "age1bbbb";

    #[test]
    fn parses_like_age() {
        let text = "# phones\nage1aaaa\n\n  age1bbbb  \n# age1cccc\nage1aaaa\n";
        assert_eq!(recipients_in(text), vec![A, B]);
    }

    #[test]
    fn add_creates_appends_and_skips_present() {
        let created = add_recipients("", &[A.to_owned()]);
        assert_eq!(
            created,
            Added {
                text: "age1aaaa\n".into(),
                added: 1
            }
        );

        let again = add_recipients(&created.text, &[A.to_owned(), B.to_owned()]);
        assert_eq!(
            again,
            Added {
                text: "age1aaaa\nage1bbbb\n".into(),
                added: 1
            }
        );

        let none = add_recipients(&again.text, &[B.to_owned(), " ".to_owned()]);
        assert_eq!(none.added, 0);
        assert_eq!(none.text, again.text);
    }

    #[test]
    fn add_keeps_comments_and_fixes_a_missing_newline() {
        let out = add_recipients("# mine\nage1aaaa", &[B.to_owned()]);
        assert_eq!(out.text, "# mine\nage1aaaa\nage1bbbb\n");
    }

    #[test]
    fn remove_drops_only_that_key() {
        let out = remove_recipient("# mine\nage1aaaa\nage1bbbb\n", B);
        assert_eq!(
            out,
            Removed {
                text: "# mine\nage1aaaa\n".into(),
                removed: true
            }
        );
        let same = remove_recipient(&out.text, B);
        assert!(!same.removed);
        assert_eq!(same.text, out.text);
        // A commented-out key is not a recipient and is left alone.
        assert_eq!(remove_recipient("# age1bbbb\n", B).text, "# age1bbbb\n");
    }
}
