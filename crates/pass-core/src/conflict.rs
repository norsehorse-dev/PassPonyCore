//! Conflict copies a file-sync tool leaves in a folder store (3.0).
//!
//! When two devices change the same file before they have synced, Syncthing
//! keeps one version under the name and renames the other to
//! `<name>.sync-conflict-<YYYYMMDD>-<HHMMSS>-<device>.<ext>`, where
//! `<device>` is the first seven characters of the ID of the device that
//! last changed it. Old releases left the device part out. The
//! copy syncs to every device like any other file, and to the store it is
//! just another entry. This recognises one so the app can say what it is.
//!
//! Only Syncthing's pattern for now; other tools' can be added here.

/// An entry that is a sync tool's conflict copy of another entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConflictCopy {
    /// The entry this is a copy of. It may no longer exist.
    pub original: String,
    /// When the conflict happened, as the tool wrote it: `YYYYMMDD-HHMMSS`
    /// in the local time of the device that made the copy.
    pub stamp: String,
}

const MARKER: &str = ".sync-conflict-";

/// `Some` when the entry name (no extension, `/`-separated) is a conflict
/// copy. A copy of a copy names the copy it was made from as its original.
pub fn conflict_of(name: &str) -> Option<ConflictCopy> {
    let (dir, base) = match name.rsplit_once('/') {
        Some((dir, base)) => (Some(dir), base),
        None => (None, name),
    };
    let at = base.rfind(MARKER)?;
    let (stem, tail) = (&base[..at], &base[at + MARKER.len()..]);
    if stem.is_empty() {
        return None;
    }
    let digits = |s: &str, n: usize| s.len() == n && s.bytes().all(|b| b.is_ascii_digit());
    let mut parts = tail.split('-');
    let (date, time) = (parts.next()?, parts.next()?);
    if !digits(date, 8) || !digits(time, 6) {
        return None;
    }
    match parts.next() {
        None => {}
        Some(device) => {
            let base32 = device
                .bytes()
                .all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b));
            if device.len() != 7 || !base32 || parts.next().is_some() {
                return None;
            }
        }
    }
    Some(ConflictCopy {
        original: match dir {
            Some(dir) => format!("{dir}/{stem}"),
            None => stem.to_owned(),
        },
        stamp: format!("{date}-{time}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn copy(original: &str, stamp: &str) -> Option<ConflictCopy> {
        Some(ConflictCopy {
            original: original.into(),
            stamp: stamp.into(),
        })
    }

    #[test]
    fn recognises_syncthing_copies() {
        // Shapes from Syncthing's documentation and its forum: the device
        // part is seven base32 characters, and old releases had none.
        assert_eq!(
            conflict_of("github.sync-conflict-20210507-080621-CEIVOCO"),
            copy("github", "20210507-080621")
        );
        assert_eq!(
            conflict_of("web/github.com.sync-conflict-20250206-072027-VXKHMQ6"),
            copy("web/github.com", "20250206-072027")
        );
        assert_eq!(
            conflict_of("bank.sync-conflict-20170102-150405"),
            copy("bank", "20170102-150405")
        );
    }

    #[test]
    fn a_copy_of_a_copy_points_at_the_copy() {
        let first = "a.sync-conflict-20260101-000000-AAAAAAA";
        let second = format!("{first}.sync-conflict-20260102-000000-BBBBBBB");
        assert_eq!(conflict_of(&second), copy(first, "20260102-000000"));
    }

    #[test]
    fn leaves_ordinary_names_alone() {
        for name in [
            "github",
            "notes.sync-conflict",
            "notes.sync-conflict-",
            "notes.sync-conflict-2026-01-01",
            "notes.sync-conflict-20260101-0000",
            "notes.sync-conflict-20260101-000000-abcdefg",
            "notes.sync-conflict-20260101-000000-ABCDEF",
            "notes.sync-conflict-20260101-000000-ABCDEFG-extra",
            "notes.sync-conflict-20260101-000000-ABCDEF1",
            ".sync-conflict-20260101-000000-ABCDEFG",
            "web.sync-conflict-20260101-000000-ABCDEFG/github",
        ] {
            assert_eq!(conflict_of(name), None, "{name}");
        }
    }
}
