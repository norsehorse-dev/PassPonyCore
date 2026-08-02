//! Entry codec: first line is the password, subsequent `key: value` lines,
//! `otpauth://` lines per pass-otp.
//!
//! Hard gate (section 3 of the plan): byte-faithful rewriting. An entry is
//! stored as its raw bytes; parsed views borrow from them, and serializing an
//! unmodified entry returns the identical bytes. Unknown lines are preserved
//! verbatim, ordering untouched. Never normalize line endings or trailing
//! newlines. Every edit operation below touches only the bytes of the thing
//! being edited.

/// A decrypted entry, held as raw bytes. Parsing produces views; only an
/// explicit field edit rewrites bytes, and it rewrites nothing else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    raw: Vec<u8>,
}

/// A parsed `key: value` view into an entry line. Byte offsets refer to the
/// entry's raw buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field<'a> {
    pub key: &'a str,
    pub value: &'a str,
}

impl Entry {
    pub fn from_bytes(raw: Vec<u8>) -> Self {
        Entry { raw }
    }

    /// Build a new entry from a password (no trailing newline is added when
    /// `password` is the whole content — callers append fields as needed).
    pub fn from_password(password: &[u8]) -> Self {
        let mut raw = password.to_vec();
        raw.push(b'\n');
        Entry { raw }
    }

    /// Byte-identical serialization — the round-trip guarantee.
    pub fn to_bytes(&self) -> &[u8] {
        &self.raw
    }

    /// The password: everything on the first line, excluding the newline.
    /// An empty entry yields an empty password, matching `pass show`.
    pub fn password(&self) -> &[u8] {
        match self.raw.iter().position(|&b| b == b'\n') {
            Some(idx) => &self.raw[..idx],
            None => &self.raw,
        }
    }

    /// Replace the first line only; every byte after the first newline is
    /// untouched. Mirrors `pass generate --in-place`.
    pub fn set_password(&mut self, new_password: &[u8]) {
        match self.raw.iter().position(|&b| b == b'\n') {
            Some(idx) => {
                let tail = self.raw.split_off(idx); // tail starts with '\n'
                self.raw = new_password.to_vec();
                self.raw.extend_from_slice(&tail);
            }
            None => {
                self.raw = new_password.to_vec();
            }
        }
    }

    /// Lines after the first, split on the *first* `": "` or `":"`, matching
    /// how pass ecosystem tools read `key: value` metadata. Lines without a
    /// colon, and `otpauth://` lines, are not fields.
    pub fn fields(&self) -> Vec<Field<'_>> {
        let mut out = Vec::new();
        for line in self.lines().skip(1) {
            let Ok(text) = std::str::from_utf8(line) else {
                continue;
            };
            if text.starts_with("otpauth://") {
                continue;
            }
            if let Some((key, value)) = text.split_once(':') {
                out.push(Field {
                    key: key.trim_end(),
                    value: value.strip_prefix(' ').unwrap_or(value),
                });
            }
        }
        out
    }

    /// First `otpauth://` line, if any (pass-otp semantics: the first wins).
    pub fn otpauth(&self) -> Option<&str> {
        self.lines()
            .skip(1)
            .filter_map(|l| std::str::from_utf8(l).ok())
            .find(|l| l.starts_with("otpauth://"))
    }

    /// Set `key` to `value`: rewrites only the value bytes of the first
    /// matching field line (key match is exact on the pre-colon text, after
    /// trailing-space trim). If no such field exists, appends a `key: value`
    /// line at the end; existing bytes are preserved as an exact prefix
    /// (a missing final newline is supplied before appending, which is the
    /// only byte ever added outside the new line itself).
    pub fn set_field(&mut self, key: &str, value: &str) {
        let mut offset = 0usize;
        let mut line_no = 0usize;
        let raw_len = self.raw.len();
        while offset < raw_len {
            let end = self.raw[offset..]
                .iter()
                .position(|&b| b == b'\n')
                .map(|i| offset + i)
                .unwrap_or(raw_len);
            if line_no > 0 {
                if let Ok(text) = std::str::from_utf8(&self.raw[offset..end]) {
                    if !text.starts_with("otpauth://") {
                        if let Some((k, v)) = text.split_once(':') {
                            if k.trim_end() == key {
                                // Preserve the key text and the colon exactly;
                                // keep one space unless the old value had none.
                                let colon = offset + k.len(); // index of ':'
                                let value_start =
                                    if v.starts_with(' ') { colon + 2 } else { colon + 1 };
                                let mut new_raw =
                                    Vec::with_capacity(raw_len - (end - value_start) + value.len());
                                new_raw.extend_from_slice(&self.raw[..value_start]);
                                new_raw.extend_from_slice(value.as_bytes());
                                new_raw.extend_from_slice(&self.raw[end..]);
                                self.raw = new_raw;
                                return;
                            }
                        }
                    }
                }
            }
            if end == raw_len {
                break;
            }
            offset = end + 1;
            line_no += 1;
        }
        // Append.
        if !self.raw.is_empty() && !self.raw.ends_with(b"\n") {
            self.raw.push(b'\n');
        }
        self.raw.extend_from_slice(key.as_bytes());
        self.raw.extend_from_slice(b": ");
        self.raw.extend_from_slice(value.as_bytes());
        self.raw.push(b'\n');
    }

    fn lines(&self) -> impl Iterator<Item = &[u8]> {
        self.raw.split(|&b| b == b'\n')
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_is_byte_identical() {
        let cases: &[&[u8]] = &[
            b"hunter2\nusername: kevin\nurl: example.com\n",
            b"no trailing newline",
            b"",
            b"\n\nweird: but preserved\r\n\xff\xfe binary tail",
        ];
        for &raw in cases {
            let entry = Entry::from_bytes(raw.to_vec());
            assert_eq!(entry.to_bytes(), raw);
        }
    }

    #[test]
    fn password_is_first_line() {
        assert_eq!(
            Entry::from_bytes(b"hunter2\nusername: kevin\n".to_vec()).password(),
            b"hunter2"
        );
        assert_eq!(Entry::from_bytes(b"bare".to_vec()).password(), b"bare");
        assert_eq!(Entry::from_bytes(b"".to_vec()).password(), b"");
        assert_eq!(Entry::from_bytes(b"\nsecond\n".to_vec()).password(), b"");
    }

    #[test]
    fn set_password_touches_only_first_line() {
        let tail = b"username: kevin\nnote:   weird   spacing kept\nno colon line\n\ntrailing";
        let mut raw = b"old-pw\n".to_vec();
        raw.extend_from_slice(tail);
        let mut e = Entry::from_bytes(raw);
        e.set_password(b"new-pw!");
        let mut expected = b"new-pw!\n".to_vec();
        expected.extend_from_slice(tail);
        assert_eq!(e.to_bytes(), expected.as_slice());
    }

    #[test]
    fn set_password_no_newline_case() {
        let mut e = Entry::from_bytes(b"only-password".to_vec());
        e.set_password(b"replaced");
        assert_eq!(e.to_bytes(), b"replaced");
    }

    #[test]
    fn fields_parse_and_otpauth_detected() {
        let e = Entry::from_bytes(
            b"pw\nusername: kevin\nurl:example.com\notpauth://totp/x?secret=ABC\nplain line\n"
                .to_vec(),
        );
        let fields = e.fields();
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].key, "username");
        assert_eq!(fields[0].value, "kevin");
        assert_eq!(fields[1].key, "url");
        assert_eq!(fields[1].value, "example.com");
        assert_eq!(e.otpauth(), Some("otpauth://totp/x?secret=ABC"));
    }

    #[test]
    fn set_field_rewrites_only_value_bytes() {
        let mut e = Entry::from_bytes(
            b"pw\nusername: kevin\nurl: old.example.com\nnote: keep me\n".to_vec(),
        );
        e.set_field("url", "new.example.com");
        assert_eq!(
            e.to_bytes(),
            b"pw\nusername: kevin\nurl: new.example.com\nnote: keep me\n"
        );
        // No-space style preserved:
        let mut e = Entry::from_bytes(b"pw\nurl:tight.example\n".to_vec());
        e.set_field("url", "still.tight");
        assert_eq!(e.to_bytes(), b"pw\nurl:still.tight\n");
    }

    #[test]
    fn set_field_appends_when_missing() {
        let mut e = Entry::from_bytes(b"pw\nexisting: yes\n".to_vec());
        e.set_field("username", "kevin");
        assert_eq!(e.to_bytes(), b"pw\nexisting: yes\nusername: kevin\n");
        // Missing trailing newline: prefix preserved exactly, one '\n' supplied.
        let mut e = Entry::from_bytes(b"pw\nexisting: yes".to_vec());
        e.set_field("username", "kevin");
        assert_eq!(e.to_bytes(), b"pw\nexisting: yes\nusername: kevin\n");
    }

    #[test]
    fn set_field_never_matches_password_line() {
        let mut e = Entry::from_bytes(b"looks: like a field\nreal: field\n".to_vec());
        e.set_field("looks", "changed");
        // First line is the password even when it contains a colon; a new
        // field line is appended instead.
        assert_eq!(
            e.to_bytes(),
            b"looks: like a field\nreal: field\nlooks: changed\n"
        );
    }
}
