//! Entry codec: first line is the password, subsequent `key: value` lines,
//! `otpauth://` lines per pass-otp.
//!
//! Hard gate (section 3 of the plan): byte-faithful rewriting. An entry is
//! stored as its raw bytes; parsed views borrow from them, and serializing an
//! unmodified entry returns the identical bytes. Unknown lines are preserved
//! verbatim, ordering untouched. Never normalize line endings or trailing
//! newlines.

/// A decrypted entry, held as raw bytes. Parsing produces views; only an
/// explicit field edit rewrites bytes, and it rewrites nothing else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    raw: Vec<u8>,
}

impl Entry {
    pub fn from_bytes(raw: Vec<u8>) -> Self {
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
}
