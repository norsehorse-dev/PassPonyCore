//! Google Authenticator export QR codes (`otpauth-migration://offline?data=`).
//!
//! The `data` parameter is URL-encoded standard base64 of a protobuf
//! `MigrationPayload`. The schema, as Google Authenticator writes it:
//!
//! ```text
//! message MigrationPayload {
//!   repeated OtpParameters otp_parameters = 1;
//!   int32 version = 2; int32 batch_size = 3; int32 batch_index = 4; int32 batch_id = 5;
//! }
//! message OtpParameters {
//!   bytes secret = 1; string name = 2; string issuer = 3;
//!   Algorithm algorithm = 4;   // 0 unspecified, 1 SHA1, 2 SHA256, 3 SHA512, 4 MD5
//!   DigitCount digits = 5;     // 0 unspecified, 1 six, 2 eight
//!   OtpType type = 6;          // 0 unspecified, 1 HOTP, 2 TOTP
//!   int64 counter = 7;
//! }
//! ```
//!
//! One export can span several QR codes; each carries the same `batch_id`
//! and its own `batch_index` out of `batch_size`. This module parses one QR
//! code at a time; collecting the batch is the scanner's job.
//!
//! Every account becomes a canonical `otpauth://` URI built by the same code
//! the manual setup uses, so an imported entry is byte-identical to one typed
//! in. HOTP counters are stored as exported: pass-otp generates at
//! counter + 1, so at worst one code is skipped, which HOTP servers tolerate,
//! and a code is never repeated.

use crate::hotp::{Hotp, OtpKind};
use crate::totp::{percent_decode, Totp, TotpAlgorithm, DEFAULT_PERIOD};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MigrationError {
    #[error("not an otpauth-migration:// URI")]
    NotMigrationUri,
    #[error("missing data parameter")]
    MissingData,
    #[error("data is not valid base64")]
    BadBase64,
    #[error("data is not a valid export payload")]
    BadPayload,
}

/// Why one account in an export could not be imported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// MD5 codes: no authenticator outside Google's own supports them.
    Md5,
    EmptySecret,
    UnknownAlgorithm,
    UnknownDigits,
    UnknownType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationAccount {
    pub account: String,
    pub issuer: Option<String>,
    pub kind: OtpKind,
    /// Canonical `otpauth://totp/` or `otpauth://hotp/` line.
    pub uri: String,
    /// A store path to offer: `issuer/account`, or the account alone.
    pub suggested_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedAccount {
    pub label: String,
    pub reason: SkipReason,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationBatch {
    pub accounts: Vec<MigrationAccount>,
    pub skipped: Vec<SkippedAccount>,
    pub version: u32,
    /// Total QR codes in this export (1 when unset).
    pub batch_size: u32,
    /// Zero-based position of this QR code in the export.
    pub batch_index: u32,
    pub batch_id: i64,
}

/// Parse one `otpauth-migration://offline?data=...` QR payload.
pub fn parse_migration_uri(uri: &str) -> Result<MigrationBatch, MigrationError> {
    let uri = uri.trim();
    let query = uri
        .strip_prefix("otpauth-migration://offline?")
        .or_else(|| uri.strip_prefix("otpauth-migration://offline/?"))
        .ok_or(MigrationError::NotMigrationUri)?;
    let data = query
        .split('&')
        .find_map(|p| p.strip_prefix("data="))
        .filter(|d| !d.is_empty())
        .ok_or(MigrationError::MissingData)?;
    let bytes = decode_base64(&percent_decode(data)).ok_or(MigrationError::BadBase64)?;
    parse_payload(&bytes)
}

fn parse_payload(buf: &[u8]) -> Result<MigrationBatch, MigrationError> {
    let mut batch = MigrationBatch {
        accounts: Vec::new(),
        skipped: Vec::new(),
        version: 0,
        batch_size: 1,
        batch_index: 0,
        batch_id: 0,
    };
    let mut r = Reader { buf, pos: 0 };
    while !r.done() {
        let (field, wire) = r.key()?;
        match (field, wire) {
            (1, 2) => {
                let params = r.bytes()?;
                match parse_account(params)? {
                    Ok(account) => batch.accounts.push(account),
                    Err(skipped) => batch.skipped.push(skipped),
                }
            }
            (2, 0) => batch.version = r.varint()? as u32,
            (3, 0) => batch.batch_size = (r.varint()? as u32).max(1),
            (4, 0) => batch.batch_index = r.varint()? as u32,
            (5, 0) => batch.batch_id = r.varint()? as i64,
            _ => r.skip(wire)?,
        }
    }
    Ok(batch)
}

fn parse_account(buf: &[u8]) -> Result<Result<MigrationAccount, SkippedAccount>, MigrationError> {
    let mut secret = Vec::new();
    let mut name = String::new();
    let mut issuer = String::new();
    let mut algorithm = 0u64;
    let mut digits = 0u64;
    let mut otp_type = 0u64;
    let mut counter = 0u64;
    let mut r = Reader { buf, pos: 0 };
    while !r.done() {
        let (field, wire) = r.key()?;
        match (field, wire) {
            (1, 2) => secret = r.bytes()?.to_vec(),
            (2, 2) => name = r.string()?,
            (3, 2) => issuer = r.string()?,
            (4, 0) => algorithm = r.varint()?,
            (5, 0) => digits = r.varint()?,
            (6, 0) => otp_type = r.varint()?,
            (7, 0) => counter = r.varint()?,
            _ => r.skip(wire)?,
        }
    }

    // Google writes `name` as either "account" or "Issuer:account".
    let issuer = issuer.trim().to_owned();
    let mut account = name.trim().to_owned();
    if let Some((prefix, rest)) = account.split_once(':') {
        if issuer.is_empty() || prefix.trim() == issuer {
            let (prefix, rest) = (prefix.trim().to_owned(), rest.trim().to_owned());
            account = rest;
            if issuer.is_empty() {
                return Ok(build(
                    secret,
                    account,
                    Some(prefix),
                    algorithm,
                    digits,
                    otp_type,
                    counter,
                ));
            }
        }
    }
    let issuer = (!issuer.is_empty()).then_some(issuer);
    Ok(build(
        secret, account, issuer, algorithm, digits, otp_type, counter,
    ))
}

fn build(
    secret: Vec<u8>,
    account: String,
    issuer: Option<String>,
    algorithm: u64,
    digits: u64,
    otp_type: u64,
    counter: u64,
) -> Result<MigrationAccount, SkippedAccount> {
    let label = match (&issuer, account.is_empty()) {
        (Some(i), false) => format!("{i}:{account}"),
        (Some(i), true) => i.clone(),
        (None, _) => account.clone(),
    };
    let skip = |reason| SkippedAccount {
        label: label.clone(),
        reason,
    };
    let algorithm = match algorithm {
        0 | 1 => TotpAlgorithm::Sha1,
        2 => TotpAlgorithm::Sha256,
        3 => TotpAlgorithm::Sha512,
        4 => return Err(skip(SkipReason::Md5)),
        _ => return Err(skip(SkipReason::UnknownAlgorithm)),
    };
    let digits = match digits {
        0 | 1 => 6,
        2 => 8,
        _ => return Err(skip(SkipReason::UnknownDigits)),
    };
    if secret.is_empty() {
        return Err(skip(SkipReason::EmptySecret));
    }
    let (kind, uri) = match otp_type {
        0 | 2 => (
            OtpKind::Totp,
            Totp {
                secret,
                algorithm,
                digits,
                period: DEFAULT_PERIOD,
                label,
                issuer: issuer.clone(),
            }
            .to_uri(),
        ),
        1 => (
            OtpKind::Hotp,
            Hotp {
                secret,
                algorithm,
                digits,
                counter,
                label,
                issuer: issuer.clone(),
            }
            .to_uri(),
        ),
        _ => return Err(skip(SkipReason::UnknownType)),
    };
    let suggested_name = suggest_name(issuer.as_deref(), &account);
    Ok(MigrationAccount {
        account,
        issuer,
        kind,
        uri,
        suggested_name,
    })
}

/// `issuer/account`, each part with `/` replaced so it stays one path
/// segment, and leading dots removed so nothing becomes a hidden entry.
fn suggest_name(issuer: Option<&str>, account: &str) -> String {
    let clean = |s: &str| {
        s.trim()
            .replace(['/', '\\'], "-")
            .trim_start_matches('.')
            .trim()
            .to_owned()
    };
    let parts: Vec<String> = [issuer.map(clean), Some(clean(account))]
        .into_iter()
        .flatten()
        .filter(|p| !p.is_empty())
        .collect();
    if parts.is_empty() {
        "otp".to_owned()
    } else {
        parts.join("/")
    }
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn done(&self) -> bool {
        self.pos >= self.buf.len()
    }
    fn varint(&mut self) -> Result<u64, MigrationError> {
        let mut out = 0u64;
        for shift in (0..64).step_by(7) {
            let b = *self.buf.get(self.pos).ok_or(MigrationError::BadPayload)?;
            self.pos += 1;
            out |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                return Ok(out);
            }
        }
        Err(MigrationError::BadPayload)
    }
    fn key(&mut self) -> Result<(u64, u8), MigrationError> {
        let k = self.varint()?;
        Ok((k >> 3, (k & 7) as u8))
    }
    fn bytes(&mut self) -> Result<&'a [u8], MigrationError> {
        let len = usize::try_from(self.varint()?).map_err(|_| MigrationError::BadPayload)?;
        let end = self
            .pos
            .checked_add(len)
            .ok_or(MigrationError::BadPayload)?;
        let out = self
            .buf
            .get(self.pos..end)
            .ok_or(MigrationError::BadPayload)?;
        self.pos = end;
        Ok(out)
    }
    fn string(&mut self) -> Result<String, MigrationError> {
        Ok(String::from_utf8_lossy(self.bytes()?).into_owned())
    }
    fn skip(&mut self, wire: u8) -> Result<(), MigrationError> {
        match wire {
            0 => self.varint().map(|_| ()),
            1 => self.advance(8),
            2 => self.bytes().map(|_| ()),
            5 => self.advance(4),
            _ => Err(MigrationError::BadPayload),
        }
    }
    fn advance(&mut self, n: usize) -> Result<(), MigrationError> {
        let end = self.pos.checked_add(n).ok_or(MigrationError::BadPayload)?;
        if end > self.buf.len() {
            return Err(MigrationError::BadPayload);
        }
        self.pos = end;
        Ok(())
    }
}

/// Standard or URL-safe base64, padding optional, whitespace ignored.
fn decode_base64(input: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut bits = 0u32;
    let mut nbits = 0u32;
    for c in input.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' | b' ' | b'\n' | b'\r' | b'\t' => continue,
            _ => return None,
        };
        bits = (bits << 6) | u32::from(v);
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((bits >> nbits) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // A tiny protobuf writer, enough to build export payloads for tests.
    fn varint(mut v: u64, out: &mut Vec<u8>) {
        loop {
            let b = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                out.push(b);
                return;
            }
            out.push(b | 0x80);
        }
    }
    fn field_bytes(field: u64, data: &[u8], out: &mut Vec<u8>) {
        varint(field << 3 | 2, out);
        varint(data.len() as u64, out);
        out.extend_from_slice(data);
    }
    fn field_varint(field: u64, v: u64, out: &mut Vec<u8>) {
        varint(field << 3, out);
        varint(v, out);
    }
    #[allow(clippy::too_many_arguments)]
    fn account(
        secret: &[u8],
        name: &str,
        issuer: &str,
        alg: u64,
        digits: u64,
        ty: u64,
        counter: u64,
    ) -> Vec<u8> {
        let mut a = Vec::new();
        field_bytes(1, secret, &mut a);
        field_bytes(2, name.as_bytes(), &mut a);
        if !issuer.is_empty() {
            field_bytes(3, issuer.as_bytes(), &mut a);
        }
        field_varint(4, alg, &mut a);
        field_varint(5, digits, &mut a);
        field_varint(6, ty, &mut a);
        if counter != 0 {
            field_varint(7, counter, &mut a);
        }
        a
    }
    fn payload(accounts: &[Vec<u8>], size: u64, index: u64, id: u64) -> Vec<u8> {
        let mut p = Vec::new();
        for a in accounts {
            field_bytes(1, a, &mut p);
        }
        field_varint(2, 1, &mut p);
        field_varint(3, size, &mut p);
        field_varint(4, index, &mut p);
        field_varint(5, id, &mut p);
        p
    }
    fn encode_base64(data: &[u8]) -> String {
        const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut s = String::new();
        for chunk in data.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
            for i in 0..4 {
                if i <= chunk.len() {
                    s.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
                } else {
                    s.push('=');
                }
            }
        }
        s
    }
    fn uri(p: &[u8]) -> String {
        let b64 = encode_base64(p)
            .replace('+', "%2B")
            .replace('/', "%2F")
            .replace('=', "%3D");
        format!("otpauth-migration://offline?data={b64}")
    }

    const HELLO: &[u8] = b"Hello!\xde\xad\xbe\xef"; // JBSWY3DPEHPK3PXP

    #[test]
    fn single_totp_account() {
        let p = payload(
            &[account(HELLO, "kevin@example.com", "Example", 1, 1, 2, 0)],
            1,
            0,
            42,
        );
        let b = parse_migration_uri(&uri(&p)).unwrap();
        assert_eq!(
            (b.batch_size, b.batch_index, b.batch_id, b.version),
            (1, 0, 42, 1)
        );
        assert!(b.skipped.is_empty());
        let a = &b.accounts[0];
        assert_eq!(a.kind, OtpKind::Totp);
        assert_eq!(
            a.uri,
            "otpauth://totp/Example:kevin@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"
        );
        assert_eq!(a.suggested_name, "Example/kevin@example.com");
        // Same bytes the manual setup would write.
        let manual = Totp::new(
            "JBSWY3DPEHPK3PXP",
            "kevin@example.com",
            Some("Example"),
            TotpAlgorithm::Sha1,
            6,
            30,
        )
        .unwrap()
        .to_uri();
        assert_eq!(a.uri, manual);
    }

    #[test]
    fn issuer_prefixed_name_hotp_eight_digits_and_md5() {
        let p = payload(
            &[
                account(HELLO, "Bank:me", "", 2, 2, 2, 0),
                account(HELLO, "Corp:vpn", "Corp", 1, 1, 1, 5),
                account(HELLO, "old", "Legacy", 4, 1, 2, 0),
                account(b"", "empty", "", 1, 1, 2, 0),
            ],
            2,
            1,
            7,
        );
        let b = parse_migration_uri(&uri(&p)).unwrap();
        assert_eq!((b.batch_size, b.batch_index), (2, 1));
        assert_eq!(b.accounts.len(), 2);
        assert_eq!(
            b.accounts[0].uri,
            "otpauth://totp/Bank:me?secret=JBSWY3DPEHPK3PXP&issuer=Bank&algorithm=SHA256&digits=8"
        );
        assert_eq!(b.accounts[0].issuer.as_deref(), Some("Bank"));
        assert_eq!(b.accounts[1].kind, OtpKind::Hotp);
        assert_eq!(
            b.accounts[1].uri,
            "otpauth://hotp/Corp:vpn?secret=JBSWY3DPEHPK3PXP&counter=5&issuer=Corp"
        );
        assert_eq!(
            b.skipped,
            vec![
                SkippedAccount {
                    label: "Legacy:old".into(),
                    reason: SkipReason::Md5
                },
                SkippedAccount {
                    label: "empty".into(),
                    reason: SkipReason::EmptySecret
                },
            ]
        );
    }

    #[test]
    fn names_stay_one_segment_each() {
        assert_eq!(suggest_name(Some("A/B"), "x/y"), "A-B/x-y");
        assert_eq!(suggest_name(None, ".hidden"), "hidden");
        assert_eq!(suggest_name(Some(" "), " "), "otp");
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(
            parse_migration_uri("otpauth://totp/X?secret=A").unwrap_err(),
            MigrationError::NotMigrationUri
        );
        assert_eq!(
            parse_migration_uri("otpauth-migration://offline?foo=1").unwrap_err(),
            MigrationError::MissingData
        );
        assert_eq!(
            parse_migration_uri("otpauth-migration://offline?data=%%%").unwrap_err(),
            MigrationError::BadBase64
        );
        // Truncated payload: length prefix runs past the end.
        assert_eq!(
            parse_migration_uri(&uri(&[0x0a, 0x50, 0x01])).unwrap_err(),
            MigrationError::BadPayload
        );
    }

    #[test]
    fn unknown_fields_are_skipped() {
        let mut a = account(HELLO, "k", "I", 1, 1, 2, 0);
        field_varint(99, 1, &mut a);
        field_bytes(98, b"future", &mut a);
        let mut p = payload(&[a], 1, 0, 1);
        field_bytes(97, b"also future", &mut p);
        let b = parse_migration_uri(&uri(&p)).unwrap();
        assert_eq!(b.accounts.len(), 1);
    }
}
