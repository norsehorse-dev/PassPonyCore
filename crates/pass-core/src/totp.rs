//! TOTP per RFC 6238 (HOTP per RFC 4226), with `otpauth://` URI parsing and
//! building as used by pass-otp entry lines. SHA-1/SHA-256/SHA-512,
//! configurable digits and period. Secrets are RFC 4648 base32 (padding
//! optional, case- and whitespace-tolerant, as keys are pasted in the wild).
//!
//! Reading is tolerant; writing is canonical. `Totp::to_uri` emits one
//! spelling for any given configuration so a code set up on either phone or
//! the desktop produces the identical entry line.

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TotpAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Debug, thiserror::Error)]
pub enum TotpError {
    #[error("not an otpauth:// totp URI")]
    NotTotpUri,
    #[error("missing secret parameter")]
    MissingSecret,
    #[error("invalid base32 secret")]
    BadSecret,
    #[error("unsupported algorithm: {0}")]
    BadAlgorithm(String),
    #[error("invalid numeric parameter: {0}")]
    BadNumber(String),
}

impl TotpAlgorithm {
    /// The spelling the `algorithm=` URI parameter uses.
    pub fn uri_name(self) -> &'static str {
        match self {
            TotpAlgorithm::Sha1 => "SHA1",
            TotpAlgorithm::Sha256 => "SHA256",
            TotpAlgorithm::Sha512 => "SHA512",
        }
    }
}

/// Defaults per the otpauth URI convention (Google Authenticator's key URI
/// format, which pass-otp follows): omitted parameters mean these.
pub const DEFAULT_DIGITS: u32 = 6;
pub const DEFAULT_PERIOD: u64 = 30;
/// Digit counts every authenticator and oathtool agree on.
pub const MIN_DIGITS: u32 = 6;
pub const MAX_DIGITS: u32 = 8;

/// A parsed TOTP configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Totp {
    pub secret: Vec<u8>,
    pub algorithm: TotpAlgorithm,
    pub digits: u32,
    pub period: u64,
    pub label: String,
    pub issuer: Option<String>,
}

impl Totp {
    /// Parse an `otpauth://totp/...` URI (the format pass-otp stores).
    /// Unknown query parameters are ignored. `counter`/`hotp` URIs are
    /// rejected; HOTP is out of scope.
    pub fn from_uri(uri: &str) -> Result<Self, TotpError> {
        let rest = uri
            .strip_prefix("otpauth://totp/")
            .or_else(|| uri.strip_prefix("otpauth://totp"))
            .ok_or(TotpError::NotTotpUri)?;
        let (label_raw, query) = match rest.split_once('?') {
            Some((l, q)) => (l, q),
            None => (rest, ""),
        };
        let mut secret = None;
        let mut algorithm = TotpAlgorithm::Sha1;
        let mut digits = 6u32;
        let mut period = 30u64;
        let mut issuer = None;
        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            match k.to_ascii_lowercase().as_str() {
                "secret" => secret = Some(decode_base32(v)?),
                "algorithm" => {
                    algorithm = match v.to_ascii_uppercase().as_str() {
                        "SHA1" => TotpAlgorithm::Sha1,
                        "SHA256" => TotpAlgorithm::Sha256,
                        "SHA512" => TotpAlgorithm::Sha512,
                        other => return Err(TotpError::BadAlgorithm(other.to_owned())),
                    }
                }
                "digits" => {
                    digits = v
                        .parse()
                        .map_err(|_| TotpError::BadNumber(format!("digits={v}")))?
                }
                "period" => {
                    period = v
                        .parse()
                        .map_err(|_| TotpError::BadNumber(format!("period={v}")))?
                }
                "issuer" => issuer = Some(percent_decode(v)),
                _ => {}
            }
        }
        let secret = secret.ok_or(TotpError::MissingSecret)?;
        if secret.is_empty() {
            // `secret=` with nothing after it is not a key; treating it as
            // one would show a code that nothing on the other side accepts.
            return Err(TotpError::MissingSecret);
        }
        Ok(Totp {
            secret,
            algorithm,
            digits,
            period: period.max(1),
            label: percent_decode(label_raw),
            issuer,
        })
    }

    /// Build a configuration from its parts, validating each. `secret` is the
    /// base32 text the user was given (tolerant decoding, same as a URI);
    /// `account` and `issuer` are the names an authenticator displays. The
    /// label follows the URI convention: `Issuer:account` when both are
    /// present, otherwise whichever one is.
    pub fn new(
        secret: &str,
        account: &str,
        issuer: Option<&str>,
        algorithm: TotpAlgorithm,
        digits: u32,
        period: u64,
    ) -> Result<Self, TotpError> {
        validate_secret(secret)?;
        if !(MIN_DIGITS..=MAX_DIGITS).contains(&digits) {
            return Err(TotpError::BadNumber(format!("digits={digits}")));
        }
        if period == 0 {
            return Err(TotpError::BadNumber("period=0".to_owned()));
        }
        let issuer = issuer.map(str::trim).filter(|s| !s.is_empty());
        let account = account.trim();
        let label = match (issuer, account.is_empty()) {
            (Some(i), false) => format!("{i}:{account}"),
            (Some(i), true) => i.to_owned(),
            (None, _) => account.to_owned(),
        };
        Ok(Totp {
            secret: decode_base32(secret)?,
            algorithm,
            digits,
            period,
            label,
            issuer: issuer.map(str::to_owned),
        })
    }

    /// Serialize as the `otpauth://totp/` URI pass-otp stores. Parameters at
    /// their defaults (SHA1, 6 digits, 30 s) are omitted, so the line stays as
    /// short as the QR codes sites hand out. The secret is upper-case base32
    /// without padding, the spelling every authenticator emits.
    pub fn to_uri(&self) -> String {
        let mut uri = format!(
            "otpauth://totp/{}?secret={}",
            percent_encode(&self.label),
            encode_base32(&self.secret)
        );
        if let Some(issuer) = &self.issuer {
            uri.push_str("&issuer=");
            uri.push_str(&percent_encode(issuer));
        }
        if self.algorithm != TotpAlgorithm::Sha1 {
            uri.push_str("&algorithm=");
            uri.push_str(self.algorithm.uri_name());
        }
        if self.digits != DEFAULT_DIGITS {
            uri.push_str(&format!("&digits={}", self.digits));
        }
        if self.period != DEFAULT_PERIOD {
            uri.push_str(&format!("&period={}", self.period));
        }
        uri
    }

    /// The code for the counter window containing `unix_time`.
    pub fn code_at(&self, unix_time: u64) -> String {
        let counter = unix_time / self.period;
        hotp(&self.secret, counter, self.algorithm, self.digits)
    }

    /// Seconds remaining in the current window (for the progress ring).
    pub fn seconds_remaining(&self, unix_time: u64) -> u64 {
        self.period - (unix_time % self.period)
    }
}

fn hotp(secret: &[u8], counter: u64, algorithm: TotpAlgorithm, digits: u32) -> String {
    let msg = counter.to_be_bytes();
    let digest: Vec<u8> = match algorithm {
        TotpAlgorithm::Sha1 => {
            let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(secret).expect("hmac any key len");
            mac.update(&msg);
            mac.finalize().into_bytes().to_vec()
        }
        TotpAlgorithm::Sha256 => {
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret).expect("hmac any key len");
            mac.update(&msg);
            mac.finalize().into_bytes().to_vec()
        }
        TotpAlgorithm::Sha512 => {
            let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(secret).expect("hmac any key len");
            mac.update(&msg);
            mac.finalize().into_bytes().to_vec()
        }
    };
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let binary = ((u32::from(digest[offset]) & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    // u64 arithmetic: 10^10 no longer fits a u32, and a URI can ask for any
    // digit count on the read path.
    let modulus = 10u64.pow(digits);
    let code = u64::from(binary) % modulus;
    format!("{code:0width$}", width = digits as usize)
}

/// Check a base32 secret as a user typed or pasted it; returns the decoded
/// length in bytes. Empty (or whitespace-only) input is a missing secret,
/// anything outside the alphabet is a bad one.
pub fn validate_secret(input: &str) -> Result<usize, TotpError> {
    let decoded = decode_base32(input)?;
    if decoded.is_empty() {
        return Err(TotpError::MissingSecret);
    }
    Ok(decoded.len())
}

/// RFC 4648 base32, upper-case, no padding.
fn encode_base32(input: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::with_capacity(input.len().div_ceil(5) * 8);
    let mut bits: u64 = 0;
    let mut nbits: u32 = 0;
    for &byte in input {
        bits = (bits << 8) | u64::from(byte);
        nbits += 8;
        while nbits >= 5 {
            nbits -= 5;
            out.push(ALPHABET[((bits >> nbits) & 0x1f) as usize] as char);
        }
    }
    if nbits > 0 {
        out.push(ALPHABET[((bits << (5 - nbits)) & 0x1f) as usize] as char);
    }
    out
}

/// RFC 4648 base32, tolerant: case-insensitive, ignores whitespace and `-`,
/// padding optional.
fn decode_base32(input: &str) -> Result<Vec<u8>, TotpError> {
    let mut bits: u64 = 0;
    let mut nbits: u32 = 0;
    let mut out = Vec::new();
    for c in input.chars() {
        let c = c.to_ascii_uppercase();
        if c.is_whitespace() || c == '-' || c == '=' {
            continue;
        }
        let val = match c {
            'A'..='Z' => c as u64 - 'A' as u64,
            '2'..='7' => c as u64 - '2' as u64 + 26,
            _ => return Err(TotpError::BadSecret),
        };
        bits = (bits << 5) | val;
        nbits += 5;
        if nbits >= 8 {
            nbits -= 8;
            out.push((bits >> nbits) as u8);
        }
    }
    Ok(out)
}

/// Minimal percent-decoding for labels/issuers; invalid escapes pass through.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Percent-encode a label or issuer for the URI. Unreserved characters
/// (RFC 3986) plus `:` and `@` stay literal, since `Issuer:account` and mail
/// style account names are the norm in labels and both are legal in a query
/// value; everything else, spaces and non-ASCII included, is escaped.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b':' | b'@' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 Appendix B test vectors. Secrets are the ASCII seeds; note the
    // RFC uses 20/32/64-byte seeds for SHA-1/256/512 respectively.
    const SEED20: &[u8] = b"12345678901234567890";
    const SEED32: &[u8] = b"12345678901234567890123456789012";
    const SEED64: &[u8] = b"1234567890123456789012345678901234567890123456789012345678901234";

    fn totp(secret: &[u8], algo: TotpAlgorithm) -> Totp {
        Totp {
            secret: secret.to_vec(),
            algorithm: algo,
            digits: 8,
            period: 30,
            label: String::new(),
            issuer: None,
        }
    }

    #[test]
    fn rfc6238_vectors() {
        let cases: &[(u64, &str, TotpAlgorithm, &[u8])] = &[
            (59, "94287082", TotpAlgorithm::Sha1, SEED20),
            (59, "46119246", TotpAlgorithm::Sha256, SEED32),
            (59, "90693936", TotpAlgorithm::Sha512, SEED64),
            (1111111109, "07081804", TotpAlgorithm::Sha1, SEED20),
            (1111111111, "14050471", TotpAlgorithm::Sha1, SEED20),
            (1234567890, "89005924", TotpAlgorithm::Sha1, SEED20),
            (1234567890, "91819424", TotpAlgorithm::Sha256, SEED32),
            (1234567890, "93441116", TotpAlgorithm::Sha512, SEED64),
            (2000000000, "69279037", TotpAlgorithm::Sha1, SEED20),
            (20000000000, "65353130", TotpAlgorithm::Sha1, SEED20),
            (20000000000, "77737706", TotpAlgorithm::Sha256, SEED32),
            (20000000000, "47863826", TotpAlgorithm::Sha512, SEED64),
        ];
        for &(time, expected, algo, seed) in cases {
            assert_eq!(
                totp(seed, algo).code_at(time),
                expected,
                "t={time} algo={algo:?}"
            );
        }
    }

    #[test]
    fn uri_parsing_defaults_and_overrides() {
        let t =
            Totp::from_uri("otpauth://totp/Example:kevin?secret=JBSWY3DPEHPK3PXP&issuer=Example")
                .unwrap();
        assert_eq!(t.digits, 6);
        assert_eq!(t.period, 30);
        assert_eq!(t.algorithm, TotpAlgorithm::Sha1);
        assert_eq!(t.label, "Example:kevin");
        assert_eq!(t.issuer.as_deref(), Some("Example"));
        assert_eq!(t.secret, b"Hello!\xde\xad\xbe\xef");

        let t = Totp::from_uri(
            "otpauth://totp/X?secret=JBSWY3DPEHPK3PXP&algorithm=sha256&digits=8&period=60",
        )
        .unwrap();
        assert_eq!(t.algorithm, TotpAlgorithm::Sha256);
        assert_eq!(t.digits, 8);
        assert_eq!(t.period, 60);
        assert_eq!(t.seconds_remaining(61), 59);
    }

    #[test]
    fn uri_rejections() {
        assert!(Totp::from_uri("otpauth://hotp/X?secret=JBSWY3DPEHPK3PXP").is_err());
        assert!(Totp::from_uri("otpauth://totp/X").is_err()); // no secret
        assert!(Totp::from_uri("otpauth://totp/X?secret=1189").is_err()); // bad b32
        assert!(matches!(
            Totp::from_uri("otpauth://totp/X?secret="),
            Err(TotpError::MissingSecret)
        ));
        assert!(matches!(
            Totp::from_uri("otpauth-migration://offline?data=abc"),
            Err(TotpError::NotTotpUri)
        ));
    }

    #[test]
    fn new_builds_the_canonical_label() {
        let t = Totp::new(
            "jbsw y3dp ehpk 3pxp",
            "kevin",
            Some("Example"),
            TotpAlgorithm::Sha1,
            6,
            30,
        )
        .unwrap();
        assert_eq!(t.label, "Example:kevin");
        assert_eq!(t.issuer.as_deref(), Some("Example"));
        assert_eq!(t.secret, b"Hello!\xde\xad\xbe\xef");
        // Issuer only, account only, and blank issuer treated as none.
        let t = Totp::new("JBSWY3DP", "", Some("Example"), TotpAlgorithm::Sha1, 6, 30).unwrap();
        assert_eq!(t.label, "Example");
        let t = Totp::new("JBSWY3DP", "kevin", Some("  "), TotpAlgorithm::Sha1, 6, 30).unwrap();
        assert_eq!(t.label, "kevin");
        assert_eq!(t.issuer, None);
    }

    #[test]
    fn new_rejects_bad_parts() {
        assert!(matches!(
            Totp::new("", "kevin", None, TotpAlgorithm::Sha1, 6, 30),
            Err(TotpError::MissingSecret)
        ));
        assert!(matches!(
            Totp::new("1189", "kevin", None, TotpAlgorithm::Sha1, 6, 30),
            Err(TotpError::BadSecret)
        ));
        assert!(matches!(
            Totp::new("JBSWY3DP", "kevin", None, TotpAlgorithm::Sha1, 5, 30),
            Err(TotpError::BadNumber(_))
        ));
        assert!(matches!(
            Totp::new("JBSWY3DP", "kevin", None, TotpAlgorithm::Sha1, 9, 30),
            Err(TotpError::BadNumber(_))
        ));
        assert!(matches!(
            Totp::new("JBSWY3DP", "kevin", None, TotpAlgorithm::Sha1, 6, 0),
            Err(TotpError::BadNumber(_))
        ));
    }

    #[test]
    fn to_uri_is_canonical_and_round_trips() {
        // Defaults are omitted, the secret is upper-case unpadded base32.
        let t = Totp::new(
            "jbswy3dpehpk3pxp====",
            "kevin",
            Some("Example"),
            TotpAlgorithm::Sha1,
            6,
            30,
        )
        .unwrap();
        assert_eq!(
            t.to_uri(),
            "otpauth://totp/Example:kevin?secret=JBSWY3DPEHPK3PXP&issuer=Example"
        );
        assert_eq!(Totp::from_uri(&t.to_uri()).unwrap(), t);
        // Every override is spelled out, in a fixed order.
        let t = Totp::new(
            "JBSWY3DPEHPK3PXP",
            "kevin",
            Some("Example"),
            TotpAlgorithm::Sha512,
            8,
            60,
        )
        .unwrap();
        assert_eq!(
            t.to_uri(),
            "otpauth://totp/Example:kevin?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA512&digits=8&period=60"
        );
        assert_eq!(Totp::from_uri(&t.to_uri()).unwrap(), t);
        // Spaces and non-ASCII are escaped; `:` and `@` stay literal.
        let t = Totp::new(
            "JBSWY3DP",
            "kevin@example.com",
            Some("Caf\u{e9} Bank"),
            TotpAlgorithm::Sha1,
            6,
            30,
        )
        .unwrap();
        assert_eq!(
            t.to_uri(),
            "otpauth://totp/Caf%C3%A9%20Bank:kevin@example.com?secret=JBSWY3DP&issuer=Caf%C3%A9%20Bank"
        );
        let back = Totp::from_uri(&t.to_uri()).unwrap();
        assert_eq!(back.label, "Caf\u{e9} Bank:kevin@example.com");
        assert_eq!(back.issuer.as_deref(), Some("Caf\u{e9} Bank"));
        // A parsed URI with no issuer and a secret that is not a multiple of
        // five bytes survives too (MZXW6YTBOI is the canonical spelling of
        // the six bytes "foobar").
        let t = Totp::from_uri("otpauth://totp/plain?secret=mzxw6ytboi&period=15").unwrap();
        assert_eq!(
            t.to_uri(),
            "otpauth://totp/plain?secret=MZXW6YTBOI&period=15"
        );
    }

    #[test]
    fn base32_encode_round_trips() {
        for bytes in [
            &b""[..],
            b"f",
            b"fo",
            b"foo",
            b"foob",
            b"fooba",
            b"foobar",
            b"Hello!\xde\xad\xbe\xef",
        ] {
            let text = encode_base32(bytes);
            assert!(!text.contains('='));
            assert_eq!(decode_base32(&text).unwrap(), bytes, "{text}");
        }
        assert_eq!(encode_base32(b"foobar"), "MZXW6YTBOI");
    }

    #[test]
    fn validate_secret_reports_length() {
        assert_eq!(validate_secret("JBSWY3DPEHPK3PXP").unwrap(), 10);
        assert_eq!(validate_secret("jbsw-y3dp ehpk 3pxp").unwrap(), 10);
        assert!(matches!(validate_secret(""), Err(TotpError::MissingSecret)));
        assert!(matches!(
            validate_secret("   "),
            Err(TotpError::MissingSecret)
        ));
        assert!(matches!(validate_secret("1189"), Err(TotpError::BadSecret)));
    }

    #[test]
    fn ten_digit_codes_do_not_overflow() {
        let t = Totp::from_uri("otpauth://totp/X?secret=JBSWY3DPEHPK3PXP&digits=10").unwrap();
        assert_eq!(t.code_at(59).len(), 10);
    }

    #[test]
    fn base32_tolerance() {
        // padded, lowercase, spaced variants all decode identically
        for s in [
            "JBSWY3DPEHPK3PXP",
            "jbswy3dpehpk3pxp",
            "JBSW Y3DP EHPK 3PXP",
            "JBSWY3DPEHPK3PXP====",
        ] {
            assert_eq!(decode_base32(s).unwrap(), b"Hello!\xde\xad\xbe\xef");
        }
    }
}
