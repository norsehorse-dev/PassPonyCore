//! TOTP per RFC 6238 (HOTP per RFC 4226), with `otpauth://` URI parsing as
//! used by pass-otp entry lines. SHA-1/SHA-256/SHA-512, configurable digits
//! and period. Secrets are RFC 4648 base32 (padding optional, case- and
//! whitespace-tolerant, as keys are pasted in the wild).

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
    /// rejected — HOTP is out of scope.
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
        Ok(Totp {
            secret: secret.ok_or(TotpError::MissingSecret)?,
            algorithm,
            digits,
            period: period.max(1),
            label: percent_decode(label_raw),
            issuer,
        })
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
    let modulus = 10u64.pow(digits) as u32;
    let code = binary % modulus;
    format!("{code:0width$}", width = digits as usize)
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
