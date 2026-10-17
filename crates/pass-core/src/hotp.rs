//! HOTP (RFC 4226) entries, the counter-based codes pass-otp stores as
//! `otpauth://hotp/...?secret=...&counter=N`.
//!
//! pass-otp's rule, which this module follows so a store moves between the
//! CLI and the apps without skipping or repeating codes: the stored counter
//! is the last one used. `pass otp code` computes the code at counter + 1,
//! then rewrites the entry with that counter and commits
//! "Increment HOTP counter for <name>." A URI fresh from `pass otp insert`
//! with `counter=0` therefore yields the code for counter 1 first.
//!
//! Rewriting touches only the counter's value inside the URI, so every other
//! byte of the line, parameter order included, survives. (pass-otp's own
//! rewrite only matches `&counter=`, so a URI that leads with `?counter=`
//! never advances there; this one does, and `Hotp::to_uri` always writes the
//! counter after the secret so the CLI can advance what the apps write.)

use crate::totp::{
    decode_base32, encode_base32, hotp, percent_decode, percent_encode, validate_secret,
    TotpAlgorithm, TotpError, DEFAULT_DIGITS, MAX_DIGITS, MIN_DIGITS,
};

/// A parsed HOTP configuration. `counter` is the last counter used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hotp {
    pub secret: Vec<u8>,
    pub algorithm: TotpAlgorithm,
    pub digits: u32,
    pub counter: u64,
    pub label: String,
    pub issuer: Option<String>,
}

/// The next code and the counter it was computed at, which is the counter to
/// store back into the entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HotpStep {
    pub code: String,
    pub counter: u64,
}

impl Hotp {
    /// Parse an `otpauth://hotp/...` URI. A counter is required (pass-otp
    /// refuses an HOTP URI without one); unknown parameters are ignored.
    pub fn from_uri(uri: &str) -> Result<Self, TotpError> {
        let rest = uri
            .strip_prefix("otpauth://hotp/")
            .or_else(|| uri.strip_prefix("otpauth://hotp"))
            .ok_or(TotpError::NotHotpUri)?;
        let (label_raw, query) = rest.split_once('?').unwrap_or((rest, ""));
        let mut secret = None;
        let mut algorithm = TotpAlgorithm::Sha1;
        let mut digits = DEFAULT_DIGITS;
        let mut counter = None;
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
                "counter" => {
                    counter = Some(
                        v.parse()
                            .map_err(|_| TotpError::BadNumber(format!("counter={v}")))?,
                    )
                }
                "issuer" => issuer = Some(percent_decode(v)),
                _ => {}
            }
        }
        let secret = secret.ok_or(TotpError::MissingSecret)?;
        if secret.is_empty() {
            return Err(TotpError::MissingSecret);
        }
        if !(1..=10).contains(&digits) {
            return Err(TotpError::BadNumber(format!("digits={digits}")));
        }
        Ok(Hotp {
            secret,
            algorithm,
            digits,
            counter: counter.ok_or(TotpError::MissingCounter)?,
            label: percent_decode(label_raw),
            issuer,
        })
    }

    /// Build from parts, validating each, with the same label rule as
    /// `Totp::new` (`Issuer:account` when both are present).
    pub fn new(
        secret: &str,
        account: &str,
        issuer: Option<&str>,
        algorithm: TotpAlgorithm,
        digits: u32,
        counter: u64,
    ) -> Result<Self, TotpError> {
        validate_secret(secret)?;
        if !(MIN_DIGITS..=MAX_DIGITS).contains(&digits) {
            return Err(TotpError::BadNumber(format!("digits={digits}")));
        }
        let issuer = issuer.map(str::trim).filter(|s| !s.is_empty());
        let account = account.trim();
        let label = match (issuer, account.is_empty()) {
            (Some(i), false) => format!("{i}:{account}"),
            (Some(i), true) => i.to_owned(),
            (None, _) => account.to_owned(),
        };
        Ok(Hotp {
            secret: decode_base32(secret)?,
            algorithm,
            digits,
            counter,
            label,
            issuer: issuer.map(str::to_owned),
        })
    }

    /// Canonical URI: secret first, then `&counter=` (so pass-otp's in-place
    /// rewrite finds it), then issuer and any non-default algorithm/digits.
    pub fn to_uri(&self) -> String {
        let mut uri = format!(
            "otpauth://hotp/{}?secret={}&counter={}",
            percent_encode(&self.label),
            encode_base32(&self.secret),
            self.counter
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
        uri
    }

    /// The code for an explicit counter value.
    pub fn code_at_counter(&self, counter: u64) -> String {
        hotp(&self.secret, counter, self.algorithm, self.digits)
    }

    /// The next code, pass-otp style: computed at `counter + 1`.
    pub fn next(&self) -> Result<HotpStep, TotpError> {
        let counter = self
            .counter
            .checked_add(1)
            .ok_or_else(|| TotpError::BadNumber("counter overflow".to_owned()))?;
        Ok(HotpStep {
            code: self.code_at_counter(counter),
            counter,
        })
    }
}

/// `uri` with its `counter` parameter's value replaced by `counter`, every
/// other byte unchanged. A URI with no counter parameter gets
/// `&counter=<n>` appended.
pub fn uri_with_counter(uri: &str, counter: u64) -> String {
    let Some((head, query)) = uri.split_once('?') else {
        return format!("{uri}?counter={counter}");
    };
    let mut replaced = false;
    let params: Vec<String> = query
        .split('&')
        .map(|pair| {
            let key = pair.split_once('=').map_or(pair, |(k, _)| k);
            if !replaced && key.eq_ignore_ascii_case("counter") {
                replaced = true;
                format!("{key}={counter}")
            } else {
                pair.to_owned()
            }
        })
        .collect();
    let mut out = format!("{head}?{}", params.join("&"));
    if !replaced {
        if !query.is_empty() {
            out.push('&');
        }
        out.push_str(&format!("counter={counter}"));
    }
    out
}

/// Which kind of `otpauth://` line an entry carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtpKind {
    Totp,
    Hotp,
}

/// Classify an `otpauth://` URI by its type segment, without validating
/// the rest.
pub fn otp_kind(uri: &str) -> Option<OtpKind> {
    if uri.starts_with("otpauth://totp") {
        Some(OtpKind::Totp)
    } else if uri.starts_with("otpauth://hotp") {
        Some(OtpKind::Hotp)
    } else {
        None
    }
}

/// Advance the HOTP line of an entry: returns the code and the new entry
/// bytes with only the counter value changed. Errors when the entry has no
/// `otpauth://hotp` line or it does not parse.
pub fn advance_entry(entry: &mut crate::entry::Entry) -> Result<HotpStep, TotpError> {
    let uri = entry.otpauth().ok_or(TotpError::NotHotpUri)?.to_owned();
    let hotp = Hotp::from_uri(&uri)?;
    let step = hotp.next()?;
    entry.set_otpauth(&uri_with_counter(&uri, step.counter));
    Ok(step)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::Entry;

    // RFC 4226 Appendix D: secret "12345678901234567890", counters 0..9.
    const RFC4226: [&str; 10] = [
        "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871",
        "520489",
    ];

    fn rfc_hotp(counter: u64) -> Hotp {
        Hotp {
            secret: b"12345678901234567890".to_vec(),
            algorithm: TotpAlgorithm::Sha1,
            digits: 6,
            counter,
            label: String::new(),
            issuer: None,
        }
    }

    #[test]
    fn rfc4226_vectors() {
        for (c, expected) in RFC4226.iter().enumerate() {
            assert_eq!(
                rfc_hotp(0).code_at_counter(c as u64),
                *expected,
                "counter {c}"
            );
        }
    }

    #[test]
    fn next_uses_counter_plus_one_like_pass_otp() {
        let step = rfc_hotp(0).next().unwrap();
        assert_eq!(
            step,
            HotpStep {
                code: RFC4226[1].to_owned(),
                counter: 1
            }
        );
        assert!(rfc_hotp(u64::MAX).next().is_err());
    }

    #[test]
    fn parse_requires_counter_and_secret() {
        let h = Hotp::from_uri(
            "otpauth://hotp/Example:kevin?secret=JBSWY3DPEHPK3PXP&counter=7&issuer=Example",
        )
        .unwrap();
        assert_eq!(h.counter, 7);
        assert_eq!(h.label, "Example:kevin");
        assert_eq!(h.issuer.as_deref(), Some("Example"));
        assert!(matches!(
            Hotp::from_uri("otpauth://hotp/X?secret=JBSWY3DPEHPK3PXP"),
            Err(TotpError::MissingCounter)
        ));
        assert!(matches!(
            Hotp::from_uri("otpauth://hotp/X?counter=1"),
            Err(TotpError::MissingSecret)
        ));
        assert!(matches!(
            Hotp::from_uri("otpauth://totp/X?secret=JBSWY3DPEHPK3PXP"),
            Err(TotpError::NotHotpUri)
        ));
        assert!(Hotp::from_uri("otpauth://hotp/X?secret=JBSWY3DPEHPK3PXP&counter=-1").is_err());
    }

    #[test]
    fn counter_rewrite_touches_only_the_value() {
        let uri = "otpauth://hotp/A?secret=S&counter=9&issuer=A%20B";
        assert_eq!(
            uri_with_counter(uri, 10),
            "otpauth://hotp/A?secret=S&counter=10&issuer=A%20B"
        );
        // Leading counter (which pass-otp itself cannot advance) still works.
        assert_eq!(
            uri_with_counter("otpauth://hotp/A?counter=3&secret=S", 4),
            "otpauth://hotp/A?counter=4&secret=S"
        );
        assert_eq!(
            uri_with_counter("otpauth://hotp/A?secret=S", 1),
            "otpauth://hotp/A?secret=S&counter=1"
        );
    }

    #[test]
    fn canonical_uri_puts_counter_after_secret() {
        let h = Hotp::new(
            "JBSWY3DPEHPK3PXP",
            "kevin",
            Some("Example"),
            TotpAlgorithm::Sha1,
            6,
            0,
        )
        .unwrap();
        assert_eq!(
            h.to_uri(),
            "otpauth://hotp/Example:kevin?secret=JBSWY3DPEHPK3PXP&counter=0&issuer=Example"
        );
        assert_eq!(Hotp::from_uri(&h.to_uri()).unwrap(), h);
        let h8 = Hotp::new("JBSWY3DPEHPK3PXP", "k", None, TotpAlgorithm::Sha256, 8, 5).unwrap();
        assert_eq!(
            h8.to_uri(),
            "otpauth://hotp/k?secret=JBSWY3DPEHPK3PXP&counter=5&algorithm=SHA256&digits=8"
        );
    }

    #[test]
    fn advance_entry_keeps_other_lines() {
        let mut e = Entry::from_bytes(
            b"pw\nuser: k\notpauth://hotp/X?secret=JBSWY3DPEHPK3PXP&counter=0\nnote\n".to_vec(),
        );
        let step = advance_entry(&mut e).unwrap();
        assert_eq!(step.counter, 1);
        assert_eq!(
            e.to_bytes(),
            b"pw\nuser: k\notpauth://hotp/X?secret=JBSWY3DPEHPK3PXP&counter=1\nnote\n"
        );
        let mut plain = Entry::from_bytes(b"pw\n".to_vec());
        assert!(advance_entry(&mut plain).is_err());
    }

    #[test]
    fn kind_detection() {
        assert_eq!(otp_kind("otpauth://totp/X?secret=A"), Some(OtpKind::Totp));
        assert_eq!(otp_kind("otpauth://hotp/X?secret=A"), Some(OtpKind::Hotp));
        assert_eq!(otp_kind("otpauth-migration://offline?data=x"), None);
    }
}
