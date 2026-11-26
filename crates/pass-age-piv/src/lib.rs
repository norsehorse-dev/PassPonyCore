//! The `piv-p256` age recipient type that age-plugin-yubikey defines,
//! implemented natively so a passage store whose `.age-recipients`
//! lists `age1yubikey1...` keys can be written to without the plugin
//! binary or the YubiKey itself (wrapping a file key only needs the
//! public key).
//!
//! Format, matching age-plugin-yubikey 0.5 (`src/format.rs`, `src/p256.rs`):
//! - recipient: bech32 (not bech32m), HRP `age1yubikey`, data the
//!   33-byte compressed SEC1 P-256 point;
//! - stanza: `-> piv-p256 <tag> <epk>` with `tag` the first 4 bytes of
//!   SHA-256(compressed recipient point) and `epk` the compressed
//!   ephemeral point, both unpadded standard base64; the body is the
//!   file key sealed with ChaCha20-Poly1305 (zero nonce) under
//!   HKDF-SHA256(ikm = ECDH x-coordinate, salt = epk || recipient,
//!   info = "piv-p256").
//!
//! The crate is independent of the `age` crate on purpose: PassPony
//! Android's engine (pass-ffi, age 0.11) and PassPony Desktop (age 0.12)
//! each adapt [`PivRecipient::wrap`] to their own `age::Recipient` in a
//! few lines. [`PivStanza::unwrap`] takes the ECDH result rather than a
//! key, since on a real YubiKey that step happens on the card (PIV
//! GENERAL AUTHENTICATE with the ephemeral point, which returns the same
//! 32-byte x-coordinate).

use std::fmt;
use std::str::FromStr;

use base64::{prelude::BASE64_STANDARD_NO_PAD, Engine};
use bech32::{primitives::decode::CheckedHrpstring, Bech32, Hrp};
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, Key, KeyInit, Nonce};
use hkdf::Hkdf;
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{EncodedPoint, PublicKey};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// The bech32 HRP of a YubiKey recipient.
pub const RECIPIENT_PREFIX: &str = "age1yubikey";
/// The stanza tag age-plugin-yubikey writes and reads.
pub const STANZA_TAG: &str = "piv-p256";
/// Length of the recipient tag in a stanza.
pub const TAG_BYTES: usize = 4;
/// Length of a compressed P-256 point.
pub const COMPRESSED_POINT_BYTES: usize = 33;
/// Length of an age file key.
pub const FILE_KEY_BYTES: usize = 16;

const STANZA_KEY_LABEL: &[u8] = b"piv-p256";
const ENCRYPTED_FILE_KEY_BYTES: usize = FILE_KEY_BYTES + 16;

/// The string isn't an `age1yubikey1...` recipient.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseRecipientError;

impl fmt::Display for ParseRecipientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("not a valid age1yubikey recipient")
    }
}

impl std::error::Error for ParseRecipientError {}

/// A YubiKey (PIV slot, P-256) age recipient.
#[derive(Clone, PartialEq, Eq)]
pub struct PivRecipient(PublicKey);

impl fmt::Debug for PivRecipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PivRecipient({self})")
    }
}

impl fmt::Display for PivRecipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hrp = Hrp::parse_unchecked(RECIPIENT_PREFIX);
        let s = bech32::encode::<Bech32>(hrp, &self.compressed()).map_err(|_| fmt::Error)?;
        f.write_str(&s)
    }
}

impl FromStr for PivRecipient {
    type Err = ParseRecipientError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parsed = CheckedHrpstring::new::<Bech32>(s).map_err(|_| ParseRecipientError)?;
        if parsed.hrp().to_lowercase() != RECIPIENT_PREFIX {
            return Err(ParseRecipientError);
        }
        let bytes: Vec<u8> = parsed.byte_iter().collect();
        Self::from_compressed(&bytes).ok_or(ParseRecipientError)
    }
}

impl PivRecipient {
    /// The recipient for a compressed SEC1 P-256 point, if it is one.
    pub fn from_compressed(bytes: &[u8]) -> Option<Self> {
        let point = EncodedPoint::from_bytes(bytes).ok()?;
        if !point.is_compressed() {
            return None;
        }
        Option::from(PublicKey::from_encoded_point(&point)).map(PivRecipient)
    }

    /// The recipient for a SEC1 P-256 point in either encoding: what a
    /// YubiKey reports for a PIV slot is uncompressed (`04 || x || y`).
    pub fn from_sec1(bytes: &[u8]) -> Option<Self> {
        PublicKey::from_sec1_bytes(bytes).ok().map(PivRecipient)
    }

    /// The compressed SEC1 encoding of the public key.
    pub fn compressed(&self) -> [u8; COMPRESSED_POINT_BYTES] {
        let mut out = [0; COMPRESSED_POINT_BYTES];
        out.copy_from_slice(self.0.to_encoded_point(true).as_bytes());
        out
    }

    /// The 4-byte tag that names this recipient in a stanza.
    pub fn tag(&self) -> [u8; TAG_BYTES] {
        let digest = Sha256::digest(self.compressed());
        let mut out = [0; TAG_BYTES];
        out.copy_from_slice(&digest[..TAG_BYTES]);
        out
    }

    /// Wraps `file_key` for this recipient: the arguments and body of a
    /// `piv-p256` stanza (its tag is [`STANZA_TAG`]).
    pub fn wrap(&self, file_key: &[u8; FILE_KEY_BYTES]) -> PivStanza {
        let esk = EphemeralSecret::random(&mut OsRng);
        let mut epk = [0; COMPRESSED_POINT_BYTES];
        epk.copy_from_slice(esk.public_key().to_encoded_point(true).as_bytes());
        let shared = esk.diffie_hellman(&self.0);
        let key = wrap_key(shared.raw_secret_bytes().as_ref(), &epk, &self.compressed());
        let sealed = ChaCha20Poly1305::new(Key::from_slice(&key[..]))
            .encrypt(&Nonce::default(), &file_key[..])
            .expect("sealing 16 bytes cannot fail");
        let mut body = [0; ENCRYPTED_FILE_KEY_BYTES];
        body.copy_from_slice(&sealed);
        PivStanza {
            tag: self.tag(),
            epk,
            body,
        }
    }
}

/// True when `s` looks like a YubiKey recipient (by prefix, not validity),
/// so callers can route it here rather than to their X25519 parser.
pub fn is_piv_recipient(s: &str) -> bool {
    s.len() > RECIPIENT_PREFIX.len()
        && s[..RECIPIENT_PREFIX.len()].eq_ignore_ascii_case(RECIPIENT_PREFIX)
}

/// The bech32 HRP of a YubiKey identity stub (written uppercase).
pub const STUB_PREFIX: &str = "age-plugin-yubikey-";

/// An age-plugin-yubikey identity line (`AGE-PLUGIN-YUBIKEY-1...`): which
/// YubiKey and PIV slot hold the key, and the recipient's tag. Nothing in
/// it is secret, and it does not carry the public key: that comes from
/// the card, and has to match [`PivStub::tag`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PivStub {
    serial: u32,
    slot: u8,
    tag: [u8; TAG_BYTES],
}

impl FromStr for PivStub {
    type Err = ParseRecipientError;

    /// Same layout as the plugin's `Stub::from_bytes`: serial (u32,
    /// little-endian), PIV slot (0x82..=0x95, the retired key slots),
    /// tag.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parsed = CheckedHrpstring::new::<Bech32>(s).map_err(|_| ParseRecipientError)?;
        if parsed.hrp().to_lowercase() != STUB_PREFIX {
            return Err(ParseRecipientError);
        }
        let bytes: Vec<u8> = parsed.byte_iter().collect();
        if bytes.len() < 4 + 1 + TAG_BYTES || !(0x82..=0x95).contains(&bytes[4]) {
            return Err(ParseRecipientError);
        }
        let mut tag = [0; TAG_BYTES];
        tag.copy_from_slice(&bytes[5..5 + TAG_BYTES]);
        Ok(PivStub {
            serial: u32::from_le_bytes(bytes[0..4].try_into().expect("4 bytes")),
            slot: bytes[4],
            tag,
        })
    }
}

impl fmt::Display for PivStub {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut bytes = Vec::with_capacity(4 + 1 + TAG_BYTES);
        bytes.extend_from_slice(&self.serial.to_le_bytes());
        bytes.push(self.slot);
        bytes.extend_from_slice(&self.tag);
        let s = bech32::encode::<Bech32>(Hrp::parse_unchecked(STUB_PREFIX), &bytes)
            .map_err(|_| fmt::Error)?;
        f.write_str(&s.to_uppercase())
    }
}

impl PivStub {
    /// The stub for `recipient`'s key in `slot` (0x82..=0x95) of YubiKey
    /// `serial`.
    pub fn new(serial: u32, slot: u8, recipient: &PivRecipient) -> Option<Self> {
        (0x82..=0x95).contains(&slot).then(|| PivStub {
            serial,
            slot,
            tag: recipient.tag(),
        })
    }

    /// The YubiKey's serial number.
    pub fn serial(&self) -> u32 {
        self.serial
    }

    /// The PIV slot (key reference) holding the key: 0x82 is the
    /// plugin's slot 1.
    pub fn slot(&self) -> u8 {
        self.slot
    }

    /// The tag of the recipient this key opens.
    pub fn tag(&self) -> [u8; TAG_BYTES] {
        self.tag
    }

    /// Whether `stanza` was written for this key.
    pub fn matches(&self, stanza: &PivStanza) -> bool {
        self.tag == stanza.tag
    }
}

/// True when `s` looks like a YubiKey identity stub (by prefix).
pub fn is_piv_stub(s: &str) -> bool {
    s.len() > STUB_PREFIX.len() && s[..STUB_PREFIX.len()].eq_ignore_ascii_case(STUB_PREFIX)
}

/// A `piv-p256` stanza: written by [`PivRecipient::wrap`], or read back
/// from a header with [`PivStanza::parse`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PivStanza {
    tag: [u8; TAG_BYTES],
    epk: [u8; COMPRESSED_POINT_BYTES],
    body: [u8; ENCRYPTED_FILE_KEY_BYTES],
}

impl PivStanza {
    /// The stanza's arguments, in header order.
    pub fn args(&self) -> Vec<String> {
        vec![
            BASE64_STANDARD_NO_PAD.encode(self.tag),
            BASE64_STANDARD_NO_PAD.encode(self.epk),
        ]
    }

    /// The stanza's body (the sealed file key).
    pub fn body(&self) -> Vec<u8> {
        self.body.to_vec()
    }

    /// Reads a stanza's arguments and body. `None` when they aren't a
    /// structurally valid `piv-p256` stanza (the caller checks the tag).
    pub fn parse(args: &[String], body: &[u8]) -> Option<Self> {
        let [tag, epk] = args else { return None };
        let tag = decode_exact::<TAG_BYTES>(tag)?;
        let epk = decode_exact::<COMPRESSED_POINT_BYTES>(epk)?;
        PivRecipient::from_compressed(&epk)?;
        let body = body.try_into().ok()?;
        Some(PivStanza { tag, epk, body })
    }

    /// Whether this stanza was written for `recipient`.
    pub fn is_for(&self, recipient: &PivRecipient) -> bool {
        self.tag == recipient.tag()
    }

    /// The ephemeral public key, uncompressed (65 bytes, `04 || x || y`):
    /// the form a YubiKey's PIV ECDH command takes.
    pub fn ephemeral_uncompressed(&self) -> Vec<u8> {
        let point = PivRecipient::from_compressed(&self.epk).expect("checked in parse");
        point.0.to_encoded_point(false).as_bytes().to_vec()
    }

    /// Opens the file key, given the ECDH x-coordinate between
    /// `recipient`'s private key and [`Self::ephemeral_uncompressed`].
    /// `None` when the stanza isn't for `recipient` or fails to open.
    pub fn unwrap(
        &self,
        recipient: &PivRecipient,
        shared_secret: &[u8],
    ) -> Option<Zeroizing<[u8; FILE_KEY_BYTES]>> {
        if !self.is_for(recipient) {
            return None;
        }
        let key = wrap_key(shared_secret, &self.epk, &recipient.compressed());
        let opened = Zeroizing::new(
            ChaCha20Poly1305::new(Key::from_slice(&key[..]))
                .decrypt(&Nonce::default(), &self.body[..])
                .ok()?,
        );
        let mut out = Zeroizing::new([0; FILE_KEY_BYTES]);
        out.copy_from_slice(&opened);
        Some(out)
    }
}

fn wrap_key(shared_secret: &[u8], epk: &[u8], recipient: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut salt = Vec::with_capacity(epk.len() + recipient.len());
    salt.extend_from_slice(epk);
    salt.extend_from_slice(recipient);
    let mut okm = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::new(Some(&salt), shared_secret)
        .expand(STANZA_KEY_LABEL, &mut okm[..])
        .expect("32 bytes is a valid HKDF-SHA256 length");
    okm
}

fn decode_exact<const N: usize>(arg: &str) -> Option<[u8; N]> {
    let bytes = BASE64_STANDARD_NO_PAD.decode(arg).ok()?;
    bytes.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::SecretKey;

    fn software_key() -> (SecretKey, PivRecipient) {
        let sk = SecretKey::random(&mut OsRng);
        let r = PivRecipient::from_compressed(sk.public_key().to_encoded_point(true).as_bytes())
            .unwrap();
        (sk, r)
    }

    fn card_ecdh(sk: &SecretKey, stanza: &PivStanza) -> Vec<u8> {
        let epk = PublicKey::from_sec1_bytes(&stanza.ephemeral_uncompressed()).unwrap();
        p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), epk.as_affine())
            .raw_secret_bytes()
            .to_vec()
    }

    #[test]
    fn recipient_string_round_trips() {
        let (_, r) = software_key();
        let s = r.to_string();
        assert!(s.starts_with("age1yubikey1"));
        assert!(is_piv_recipient(&s));
        assert_eq!(s.parse::<PivRecipient>().unwrap(), r);
        assert_eq!(s.to_uppercase().parse::<PivRecipient>().unwrap(), r);
    }

    #[test]
    fn rejects_other_recipients() {
        // An X25519 recipient: valid bech32, wrong HRP.
        let x = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p";
        assert!(!is_piv_recipient(x));
        assert_eq!(x.parse::<PivRecipient>(), Err(ParseRecipientError));
        assert!("age1yubikey1notbech32".parse::<PivRecipient>().is_err());
        assert!("".parse::<PivRecipient>().is_err());
    }

    #[test]
    fn stub_round_trips_and_matches() {
        let (sk, r) = software_key();
        let stub = PivStub::new(12345678, 0x82, &r).unwrap();
        let s = stub.to_string();
        assert!(s.starts_with("AGE-PLUGIN-YUBIKEY-1"));
        assert!(is_piv_stub(&s));
        let back: PivStub = s.parse().unwrap();
        assert_eq!(back, stub);
        assert_eq!((back.serial(), back.slot()), (12345678, 0x82));
        assert_eq!(s.to_lowercase().parse::<PivStub>().unwrap(), stub);

        let stanza = r.wrap(&[3; FILE_KEY_BYTES]);
        assert!(back.matches(&stanza));
        let card_pk = sk.public_key().to_encoded_point(false);
        let from_card = PivRecipient::from_sec1(card_pk.as_bytes()).unwrap();
        assert_eq!(from_card, r);
        assert_eq!(from_card.tag(), back.tag());

        let (_, other) = software_key();
        assert!(!back.matches(&other.wrap(&[3; FILE_KEY_BYTES])));
    }

    #[test]
    fn stub_rejects_bad_slots_and_prefixes() {
        let (_, r) = software_key();
        assert!(PivStub::new(1, 0x9a, &r).is_none());
        assert!(PivStub::new(1, 0x81, &r).is_none());
        assert!(r.to_string().parse::<PivStub>().is_err());
        assert!(!is_piv_stub(&r.to_string()));
        assert!("AGE-SECRET-KEY-1QQQQ".parse::<PivStub>().is_err());
    }

    #[test]
    fn wrap_then_unwrap() {
        let (sk, r) = software_key();
        let fk = [7u8; FILE_KEY_BYTES];
        let stanza = r.wrap(&fk);
        let parsed = PivStanza::parse(&stanza.args(), &stanza.body()).unwrap();
        assert_eq!(parsed, stanza);
        assert!(parsed.is_for(&r));
        let opened = parsed.unwrap(&r, &card_ecdh(&sk, &parsed)).unwrap();
        assert_eq!(*opened, fk);
    }

    #[test]
    fn other_key_cannot_unwrap() {
        let (_, r) = software_key();
        let (other_sk, other) = software_key();
        let stanza = r.wrap(&[1; FILE_KEY_BYTES]);
        assert!(!stanza.is_for(&other));
        assert!(stanza
            .unwrap(&other, &card_ecdh(&other_sk, &stanza))
            .is_none());
        // Right tag, wrong secret.
        assert!(stanza.unwrap(&r, &[0; 32]).is_none());
    }

    #[test]
    fn parse_rejects_malformed_stanzas() {
        let (_, r) = software_key();
        let s = r.wrap(&[2; FILE_KEY_BYTES]);
        let args = s.args();
        let body = s.body();
        assert!(PivStanza::parse(&args[..1], &body).is_none());
        assert!(PivStanza::parse(&[args[0].clone(), args[1].clone(), "x".into()], &body).is_none());
        assert!(PivStanza::parse(&args, &body[..31]).is_none());
        let padded = format!("{}=", args[0]);
        assert!(PivStanza::parse(&[padded, args[1].clone()], &body).is_none());
        // x = 2^256 - 1 is past the field modulus: never a valid point.
        let mut off_curve = [0xffu8; COMPRESSED_POINT_BYTES];
        off_curve[0] = 0x02;
        let off_curve = BASE64_STANDARD_NO_PAD.encode(off_curve);
        assert!(PivStanza::parse(&[args[0].clone(), off_curve], &body).is_none());
        let uncompressed = BASE64_STANDARD_NO_PAD.encode(s.ephemeral_uncompressed());
        assert!(PivStanza::parse(&[args[0].clone(), uncompressed], &body).is_none());
    }
}
