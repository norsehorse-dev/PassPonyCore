//! Rust age (passage) crypto engine, exposed over the FFI as an
//! Android-only feature. iOS keeps its own platform engine
//! (AgePonyCore, pure-Swift); this exists so PassPony Android does not
//! need a from-scratch Kotlin age implementation.
//!
//! Semantics match the iOS AgePonyEngine exactly:
//! - identities text is one AGE-SECRET-KEY-1... per line, blank lines
//!   and `#` comments ignored;
//! - encrypt to the resolved recipient set when non-empty, else falls
//!   back to the loaded identities' own public keys (the
//!   `age -e -i identities` behavior);
//! - decrypt tries every loaded identity;
//! - YubiKey identities (age-plugin-yubikey's `AGE-PLUGIN-YUBIKEY-1...`
//!   stub lines) decrypt through a [`YubiKeyCard`] the app implements,
//!   when the engine is built with one; plain identities are tried
//!   first, so the card is asked only when nothing else opens the file;
//! - errors never carry entry names or plaintext, only the FFI's
//!   existing CryptoError variants.

use std::collections::HashSet;
use std::io::{Read, Write};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use age::armor::ArmoredReader;
use age::secrecy::{ExposeSecret, SecretString};
use age::x25519::{Identity, Recipient as X25519Recipient};
use age::{scrypt, DecryptError, Decryptor, Encryptor};
use zeroize::Zeroizing;

use crate::CryptoError;

/// A freshly generated identity, in both forms the caller needs: the
/// secret string to persist (identities file) and the recipient string
/// to show the user or use for self-encryption.
#[derive(Debug, Clone, uniffi::Record)]
pub struct GeneratedIdentity {
    pub identity_string: String,
    pub recipient_string: String,
}

/// Generates a new X25519 identity. Free function rather than a
/// constructor on `AgeEngine`, since the caller needs both halves
/// before it has anywhere to persist them.
#[uniffi::export]
pub fn age_generate_identity() -> GeneratedIdentity {
    let identity = Identity::generate();
    GeneratedIdentity {
        identity_string: identity.to_string().expose_secret().to_owned(),
        recipient_string: identity.to_public().to_string(),
    }
}

/// The public key (`age1...`) of every X25519 identity in an identities
/// file's text, in file order, read the same way `AgeEngine` loads them.
/// 2.0 rc4: what a device lists in the store's `.age-recipients`.
#[uniffi::export]
pub fn age_identities_recipients(text: String) -> Vec<String> {
    let text = Zeroizing::new(text);
    let mut out: Vec<String> = Vec::new();
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Ok(identity) = Identity::from_str(line) {
            let r = identity.to_public().to_string();
            if !out.contains(&r) {
                out.push(r);
            }
        }
    }
    out
}

/// Highest scrypt work factor (log2 N) accepted when unlocking a
/// passphrase-protected identities file. age and gopass default to 18
/// (256 MiB of scrypt memory); each step doubles memory and time, so 20
/// (1 GiB) leaves 4x headroom for files written with a stronger setting
/// while still refusing a hostile file that asks for an unbounded amount
/// of work. age's own ceiling (target + 4 = 22) would need 4 GiB, which
/// is not a safe ask on a phone.
const MAX_IDENTITIES_SCRYPT_LOG_N: u8 = 20;

/// Decrypts a passphrase-protected (scrypt) age identities file, as
/// written by `age -p` or gopass's age backend, binary or armored, and
/// returns the plaintext identities text as bytes so the caller can
/// clear them after use. Feed the result to
/// `AgeEngine::from_identities_text` / the app's import validation.
///
/// Errors carry no file content: a wrong passphrase and a file that is
/// not passphrase-encrypted both report `DecryptionFailed`; a file that
/// demands more scrypt work than `MAX_IDENTITIES_SCRYPT_LOG_N` reports
/// `Unavailable` rather than burning the device's memory on it.
#[uniffi::export]
pub fn age_decrypt_identities_file(
    data: Vec<u8>,
    passphrase: String,
) -> Result<Vec<u8>, CryptoError> {
    decrypt_identities_file(data, passphrase, MAX_IDENTITIES_SCRYPT_LOG_N)
}

/// Decrypts any passphrase-protected age file, binary or armored, with the
/// same scrypt work-factor cap as identities files. Used for `.passpony`
/// backups; see `docs/BACKUP.md`.
#[uniffi::export]
pub fn age_decrypt_with_passphrase(
    data: Vec<u8>,
    passphrase: String,
) -> Result<Vec<u8>, CryptoError> {
    decrypt_identities_file(data, passphrase, MAX_IDENTITIES_SCRYPT_LOG_N)
}

/// Encrypts `plaintext` to a passphrase as a binary age v1 file with a
/// single scrypt recipient at age's default work factor (log2 N = 18, the
/// same as `age -p`), so any age implementation can open it. Used for
/// `.passpony` backups.
#[uniffi::export]
pub fn age_encrypt_with_passphrase(
    plaintext: Vec<u8>,
    passphrase: String,
) -> Result<Vec<u8>, CryptoError> {
    let plaintext = Zeroizing::new(plaintext);
    let recipient = scrypt::Recipient::new(SecretString::from(passphrase));
    let encryptor = Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
        .map_err(|_| CryptoError::EncryptionFailed)?;
    let mut out = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut out)
        .map_err(|_| CryptoError::EncryptionFailed)?;
    writer
        .write_all(&plaintext)
        .map_err(|_| CryptoError::EncryptionFailed)?;
    writer.finish().map_err(|_| CryptoError::EncryptionFailed)?;
    Ok(out)
}

fn decrypt_identities_file(
    data: Vec<u8>,
    passphrase: String,
    max_log_n: u8,
) -> Result<Vec<u8>, CryptoError> {
    let passphrase = SecretString::from(passphrase);
    // Same leading-whitespace tolerance as `age_is_encrypted_identities_file`
    // (pass_core::identities::is_age_encrypted),
    // so a file detected as encrypted is also one the reader accepts.
    let decryptor = Decryptor::new(ArmoredReader::new(data.trim_ascii_start()))
        .map_err(|_| CryptoError::DecryptionFailed)?;
    if !decryptor.is_scrypt() {
        return Err(CryptoError::DecryptionFailed);
    }

    let mut identity = scrypt::Identity::new(passphrase);
    identity.set_max_work_factor(max_log_n);
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|e| match e {
            DecryptError::ExcessiveWork { .. } => CryptoError::Unavailable {
                reason: "passphrase work factor too high for this device".to_owned(),
            },
            _ => CryptoError::DecryptionFailed,
        })?;

    let mut plaintext = Zeroizing::new(Vec::new());
    reader
        .read_to_end(&mut plaintext)
        .map_err(|_| CryptoError::DecryptionFailed)?;
    Ok(std::mem::take(&mut *plaintext))
}

/// A loaded set of age identities, implementing the same
/// encrypt/decrypt shape as the FFI's `CryptoBackend` trait so the
/// Kotlin wrapper is a two-line delegation.
#[derive(uniffi::Object)]
pub struct AgeEngine {
    identities: Vec<Identity>,
    yubikeys: Vec<YubiKeyIdentity>,
}

/// What a YubiKey returns for one decryption.
#[derive(uniffi::Record)]
pub struct YubiKeyEcdh {
    /// The 32-byte ECDH result (x-coordinate) from PIV GENERAL
    /// AUTHENTICATE with the given ephemeral point.
    pub shared_secret: Vec<u8>,
    /// The slot's P-256 public key, SEC1 (uncompressed is what the card
    /// reports). Checked against the identity's tag before use.
    pub public_key: Vec<u8>,
}

/// A YubiKey, as the app reaches it (NFC or USB): the one step of a
/// YubiKey decryption that has to happen on the card.
///
/// `ecdh` is called on the thread that called `decrypt`, once per
/// matching YubiKey identity, in identities-file order, and may block
/// while the user presents the key, enters the PIV PIN and touches it.
/// Return `Cancelled` when the user gives up: the engine then asks no
/// further YubiKey and `decrypt` fails with `Cancelled`. Any other error
/// (say, a different YubiKey was presented) moves on to the next one.
#[uniffi::export(with_foreign)]
pub trait YubiKeyCard: Send + Sync {
    /// ECDH between the private key in PIV `slot` (0x82 is the plugin's
    /// slot 1) of the YubiKey with serial `serial` and
    /// `ephemeral_point` (65-byte uncompressed SEC1).
    fn ecdh(
        &self,
        serial: u32,
        slot: u8,
        ephemeral_point: Vec<u8>,
    ) -> Result<YubiKeyEcdh, CryptoError>;
}

/// One YubiKey identity stub, opened through the app's card.
struct YubiKeyIdentity {
    stub: pass_age_piv::PivStub,
    card: Arc<dyn YubiKeyCard>,
    cancelled: Arc<AtomicBool>,
}

impl age::Identity for YubiKeyIdentity {
    fn unwrap_stanza(
        &self,
        stanza: &age_core::format::Stanza,
    ) -> Option<Result<age_core::format::FileKey, DecryptError>> {
        if stanza.tag != pass_age_piv::STANZA_TAG || self.cancelled.load(Ordering::Relaxed) {
            return None;
        }
        let parsed = pass_age_piv::PivStanza::parse(&stanza.args, &stanza.body)?;
        if !self.stub.matches(&parsed) {
            return None;
        }
        let answer = match self.card.ecdh(
            self.stub.serial(),
            self.stub.slot(),
            parsed.ephemeral_uncompressed(),
        ) {
            Ok(answer) => answer,
            Err(CryptoError::Cancelled) => {
                self.cancelled.store(true, Ordering::Relaxed);
                return None;
            }
            Err(_) => return None,
        };
        let shared = Zeroizing::new(answer.shared_secret);
        let recipient = match pass_age_piv::PivRecipient::from_sec1(&answer.public_key) {
            Some(r) if r.tag() == self.stub.tag() => r,
            _ => return Some(Err(DecryptError::DecryptionFailed)),
        };
        Some(
            parsed
                .unwrap(&recipient, &shared)
                .map(|fk| age_core::format::FileKey::new(Box::new(*fk)))
                .ok_or(DecryptError::DecryptionFailed),
        )
    }
}

#[uniffi::export]
impl AgeEngine {
    /// Parses an identities file's text. Malformed or non-identity
    /// lines are skipped, matching the iOS loader; an engine with zero
    /// usable identities is not an error here; encrypt/decrypt fail
    /// with `NoUsableKey` only when actually used, matching iOS.
    #[uniffi::constructor]
    pub fn from_identities_text(text: String) -> Arc<Self> {
        let identities = text
            .lines()
            .map(|line| line.trim())
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .filter_map(|line| Identity::from_str(line).ok())
            .collect();
        Arc::new(AgeEngine {
            identities,
            yubikeys: Vec::new(),
        })
    }

    /// Like `from_identities_text`, but YubiKey identity stubs
    /// (`AGE-PLUGIN-YUBIKEY-1...`) are kept too, and decrypt through
    /// `card`.
    #[uniffi::constructor]
    pub fn from_identities_text_with_card(text: String, card: Arc<dyn YubiKeyCard>) -> Arc<Self> {
        let lines: Vec<&str> = text
            .lines()
            .map(|line| line.trim())
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .collect();
        let identities = lines
            .iter()
            .filter_map(|line| Identity::from_str(line).ok())
            .collect();
        let cancelled = Arc::new(AtomicBool::new(false));
        let yubikeys = lines
            .iter()
            .filter(|line| pass_age_piv::is_piv_stub(line))
            .filter_map(|line| pass_age_piv::PivStub::from_str(line).ok())
            .map(|stub| YubiKeyIdentity {
                stub,
                card: Arc::clone(&card),
                cancelled: Arc::clone(&cancelled),
            })
            .collect();
        Arc::new(AgeEngine {
            identities,
            yubikeys,
        })
    }

    pub fn encrypt(
        &self,
        plaintext: Vec<u8>,
        recipients: Vec<String>,
    ) -> Result<Vec<u8>, CryptoError> {
        if self.identities.is_empty() && recipients.is_empty() {
            return Err(CryptoError::NoUsableKey);
        }

        let targets: Vec<Box<dyn age::Recipient>> = if recipients.is_empty() {
            self.identities
                .iter()
                .map(|i| Box::new(i.to_public()) as Box<dyn age::Recipient>)
                .collect()
        } else {
            let mut parsed = Vec::with_capacity(recipients.len());
            for spec in &recipients {
                parsed.push(parse_recipient(spec)?);
            }
            parsed
        };

        let refs: Vec<&dyn age::Recipient> = targets.iter().map(|r| r.as_ref()).collect();
        let encryptor = Encryptor::with_recipients(refs.into_iter())
            .map_err(|_| CryptoError::EncryptionFailed)?;

        let mut ciphertext = Vec::with_capacity(plaintext.len());
        let mut writer = encryptor
            .wrap_output(&mut ciphertext)
            .map_err(|_| CryptoError::EncryptionFailed)?;
        writer
            .write_all(&plaintext)
            .map_err(|_| CryptoError::EncryptionFailed)?;
        writer.finish().map_err(|_| CryptoError::EncryptionFailed)?;

        Ok(ciphertext)
    }

    pub fn decrypt(&self, ciphertext: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
        if self.identities.is_empty() && self.yubikeys.is_empty() {
            return Err(CryptoError::NoUsableKey);
        }
        for yk in &self.yubikeys {
            yk.cancelled.store(false, Ordering::Relaxed);
        }

        let decryptor =
            Decryptor::new(&ciphertext[..]).map_err(|_| CryptoError::DecryptionFailed)?;
        let refs: Vec<&dyn age::Identity> = self
            .identities
            .iter()
            .map(|i| i as &dyn age::Identity)
            .chain(self.yubikeys.iter().map(|y| y as &dyn age::Identity))
            .collect();
        let mut reader = decryptor.decrypt(refs.into_iter()).map_err(|_| {
            if self
                .yubikeys
                .iter()
                .any(|y| y.cancelled.load(Ordering::Relaxed))
            {
                CryptoError::Cancelled
            } else {
                CryptoError::DecryptionFailed
            }
        })?;

        let mut plaintext = Vec::new();
        reader
            .read_to_end(&mut plaintext)
            .map_err(|_| CryptoError::DecryptionFailed)?;
        Ok(plaintext)
    }
}

/// One `.age-recipients` line: an X25519 key, or a YubiKey key that
/// age-plugin-yubikey made (`age1yubikey1...`), which encrypting to
/// needs neither the plugin nor the key. Matches AgePonyEngine.swift:
/// any parse failure collapses to a generic EncryptionFailed rather
/// than naming the bad recipient in the error.
fn parse_recipient(spec: &str) -> Result<Box<dyn age::Recipient>, CryptoError> {
    if pass_age_piv::is_piv_recipient(spec) {
        pass_age_piv::PivRecipient::from_str(spec)
            .map(|r| Box::new(YubiKeyRecipient(r)) as Box<dyn age::Recipient>)
            .map_err(|_| CryptoError::EncryptionFailed)
    } else {
        X25519Recipient::from_str(spec)
            .map(|r| Box::new(r) as Box<dyn age::Recipient>)
            .map_err(|_| CryptoError::EncryptionFailed)
    }
}

/// [`pass_age_piv::PivRecipient`] as an age 0.11 recipient: one
/// `piv-p256` stanza, no labels (it mixes with X25519, as with the
/// plugin).
struct YubiKeyRecipient(pass_age_piv::PivRecipient);

impl age::Recipient for YubiKeyRecipient {
    fn wrap_file_key(
        &self,
        file_key: &age_core::format::FileKey,
    ) -> Result<(Vec<age_core::format::Stanza>, HashSet<String>), age::EncryptError> {
        let s = self.0.wrap(file_key.expose_secret());
        Ok((
            vec![age_core::format::Stanza {
                tag: pass_age_piv::STANZA_TAG.to_owned(),
                args: s.args(),
                body: s.body(),
            }],
            HashSet::new(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A store whose recipients mix a YubiKey and this device: the
    /// device can still save, and still read what it saved. The YubiKey
    /// stanza itself is checked against age-plugin-yubikey in
    /// pass-age-piv's tests.
    #[test]
    fn encrypts_to_yubikey_and_x25519_recipients() {
        use p256::elliptic_curve::sec1::ToEncodedPoint as _;

        let me = age_generate_identity();
        let sk = p256::SecretKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let yk = pass_age_piv::PivRecipient::from_compressed(
            sk.public_key().to_encoded_point(true).as_bytes(),
        )
        .unwrap();
        let engine = AgeEngine::from_identities_text(me.identity_string.clone());

        let plaintext = b"shared with the yubikey\n".to_vec();
        let ciphertext = engine
            .encrypt(
                plaintext.clone(),
                vec![yk.to_string(), me.recipient_string.clone()],
            )
            .expect("encrypt to a yubikey and an x25519 recipient");
        assert!(ciphertext
            .windows(b"-> piv-p256 ".len())
            .any(|w| w == b"-> piv-p256 "));
        assert_eq!(engine.decrypt(ciphertext).unwrap(), plaintext);
    }

    /// A software stand-in for a YubiKey: one P-256 key in one slot of
    /// one serial, and a log of what it was asked.
    struct SoftCard {
        serial: u32,
        sk: p256::SecretKey,
        answer: Result<(), CryptoError>,
        lie_about_key: bool,
        calls: std::sync::Mutex<Vec<u32>>,
    }

    impl SoftCard {
        fn new(serial: u32) -> Self {
            SoftCard {
                serial,
                sk: p256::SecretKey::random(&mut p256::elliptic_curve::rand_core::OsRng),
                answer: Ok(()),
                lie_about_key: false,
                calls: Default::default(),
            }
        }

        fn recipient(&self) -> pass_age_piv::PivRecipient {
            use p256::elliptic_curve::sec1::ToEncodedPoint as _;
            pass_age_piv::PivRecipient::from_sec1(
                self.sk.public_key().to_encoded_point(false).as_bytes(),
            )
            .unwrap()
        }

        fn stub(&self) -> String {
            pass_age_piv::PivStub::new(self.serial, 0x82, &self.recipient())
                .unwrap()
                .to_string()
        }
    }

    /// Answers for whichever SoftCard has the asked-for serial.
    struct Cards(Vec<Arc<SoftCard>>);

    impl YubiKeyCard for Cards {
        fn ecdh(
            &self,
            serial: u32,
            slot: u8,
            ephemeral_point: Vec<u8>,
        ) -> Result<YubiKeyEcdh, CryptoError> {
            use p256::elliptic_curve::sec1::ToEncodedPoint as _;
            assert_eq!(slot, 0x82);
            let card = self
                .0
                .iter()
                .find(|c| c.serial == serial)
                .expect("asked for a known serial");
            card.calls.lock().unwrap().push(serial);
            match &card.answer {
                Ok(()) => {}
                Err(CryptoError::Cancelled) => return Err(CryptoError::Cancelled),
                Err(_) => {
                    return Err(CryptoError::Unavailable {
                        reason: "other key".into(),
                    })
                }
            }
            let epk = p256::PublicKey::from_sec1_bytes(&ephemeral_point).unwrap();
            let shared = p256::ecdh::diffie_hellman(card.sk.to_nonzero_scalar(), epk.as_affine());
            let public_key = if card.lie_about_key {
                p256::SecretKey::random(&mut p256::elliptic_curve::rand_core::OsRng).public_key()
            } else {
                card.sk.public_key()
            };
            Ok(YubiKeyEcdh {
                shared_secret: shared.raw_secret_bytes().to_vec(),
                public_key: public_key.to_encoded_point(false).as_bytes().to_vec(),
            })
        }
    }

    fn encrypt_to(recipients: Vec<String>) -> Vec<u8> {
        let writer = age_generate_identity();
        AgeEngine::from_identities_text(writer.identity_string)
            .encrypt(b"opened by a yubikey\n".to_vec(), recipients)
            .unwrap()
    }

    #[test]
    fn card_decrypts_a_yubikey_only_entry() {
        let a = Arc::new(SoftCard::new(1111));
        let ct = encrypt_to(vec![a.recipient().to_string()]);
        let text = format!("# yk\n{}\n", a.stub());
        let engine =
            AgeEngine::from_identities_text_with_card(text, Arc::new(Cards(vec![a.clone()])));
        assert_eq!(engine.decrypt(ct).unwrap(), b"opened by a yubikey\n");
        assert_eq!(*a.calls.lock().unwrap(), vec![1111]);
    }

    #[test]
    fn plain_identity_is_tried_before_the_card() {
        let a = Arc::new(SoftCard::new(1111));
        let phone = age_generate_identity();
        let ct = encrypt_to(vec![a.recipient().to_string(), phone.recipient_string]);
        let text = format!("{}\n{}\n", a.stub(), phone.identity_string);
        let engine =
            AgeEngine::from_identities_text_with_card(text, Arc::new(Cards(vec![a.clone()])));
        assert_eq!(engine.decrypt(ct).unwrap(), b"opened by a yubikey\n");
        assert!(a.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn cancelling_stops_asking_and_reports_cancelled() {
        let mut a = SoftCard::new(1111);
        a.answer = Err(CryptoError::Cancelled);
        let a = Arc::new(a);
        let b = Arc::new(SoftCard::new(2222));
        let ct = encrypt_to(vec![a.recipient().to_string(), b.recipient().to_string()]);
        let text = format!("{}\n{}\n", a.stub(), b.stub());
        let engine = AgeEngine::from_identities_text_with_card(
            text,
            Arc::new(Cards(vec![a.clone(), b.clone()])),
        );
        assert!(matches!(
            engine.decrypt(ct.clone()).unwrap_err(),
            CryptoError::Cancelled
        ));
        assert!(b.calls.lock().unwrap().is_empty());
        // The next decrypt asks again rather than staying cancelled.
        let _ = engine.decrypt(ct);
        assert_eq!(a.calls.lock().unwrap().len(), 2);
    }

    #[test]
    fn a_missing_yubikey_moves_on_to_the_next() {
        let mut a = SoftCard::new(1111);
        a.answer = Err(CryptoError::NoUsableKey);
        let a = Arc::new(a);
        let b = Arc::new(SoftCard::new(2222));
        let ct = encrypt_to(vec![a.recipient().to_string(), b.recipient().to_string()]);
        let text = format!("{}\n{}\n", a.stub(), b.stub());
        let engine = AgeEngine::from_identities_text_with_card(
            text,
            Arc::new(Cards(vec![a.clone(), b.clone()])),
        );
        assert_eq!(engine.decrypt(ct).unwrap(), b"opened by a yubikey\n");
        assert_eq!(*b.calls.lock().unwrap(), vec![2222]);
    }

    #[test]
    fn a_card_reporting_another_key_fails() {
        let mut a = SoftCard::new(1111);
        a.lie_about_key = true;
        let a = Arc::new(a);
        let ct = encrypt_to(vec![a.recipient().to_string()]);
        let engine =
            AgeEngine::from_identities_text_with_card(a.stub(), Arc::new(Cards(vec![a.clone()])));
        assert!(matches!(
            engine.decrypt(ct).unwrap_err(),
            CryptoError::DecryptionFailed
        ));
    }

    #[test]
    fn without_a_card_stubs_are_ignored() {
        let a = SoftCard::new(1111);
        let ct = encrypt_to(vec![a.recipient().to_string()]);
        let engine = AgeEngine::from_identities_text(a.stub());
        assert!(matches!(
            engine.decrypt(ct).unwrap_err(),
            CryptoError::NoUsableKey
        ));
    }

    #[test]
    fn malformed_yubikey_recipient_reports_encryption_failed() {
        let a = age_generate_identity();
        let engine = AgeEngine::from_identities_text(a.identity_string);
        let err = engine
            .encrypt(b"x".to_vec(), vec!["age1yubikey1qqqqqq".to_owned()])
            .unwrap_err();
        assert!(matches!(err, CryptoError::EncryptionFailed));
    }

    #[test]
    fn identities_recipients_lists_each_public_key_once() {
        let a = age_generate_identity();
        let b = age_generate_identity();
        let text = format!(
            "# created by PassPony\n# public key: {}\n{}\n\n{}\n{}\nnot-a-key\n",
            a.recipient_string, a.identity_string, b.identity_string, a.identity_string
        );
        assert_eq!(
            age_identities_recipients(text),
            vec![a.recipient_string, b.recipient_string]
        );
    }

    #[test]
    fn round_trips_through_generated_identity() {
        let generated = age_generate_identity();
        let engine = AgeEngine::from_identities_text(generated.identity_string.clone());

        let plaintext = b"web/github.com\nusername: kevin\n".to_vec();
        let ciphertext = engine
            .encrypt(plaintext.clone(), vec![generated.recipient_string.clone()])
            .expect("encrypt to explicit recipient");
        let decrypted = engine
            .decrypt(ciphertext)
            .expect("decrypt with own identity");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn identities_file_parsing_skips_comments_and_blanks() {
        let generated = age_generate_identity();
        let text = format!(
            "# created by PassPony\n# public key: {}\n\n{}\n",
            generated.recipient_string, generated.identity_string
        );
        let engine = AgeEngine::from_identities_text(text);
        let plaintext = b"pw\n".to_vec();
        let ciphertext = engine
            .encrypt(plaintext.clone(), vec![])
            .expect("recipients-fallback encrypt");
        let decrypted = engine.decrypt(ciphertext).expect("decrypt");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn empty_recipients_falls_back_to_own_public_keys() {
        let generated = age_generate_identity();
        let engine = AgeEngine::from_identities_text(generated.identity_string);
        let plaintext = b"self-encrypted\n".to_vec();
        let ciphertext = engine
            .encrypt(plaintext.clone(), vec![])
            .expect("fallback encrypt");
        let decrypted = engine.decrypt(ciphertext).expect("decrypt");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn multi_recipient_encrypt_each_identity_decrypts() {
        let a = age_generate_identity();
        let b = age_generate_identity();
        let engine_a = AgeEngine::from_identities_text(a.identity_string.clone());
        let engine_b = AgeEngine::from_identities_text(b.identity_string.clone());

        let plaintext = b"shared entry\n".to_vec();
        let ciphertext = engine_a
            .encrypt(
                plaintext.clone(),
                vec![a.recipient_string, b.recipient_string],
            )
            .expect("encrypt to two recipients");

        assert_eq!(engine_a.decrypt(ciphertext.clone()).unwrap(), plaintext);
        assert_eq!(engine_b.decrypt(ciphertext).unwrap(), plaintext);
    }

    #[test]
    fn wrong_identity_fails_with_decryption_failed() {
        let a = age_generate_identity();
        let stranger = age_generate_identity();
        let engine_a = AgeEngine::from_identities_text(a.identity_string);
        let engine_stranger = AgeEngine::from_identities_text(stranger.identity_string);

        let ciphertext = engine_a.encrypt(b"secret\n".to_vec(), vec![]).unwrap();
        let err = engine_stranger.decrypt(ciphertext).unwrap_err();
        assert!(matches!(err, CryptoError::DecryptionFailed));
    }

    #[test]
    fn engine_with_no_identities_and_no_recipients_reports_no_usable_key() {
        let engine = AgeEngine::from_identities_text(String::new());
        let err = engine.encrypt(b"x".to_vec(), vec![]).unwrap_err();
        assert!(matches!(err, CryptoError::NoUsableKey));
    }

    #[test]
    fn decrypt_with_no_identities_reports_no_usable_key() {
        let engine = AgeEngine::from_identities_text(String::new());
        let err = engine.decrypt(vec![0u8; 4]).unwrap_err();
        assert!(matches!(err, CryptoError::NoUsableKey));
    }

    #[test]
    fn invalid_recipient_spec_reports_encryption_failed() {
        let a = age_generate_identity();
        let engine = AgeEngine::from_identities_text(a.identity_string);
        let err = engine
            .encrypt(b"x".to_vec(), vec!["not-a-real-recipient".to_owned()])
            .unwrap_err();
        assert!(matches!(err, CryptoError::EncryptionFailed));
    }

    /// Opens the real `passage/minimal` fixture from the PassPonyCore
    /// corpus (shared with the parity and git-matrix suites) and checks
    /// AgeEngine decrypts `alpha.age` to the exact golden plaintext the
    /// other backends are held to. This is the "does it actually work
    /// against corpus produced by the real `age` tool" check; the tests
    /// above only prove internal round-trip consistency.
    #[test]
    fn fixture_corpus_alpha_matches_golden() {
        let fixtures =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/passage/minimal");
        let identities_text = std::fs::read_to_string(fixtures.join("identities"))
            .expect("fixtures/passage/minimal/identities present");
        let ciphertext = std::fs::read(fixtures.join("store/alpha.age"))
            .expect("fixtures/passage/minimal/store/alpha.age present");

        let engine = AgeEngine::from_identities_text(identities_text);
        let plaintext = engine.decrypt(ciphertext).expect("decrypt fixture entry");
        assert_eq!(plaintext, b"alpha-password-1\n");
    }

    // Fixture 6 of docs/passage-store-semantics.md, written by the real
    // `age -p` CLI (armored `identities`, binary `identities.binary`).
    const PASSPHRASE_FIXTURE_PW: &str = "correct horse pony";

    fn passphrase_fixture(name: &str) -> Vec<u8> {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/passage/passphrase-identities");
        std::fs::read(dir.join(name)).unwrap_or_else(|_| panic!("fixture {name} present"))
    }

    #[test]
    fn passphrase_identities_binary_decrypts_to_plain_identities() {
        let plain = passphrase_fixture("identities.plain");
        let got = age_decrypt_identities_file(
            passphrase_fixture("identities.binary"),
            PASSPHRASE_FIXTURE_PW.to_owned(),
        )
        .expect("decrypt binary fixture");
        assert_eq!(got, plain);

        // And the result is directly usable as an identities file.
        let engine = AgeEngine::from_identities_text(String::from_utf8(got).unwrap());
        let ct = engine.encrypt(b"x\n".to_vec(), vec![]).unwrap();
        assert_eq!(engine.decrypt(ct).unwrap(), b"x\n");
    }

    #[test]
    fn passphrase_identities_armored_decrypts_to_plain_identities() {
        let got = age_decrypt_identities_file(
            passphrase_fixture("identities"),
            PASSPHRASE_FIXTURE_PW.to_owned(),
        )
        .expect("decrypt armored fixture");
        assert_eq!(got, passphrase_fixture("identities.plain"));
    }

    #[test]
    fn unlocked_identities_decrypt_the_fixture_store_entry() {
        let text = age_decrypt_identities_file(
            passphrase_fixture("identities"),
            PASSPHRASE_FIXTURE_PW.to_owned(),
        )
        .unwrap();
        let engine = AgeEngine::from_identities_text(String::from_utf8(text).unwrap());
        let plaintext = engine
            .decrypt(passphrase_fixture("store/alpha.age"))
            .unwrap();
        assert_eq!(plaintext, passphrase_fixture("goldens/alpha.plain"));
    }

    #[test]
    fn multi_identity_passphrase_file_unlocks_both_identities() {
        let text = String::from_utf8(
            age_decrypt_identities_file(
                passphrase_fixture("identities.multi"),
                PASSPHRASE_FIXTURE_PW.to_owned(),
            )
            .expect("decrypt multi-identity fixture"),
        )
        .unwrap();
        assert!(text.starts_with("# gopass-style"));

        let recipients: Vec<String> = text
            .lines()
            .filter_map(|l| l.strip_prefix("# public key: "))
            .map(str::to_owned)
            .collect();
        let secrets: Vec<&str> = text
            .lines()
            .filter(|l| l.starts_with("AGE-SECRET-KEY-1"))
            .collect();
        assert_eq!((recipients.len(), secrets.len()), (2, 2));

        let engine = AgeEngine::from_identities_text(text.clone());
        for (i, recipient) in recipients.iter().enumerate() {
            let entry = format!("entry-for-identity-{}\n", i + 1).into_bytes();
            let ct = engine
                .encrypt(entry.clone(), vec![recipient.clone()])
                .expect("encrypt to one recipient only");
            assert_eq!(engine.decrypt(ct.clone()).unwrap(), entry);

            // Only that one identity opens it, not the other.
            let own = AgeEngine::from_identities_text(secrets[i].to_owned());
            let other = AgeEngine::from_identities_text(secrets[1 - i].to_owned());
            assert_eq!(own.decrypt(ct.clone()).unwrap(), entry);
            assert!(matches!(
                other.decrypt(ct).unwrap_err(),
                CryptoError::DecryptionFailed
            ));
        }
    }

    #[test]
    fn passphrase_identities_wrong_passphrase_fails_cleanly() {
        for name in ["identities.binary", "identities"] {
            let err = age_decrypt_identities_file(passphrase_fixture(name), "wrong".to_owned())
                .unwrap_err();
            assert!(matches!(err, CryptoError::DecryptionFailed), "{name}");
        }
    }

    #[test]
    fn passphrase_identities_rejects_non_age_and_non_passphrase_input() {
        let plain = passphrase_fixture("identities.plain");
        let err = age_decrypt_identities_file(plain, "x".to_owned()).unwrap_err();
        assert!(matches!(err, CryptoError::DecryptionFailed));

        // A real age file encrypted to an X25519 recipient is not a
        // passphrase file either.
        let generated = age_generate_identity();
        let engine = AgeEngine::from_identities_text(generated.identity_string);
        let ct = engine.encrypt(b"x".to_vec(), vec![]).unwrap();
        let err = age_decrypt_identities_file(ct, "x".to_owned()).unwrap_err();
        assert!(matches!(err, CryptoError::DecryptionFailed));
    }

    #[test]
    fn passphrase_identities_excessive_work_factor_is_refused() {
        let mut recipient = scrypt::Recipient::new(SecretString::from("pw".to_owned()));
        // Cheap to write, over the (lowered) ceiling used below; the check
        // fires before any scrypt work, so the real 2^20 limit is not
        // exercised with a multi-GiB file here.
        recipient.set_work_factor(12);
        let encryptor =
            Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient)).unwrap();
        let mut ct = Vec::new();
        let mut w = encryptor.wrap_output(&mut ct).unwrap();
        w.write_all(b"AGE-SECRET-KEY-1X\n").unwrap();
        w.finish().unwrap();

        let err = decrypt_identities_file(ct.clone(), "pw".to_owned(), 11).unwrap_err();
        assert!(matches!(err, CryptoError::Unavailable { .. }));

        // At or under the ceiling the same file opens.
        let got = decrypt_identities_file(ct, "pw".to_owned(), 12).unwrap();
        assert_eq!(got, b"AGE-SECRET-KEY-1X\n");
    }

    #[test]
    fn padded_armored_identities_decrypt() {
        // Detection skips leading whitespace, so decryption must too.
        let mut padded = b"\n  ".to_vec();
        padded.extend(passphrase_fixture("identities"));
        let got = age_decrypt_identities_file(padded, PASSPHRASE_FIXTURE_PW.to_owned())
            .expect("decrypt padded armored fixture");
        assert_eq!(got, passphrase_fixture("identities.plain"));
    }

    #[test]
    fn encrypted_identities_detection() {
        assert!(crate::age_is_encrypted_identities_file(passphrase_fixture(
            "identities.binary"
        )));
        assert!(crate::age_is_encrypted_identities_file(passphrase_fixture(
            "identities"
        )));
        let mut padded = b"\n  ".to_vec();
        padded.extend(passphrase_fixture("identities"));
        assert!(crate::age_is_encrypted_identities_file(padded));

        // Plaintext identities (with and without comments) pass through.
        assert!(!crate::age_is_encrypted_identities_file(
            passphrase_fixture("identities.plain")
        ));
        assert!(!crate::age_is_encrypted_identities_file(
            b"AGE-SECRET-KEY-1ABC\n".to_vec()
        ));
        assert!(!crate::age_is_encrypted_identities_file(Vec::new()));
    }

    #[test]
    fn passphrase_encrypt_round_trips_and_is_plain_age() {
        let ct = age_encrypt_with_passphrase(b"PassPony backup 1\nend\n".to_vec(), "AB-CD".into())
            .unwrap();
        assert!(ct.starts_with(b"age-encryption.org/v1\n-> scrypt "));
        assert!(crate::age_is_encrypted_identities_file(ct.clone()));
        assert_eq!(
            age_decrypt_with_passphrase(ct.clone(), "AB-CD".into()).unwrap(),
            b"PassPony backup 1\nend\n"
        );
        assert!(matches!(
            age_decrypt_with_passphrase(ct, "nope".into()),
            Err(CryptoError::DecryptionFailed)
        ));
    }
}
