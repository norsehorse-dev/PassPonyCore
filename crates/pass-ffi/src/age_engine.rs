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
//! - errors never carry entry names or plaintext, only the FFI's
//!   existing CryptoError variants.
//!
//! With the `age-pq` feature the engine also handles age's post-quantum
//! keys (`age1pq1...` recipients, `AGE-SECRET-KEY-PQ-1...` identities,
//! see age_pq.rs). An identities file may hold both kinds and decrypt
//! tries all of them. A file is never encrypted to a mix of the two:
//! age refuses, since the classic stanza would undo the post-quantum
//! one, and `encrypt` reports that as `EncryptionFailed`. Without the
//! feature every post-quantum line is skipped or refused as before.

use std::io::{Read, Write};
use std::str::FromStr;
use std::sync::Arc;

use age::armor::ArmoredReader;
use age::secrecy::{ExposeSecret, SecretString};
use age::x25519::{Identity, Recipient as X25519Recipient};
use age::{scrypt, DecryptError, Decryptor, Encryptor};
use zeroize::Zeroizing;

#[cfg(feature = "age-pq")]
use crate::age_pq::{HybridIdentity, HybridRecipient};
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

/// Generates a new post-quantum identity (`AGE-SECRET-KEY-PQ-1...`) with
/// its `age1pq1...` recipient. The classic counterpart is
/// `age_generate_identity`.
#[cfg(feature = "age-pq")]
#[uniffi::export]
pub fn age_generate_pq_identity() -> GeneratedIdentity {
    let identity = HybridIdentity::generate();
    GeneratedIdentity {
        identity_string: identity.encode().as_str().to_owned(),
        recipient_string: identity.to_public().encode(),
    }
}

/// The public key (`age1pq1...`) of every post-quantum identity in an
/// identities file's text, in file order. The classic counterpart is
/// `age_identities_recipients`; the two lists never overlap, so a caller
/// picks the one that matches the store it is writing to.
#[cfg(feature = "age-pq")]
#[uniffi::export]
pub fn age_identities_pq_recipients(text: String) -> Vec<String> {
    let text = Zeroizing::new(text);
    let mut out: Vec<String> = Vec::new();
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(identity) = HybridIdentity::parse(line) {
            let r = identity.to_public().encode();
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
    #[cfg(feature = "age-pq")]
    pq_identities: Vec<HybridIdentity>,
}

#[uniffi::export]
impl AgeEngine {
    /// Parses an identities file's text. Malformed or non-identity
    /// lines are skipped, matching the iOS loader; an engine with zero
    /// usable identities is not an error here; encrypt/decrypt fail
    /// with `NoUsableKey` only when actually used, matching iOS.
    #[uniffi::constructor]
    pub fn from_identities_text(text: String) -> Arc<Self> {
        let text = Zeroizing::new(text);
        let mut identities = Vec::new();
        #[cfg(feature = "age-pq")]
        let mut pq_identities = Vec::new();
        for line in text.lines().map(str::trim) {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Ok(identity) = Identity::from_str(line) {
                identities.push(identity);
                continue;
            }
            #[cfg(feature = "age-pq")]
            if let Some(identity) = HybridIdentity::parse(line) {
                pq_identities.push(identity);
            }
        }
        Arc::new(AgeEngine {
            identities,
            #[cfg(feature = "age-pq")]
            pq_identities,
        })
    }

    pub fn encrypt(
        &self,
        plaintext: Vec<u8>,
        recipients: Vec<String>,
    ) -> Result<Vec<u8>, CryptoError> {
        if !self.has_identities() && recipients.is_empty() {
            return Err(CryptoError::NoUsableKey);
        }

        // Caught by prefix before any parsing, so the caller gets the
        // same answer whether or not this build has post-quantum support.
        if pass_core::recipients::key_type_of(&recipients)
            == pass_core::recipients::StoreKeyType::Mixed
        {
            return Err(CryptoError::MixedRecipients);
        }

        let targets: Vec<Box<dyn age::Recipient>> = if recipients.is_empty() {
            self.own_recipients()
        } else {
            let mut parsed = Vec::with_capacity(recipients.len());
            for spec in &recipients {
                match parse_recipient(spec) {
                    Some(r) => parsed.push(r),
                    // A build without post-quantum support says so, so
                    // the app can tell the user why instead of showing a
                    // generic failure.
                    #[cfg(not(feature = "age-pq"))]
                    None if pass_core::recipients::is_post_quantum_recipient(spec) => {
                        return Err(CryptoError::Unavailable {
                            reason: "post-quantum keys are not supported in this build".to_owned(),
                        })
                    }
                    // Matches AgePonyEngine.swift: any parse failure
                    // collapses to a generic EncryptionFailed rather
                    // than naming the bad recipient in the error.
                    None => return Err(CryptoError::EncryptionFailed),
                }
            }
            parsed
        };

        // age checks the labels each recipient returns as well, so a mix
        // the prefix check above somehow missed still fails here.
        let encryptor = Encryptor::with_recipients(targets.iter().map(|r| r.as_ref()))
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
        if !self.has_identities() {
            return Err(CryptoError::NoUsableKey);
        }

        let decryptor =
            Decryptor::new(&ciphertext[..]).map_err(|_| CryptoError::DecryptionFailed)?;
        #[allow(unused_mut)]
        let mut refs: Vec<&dyn age::Identity> = self
            .identities
            .iter()
            .map(|i| i as &dyn age::Identity)
            .collect();
        #[cfg(feature = "age-pq")]
        refs.extend(self.pq_identities.iter().map(|i| i as &dyn age::Identity));
        let mut reader = decryptor
            .decrypt(refs.into_iter())
            .map_err(|_| CryptoError::DecryptionFailed)?;

        let mut plaintext = Vec::new();
        reader
            .read_to_end(&mut plaintext)
            .map_err(|_| CryptoError::DecryptionFailed)?;
        Ok(plaintext)
    }
}

impl AgeEngine {
    fn has_identities(&self) -> bool {
        #[cfg(feature = "age-pq")]
        if !self.pq_identities.is_empty() {
            return true;
        }
        !self.identities.is_empty()
    }

    /// The recipients for "encrypt to myself", used when a store has no
    /// recipients file. Classic identities win when the file holds any,
    /// which is every store made before post-quantum keys existed, so
    /// loading a post-quantum identity next to them changes nothing.
    /// Only an identities file with post-quantum keys alone encrypts to
    /// those. Never both kinds: age would refuse the mix.
    fn own_recipients(&self) -> Vec<Box<dyn age::Recipient>> {
        #[cfg(feature = "age-pq")]
        if self.identities.is_empty() {
            return self
                .pq_identities
                .iter()
                .map(|i| Box::new(i.to_public()) as Box<dyn age::Recipient>)
                .collect();
        }
        self.identities
            .iter()
            .map(|i| Box::new(i.to_public()) as Box<dyn age::Recipient>)
            .collect()
    }
}

/// Parses one line of a recipients file: a classic `age1...` key or an
/// `age1tag1...` hardware key (Secure Enclave, YubiKey), and with `age-pq`
/// their post-quantum counterparts `age1pq1...` and `age1tagpq1...`.
/// The tag kinds are encrypt-only here: the private half never leaves the
/// hardware, so decrypting is the job of the device that holds it.
fn parse_recipient(spec: &str) -> Option<Box<dyn age::Recipient>> {
    let spec = spec.trim();
    if let Ok(r) = X25519Recipient::from_str(spec) {
        return Some(Box::new(r));
    }
    if let Ok(r) = age::tag::Recipient::from_str(spec) {
        return Some(Box::new(r));
    }
    #[cfg(feature = "age-pq")]
    {
        if let Some(r) = HybridRecipient::parse(spec) {
            return Some(Box::new(r));
        }
        if let Ok(r) = age::tagpq::Recipient::from_str(spec) {
            return Some(Box::new(r));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// The P-256 tag recipient from the age crate's own tests. Encrypt
    /// only: the private half lives in hardware this engine never sees.
    const TAG_RECIPIENT: &str =
        "age1tag1qt8lw0ual6avlwmwatk888yqnmdamm7xfd0wak53ut6elz5c4swx2yqdj4e";

    #[test]
    fn hardware_tag_recipients_sit_next_to_classic_ones() {
        let generated = age_generate_identity();
        let engine = AgeEngine::from_identities_text(generated.identity_string);
        let ciphertext = engine
            .encrypt(
                b"x".to_vec(),
                vec![TAG_RECIPIENT.to_owned(), generated.recipient_string],
            )
            .unwrap();
        let header = String::from_utf8_lossy(&ciphertext);
        assert!(header.contains("-> p256tag "));
        assert!(header.contains("-> X25519 "));
        assert_eq!(engine.decrypt(ciphertext).unwrap(), b"x");
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

#[cfg(all(test, feature = "age-pq"))]
mod pq_tests {
    use super::*;

    /// The recipient stanza types in an age file's header.
    fn stanza_types(ciphertext: &[u8]) -> Vec<String> {
        let header_end = ciphertext
            .windows(4)
            .position(|w| w == b"\n---")
            .expect("age header ends with a MAC line");
        std::str::from_utf8(&ciphertext[..header_end])
            .expect("age headers are ASCII")
            .lines()
            .filter_map(|l| l.strip_prefix("-> "))
            .filter_map(|l| l.split(' ').next())
            // age adds a random "grease" stanza to some files.
            .filter(|tag| !tag.ends_with("-grease"))
            .map(str::to_owned)
            .collect()
    }

    fn both_kinds() -> (GeneratedIdentity, GeneratedIdentity, String) {
        let classic = age_generate_identity();
        let pq = age_generate_pq_identity();
        let text = format!(
            "# classic\n{}\n# post-quantum\n{}\n",
            classic.identity_string, pq.identity_string
        );
        (classic, pq, text)
    }

    #[test]
    fn generated_pq_identity_has_the_expected_shape() {
        let pq = age_generate_pq_identity();
        assert!(pq.identity_string.starts_with("AGE-SECRET-KEY-PQ-1"));
        assert!(pq.recipient_string.starts_with("age1pq1"));
        assert!(pass_core::recipients::is_post_quantum_recipient(
            &pq.recipient_string
        ));
        assert!(!pass_core::recipients::is_post_quantum_recipient(
            &age_generate_identity().recipient_string
        ));
    }

    #[test]
    fn recipient_lists_keep_the_two_kinds_apart() {
        let (classic, pq, text) = both_kinds();
        assert_eq!(
            age_identities_recipients(text.clone()),
            vec![classic.recipient_string]
        );
        assert_eq!(
            age_identities_pq_recipients(text),
            vec![pq.recipient_string]
        );
    }

    #[test]
    fn encrypts_to_pq_recipients_and_decrypts() {
        let a = age_generate_pq_identity();
        let b = age_generate_pq_identity();
        let writer = AgeEngine::from_identities_text(a.identity_string.clone());
        let ciphertext = writer
            .encrypt(
                b"hunter2\n".to_vec(),
                vec![a.recipient_string.clone(), b.recipient_string.clone()],
            )
            .expect("two post-quantum recipients");
        assert_eq!(
            stanza_types(&ciphertext),
            vec!["mlkem768x25519", "mlkem768x25519"]
        );
        for secret in [a.identity_string, b.identity_string] {
            let reader = AgeEngine::from_identities_text(secret);
            assert_eq!(reader.decrypt(ciphertext.clone()).unwrap(), b"hunter2\n");
        }
    }

    #[test]
    fn one_identities_file_reads_both_kinds_of_entry() {
        let (classic, pq, text) = both_kinds();
        let engine = AgeEngine::from_identities_text(text);
        let old = engine
            .encrypt(b"old".to_vec(), vec![classic.recipient_string])
            .unwrap();
        let new = engine
            .encrypt(b"new".to_vec(), vec![pq.recipient_string])
            .unwrap();
        assert_eq!(stanza_types(&old), vec!["X25519"]);
        assert_eq!(stanza_types(&new), vec!["mlkem768x25519"]);
        assert_eq!(engine.decrypt(old).unwrap(), b"old");
        assert_eq!(engine.decrypt(new).unwrap(), b"new");
    }

    #[test]
    fn mixed_recipients_are_refused() {
        let (classic, pq, text) = both_kinds();
        let engine = AgeEngine::from_identities_text(text);
        let mixed = vec![pq.recipient_string, classic.recipient_string];
        assert!(matches!(
            engine.encrypt(b"x".to_vec(), mixed),
            Err(CryptoError::MixedRecipients)
        ));
    }

    const TAGPQ_RECIPIENT: &str = include_str!("../../../fixtures/age-pq/tagpq-recipient.txt");

    #[test]
    fn hardware_pq_recipients_sit_in_a_pq_store() {
        let (classic, pq, text) = both_kinds();
        let engine = AgeEngine::from_identities_text(text);
        let ciphertext = engine
            .encrypt(
                b"x".to_vec(),
                vec![TAGPQ_RECIPIENT.to_owned(), pq.recipient_string],
            )
            .unwrap();
        assert_eq!(
            stanza_types(&ciphertext),
            vec!["mlkem768p256tag", "mlkem768x25519"]
        );
        assert_eq!(engine.decrypt(ciphertext).unwrap(), b"x");
        assert!(matches!(
            engine.encrypt(
                b"x".to_vec(),
                vec![TAGPQ_RECIPIENT.to_owned(), classic.recipient_string]
            ),
            Err(CryptoError::MixedRecipients)
        ));
    }

    #[test]
    fn self_encryption_stays_classic_when_a_classic_identity_exists() {
        let (_, _, text) = both_kinds();
        let engine = AgeEngine::from_identities_text(text);
        let ciphertext = engine.encrypt(b"x".to_vec(), vec![]).unwrap();
        assert_eq!(stanza_types(&ciphertext), vec!["X25519"]);
        assert_eq!(engine.decrypt(ciphertext).unwrap(), b"x");
    }

    #[test]
    fn self_encryption_is_pq_with_only_pq_identities() {
        let pq = age_generate_pq_identity();
        let engine = AgeEngine::from_identities_text(pq.identity_string);
        let ciphertext = engine.encrypt(b"x".to_vec(), vec![]).unwrap();
        assert_eq!(stanza_types(&ciphertext), vec!["mlkem768x25519"]);
        assert_eq!(engine.decrypt(ciphertext).unwrap(), b"x");
    }

    #[test]
    fn engine_decrypts_an_upstream_vector() {
        let path = format!(
            "{}/../../fixtures/age-pq/hybrid",
            env!("CARGO_MANIFEST_DIR")
        );
        let raw = std::fs::read(path).unwrap();
        let split = raw.windows(2).position(|w| w == b"\n\n").unwrap();
        let header = std::str::from_utf8(&raw[..split]).unwrap();
        let identity = header
            .lines()
            .find_map(|l| l.strip_prefix("identity: "))
            .unwrap();
        let engine = AgeEngine::from_identities_text(identity.to_owned());
        let plaintext = engine.decrypt(raw[split + 2..].to_vec()).unwrap();
        assert_eq!(plaintext, b"age");
    }
}

#[cfg(all(test, not(feature = "age-pq")))]
mod no_pq_tests {
    use super::*;

    /// Without the feature a post-quantum key is not something this
    /// engine knows: the identity line is skipped and the recipient is
    /// refused, exactly as in 2.x.
    #[test]
    fn pq_keys_are_skipped_or_refused() {
        // A syntactically plausible pair; never parsed, so it need not
        // be a real key.
        let pq_identity = format!("AGE-SECRET-KEY-PQ-1{}", "Q".repeat(58));
        let pq_recipient = format!("age1pq1{}", "q".repeat(1952));
        let classic = age_generate_identity();
        let engine = AgeEngine::from_identities_text(format!(
            "{pq_identity}\n{}\n",
            classic.identity_string
        ));
        let ciphertext = engine.encrypt(b"x".to_vec(), vec![]).unwrap();
        assert_eq!(engine.decrypt(ciphertext).unwrap(), b"x");
        assert!(matches!(
            engine.encrypt(b"x".to_vec(), vec![pq_recipient.clone()]),
            Err(CryptoError::Unavailable { .. })
        ));
        assert!(matches!(
            engine.encrypt(
                b"x".to_vec(),
                vec![pq_recipient, classic.recipient_string.clone()]
            ),
            Err(CryptoError::MixedRecipients)
        ));
        let only_pq = AgeEngine::from_identities_text(pq_identity);
        assert!(matches!(
            only_pq.encrypt(b"x".to_vec(), vec![]),
            Err(CryptoError::NoUsableKey)
        ));
    }
}
