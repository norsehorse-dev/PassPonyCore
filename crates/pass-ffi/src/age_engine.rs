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

use std::io::{Read, Write};
use std::str::FromStr;
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

/// Highest scrypt work factor (log2 N) accepted when unlocking a
/// passphrase-protected identities file. age and gopass default to 18
/// (256 MiB of scrypt memory); each step doubles memory and time, so 20
/// (1 GiB) leaves 4x headroom for files written with a stronger setting
/// while still refusing a hostile file that asks for an unbounded amount
/// of work. age's own ceiling (target + 4 = 22) would need 4 GiB, which
/// is not a safe ask on a phone.
const MAX_IDENTITIES_SCRYPT_LOG_N: u8 = 20;

const AGE_BINARY_MAGIC: &[u8] = b"age-encryption.org/v1";
const AGE_ARMOR_MAGIC: &[u8] = b"-----BEGIN AGE ENCRYPTED FILE-----";

/// True when `data` looks like an age-encrypted file (binary header or
/// ASCII armor) rather than a plaintext identities file. A cheap prefix
/// check, not a parse: it only decides whether to ask for a passphrase.
#[uniffi::export]
pub fn age_is_encrypted_identities_file(data: Vec<u8>) -> bool {
    let data = data.trim_ascii_start();
    data.starts_with(AGE_BINARY_MAGIC) || data.starts_with(AGE_ARMOR_MAGIC)
}

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

fn decrypt_identities_file(
    data: Vec<u8>,
    passphrase: String,
    max_log_n: u8,
) -> Result<Vec<u8>, CryptoError> {
    let passphrase = SecretString::from(passphrase);
    let decryptor =
        Decryptor::new(ArmoredReader::new(&data[..])).map_err(|_| CryptoError::DecryptionFailed)?;
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
        Arc::new(AgeEngine { identities })
    }

    pub fn encrypt(
        &self,
        plaintext: Vec<u8>,
        recipients: Vec<String>,
    ) -> Result<Vec<u8>, CryptoError> {
        if self.identities.is_empty() && recipients.is_empty() {
            return Err(CryptoError::NoUsableKey);
        }

        let targets: Vec<X25519Recipient> = if recipients.is_empty() {
            self.identities.iter().map(Identity::to_public).collect()
        } else {
            let mut parsed = Vec::with_capacity(recipients.len());
            for spec in &recipients {
                match X25519Recipient::from_str(spec) {
                    Ok(r) => parsed.push(r),
                    // Matches AgePonyEngine.swift: any parse failure
                    // collapses to a generic EncryptionFailed rather
                    // than naming the bad recipient in the error.
                    Err(_) => return Err(CryptoError::EncryptionFailed),
                }
            }
            parsed
        };

        let refs: Vec<&dyn age::Recipient> =
            targets.iter().map(|r| r as &dyn age::Recipient).collect();
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
        if self.identities.is_empty() {
            return Err(CryptoError::NoUsableKey);
        }

        let decryptor =
            Decryptor::new(&ciphertext[..]).map_err(|_| CryptoError::DecryptionFailed)?;
        let refs: Vec<&dyn age::Identity> = self
            .identities
            .iter()
            .map(|i| i as &dyn age::Identity)
            .collect();
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn encrypted_identities_detection() {
        assert!(age_is_encrypted_identities_file(passphrase_fixture(
            "identities.binary"
        )));
        assert!(age_is_encrypted_identities_file(passphrase_fixture(
            "identities"
        )));
        let mut padded = b"\n  ".to_vec();
        padded.extend(passphrase_fixture("identities"));
        assert!(age_is_encrypted_identities_file(padded));

        // Plaintext identities (with and without comments) pass through.
        assert!(!age_is_encrypted_identities_file(passphrase_fixture(
            "identities.plain"
        )));
        assert!(!age_is_encrypted_identities_file(
            b"AGE-SECRET-KEY-1ABC\n".to_vec()
        ));
        assert!(!age_is_encrypted_identities_file(Vec::new()));
    }
}
