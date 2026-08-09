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

use age::secrecy::ExposeSecret;
use age::x25519::{Identity, Recipient as X25519Recipient};
use age::{Decryptor, Encryptor};

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
}
