//! The crypto boundary. pass-core never encrypts or decrypts anything itself;
//! it hands ciphertext and a resolved recipient set to a [`CryptoBackend`].
//!
//! Implementations live outside this crate:
//! - iOS: NorseHorsePGPCore + AgePony Swift engine (via FFI callback)
//! - Android: PGPony Kotlin engine + AgePony Android engine (via FFI callback)
//! - Desktop: sequoia-openpgp + the age crate, natively in Rust

use zeroize::Zeroizing;

/// Errors a crypto backend can report. Variants intentionally carry no entry
/// names and no plaintext — see THREAT_MODEL.md.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("no usable key for recipient set")]
    NoUsableKey,
    #[error("operation cancelled by user")]
    Cancelled,
    #[error("backend unavailable: {reason}")]
    Unavailable { reason: String },
}

/// A recipient as written in a `.gpg-id` or `.age-recipients` file: an OpenPGP
/// key ID / fingerprint / UID, or an age recipient line. Opaque to pass-core.
pub type Recipient = String;

/// Platform-native crypto engine. Object-safe; crossed via UniFFI callback
/// interface on mobile, implemented directly in Rust on desktop.
pub trait CryptoBackend: Send + Sync {
    /// Encrypt plaintext to the resolved recipient set.
    fn encrypt(&self, plaintext: &[u8], recipients: &[Recipient]) -> Result<Vec<u8>, CryptoError>;

    /// Decrypt ciphertext with whatever identities/keys the backend holds.
    /// The backend owns passphrase prompting and caching policy.
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError>;
}

/// A do-nothing backend for walking-skeleton and store-model tests.
/// "Encryption" is a reversible byte-flip — obviously not crypto; it exists so
/// round-trip plumbing can be tested without any engine attached.
pub struct StubCryptoBackend;

impl CryptoBackend for StubCryptoBackend {
    fn encrypt(&self, plaintext: &[u8], _recipients: &[Recipient]) -> Result<Vec<u8>, CryptoError> {
        Ok(plaintext.iter().map(|b| !b).collect())
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        Ok(Zeroizing::new(ciphertext.iter().map(|b| !b).collect()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_round_trips() {
        let backend = StubCryptoBackend;
        let plaintext = b"correct horse battery staple\n".to_vec();
        let ct = backend.encrypt(&plaintext, &["ponykey".into()]).unwrap();
        assert_ne!(ct, plaintext);
        let pt = backend.decrypt(&ct).unwrap();
        assert_eq!(&*pt, &plaintext);
    }
}
