//! UniFFI surface over pass-core.
//!
//! The walking skeleton: platform code (Kotlin/Swift) implements
//! [`CryptoBackend`] as a foreign callback interface and hands it across;
//! [`verify_backend`] proves the round trip end to end. Everything real that
//! follows (store open, list, show, save) rides the same seam.
//!
//! Generate bindings with:
//! `cargo run -p pass-ffi --features cli --bin uniffi-bindgen -- generate --library target/debug/libpass_ffi.so --language kotlin --language swift --out-dir bindings-out`

use std::sync::Arc;

mod store_api;
pub use store_api::*;

// Android-only Rust age engine. Off by default (iOS's FFI surface is
// unchanged unless this feature is explicitly enabled); see
// docs/plan/P04-core-age-engine.md in PassPonyAndroid for why this lives
// in Rust rather than as a platform engine, the way iOS does it.
#[cfg(feature = "age-engine")]
mod age_engine;
#[cfg(feature = "age-engine")]
pub use age_engine::*;

uniffi::setup_scaffolding!();

/// Point the git transport's OpenSSL at a CA bundle.
///
/// Android has no OpenSSL-visible system trust store, so the vendored
/// OpenSSL the git core links starts with zero trust anchors and every
/// HTTPS git handshake fails certificate verification (libgit2 reports
/// class=Ssl (16)). On desktop and CI, OpenSSL finds the system store at
/// its built-in path, which is why sync works there. The platform copies
/// the app's bundled cacert.pem into local storage and passes its path
/// here once at startup, before any clone/fetch/push. OpenSSL's default
/// verify paths honor SSL_CERT_FILE, which is the store libgit2 falls back
/// to when no explicit CA file is set on the transport.
#[uniffi::export]
pub fn init_tls(ca_file: String) {
    // Safe on edition 2021, and only ever called once at process startup
    // before any network or git use.
    std::env::set_var("SSL_CERT_FILE", ca_file);
}

/// FFI-facing crypto error. Mirrors `pass_core::crypto::CryptoError`; variants
/// carry no entry names and no plaintext.
#[derive(Debug, thiserror::Error, uniffi::Error)]
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

impl From<pass_core::crypto::CryptoError> for CryptoError {
    fn from(e: pass_core::crypto::CryptoError) -> Self {
        use pass_core::crypto::CryptoError as Core;
        match e {
            Core::DecryptionFailed => CryptoError::DecryptionFailed,
            Core::EncryptionFailed => CryptoError::EncryptionFailed,
            Core::NoUsableKey => CryptoError::NoUsableKey,
            Core::Cancelled => CryptoError::Cancelled,
            Core::Unavailable { reason } => CryptoError::Unavailable { reason },
        }
    }
}

/// Platform-native crypto engine, implemented in Kotlin/Swift and passed in.
#[uniffi::export(with_foreign)]
pub trait CryptoBackend: Send + Sync {
    fn encrypt(&self, plaintext: Vec<u8>, recipients: Vec<String>) -> Result<Vec<u8>, CryptoError>;
    fn decrypt(&self, ciphertext: Vec<u8>) -> Result<Vec<u8>, CryptoError>;
}

/// Adapts a foreign-implemented backend to pass-core's trait so core code
/// stays FFI-unaware.
pub(crate) struct ForeignBackendAdapter(pub(crate) Arc<dyn CryptoBackend>);

impl pass_core::crypto::CryptoBackend for ForeignBackendAdapter {
    fn encrypt(
        &self,
        plaintext: &[u8],
        recipients: &[String],
    ) -> Result<Vec<u8>, pass_core::crypto::CryptoError> {
        self.0
            .encrypt(plaintext.to_vec(), recipients.to_vec())
            .map_err(|e| match e {
                CryptoError::Cancelled => pass_core::crypto::CryptoError::Cancelled,
                CryptoError::Unavailable { reason } => {
                    pass_core::crypto::CryptoError::Unavailable { reason }
                }
                _ => pass_core::crypto::CryptoError::EncryptionFailed,
            })
    }

    fn decrypt(
        &self,
        ciphertext: &[u8],
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, pass_core::crypto::CryptoError> {
        self.0
            .decrypt(ciphertext.to_vec())
            .map(zeroize::Zeroizing::new)
            .map_err(|e| match e {
                CryptoError::Cancelled => pass_core::crypto::CryptoError::Cancelled,
                CryptoError::Unavailable { reason } => {
                    pass_core::crypto::CryptoError::Unavailable { reason }
                }
                _ => pass_core::crypto::CryptoError::DecryptionFailed,
            })
    }
}

/// pass-core version string, for diagnostics screens.
#[uniffi::export]
pub fn core_version() -> String {
    pass_core::core_version()
}

/// Walking-skeleton proof: encrypt and decrypt a known payload through the
/// supplied backend and confirm the round trip. Platform integration tests
/// call this first; if it passes, the FFI seam and the callback interface
/// both work.
#[uniffi::export]
pub fn verify_backend(backend: Arc<dyn CryptoBackend>) -> Result<(), CryptoError> {
    let adapter = ForeignBackendAdapter(backend);
    let payload = b"passpony walking skeleton".to_vec();
    let core_backend: &dyn pass_core::crypto::CryptoBackend = &adapter;
    let ct = core_backend.encrypt(&payload, &["skeleton-recipient".into()])?;
    let pt = core_backend.decrypt(&ct)?;
    if *pt == payload {
        Ok(())
    } else {
        Err(CryptoError::DecryptionFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FlipBackend;
    impl CryptoBackend for FlipBackend {
        fn encrypt(
            &self,
            plaintext: Vec<u8>,
            _recipients: Vec<String>,
        ) -> Result<Vec<u8>, CryptoError> {
            Ok(plaintext.iter().map(|b| !b).collect())
        }
        fn decrypt(&self, ciphertext: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
            Ok(ciphertext.iter().map(|b| !b).collect())
        }
    }

    #[test]
    fn verify_backend_round_trips() {
        assert!(verify_backend(Arc::new(FlipBackend)).is_ok());
    }
}
