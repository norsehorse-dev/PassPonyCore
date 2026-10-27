//! Rust OpenPGP engine for pass stores, exposed over the FFI as an
//! iOS-only feature (`pgp-engine`).
//!
//! iOS's own engine (PGPonyEngine over NorseHorsePGPCore) only handles
//! Curve25519 keys. Long-lived pass stores are often keyed to RSA, and
//! modern GnuPG writes AEAD (OCB) packets the Swift parser does not read,
//! so iOS hands those cases to this engine: rpgp, the same backend
//! PassPony Desktop uses for pass stores. Android has BouncyCastle and
//! leaves the feature off.
//!
//! Semantics follow PGPonyEngine.swift:
//! - key blobs may be armored or binary, public or secret, one or many
//!   keys per blob; anything that is not an OpenPGP key is skipped;
//! - recipients are `.gpg-id` lines matched against any primary or
//!   subkey fingerprint, a 16-hex key ID, or a fingerprint suffix of 16+
//!   hex digits, with `0x` and inner spaces tolerated;
//! - encrypt never encrypts to fewer recipients than it was given: the
//!   first recipient that does not resolve fails the whole call;
//! - errors never carry entry names or plaintext.

use std::io::Cursor;
use std::sync::Arc;

use pgp::composed::{
    DecryptionOptions, Deserializable, Message, MessageBuilder, SignedPublicKey,
    SignedPublicSubKey, SignedSecretKey, TheRing,
};
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::packet::{Signature, SignatureType};
use pgp::types::{KeyDetails, KeyVersion, Password, S2kParams, SecretParams, StringToKey};
use zeroize::Zeroizing;

use crate::CryptoError;

/// Summary of one key in a blob, for the key list and the Initialize
/// picker. Fingerprints and key IDs are uppercase hex.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PgpKeyInfo {
    pub primary_fingerprint: String,
    /// Primary and subkey fingerprints, primary first.
    pub fingerprints: Vec<String>,
    /// Primary and subkey 16-hex key IDs, primary first.
    pub key_ids: Vec<String>,
    /// Display name of the primary key's algorithm, e.g. "RSA 4096".
    pub algorithm: String,
    pub is_v6: bool,
    pub has_secret: bool,
    /// Whether the key has a subkey (or primary) usable for encryption.
    pub can_encrypt: bool,
}

/// Whether a secret key needs a passphrase, given the one on hand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum PgpLockState {
    /// No secret material in the blob.
    NotSecret,
    /// Secret material is stored unprotected.
    Unprotected,
    /// Protected, and the given passphrase unlocks it.
    Unlocked,
    /// Protected, and no passphrase was given.
    PassphraseRequired,
    /// Protected, and the given passphrase does not unlock it.
    WrongPassphrase,
}

/// Every key in a blob, in file order. Empty when the blob holds no
/// OpenPGP key this engine can parse.
#[uniffi::export]
pub fn pgp_key_infos(blob: Vec<u8>) -> Vec<PgpKeyInfo> {
    let parsed = parse_blob(&blob);
    let mut out = Vec::new();
    for secret in &parsed.secret {
        out.push(info(&secret.to_public_key(), true));
    }
    for public in &parsed.public {
        out.push(info(public, false));
    }
    out
}

/// Lock state of the first secret key in a blob.
#[uniffi::export]
pub fn pgp_key_lock_state(blob: Vec<u8>, passphrase: Option<String>) -> PgpLockState {
    let parsed = parse_blob(&blob);
    let Some(key) = parsed.secret.into_iter().next() else {
        return PgpLockState::NotSecret;
    };
    let passphrase = passphrase.filter(|p| !p.is_empty());
    unlock_in_place(key, passphrase.as_deref()).1
}

/// A loaded set of OpenPGP keys implementing the FFI's `CryptoBackend`
/// shape, so the Swift wrapper is a two-line delegation.
///
/// Protected keys are unlocked once, here, and held unlocked in memory
/// for the engine's lifetime (as the Swift engine holds its extracted
/// Cv25519 keys). Keys that stay locked are left out of decryption
/// entirely, so a locked key costs nothing per entry: decrypt returns
/// `NoUsableKey` straight away instead of re-running the S2K each time.
#[derive(uniffi::Object)]
pub struct PgpEngine {
    /// Only keys with at least one unlocked secret component.
    secret: Vec<SignedSecretKey>,
    /// Every cert, secret or not, for encryption.
    public: Vec<SignedPublicKey>,
    /// Per input blob, the lock state of its first secret key.
    blob_lock_states: Vec<PgpLockState>,
}

#[uniffi::export]
impl PgpEngine {
    /// Load every key in every blob. Unparsable blobs are skipped, so an
    /// engine with no usable key is not an error here; decrypt and
    /// encrypt fail with `NoUsableKey` when used, matching iOS.
    #[uniffi::constructor]
    pub fn from_key_blobs(blobs: Vec<Vec<u8>>, passphrase: Option<String>) -> Arc<Self> {
        let passphrase = passphrase.filter(|p| !p.is_empty()).map(Zeroizing::new);
        let mut secret = Vec::new();
        let mut public = Vec::new();
        let mut blob_lock_states = Vec::with_capacity(blobs.len());
        for blob in &blobs {
            let parsed = parse_blob(blob);
            let mut first_state = None;
            for key in parsed.secret {
                public.push(key.to_public_key());
                let (unlocked, state) =
                    unlock_in_place(key, passphrase.as_deref().map(String::as_str));
                first_state.get_or_insert(state);
                if let Some(key) = unlocked {
                    secret.push(key);
                }
            }
            public.extend(parsed.public);
            blob_lock_states.push(first_state.unwrap_or(PgpLockState::NotSecret));
        }
        Arc::new(PgpEngine {
            secret,
            public,
            blob_lock_states,
        })
    }

    /// One entry per blob given to `from_key_blobs`, in order: the lock
    /// state of that blob's first secret key, worked out during the load
    /// (no second S2K).
    pub fn blob_lock_states(&self) -> Vec<PgpLockState> {
        self.blob_lock_states.clone()
    }

    /// Whether any loaded key carries secret material.
    pub fn has_secret_keys(&self) -> bool {
        !self.secret.is_empty()
    }

    pub fn decrypt(&self, ciphertext: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
        if self.secret.is_empty() {
            return Err(CryptoError::NoUsableKey);
        }
        let (message, _) = Message::from_reader(Cursor::new(ciphertext.as_slice()))
            .map_err(|_| CryptoError::DecryptionFailed)?;
        if !message.is_encrypted() {
            return Err(CryptoError::DecryptionFailed);
        }

        // Every loaded key was unlocked at load. A component that is still
        // marked encrypted here is a gpg stub, which no password opens.
        let empty = Password::empty();
        let ring = TheRing {
            secret_keys: self.secret.iter().collect(),
            key_passwords: vec![&empty],
            message_password: Vec::new(),
            session_keys: Vec::new(),
            // Modern GnuPG writes its pre-RFC 9580 AEAD (OCB) packets by
            // default when every recipient key advertises support.
            decrypt_options: DecryptionOptions::new().enable_gnupg_aead(),
        };
        // An error here means no key produced a session key: none matched,
        // or the match was locked. Both read as "import or unlock the key".
        // (RingResult is not used: rpgp resets each key's slot per PKESK,
        // so a multi-recipient message can report NoMatch for the key that
        // did decrypt it.)
        let (mut message, _) = message
            .decrypt_the_ring(ring, true)
            .map_err(|_| CryptoError::NoUsableKey)?;

        if message.is_compressed() {
            message = message
                .decompress()
                .map_err(|_| CryptoError::DecryptionFailed)?;
        }
        let mut plaintext = message
            .as_data_vec()
            .map_err(|_| CryptoError::DecryptionFailed)?;
        // Reading to the end checks the MDC / AEAD tag; a message that
        // fails it is rejected above via the read error.
        Ok(std::mem::take(&mut plaintext))
    }

    pub fn encrypt(
        &self,
        plaintext: Vec<u8>,
        recipients: Vec<String>,
    ) -> Result<Vec<u8>, CryptoError> {
        // pass stores always resolve a .gpg-id; empty means uninitialized.
        if recipients.is_empty() {
            return Err(CryptoError::NoUsableKey);
        }
        let mut certs: Vec<&SignedPublicKey> = Vec::new();
        for spec in &recipients {
            let cert = self.resolve(spec).ok_or_else(|| CryptoError::Unavailable {
                reason: format!("No imported key matches {spec} (fingerprint or 16-hex key ID)"),
            })?;
            if !certs.iter().any(|c| c.fingerprint() == cert.fingerprint()) {
                certs.push(cert);
            }
        }

        let mut rng = rand::thread_rng();
        let all_v6 = certs.iter().all(|c| c.version() == KeyVersion::V6);
        let source = MessageBuilder::from_bytes("", plaintext);
        let out = if all_v6 {
            let mut builder = source.seipd_v2(
                &mut rng,
                SymmetricKeyAlgorithm::AES256,
                pgp::crypto::aead::AeadAlgorithm::Ocb,
                pgp::crypto::aead::ChunkSize::default(),
            );
            for cert in &certs {
                for target in encryption_targets(cert)? {
                    target_encrypt_v2(&mut builder, &mut rng, target)?;
                }
            }
            builder.to_vec(&mut rng)
        } else {
            let mut builder = source.seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);
            for cert in &certs {
                for target in encryption_targets(cert)? {
                    target_encrypt_v1(&mut builder, &mut rng, target)?;
                }
            }
            builder.to_vec(&mut rng)
        };
        out.map_err(|_| CryptoError::EncryptionFailed)
    }
}

impl PgpEngine {
    /// Match a `.gpg-id` line the way PGPonyEngine.resolve() does.
    fn resolve(&self, spec: &str) -> Option<&SignedPublicKey> {
        let needle = spec.to_uppercase().replace("0X", "").replace(' ', "");
        if needle.is_empty() {
            return None;
        }
        self.public.iter().find(|cert| {
            let i = info(cert, false);
            i.fingerprints
                .iter()
                .any(|fp| fp == &needle || (needle.len() >= 16 && fp.ends_with(&needle)))
                || i.key_ids.iter().any(|id| id == &needle)
        })
    }
}

/// A key to encrypt the session key to: a subkey or the primary.
enum Target<'a> {
    Subkey(&'a SignedPublicSubKey),
    Primary(&'a SignedPublicKey),
}

fn target_encrypt_v1<R: rand::CryptoRng + rand::Rng>(
    builder: &mut MessageBuilder<'_, pgp::composed::DummyReader, pgp::composed::EncryptionSeipdV1>,
    rng: &mut R,
    target: Target<'_>,
) -> Result<(), CryptoError> {
    let r = match target {
        Target::Subkey(k) => builder.encrypt_to_key(&mut *rng, &k.key),
        Target::Primary(k) => builder.encrypt_to_key(&mut *rng, &k.primary_key),
    };
    r.map(|_| ()).map_err(|_| CryptoError::EncryptionFailed)
}

fn target_encrypt_v2<R: rand::CryptoRng + rand::Rng>(
    builder: &mut MessageBuilder<'_, pgp::composed::DummyReader, pgp::composed::EncryptionSeipdV2>,
    rng: &mut R,
    target: Target<'_>,
) -> Result<(), CryptoError> {
    let r = match target {
        Target::Subkey(k) => builder.encrypt_to_key(&mut *rng, &k.key),
        Target::Primary(k) => builder.encrypt_to_key(&mut *rng, &k.primary_key),
    };
    r.map(|_| ()).map_err(|_| CryptoError::EncryptionFailed)
}

/// Every live encryption-capable subkey of a cert, the way gpg encrypts
/// to all of them; the primary only when no subkey qualifies and the
/// primary itself can encrypt.
fn encryption_targets(cert: &SignedPublicKey) -> Result<Vec<Target<'_>>, CryptoError> {
    let mut out: Vec<Target<'_>> = cert
        .public_subkeys
        .iter()
        .filter(|sub| subkey_encrypts(sub))
        .map(Target::Subkey)
        .collect();
    if out.is_empty() && cert.primary_key.algorithm().can_encrypt() {
        out.push(Target::Primary(cert));
    }
    if out.is_empty() {
        return Err(CryptoError::Unavailable {
            reason: format!(
                "Key for {:X} has no usable encryption subkey",
                cert.fingerprint()
            ),
        });
    }
    Ok(out)
}

fn subkey_encrypts(sub: &SignedPublicSubKey) -> bool {
    if !sub.key.algorithm().can_encrypt() {
        return false;
    }
    if sub
        .signatures
        .iter()
        .any(|s| s.typ() == Some(SignatureType::SubkeyRevocation))
    {
        return false;
    }
    let Some(binding) = newest_binding(&sub.signatures) else {
        return false;
    };
    let flags = binding.key_flags();
    if !(flags.encrypt_comms() || flags.encrypt_storage()) {
        return false;
    }
    if let Some(validity) = binding.key_expiration_time() {
        if validity.as_secs() != 0 {
            let created = u64::from(sub.key.created_at().as_secs());
            let expires = created.saturating_add(u64::from(validity.as_secs()));
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            if now >= expires {
                return false;
            }
        }
    }
    true
}

fn newest_binding(sigs: &[Signature]) -> Option<&Signature> {
    sigs.iter()
        .filter(|s| s.typ() == Some(SignatureType::SubkeyBinding))
        .max_by_key(|s| s.created().map(|t| t.as_secs()).unwrap_or(0))
}

struct ParsedBlob {
    secret: Vec<SignedSecretKey>,
    public: Vec<SignedPublicKey>,
}

/// Secret keys first (a secret export also carries the public half), then
/// public keys. Armored or binary, any number of keys.
fn parse_blob(blob: &[u8]) -> ParsedBlob {
    let mut secret = Vec::new();
    if let Ok((iter, _)) = SignedSecretKey::from_reader_many(Cursor::new(blob)) {
        secret.extend(iter.filter_map(Result::ok));
    }
    let mut public = Vec::new();
    if secret.is_empty() {
        if let Ok((iter, _)) = SignedPublicKey::from_reader_many(Cursor::new(blob)) {
            public.extend(iter.filter_map(Result::ok));
        }
    }
    ParsedBlob { secret, public }
}

fn info(cert: &SignedPublicKey, has_secret: bool) -> PgpKeyInfo {
    let mut fingerprints = vec![format!("{:X}", cert.fingerprint())];
    let mut key_ids = vec![key_id_hex(&cert.primary_key)];
    for sub in &cert.public_subkeys {
        fingerprints.push(format!("{:X}", sub.key.fingerprint()));
        key_ids.push(key_id_hex(&sub.key));
    }
    let can_encrypt = encryption_targets(cert).is_ok();
    PgpKeyInfo {
        primary_fingerprint: fingerprints[0].clone(),
        fingerprints,
        key_ids,
        algorithm: algorithm_name(&cert.primary_key),
        is_v6: cert.version() == KeyVersion::V6,
        has_secret,
        can_encrypt,
    }
}

fn key_id_hex(key: &impl KeyDetails) -> String {
    let id = key.legacy_key_id();
    id.as_ref().iter().map(|b| format!("{b:02X}")).collect()
}

fn algorithm_name(key: &impl KeyDetails) -> String {
    use pgp::crypto::public_key::PublicKeyAlgorithm as A;
    use pgp::types::PublicParams as P;
    match (key.algorithm(), key.public_params()) {
        (A::RSA | A::RSAEncrypt | A::RSASign, P::RSA(params)) => {
            format!("RSA {}", rsa_bits(params))
        }
        (A::EdDSALegacy | A::Ed25519, _) => "Ed25519".to_owned(),
        (A::Ed448, _) => "Ed448".to_owned(),
        (A::X25519, _)
        | (A::ECDH, P::ECDH(pgp::types::EcdhPublicParams::Curve25519Legacy { .. })) => {
            "Cv25519".to_owned()
        }
        (A::ECDSA, P::ECDSA(params)) => format!("ECDSA {}", ecdsa_curve(params)),
        (A::ECDH, _) => "ECDH".to_owned(),
        (A::DSA, _) => "DSA".to_owned(),
        (A::Elgamal | A::ElgamalEncrypt, _) => "Elgamal".to_owned(),
        (other, _) => format!("{other:?}"),
    }
}

fn rsa_bits(params: &pgp::types::RsaPublicParams) -> usize {
    use rsa::traits::PublicKeyParts;
    params.key.n().bits()
}

fn ecdsa_curve(params: &pgp::types::EcdsaPublicParams) -> &'static str {
    use pgp::types::EcdsaPublicParams as E;
    match params {
        E::P256 { .. } => "P-256",
        E::P384 { .. } => "P-384",
        E::P521 { .. } => "P-521",
        _ => "",
    }
}

/// A gpg stub: `--export-secret-subkeys` writes the primary this way
/// (GNU extension S2K 101, "no secret material here"), and a key moved to
/// a smartcard leaves stubs for every component. No password opens one.
fn is_gnu_stub(params: &SecretParams) -> bool {
    let SecretParams::Encrypted(enc) = params else {
        return false;
    };
    match enc.string_to_key_params() {
        S2kParams::Cfb { s2k, .. }
        | S2kParams::MalleableCfb { s2k, .. }
        | S2kParams::Aead { s2k, .. } => matches!(s2k, StringToKey::Private { typ: 101, .. }),
        _ => false,
    }
}

/// Unlock every protected (non-stub) component of a key with the
/// passphrase, in memory. Returns the key when at least one secret
/// component is usable afterwards, plus the key's lock state:
/// - nothing protected: `Unprotected` (or `NotSecret` if it is all stubs);
/// - protected and no passphrase: `PassphraseRequired`;
/// - protected and the passphrase opens nothing: `WrongPassphrase`;
/// - otherwise `Unlocked`.
fn unlock_in_place(
    mut key: SignedSecretKey,
    passphrase: Option<&str>,
) -> (Option<SignedSecretKey>, PgpLockState) {
    let pw = passphrase.map(Password::from);
    let mut protected = 0usize;
    let mut opened = 0usize;

    let primary = key.primary_key.secret_params();
    if primary.is_encrypted() && !is_gnu_stub(primary) {
        protected += 1;
        if let Some(pw) = &pw {
            if key.primary_key.remove_password(pw).is_ok() {
                opened += 1;
            }
        }
    }
    for sub in &mut key.secret_subkeys {
        let params = sub.key.secret_params();
        if params.is_encrypted() && !is_gnu_stub(params) {
            protected += 1;
            if let Some(pw) = &pw {
                if sub.key.remove_password(pw).is_ok() {
                    opened += 1;
                }
            }
        }
    }

    let usable = !key.primary_key.secret_params().is_encrypted()
        || key
            .secret_subkeys
            .iter()
            .any(|s| !s.key.secret_params().is_encrypted());
    let state = if protected == 0 {
        if usable {
            PgpLockState::Unprotected
        } else {
            PgpLockState::NotSecret
        }
    } else if pw.is_none() {
        PgpLockState::PassphraseRequired
    } else if opened == 0 {
        PgpLockState::WrongPassphrase
    } else {
        PgpLockState::Unlocked
    };
    (usable.then_some(key), state)
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! fx {
        ($name:literal) => {
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../fixtures/pgp-engine/",
                $name
            ))
            .to_vec()
        };
    }

    const PASS: &str = "pony-test-passphrase";

    fn plaintext() -> Vec<u8> {
        fx!("plaintext.txt")
    }

    fn fpr(bytes: Vec<u8>) -> String {
        String::from_utf8(bytes).unwrap().trim().to_owned()
    }

    fn engine(blobs: Vec<Vec<u8>>, passphrase: Option<&str>) -> Arc<PgpEngine> {
        PgpEngine::from_key_blobs(blobs, passphrase.map(str::to_owned))
    }

    #[test]
    fn decrypts_gpg_rsa_entries_binary_and_armored() {
        let e = engine(vec![fx!("rsa.sec.asc")], None);
        assert!(e.has_secret_keys());
        assert_eq!(e.decrypt(fx!("rsa.gpg")).unwrap(), plaintext());
        assert_eq!(e.decrypt(fx!("rsa-armored.gpg")).unwrap(), plaintext());
    }

    #[test]
    fn decrypts_with_secret_subkeys_only_export() {
        let e = engine(vec![fx!("rsa-subkeys-only.sec.asc")], None);
        assert_eq!(e.decrypt(fx!("rsa.gpg")).unwrap(), plaintext());
    }

    #[test]
    fn decrypts_gnupg_aead_ocb_entry() {
        let e = engine(vec![fx!("ecc.sec.gpg")], None);
        assert_eq!(e.decrypt(fx!("ecc-aead.gpg")).unwrap(), plaintext());
    }

    #[test]
    fn multi_recipient_entry_opens_with_either_key() {
        let rsa = engine(vec![fx!("rsa.sec.asc")], None);
        let ecc = engine(vec![fx!("ecc.sec.gpg")], None);
        assert_eq!(rsa.decrypt(fx!("rsa-and-ecc.gpg")).unwrap(), plaintext());
        assert_eq!(ecc.decrypt(fx!("rsa-and-ecc.gpg")).unwrap(), plaintext());
    }

    #[test]
    fn locked_key_needs_the_passphrase() {
        let none = engine(vec![fx!("rsa-locked.sec.asc")], None);
        assert!(matches!(
            none.decrypt(fx!("rsa-locked.gpg")),
            Err(CryptoError::NoUsableKey)
        ));
        let wrong = engine(vec![fx!("rsa-locked.sec.asc")], Some("nope"));
        assert!(matches!(
            wrong.decrypt(fx!("rsa-locked.gpg")),
            Err(CryptoError::NoUsableKey)
        ));
        let right = engine(vec![fx!("rsa-locked.sec.asc")], Some(PASS));
        assert_eq!(right.decrypt(fx!("rsa-locked.gpg")).unwrap(), plaintext());
    }

    #[test]
    fn unprotected_key_still_works_with_a_cached_passphrase() {
        // iOS caches one passphrase for the whole key directory.
        let e = engine(
            vec![fx!("rsa.sec.asc"), fx!("rsa-locked.sec.asc")],
            Some(PASS),
        );
        assert_eq!(e.decrypt(fx!("rsa.gpg")).unwrap(), plaintext());
        assert_eq!(e.decrypt(fx!("rsa-locked.gpg")).unwrap(), plaintext());
    }

    #[test]
    fn wrong_key_is_no_usable_key() {
        let e = engine(vec![fx!("ecc.sec.gpg")], None);
        assert!(matches!(
            e.decrypt(fx!("rsa.gpg")),
            Err(CryptoError::NoUsableKey)
        ));
        let empty = engine(vec![], None);
        assert!(matches!(
            empty.decrypt(fx!("rsa.gpg")),
            Err(CryptoError::NoUsableKey)
        ));
    }

    #[test]
    fn garbage_is_decryption_failed() {
        let e = engine(vec![fx!("rsa.sec.asc")], None);
        assert!(matches!(
            e.decrypt(b"not an openpgp message".to_vec()),
            Err(CryptoError::DecryptionFailed)
        ));
    }

    #[test]
    fn encrypt_round_trips_for_rsa_ecc_and_both() {
        let rsa = fpr(fx!("rsa.fpr"));
        let ecc = fpr(fx!("ecc.fpr"));
        let e = engine(vec![fx!("rsa.sec.asc"), fx!("ecc.sec.gpg")], None);
        for recipients in [
            vec![rsa.clone()],
            vec![ecc.clone()],
            vec![rsa.clone(), ecc.clone()],
        ] {
            let ct = e.encrypt(plaintext(), recipients.clone()).unwrap();
            assert_eq!(e.decrypt(ct.clone()).unwrap(), plaintext());
            // Every listed recipient can open it on its own.
            if recipients.len() == 2 {
                let only_rsa = engine(vec![fx!("rsa.sec.asc")], None);
                let only_ecc = engine(vec![fx!("ecc.sec.gpg")], None);
                assert_eq!(only_rsa.decrypt(ct.clone()).unwrap(), plaintext());
                assert_eq!(only_ecc.decrypt(ct).unwrap(), plaintext());
            }
        }
    }

    #[test]
    fn encrypt_needs_only_the_public_key() {
        let rsa = fpr(fx!("rsa.fpr"));
        let public_only = engine(vec![fx!("rsa.pub.asc")], None);
        assert!(!public_only.has_secret_keys());
        let ct = public_only.encrypt(plaintext(), vec![rsa]).unwrap();
        let secret = engine(vec![fx!("rsa.sec.asc")], None);
        assert_eq!(secret.decrypt(ct).unwrap(), plaintext());
    }

    #[test]
    fn recipient_resolution_matches_the_swift_rule() {
        let rsa = fpr(fx!("rsa.fpr"));
        let e = engine(vec![fx!("rsa.sec.asc")], None);
        let key_id = rsa[rsa.len() - 16..].to_owned();
        let spaced = format!("0x{} {}", rsa[..20].to_lowercase(), &rsa[20..]);
        for spec in [rsa.clone(), key_id, spaced] {
            assert!(e.encrypt(plaintext(), vec![spec.clone()]).is_ok(), "{spec}");
        }
        assert!(matches!(
            e.encrypt(plaintext(), vec![rsa, "DEADBEEFDEADBEEF".to_owned()]),
            Err(CryptoError::Unavailable { .. })
        ));
        assert!(matches!(
            e.encrypt(plaintext(), vec![]),
            Err(CryptoError::NoUsableKey)
        ));
    }

    #[test]
    fn key_infos_describe_rsa_and_ecc() {
        let rsa = pgp_key_infos(fx!("rsa.sec.asc"));
        assert_eq!(rsa.len(), 1);
        assert_eq!(rsa[0].primary_fingerprint, fpr(fx!("rsa.fpr")));
        assert_eq!(rsa[0].algorithm, "RSA 3072");
        assert!(rsa[0].has_secret && rsa[0].can_encrypt && !rsa[0].is_v6);
        assert_eq!(rsa[0].fingerprints.len(), 2);
        assert_eq!(rsa[0].key_ids[0].len(), 16);

        let stub = pgp_key_infos(fx!("rsa-subkeys-only.sec.asc"));
        assert_eq!(stub[0].primary_fingerprint, fpr(fx!("rsa.fpr")));

        let public = pgp_key_infos(fx!("rsa.pub.asc"));
        assert!(!public[0].has_secret && public[0].can_encrypt);

        let ecc = pgp_key_infos(fx!("ecc.sec.gpg"));
        assert_eq!(ecc[0].primary_fingerprint, fpr(fx!("ecc.fpr")));
        assert_eq!(ecc[0].algorithm, "Ed25519");

        assert!(pgp_key_infos(b"hello".to_vec()).is_empty());
    }

    #[test]
    fn subkeys_only_export_is_not_locked() {
        // The primary is a gpg stub; only the subkeys carry material.
        assert_eq!(
            pgp_key_lock_state(fx!("rsa-subkeys-only.sec.asc"), None),
            PgpLockState::Unprotected
        );
        assert_eq!(
            pgp_key_lock_state(fx!("rsa-subkeys-only.sec.asc"), Some(PASS.into())),
            PgpLockState::Unprotected
        );
    }

    #[test]
    fn engine_reports_blob_lock_states_in_order() {
        let blobs = vec![
            fx!("rsa.sec.asc"),
            fx!("rsa-locked.sec.asc"),
            fx!("rsa.pub.asc"),
            b"junk".to_vec(),
        ];
        let none = engine(blobs.clone(), None);
        assert_eq!(
            none.blob_lock_states(),
            vec![
                PgpLockState::Unprotected,
                PgpLockState::PassphraseRequired,
                PgpLockState::NotSecret,
                PgpLockState::NotSecret,
            ]
        );
        let wrong = engine(blobs.clone(), Some("nope"));
        assert_eq!(wrong.blob_lock_states()[1], PgpLockState::WrongPassphrase);
        let right = engine(blobs, Some(PASS));
        assert_eq!(right.blob_lock_states()[1], PgpLockState::Unlocked);
    }

    #[test]
    fn locked_key_fails_fast_without_rerunning_s2k() {
        // The locked key is dropped at load, so this must not pay an S2K
        // per call (the passkey index rebuild decrypts every entry).
        let e = engine(vec![fx!("rsa-locked.sec.asc")], None);
        assert!(!e.has_secret_keys());
        let start = std::time::Instant::now();
        for _ in 0..20 {
            assert!(matches!(
                e.decrypt(fx!("rsa-locked.gpg")),
                Err(CryptoError::NoUsableKey)
            ));
        }
        assert!(start.elapsed() < std::time::Duration::from_secs(2));
    }

    #[test]
    fn lock_states() {
        assert_eq!(
            pgp_key_lock_state(fx!("rsa.sec.asc"), None),
            PgpLockState::Unprotected
        );
        assert_eq!(
            pgp_key_lock_state(fx!("rsa.pub.asc"), None),
            PgpLockState::NotSecret
        );
        let locked = || fx!("rsa-locked.sec.asc");
        assert_eq!(
            pgp_key_lock_state(locked(), None),
            PgpLockState::PassphraseRequired
        );
        assert_eq!(
            pgp_key_lock_state(locked(), Some("nope".into())),
            PgpLockState::WrongPassphrase
        );
        assert_eq!(
            pgp_key_lock_state(locked(), Some(PASS.into())),
            PgpLockState::Unlocked
        );
    }
}
