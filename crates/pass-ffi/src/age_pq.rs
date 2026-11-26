//! age's native post-quantum recipient type, `mlkem768x25519`
//! (`age1pq1...` recipients, `AGE-SECRET-KEY-PQ-1...` identities), for the
//! Rust age engine. Gated behind the `age-pq` feature.
//!
//! The `age` crate has no native support for this type yet (0.12 ships
//! only the encrypt-side `tag` and `tagpq` recipients), so this module
//! implements it on the crate's `Recipient` and `Identity` traits. It
//! follows Go age 1.3 (`pq.go`) and `filippo.io/hpke`:
//!
//! - KEM: MLKEM768-X25519, also called X-Wing. The public key is the
//!   ML-KEM-768 encapsulation key followed by the X25519 public key
//!   (1216 bytes), the encapsulated key is the ML-KEM ciphertext followed
//!   by the ephemeral X25519 public key (1120 bytes), and the private key
//!   is a 32-byte seed expanded with SHAKE256. The shared secret is
//!   SHA3-256(ss_M || ss_X || ct_X || pk_X || label).
//! - HPKE base mode (RFC 9180) with that KEM (id 0x647a), HKDF-SHA256 and
//!   ChaCha20-Poly1305, `info` set to the age label, one message sealed
//!   under the base nonce.
//! - Stanza: `-> mlkem768x25519 <enc, unpadded base64>` with the sealed
//!   16-byte file key as the body, and the `postquantum` label so age
//!   refuses to combine it with a classic recipient.
//!
//! `x-wing` on crates.io is not used: it needs `kem` 0.3 while the `age`
//! crate's own `ml-kem` 0.2 needs `kem` 0.3.0-pre.0, and the two cannot
//! be in one build. This sits on the same `ml-kem` version age pulls in.
//!
//! The tests run the upstream age test vectors for this stanza
//! (`fixtures/age-pq`, from C2SP/CCTV).

use std::collections::HashSet;

use age::{DecryptError, EncryptError};
use age_core::format::{FileKey, Stanza, FILE_KEY_BYTES};
use age_core::secrecy::ExposeSecret;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use bech32::primitives::decode::CheckedHrpstring;
use bech32::Hrp;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{Ciphertext, EncodedSizeUser, KemCore, MlKem768};
use sha2::Sha256;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Digest, Sha3_256, Shake256};
use zeroize::{Zeroize, Zeroizing};

const STANZA_TAG: &str = "mlkem768x25519";
const AGE_LABEL: &[u8] = b"age-encryption.org/mlkem768x25519";
const PQ_LABEL: &str = "postquantum";

/// bech32 prefixes; with the `1` separator they read `age1pq1...` and
/// `AGE-SECRET-KEY-PQ-1...`.
const RECIPIENT_HRP: &str = "age1pq";
const IDENTITY_HRP: &str = "age-secret-key-pq-";

const MLKEM_EK_BYTES: usize = 1184;
const MLKEM_CT_BYTES: usize = 1088;
const PUBLIC_KEY_BYTES: usize = MLKEM_EK_BYTES + 32;
const ENC_BYTES: usize = MLKEM_CT_BYTES + 32;
const TAG_BYTES: usize = 16;

/// The six-byte X-Wing combiner label, `\.//^\`.
const XWING_LABEL: [u8; 6] = [0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c];

/// HPKE suite id: "HPKE" || KEM 0x647a || KDF 0x0001 || AEAD 0x0003.
const SUITE_ID: &[u8] = b"HPKE\x64\x7a\x00\x01\x00\x03";

type MlEk = <MlKem768 as KemCore>::EncapsulationKey;
type MlDk = <MlKem768 as KemCore>::DecapsulationKey;

/// Bech32 with the length cap lifted. A post-quantum recipient is 1959
/// characters, past the 1023 the stock checksum type accepts. age makes
/// the same allowance.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum LongBech32 {}

impl bech32::Checksum for LongBech32 {
    type MidstateRepr = u32;
    const CODE_LENGTH: usize = 4096;
    const CHECKSUM_LENGTH: usize = 6;
    const GENERATOR_SH: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    const TARGET_RESIDUE: u32 = 1;
}

fn bech32_decode(s: &str) -> Option<(String, Zeroizing<Vec<u8>>)> {
    let parsed = CheckedHrpstring::new::<LongBech32>(s).ok()?;
    Some((
        parsed.hrp().to_lowercase(),
        Zeroizing::new(parsed.byte_iter().collect()),
    ))
}

fn bech32_encode(hrp: &str, data: &[u8]) -> Option<String> {
    let hrp = Hrp::parse(hrp).ok()?;
    bech32::encode_lower::<LongBech32>(hrp, data).ok()
}

fn labeled_extract(salt: &[u8], label: &[u8], ikm: &[u8]) -> (Zeroizing<Vec<u8>>, Hkdf<Sha256>) {
    let mut labeled = Zeroizing::new(Vec::with_capacity(
        7 + SUITE_ID.len() + label.len() + ikm.len(),
    ));
    labeled.extend_from_slice(b"HPKE-v1");
    labeled.extend_from_slice(SUITE_ID);
    labeled.extend_from_slice(label);
    labeled.extend_from_slice(ikm);
    let (prk, hk) = Hkdf::<Sha256>::extract(Some(salt), &labeled);
    (Zeroizing::new(prk.to_vec()), hk)
}

fn labeled_expand(hk: &Hkdf<Sha256>, label: &[u8], info: &[u8], out: &mut [u8]) {
    let mut labeled = Vec::with_capacity(9 + SUITE_ID.len() + label.len() + info.len());
    // Output lengths here are 12 and 32, so the cast cannot truncate.
    labeled.extend_from_slice(&(out.len() as u16).to_be_bytes());
    labeled.extend_from_slice(b"HPKE-v1");
    labeled.extend_from_slice(SUITE_ID);
    labeled.extend_from_slice(label);
    labeled.extend_from_slice(info);
    hk.expand(&labeled, out)
        .expect("HKDF-SHA256 expands to 12 and 32 bytes");
}

/// RFC 9180 base-mode key schedule: the AEAD key and base nonce for a
/// KEM shared secret.
fn key_schedule(shared_secret: &[u8; 32]) -> (Zeroizing<[u8; 32]>, [u8; 12]) {
    let (psk_id_hash, _) = labeled_extract(b"", b"psk_id_hash", b"");
    let (info_hash, _) = labeled_extract(b"", b"info_hash", AGE_LABEL);
    let mut context = Vec::with_capacity(1 + psk_id_hash.len() + info_hash.len());
    context.push(0); // mode_base
    context.extend_from_slice(&psk_id_hash);
    context.extend_from_slice(&info_hash);

    let (_, secret) = labeled_extract(shared_secret, b"secret", b"");
    let mut key = Zeroizing::new([0u8; 32]);
    let mut nonce = [0u8; 12];
    labeled_expand(&secret, b"key", &context, &mut key[..]);
    labeled_expand(&secret, b"base_nonce", &context, &mut nonce);
    (key, nonce)
}

fn combiner(ss_m: &[u8], ss_x: &[u8], ct_x: &[u8], pk_x: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut h = Sha3_256::new();
    Digest::update(&mut h, ss_m);
    Digest::update(&mut h, ss_x);
    Digest::update(&mut h, ct_x);
    Digest::update(&mut h, pk_x);
    Digest::update(&mut h, XWING_LABEL);
    Zeroizing::new(h.finalize().into())
}

/// A post-quantum age recipient (`age1pq1...`).
#[derive(Clone)]
pub struct HybridRecipient {
    ek_m: MlEk,
    pk_x: x25519_dalek::PublicKey,
}

impl HybridRecipient {
    /// Parses an `age1pq1...` string. Returns `None` for anything else,
    /// including a key whose ML-KEM half is not in canonical form.
    pub fn parse(s: &str) -> Option<Self> {
        let (hrp, data) = bech32_decode(s)?;
        if hrp != RECIPIENT_HRP || data.len() != PUBLIC_KEY_BYTES {
            return None;
        }
        let (m_bytes, x_bytes) = data.split_at(MLKEM_EK_BYTES);
        let ek_m = MlEk::from_bytes(m_bytes.try_into().ok()?);
        // FIPS 203 requires the encoded key to round-trip unchanged.
        if ek_m.as_bytes().as_slice() != m_bytes {
            return None;
        }
        let x: [u8; 32] = x_bytes.try_into().ok()?;
        Some(Self {
            ek_m,
            pk_x: x25519_dalek::PublicKey::from(x),
        })
    }

    /// The `age1pq1...` string for this recipient.
    pub fn encode(&self) -> String {
        let mut bytes = self.ek_m.as_bytes().to_vec();
        bytes.extend_from_slice(self.pk_x.as_bytes());
        bech32_encode(RECIPIENT_HRP, &bytes).expect("a 1216-byte key fits the lifted length cap")
    }
}

impl age::Recipient for HybridRecipient {
    fn wrap_file_key(
        &self,
        file_key: &FileKey,
    ) -> Result<(Vec<Stanza>, HashSet<String>), EncryptError> {
        let mut rng = rand::rngs::OsRng;
        // Encapsulation to a parsed ML-KEM-768 key does not fail; the
        // error type exists only because the trait is generic.
        let (ct_m, ss_m) = self
            .ek_m
            .encapsulate(&mut rng)
            .expect("ML-KEM-768 encapsulation is infallible");
        let ek_x = x25519_dalek::StaticSecret::random_from_rng(rng);
        let ct_x = x25519_dalek::PublicKey::from(&ek_x);
        let ss_x = ek_x.diffie_hellman(&self.pk_x);
        let ss = combiner(
            ss_m.as_slice(),
            ss_x.as_bytes(),
            ct_x.as_bytes(),
            self.pk_x.as_bytes(),
        );

        let (key, nonce) = key_schedule(&ss);
        let body = ChaCha20Poly1305::new(Key::from_slice(&key[..]))
            .encrypt(
                Nonce::from_slice(&nonce),
                file_key.expose_secret().as_slice(),
            )
            .expect("sealing 16 bytes cannot exceed the AEAD's limits");

        let mut enc = Vec::with_capacity(ENC_BYTES);
        enc.extend_from_slice(ct_m.as_slice());
        enc.extend_from_slice(ct_x.as_bytes());

        Ok((
            vec![Stanza {
                tag: STANZA_TAG.to_owned(),
                args: vec![STANDARD_NO_PAD.encode(enc)],
                body,
            }],
            std::iter::once(PQ_LABEL.to_owned()).collect(),
        ))
    }
}

/// A post-quantum age identity (`AGE-SECRET-KEY-PQ-1...`).
pub struct HybridIdentity {
    seed: Zeroizing<[u8; 32]>,
    dk_m: MlDk,
    sk_x: x25519_dalek::StaticSecret,
    public: HybridRecipient,
}

impl HybridIdentity {
    fn from_seed(seed: [u8; 32]) -> Self {
        let seed = Zeroizing::new(seed);
        let mut d = [0u8; 32];
        let mut z = [0u8; 32];
        let mut x = [0u8; 32];
        let mut xof = Shake256::default().chain(&seed[..]).finalize_xof();
        xof.read(&mut d);
        xof.read(&mut z);
        xof.read(&mut x);
        let (dk_m, ek_m) = MlKem768::generate_deterministic(&d.into(), &z.into());
        let sk_x = x25519_dalek::StaticSecret::from(x);
        let pk_x = x25519_dalek::PublicKey::from(&sk_x);
        d.zeroize();
        z.zeroize();
        x.zeroize();
        Self {
            seed,
            dk_m,
            sk_x,
            public: HybridRecipient { ek_m, pk_x },
        }
    }

    /// Generates a new identity from the system random source.
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
        let identity = Self::from_seed(seed);
        seed.zeroize();
        identity
    }

    /// Parses an `AGE-SECRET-KEY-PQ-1...` string. Like age, accepts the
    /// all-uppercase form only in the sense bech32 does: mixed case is
    /// rejected.
    pub fn parse(s: &str) -> Option<Self> {
        let (hrp, data) = bech32_decode(s)?;
        if hrp != IDENTITY_HRP {
            return None;
        }
        let seed: [u8; 32] = data.as_slice().try_into().ok()?;
        Some(Self::from_seed(seed))
    }

    /// The `AGE-SECRET-KEY-PQ-1...` string for this identity.
    pub fn encode(&self) -> Zeroizing<String> {
        Zeroizing::new(
            bech32_encode(IDENTITY_HRP, &self.seed[..])
                .expect("a 32-byte seed fits the length cap")
                .to_uppercase(),
        )
    }

    pub fn to_public(&self) -> HybridRecipient {
        self.public.clone()
    }

    /// X-Wing decapsulation. `None` means the encapsulated key is
    /// malformed, which is a bad header and not a wrong key: a ciphertext
    /// of the wrong shape, or an X25519 share that is the identity or a
    /// low-order point and would give an all-zero secret.
    fn decapsulate(&self, enc: &[u8]) -> Option<Zeroizing<[u8; 32]>> {
        if enc.len() != ENC_BYTES {
            return None;
        }
        let (ct_m_bytes, ct_x_bytes) = enc.split_at(MLKEM_CT_BYTES);
        let ct_m = Ciphertext::<MlKem768>::try_from(ct_m_bytes).ok()?;
        let ss_m = self.dk_m.decapsulate(&ct_m).ok()?;
        let ct_x: [u8; 32] = ct_x_bytes.try_into().ok()?;
        let ss_x = self
            .sk_x
            .diffie_hellman(&x25519_dalek::PublicKey::from(ct_x));
        if !ss_x.was_contributory() {
            return None;
        }
        Some(combiner(
            ss_m.as_slice(),
            ss_x.as_bytes(),
            &ct_x,
            self.public.pk_x.as_bytes(),
        ))
    }
}

impl age::Identity for HybridIdentity {
    fn unwrap_stanza(&self, stanza: &Stanza) -> Option<Result<FileKey, DecryptError>> {
        if stanza.tag != STANZA_TAG {
            return None;
        }
        if stanza.args.len() != 1 || stanza.body.len() != FILE_KEY_BYTES + TAG_BYTES {
            return Some(Err(DecryptError::InvalidHeader));
        }
        let enc = match STANDARD_NO_PAD.decode(&stanza.args[0]) {
            Ok(enc) => enc,
            Err(_) => return Some(Err(DecryptError::InvalidHeader)),
        };
        let Some(ss) = self.decapsulate(&enc) else {
            return Some(Err(DecryptError::InvalidHeader));
        };

        let (key, nonce) = key_schedule(&ss);
        // ML-KEM rejects implicitly, so a stanza for someone else's key
        // gets this far and fails here. That is "not for this identity".
        let file_key = Zeroizing::new(
            ChaCha20Poly1305::new(Key::from_slice(&key[..]))
                .decrypt(Nonce::from_slice(&nonce), stanza.body.as_slice())
                .ok()?,
        );
        let bytes: [u8; FILE_KEY_BYTES] = file_key.as_slice().try_into().ok()?;
        Some(Ok(FileKey::new(Box::new(bytes))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::iter;

    /// One upstream test vector: a short header, a blank line, then the
    /// age file.
    struct Vector {
        expect: String,
        payload_sha256: Option<String>,
        identities: Vec<String>,
        armored: bool,
        file: Vec<u8>,
    }

    fn load(name: &str) -> Vector {
        let path = format!(
            "{}/../../fixtures/age-pq/{name}",
            env!("CARGO_MANIFEST_DIR")
        );
        let raw = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
        let split = raw
            .windows(2)
            .position(|w| w == b"\n\n")
            .expect("header ends with a blank line");
        let header = std::str::from_utf8(&raw[..split]).expect("ASCII header");
        let mut v = Vector {
            expect: String::new(),
            payload_sha256: None,
            identities: Vec::new(),
            armored: false,
            file: raw[split + 2..].to_vec(),
        };
        for line in header.lines() {
            let Some((key, value)) = line.split_once(": ") else {
                continue;
            };
            match key {
                "expect" => v.expect = value.to_owned(),
                "payload" => v.payload_sha256 = Some(value.to_owned()),
                "identity" => v.identities.push(value.to_owned()),
                "armored" => v.armored = value == "yes",
                "compressed" => panic!("{name}: store vectors uncompressed"),
                _ => {}
            }
        }
        v
    }

    fn decrypt(v: &Vector) -> Result<Vec<u8>, String> {
        let mut identities: Vec<Box<dyn age::Identity>> = Vec::new();
        for s in &v.identities {
            if let Some(identity) = HybridIdentity::parse(s) {
                identities.push(Box::new(identity));
            } else if let Ok(identity) = s.parse::<age::x25519::Identity>() {
                identities.push(Box::new(identity));
            }
        }
        let reader: Box<dyn Read> = if v.armored {
            Box::new(age::armor::ArmoredReader::new(v.file.as_slice()))
        } else {
            Box::new(v.file.as_slice())
        };
        let decryptor = age::Decryptor::new(reader).map_err(|e| format!("header: {e}"))?;
        let mut payload = decryptor
            .decrypt(identities.iter().map(|i| i.as_ref()))
            .map_err(|e| format!("decrypt: {e}"))?;
        let mut out = Vec::new();
        payload
            .read_to_end(&mut out)
            .map_err(|e| format!("payload: {e}"))?;
        Ok(out)
    }

    fn sha256_hex(data: &[u8]) -> String {
        sha2::Sha256::digest(data)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// Every upstream vector for the `mlkem768x25519` stanza. The ones
    /// marked `success` must decrypt to the recorded payload, the rest
    /// must fail.
    #[test]
    fn upstream_hybrid_vectors() {
        const VECTORS: [&str; 19] = [
            "hybrid",
            "armor_hybrid",
            "hybrid_and_x25519",
            "hybrid_bad_tag",
            "hybrid_currupted_enc_mlkem",
            "hybrid_currupted_enc_x25519",
            "hybrid_extra_argument",
            "hybrid_grease",
            "hybrid_identity",
            "hybrid_long_file_key",
            "hybrid_long_share",
            "hybrid_low_order",
            "hybrid_multiple_recipients",
            "hybrid_no_match",
            "hybrid_not_canonical_body",
            "hybrid_not_canonical_enc",
            "hybrid_short_share",
            "hybrid_uppercase",
            "hybrid_x25519_arg",
        ];
        let mut successes = 0;
        for name in VECTORS {
            let v = load(name);
            let got = decrypt(&v);
            match (v.expect.as_str(), &got) {
                ("success", Ok(payload)) => {
                    assert_eq!(
                        Some(sha256_hex(payload)),
                        v.payload_sha256,
                        "{name}: wrong payload"
                    );
                    successes += 1;
                }
                ("success", Err(e)) => panic!("{name}: should decrypt, got {e}"),
                (other, Ok(_)) => panic!("{name}: expected {other}, but it decrypted"),
                (_, Err(_)) => {}
            }
        }
        assert_eq!(successes, 5);
    }

    #[test]
    fn keys_round_trip_through_their_strings() {
        let identity = HybridIdentity::generate();
        let secret = identity.encode();
        assert!(secret.starts_with("AGE-SECRET-KEY-PQ-1"));
        let recipient = identity.to_public().encode();
        assert!(recipient.starts_with("age1pq1"));
        assert_eq!(recipient.len(), 1959);

        let reparsed = HybridIdentity::parse(&secret).expect("own secret parses");
        assert_eq!(reparsed.to_public().encode(), recipient);
        assert!(HybridRecipient::parse(&recipient).is_some());
    }

    #[test]
    fn rejects_other_key_types_and_damage() {
        let classic = age::x25519::Identity::generate();
        assert!(HybridRecipient::parse(&classic.to_public().to_string()).is_none());
        assert!(HybridIdentity::parse(classic.to_string().expose_secret()).is_none());

        let mut recipient = HybridIdentity::generate().to_public().encode();
        let flipped = if recipient.ends_with('q') { 'p' } else { 'q' };
        recipient.pop();
        recipient.push(flipped);
        assert!(HybridRecipient::parse(&recipient).is_none());
        assert!(HybridRecipient::parse("").is_none());
        assert!(HybridIdentity::parse("AGE-SECRET-KEY-PQ-1").is_none());
    }

    #[test]
    fn encrypts_and_decrypts() {
        let identity = HybridIdentity::generate();
        let recipient = identity.to_public();
        let encryptor =
            age::Encryptor::with_recipients(iter::once(&recipient as &dyn age::Recipient))
                .expect("one recipient");
        let mut ciphertext = Vec::new();
        let mut writer = encryptor.wrap_output(&mut ciphertext).unwrap();
        writer.write_all(b"hunter2\nuser: me\n").unwrap();
        writer.finish().unwrap();

        let decryptor = age::Decryptor::new(ciphertext.as_slice()).unwrap();
        let mut reader = decryptor
            .decrypt(iter::once(&identity as &dyn age::Identity))
            .unwrap();
        let mut plaintext = Vec::new();
        reader.read_to_end(&mut plaintext).unwrap();
        assert_eq!(plaintext, b"hunter2\nuser: me\n");

        let stranger = HybridIdentity::generate();
        let decryptor = age::Decryptor::new(ciphertext.as_slice()).unwrap();
        assert!(matches!(
            decryptor.decrypt(iter::once(&stranger as &dyn age::Identity)),
            Err(DecryptError::NoMatchingKeys)
        ));
    }

    #[test]
    fn age_refuses_to_mix_with_a_classic_recipient() {
        let pq = HybridIdentity::generate().to_public();
        let classic = age::x25519::Identity::generate().to_public();
        let recipients: Vec<&dyn age::Recipient> = vec![&pq, &classic];
        assert!(age::Encryptor::with_recipients(recipients.into_iter()).is_err());
    }
}
