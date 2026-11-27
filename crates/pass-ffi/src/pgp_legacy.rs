//! Public-key steps rpgp parses but does not perform: ElGamal, and ECDH
//! over the brainpool curves (P256r1, P384r1, P512r1).
//!
//! Old GnuPG defaults (DSA or RSA with an ElGamal subkey) and brainpool
//! keys are still what some long-lived pass stores are encrypted to, and
//! PassPony Android opened them before it moved to this engine. rpgp reads
//! these keys and their session-key packets but has no arithmetic for
//! them, so the engine does that one step here and hands rpgp the session
//! key (decrypt) or the finished session-key packet body (encrypt).
//! Everything else, the message format, the symmetric layer and its
//! integrity check, stays rpgp's.
//!
//! This is big-integer arithmetic written for PassPony, not an audited
//! library, and it is not constant-time. It runs on the device that holds
//! the key, on entries from the person's own store. THREAT_MODEL.md says
//! so. Every path is tested both ways against GnuPG.

use num_bigint_dig::{BigUint, ModInverse, RandBigInt};
use num_traits::{One, Zero};
use pgp::composed::PlainSessionKey;
use pgp::crypto::aes_kw;
use pgp::crypto::ecc_curve::ECCCurve;
use pgp::crypto::ecdh;
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::ser::Serialize;
use pgp::types::{
    EcdhPublicParams, EskType, KeyDetails, Mpi, PkeskBytes, PlainSecretParams, PublicParams,
    SecretParams,
};
use zeroize::Zeroizing;

/// True when this is a key type handled here and not by rpgp.
pub(crate) fn is_legacy(params: &PublicParams) -> bool {
    match params {
        PublicParams::Elgamal(_) => true,
        PublicParams::ECDH(p) => brainpool(p).is_some(),
        _ => false,
    }
}

/// The session key a PKESK holds, when `public` / `secret` are one of the
/// key types handled here and the packet was made for that key. `None`
/// for every other key type and for anything that does not check out;
/// the caller then has no session key from this key, which reads as "no
/// usable key" like any other mismatch.
pub(crate) fn session_key(
    values: &PkeskBytes,
    public: &PublicParams,
    secret: &SecretParams,
    fingerprint: &[u8],
) -> Option<PlainSessionKey> {
    let SecretParams::Plain(secret) = secret else {
        return None;
    };
    let plain = match (values, public, secret) {
        (
            PkeskBytes::Elgamal { first, second },
            PublicParams::Elgamal(params),
            PlainSecretParams::Elgamal(key),
        ) => {
            let (p, _, _) = elgamal_public(params)?;
            elgamal_decrypt(&p, key.as_bytes(), first.as_ref(), second.as_ref())?
        }
        (
            PkeskBytes::Ecdh {
                public_point,
                encrypted_session_key,
            },
            PublicParams::ECDH(params),
            PlainSecretParams::ECDH(key),
        ) => {
            let (curve, _, hash, alg_sym) = brainpool(params)?;
            let d = Zeroizing::new(key.to_bytes());
            let shared = curve.shared_secret(&d, public_point.as_ref())?;
            ecdh::derive_session_key(
                &shared,
                encrypted_session_key,
                encrypted_session_key.len(),
                params.curve(),
                hash,
                alg_sym,
                fingerprint,
            )
            .ok()?
        }
        _ => return None,
    };
    v3_session_key(&plain)
}

/// The body of a v3 PKESK for `plain` (algorithm octet, session key,
/// checksum), encrypted to a key type handled here.
pub(crate) fn encrypt<R: rand::CryptoRng + rand::Rng>(
    rng: &mut R,
    public: &PublicParams,
    fingerprint: &[u8],
    plain: &[u8],
) -> Option<PkeskBytes> {
    match public {
        PublicParams::Elgamal(params) => {
            let (p, g, y) = elgamal_public(params)?;
            let (first, second) = elgamal_encrypt(rng, &p, &g, &y, plain)?;
            Some(PkeskBytes::Elgamal {
                first: Mpi::from_slice(&first),
                second: Mpi::from_slice(&second),
            })
        }
        PublicParams::ECDH(params) => {
            let (curve, point, hash, alg_sym) = brainpool(params)?;
            // RFC 9580 9.5: these never go into an ECDH KDF.
            if matches!(
                hash,
                HashAlgorithm::Md5 | HashAlgorithm::Sha1 | HashAlgorithm::Ripemd160
            ) {
                return None;
            }
            let (ephemeral, shared) = curve.ephemeral(rng, point.as_ref())?;
            let param = ecdh::build_ecdh_param(&params.curve().oid(), alg_sym, hash, fingerprint);
            let kek = Zeroizing::new(ecdh::kdf(hash, &shared, alg_sym.key_size(), &param).ok()?);
            let wrapped = aes_kw::wrap(&kek, &pad_to_eight(plain)).ok()?;
            Some(PkeskBytes::Ecdh {
                public_point: Mpi::from_slice(&ephemeral),
                encrypted_session_key: wrapped.into(),
            })
        }
        _ => None,
    }
}

/// A recipient key of a type handled here, so rpgp's message builder can
/// encrypt to it like any other key: it asks for the PKESK body and this
/// supplies it.
#[derive(Debug)]
pub(crate) struct LegacyRecipient<'a, K: KeyDetails>(pub(crate) &'a K);

impl<K: KeyDetails> KeyDetails for LegacyRecipient<'_, K> {
    fn version(&self) -> pgp::types::KeyVersion {
        self.0.version()
    }
    fn legacy_key_id(&self) -> pgp::types::KeyId {
        self.0.legacy_key_id()
    }
    fn fingerprint(&self) -> pgp::types::Fingerprint {
        self.0.fingerprint()
    }
    fn algorithm(&self) -> pgp::crypto::public_key::PublicKeyAlgorithm {
        self.0.algorithm()
    }
    fn created_at(&self) -> pgp::types::Timestamp {
        self.0.created_at()
    }
    fn legacy_v3_expiration_days(&self) -> Option<u16> {
        self.0.legacy_v3_expiration_days()
    }
    fn public_params(&self) -> &PublicParams {
        self.0.public_params()
    }
}

impl<K: KeyDetails> pgp::types::EncryptionKey for LegacyRecipient<'_, K> {
    fn encrypt<R: rand::CryptoRng + rand::Rng>(
        &self,
        mut rng: R,
        plain: &[u8],
        typ: EskType,
    ) -> pgp::errors::Result<PkeskBytes> {
        // These are v4 keys; a v6 PKESK is never made for them.
        if !matches!(typ, EskType::V3_4) {
            return Err(pgp::errors::Error::PacketTooLarge { size: 0 });
        }
        encrypt(
            &mut rng,
            self.0.public_params(),
            self.0.fingerprint().as_bytes(),
            plain,
        )
        // The engine reports every encrypt failure the same way, so the
        // variant only has to be an error.
        .ok_or(pgp::errors::Error::PacketTooLarge { size: 0 })
    }
}

/// `algorithm || key || checksum`, as carried by a v3 PKESK.
fn v3_session_key(plain: &[u8]) -> Option<PlainSessionKey> {
    let (&alg, rest) = plain.split_first()?;
    let sym_alg = SymmetricKeyAlgorithm::from(alg);
    if sym_alg == SymmetricKeyAlgorithm::Plaintext || rest.len() != sym_alg.key_size() + 2 {
        return None;
    }
    let (key, checksum) = rest.split_at(rest.len() - 2);
    let sum = key
        .iter()
        .fold(0u16, |acc, b| acc.wrapping_add(u16::from(*b)));
    if sum.to_be_bytes() != [checksum[0], checksum[1]] {
        return None;
    }
    Some(PlainSessionKey::V3_4 {
        sym_alg,
        key: key.into(),
    })
}

/// Padding to a multiple of eight, each byte the padding length (RFC 9580
/// 11.5). Always at least one byte.
fn pad_to_eight(plain: &[u8]) -> Zeroizing<Vec<u8>> {
    let padding = 8 - plain.len() % 8;
    let mut out = Zeroizing::new(plain.to_vec());
    out.resize(plain.len() + padding, padding as u8);
    out
}

// --- ElGamal ---------------------------------------------------------------

/// p, g and y. rpgp keeps them private, so they are read back from the
/// key's own serialization: three MPIs.
fn elgamal_public(params: &pgp::types::ElgamalPublicParams) -> Option<(BigUint, BigUint, BigUint)> {
    let mut bytes = Vec::new();
    params.to_writer(&mut bytes).ok()?;
    let mut rest = bytes.as_slice();
    let mut next = || -> Option<BigUint> {
        let (head, tail) = rest.split_first_chunk::<2>()?;
        let len = usize::from(u16::from_be_bytes(*head)).div_ceil(8);
        if tail.len() < len {
            return None;
        }
        let (value, tail) = tail.split_at(len);
        rest = tail;
        Some(BigUint::from_bytes_be(value))
    };
    let (p, g, y) = (next()?, next()?, next()?);
    // A modulus this small is not a key anyone made on purpose.
    if p.bits() < 1024 || g < BigUint::from(2u8) || g >= p || y.is_zero() || y >= p {
        return None;
    }
    Some((p, g, y))
}

fn elgamal_decrypt(
    p: &BigUint,
    x: &[u8],
    first: &[u8],
    second: &[u8],
) -> Option<Zeroizing<Vec<u8>>> {
    let c1 = BigUint::from_bytes_be(first);
    let c2 = BigUint::from_bytes_be(second);
    if c1.is_zero() || c1 >= *p || c2.is_zero() || c2 >= *p {
        return None;
    }
    let x = BigUint::from_bytes_be(x);
    let shared = c1.modpow(&x, p);
    let inverse = shared.mod_inverse(p)?.to_biguint()?;
    let m = (c2 * inverse) % p;

    // EME-PKCS1-v1_5: 00 02, at least eight non-zero bytes, 00, message.
    let k = p.bits().div_ceil(8);
    let raw = Zeroizing::new(m.to_bytes_be());
    if raw.len() > k {
        return None;
    }
    let mut em = Zeroizing::new(vec![0u8; k - raw.len()]);
    em.extend_from_slice(&raw);
    if em.len() < 11 || em[0] != 0 || em[1] != 2 {
        return None;
    }
    let separator = em[2..].iter().position(|b| *b == 0)? + 2;
    if separator < 10 {
        return None;
    }
    Some(Zeroizing::new(em[separator + 1..].to_vec()))
}

fn elgamal_encrypt<R: rand::CryptoRng + rand::Rng>(
    rng: &mut R,
    p: &BigUint,
    g: &BigUint,
    y: &BigUint,
    plain: &[u8],
) -> Option<(Vec<u8>, Vec<u8>)> {
    let k = p.bits().div_ceil(8);
    if plain.len() + 11 > k {
        return None;
    }
    let mut em = Zeroizing::new(vec![0u8; k]);
    em[1] = 2;
    let pad_end = k - plain.len() - 1;
    for byte in &mut em[2..pad_end] {
        while *byte == 0 {
            *byte = rng.gen();
        }
    }
    em[pad_end + 1..].copy_from_slice(plain);
    let m = BigUint::from_bytes_be(&em);

    let one = BigUint::one();
    let exponent = rng.gen_biguint_range(&BigUint::from(2u8), &(p - &one));
    let first = g.modpow(&exponent, p);
    let second = (m * y.modpow(&exponent, p)) % p;
    Some((first.to_bytes_be(), second.to_bytes_be()))
}

// --- brainpool ECDH -----------------------------------------------------------

/// The curve, the recipient's public point, and the KDF parameters, for a
/// brainpool key. `None` for every other curve.
fn brainpool(
    params: &EcdhPublicParams,
) -> Option<(Curve, &Mpi, HashAlgorithm, SymmetricKeyAlgorithm)> {
    let (hex, p, hash, alg_sym) = match params {
        EcdhPublicParams::Brainpool256 { p, hash, alg_sym } => (&BP256, p, hash, alg_sym),
        EcdhPublicParams::Brainpool384 { p, hash, alg_sym } => (&BP384, p, hash, alg_sym),
        EcdhPublicParams::Brainpool512 { p, hash, alg_sym } => (&BP512, p, hash, alg_sym),
        _ => return None,
    };
    debug_assert!(matches!(
        params.curve(),
        ECCCurve::BrainpoolP256r1 | ECCCurve::BrainpoolP384r1 | ECCCurve::BrainpoolP512r1
    ));
    Some((Curve::from_hex(hex), p, *hash, *alg_sym))
}

/// RFC 5639 domain parameters, as hex.
struct CurveHex {
    size: usize,
    p: &'static str,
    a: &'static str,
    b: &'static str,
    gx: &'static str,
    gy: &'static str,
    n: &'static str,
}

const BP256: CurveHex = CurveHex {
    size: 32,
    p: "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377",
    a: "7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9",
    b: "26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6",
    gx: "8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262",
    gy: "547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997",
    n: "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7",
};

const BP384: CurveHex = CurveHex {
    size: 48,
    p: "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53",
    a: "7bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f90f8aa5814a503ad4eb04a8c7dd22ce2826",
    b: "04a8c7dd22ce28268b39b55416f0447c2fb77de107dcd2a62e880ea53eeb62d57cb4390295dbc9943ab78696fa504c11",
    gx: "1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e",
    gy: "8abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff99129280e4646217791811142820341263c5315",
    n: "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565",
};

const BP512: CurveHex = CurveHex {
    size: 64,
    p: "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3",
    a: "7830a3318b603b89e2327145ac234cc594cbdd8d3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94ca",
    b: "3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94cadc083e67984050b75ebae5dd2809bd638016f723",
    gx: "81aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098eff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f822",
    gy: "7dde385d566332ecc0eabfa9cf7822fdf209f70024a57b1aa000c55b881f8111b2dcde494a5f485e5bca4bd88a2763aed1ca2b2fa8f0540678cd1e0f3ad80892",
    n: "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069",
};

/// A short Weierstrass curve y^2 = x^3 + ax + b over a prime field, with
/// cofactor 1 (true of every brainpool curve).
struct Curve {
    size: usize,
    p: BigUint,
    a: BigUint,
    b: BigUint,
    g: (BigUint, BigUint),
    n: BigUint,
}

/// A point in affine coordinates; `None` is the point at infinity.
type Point = Option<(BigUint, BigUint)>;

impl Curve {
    fn from_hex(hex: &CurveHex) -> Self {
        let n = |s: &str| BigUint::parse_bytes(s.as_bytes(), 16).expect("curve constant");
        Curve {
            size: hex.size,
            p: n(hex.p),
            a: n(hex.a),
            b: n(hex.b),
            g: (n(hex.gx), n(hex.gy)),
            n: n(hex.n),
        }
    }

    fn sub(&self, x: &BigUint, y: &BigUint) -> BigUint {
        ((x + &self.p) - (y % &self.p)) % &self.p
    }

    fn on_curve(&self, x: &BigUint, y: &BigUint) -> bool {
        if x >= &self.p || y >= &self.p {
            return false;
        }
        let left = (y * y) % &self.p;
        let right = (x * x * x + &self.a * x + &self.b) % &self.p;
        left == right
    }

    fn add(&self, lhs: &Point, rhs: &Point) -> Point {
        let (Some((x1, y1)), Some((x2, y2))) = (lhs, rhs) else {
            return lhs.clone().or_else(|| rhs.clone());
        };
        let slope = if x1 == x2 {
            if ((y1 + y2) % &self.p).is_zero() {
                return None;
            }
            let numerator = (BigUint::from(3u8) * x1 * x1 + &self.a) % &self.p;
            let denominator = (BigUint::from(2u8) * y1) % &self.p;
            (numerator * denominator.mod_inverse(&self.p)?.to_biguint()?) % &self.p
        } else {
            let numerator = self.sub(y2, y1);
            let denominator = self.sub(x2, x1);
            (numerator * denominator.mod_inverse(&self.p)?.to_biguint()?) % &self.p
        };
        let x3 = self.sub(&self.sub(&((&slope * &slope) % &self.p), x1), x2);
        let y3 = self.sub(&((&slope * self.sub(x1, &x3)) % &self.p), y1);
        Some((x3, y3))
    }

    fn multiply(&self, scalar: &BigUint, point: &Point) -> Point {
        let mut result: Point = None;
        for i in (0..scalar.bits()).rev() {
            result = self.add(&result, &result);
            if (scalar >> i) & BigUint::one() == BigUint::one() {
                result = self.add(&result, point);
            }
        }
        result
    }

    /// `04 || X || Y`, checked to be a point on this curve.
    fn decode(&self, sec1: &[u8]) -> Option<(BigUint, BigUint)> {
        if sec1.len() != 1 + 2 * self.size || sec1[0] != 0x04 {
            return None;
        }
        let x = BigUint::from_bytes_be(&sec1[1..=self.size]);
        let y = BigUint::from_bytes_be(&sec1[1 + self.size..]);
        self.on_curve(&x, &y).then_some((x, y))
    }

    fn fixed(&self, value: &BigUint) -> Vec<u8> {
        let raw = value.to_bytes_be();
        let mut out = vec![0u8; self.size.saturating_sub(raw.len())];
        out.extend_from_slice(&raw);
        out
    }

    /// The x coordinate of `d * peer`, as the field-sized shared secret.
    fn shared_secret(&self, d: &[u8], peer: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        let peer = self.decode(peer)?;
        let d = BigUint::from_bytes_be(d);
        if d.is_zero() || d >= self.n {
            return None;
        }
        let (x, _) = self.multiply(&d, &Some(peer))?;
        Some(Zeroizing::new(self.fixed(&x)))
    }

    /// A fresh ephemeral key for `peer`: its public point and the shared
    /// secret.
    fn ephemeral<R: rand::CryptoRng + rand::Rng>(
        &self,
        rng: &mut R,
        peer: &[u8],
    ) -> Option<(Vec<u8>, Zeroizing<Vec<u8>>)> {
        let peer = self.decode(peer)?;
        let r = rng.gen_biguint_range(&BigUint::one(), &self.n);
        let (vx, vy) = self.multiply(&r, &Some(self.g.clone()))?;
        let (sx, _) = self.multiply(&r, &Some(peer))?;
        let mut public = vec![0x04];
        public.extend_from_slice(&self.fixed(&vx));
        public.extend_from_slice(&self.fixed(&vy));
        Some((public, Zeroizing::new(self.fixed(&sx))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn brainpool_generators_are_on_their_curves_and_have_the_stated_order() {
        for hex in [&BP256, &BP384, &BP512] {
            let curve = Curve::from_hex(hex);
            assert!(curve.on_curve(&curve.g.0, &curve.g.1));
            assert_eq!(curve.multiply(&curve.n, &Some(curve.g.clone())), None);
            let almost = &curve.n - BigUint::one();
            let (x, _) = curve.multiply(&almost, &Some(curve.g.clone())).unwrap();
            assert_eq!(x, curve.g.0);
        }
    }

    #[test]
    fn brainpool_two_sides_agree() {
        let mut rng = rand::thread_rng();
        for hex in [&BP256, &BP384, &BP512] {
            let curve = Curve::from_hex(hex);
            let d = rng.gen_biguint_range(&BigUint::one(), &curve.n);
            let (qx, qy) = curve.multiply(&d, &Some(curve.g.clone())).unwrap();
            let mut q = vec![0x04];
            q.extend_from_slice(&curve.fixed(&qx));
            q.extend_from_slice(&curve.fixed(&qy));
            let (ephemeral, theirs) = curve.ephemeral(&mut rng, &q).unwrap();
            let ours = curve.shared_secret(&d.to_bytes_be(), &ephemeral).unwrap();
            assert_eq!(*ours, *theirs);
        }
    }

    #[test]
    fn a_point_off_the_curve_is_refused() {
        let curve = Curve::from_hex(&BP256);
        let mut q = vec![0x04];
        q.extend_from_slice(&curve.fixed(&curve.g.0));
        q.extend_from_slice(&curve.fixed(&(&curve.g.1 + BigUint::one())));
        assert!(curve.shared_secret(&[1], &q).is_none());
        assert!(curve.shared_secret(&[1], &q[..10]).is_none());
    }

    #[test]
    fn elgamal_round_trip_and_bad_padding() {
        // RFC 3526 group 5 (1536-bit MODP), generator 2.
        let p = BigUint::parse_bytes(
            b"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF",
            16,
        )
        .unwrap();
        let g = BigUint::from(2u8);
        let mut rng = rand::thread_rng();
        let x = rng.gen_biguint_range(&BigUint::from(2u8), &(&p - BigUint::one()));
        let y = g.modpow(&x, &p);
        let plain = [
            9u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 0, 136,
        ];
        let (first, second) = elgamal_encrypt(&mut rng, &p, &g, &y, &plain).unwrap();
        let back = elgamal_decrypt(&p, &x.to_bytes_be(), &first, &second).unwrap();
        assert_eq!(*back, plain);
        // A different second value does not unpad to a message.
        let wrong = (BigUint::from_bytes_be(&second) + BigUint::one()).to_bytes_be();
        assert!(elgamal_decrypt(&p, &x.to_bytes_be(), &first, &wrong)
            .map(|m| *m != plain)
            .unwrap_or(true));
        assert!(elgamal_decrypt(&p, &x.to_bytes_be(), &[0], &second).is_none());
    }
}
