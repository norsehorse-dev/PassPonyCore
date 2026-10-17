//! WebAuthn plumbing for the two passkey providers (2.0 rc3).
//!
//! Everything here is byte building and JSON, written and tested once so
//! the Android and iOS providers cannot drift: authenticator data, the COSE
//! public key, the `none` attestation object, and on Android the request
//! and response JSON that Credential Manager passes around.
//!
//! What is not here: key generation and ES256 signing. Those stay platform
//! side (java.security on Android, CryptoKit on iOS), which import the
//! PKCS#8 key stored in the entry directly. A registration takes the public
//! key's x and y from the platform; an assertion hands the platform the
//! bytes to sign, `authenticator_data || client_data_hash`.
//!
//! Choices from docs/passkeys-format.md: ES256 only, a provider-generated
//! 16-byte credential id, the relying party's user handle stored as given,
//! signature counter 0 (a counter cannot stay monotonic across devices that
//! sync through git), and the app's unlock gate as user verification. The
//! backup-eligible and backup-state flags are set, since every passkey
//! lives in a synced entry.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::entry::Entry;
use crate::passkey::{Passkey, PasskeyError, FIELD_KEY};

/// COSE algorithm id for ES256.
pub const ES256: i64 = -7;
pub const CREDENTIAL_ID_LEN: usize = 16;

const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_BE: u8 = 0x08;
const FLAG_BS: u8 = 0x10;
const FLAG_AT: u8 = 0x40;

/// AAGUID: all zero, which is what an authenticator without attestation
/// reports.
const AAGUID: [u8; 16] = [0; 16];

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WebAuthnError {
    #[error("request JSON is not valid: {0}")]
    BadRequest(String),
    #[error("the relying party doesn't accept ES256 keys")]
    NoSupportedAlgorithm,
    #[error("public key coordinates must be 32 bytes each")]
    BadPublicKey,
    #[error("passkey line: {0}")]
    Passkey(String),
    #[error("no random source: {0}")]
    Random(String),
}

impl From<PasskeyError> for WebAuthnError {
    fn from(e: PasskeyError) -> Self {
        WebAuthnError::Passkey(e.to_string())
    }
}

pub fn new_credential_id() -> Result<Vec<u8>, WebAuthnError> {
    let mut id = vec![0u8; CREDENTIAL_ID_LEN];
    getrandom::fill(&mut id).map_err(|e| WebAuthnError::Random(e.to_string()))?;
    Ok(id)
}

// --- byte builders ----------------------------------------------------------

/// COSE_Key for an EC2 P-256 ES256 public key, in CTAP2 canonical order
/// (kty, alg, crv, x, y).
pub fn cose_es256_key(x: &[u8], y: &[u8]) -> Result<Vec<u8>, WebAuthnError> {
    if x.len() != 32 || y.len() != 32 {
        return Err(WebAuthnError::BadPublicKey);
    }
    let mut out = vec![
        0xa5, // map(5)
        0x01, 0x02, // 1 (kty): 2 (EC2)
        0x03, 0x26, // 3 (alg): -7 (ES256)
        0x20, 0x01, // -1 (crv): 1 (P-256)
        0x21, 0x58, 0x20, // -2 (x): bytes(32)
    ];
    out.extend_from_slice(x);
    out.extend_from_slice(&[0x22, 0x58, 0x20]); // -3 (y): bytes(32)
    out.extend_from_slice(y);
    Ok(out)
}

/// SubjectPublicKeyInfo DER for a P-256 key, which Android's registration
/// response carries as `publicKey`.
pub fn spki_es256(x: &[u8], y: &[u8]) -> Result<Vec<u8>, WebAuthnError> {
    if x.len() != 32 || y.len() != 32 {
        return Err(WebAuthnError::BadPublicKey);
    }
    let mut out = vec![
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
    ];
    out.extend_from_slice(x);
    out.extend_from_slice(y);
    Ok(out)
}

fn flags(user_verified: bool, attested: bool) -> u8 {
    let mut f = FLAG_UP | FLAG_BE | FLAG_BS;
    if user_verified {
        f |= FLAG_UV;
    }
    if attested {
        f |= FLAG_AT;
    }
    f
}

/// Authenticator data: rpIdHash, flags, a zero counter, and for a
/// registration the attested credential data.
pub fn authenticator_data(
    rp_id: &str,
    user_verified: bool,
    attested: Option<(&[u8], &[u8])>,
) -> Vec<u8> {
    let mut out = Sha256::digest(rp_id.as_bytes()).to_vec();
    out.push(flags(user_verified, attested.is_some()));
    out.extend_from_slice(&[0, 0, 0, 0]);
    if let Some((credential_id, cose_key)) = attested {
        out.extend_from_slice(&AAGUID);
        out.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
        out.extend_from_slice(credential_id);
        out.extend_from_slice(cose_key);
    }
    out
}

/// `{"fmt": "none", "attStmt": {}, "authData": <bytes>}` in CTAP2 canonical
/// key order.
pub fn attestation_object_none(auth_data: &[u8]) -> Vec<u8> {
    let mut out = vec![0xa3];
    cbor_text(&mut out, "fmt");
    cbor_text(&mut out, "none");
    cbor_text(&mut out, "attStmt");
    out.push(0xa0);
    cbor_text(&mut out, "authData");
    cbor_bytes(&mut out, auth_data);
    out
}

fn cbor_head(out: &mut Vec<u8>, major: u8, len: usize) {
    let m = major << 5;
    if len < 24 {
        out.push(m | len as u8);
    } else if len < 0x100 {
        out.extend_from_slice(&[m | 24, len as u8]);
    } else if len < 0x10000 {
        out.push(m | 25);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(m | 26);
        out.extend_from_slice(&(len as u32).to_be_bytes());
    }
}

fn cbor_text(out: &mut Vec<u8>, text: &str) {
    cbor_head(out, 3, text.len());
    out.extend_from_slice(text.as_bytes());
}

fn cbor_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    cbor_head(out, 2, bytes.len());
    out.extend_from_slice(bytes);
}

// --- registration and assertion -------------------------------------------

/// A new passkey, ready to store and to answer the relying party with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    /// The entry line value (`passkey: <this>`).
    pub value: String,
    pub credential_id: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub attestation_object: Vec<u8>,
    pub public_key_spki: Vec<u8>,
}

/// Build a registration around a platform-generated P-256 key: `key_pkcs8`
/// is the private key as PKCS#8 DER, `x` and `y` its public coordinates.
#[allow(clippy::too_many_arguments)]
pub fn register(
    rp_id: &str,
    user_handle: &[u8],
    username: &str,
    user_display_name: &str,
    key_pkcs8: &[u8],
    x: &[u8],
    y: &[u8],
    user_verified: bool,
) -> Result<Registration, WebAuthnError> {
    let credential_id = new_credential_id()?;
    register_with_id(
        credential_id,
        rp_id,
        user_handle,
        username,
        user_display_name,
        key_pkcs8,
        x,
        y,
        user_verified,
    )
}

#[allow(clippy::too_many_arguments)]
fn register_with_id(
    credential_id: Vec<u8>,
    rp_id: &str,
    user_handle: &[u8],
    username: &str,
    user_display_name: &str,
    key_pkcs8: &[u8],
    x: &[u8],
    y: &[u8],
    user_verified: bool,
) -> Result<Registration, WebAuthnError> {
    let passkey = Passkey {
        credential_id: credential_id.clone(),
        rp_id: rp_id.to_owned(),
        username: username.to_owned(),
        user_display_name: user_display_name.to_owned(),
        user_handle: user_handle.to_vec(),
        key: key_pkcs8.to_vec(),
        fido2_extensions: None,
    };
    // Round-trip through the reader so nothing unreadable gets stored.
    let value = passkey.to_value();
    Passkey::from_value(&value)?;
    let cose = cose_es256_key(x, y)?;
    let auth_data = authenticator_data(rp_id, user_verified, Some((&credential_id, &cose)));
    Ok(Registration {
        value,
        credential_id,
        attestation_object: attestation_object_none(&auth_data),
        authenticator_data: auth_data,
        public_key_spki: spki_es256(x, y)?,
    })
}

/// What a sign-in needs from a stored passkey. The platform signs
/// `authenticator_data || client_data_hash` with `key_pkcs8` (ES256, DER
/// signature).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assertion {
    pub credential_id: Vec<u8>,
    pub user_handle: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub key_pkcs8: Vec<u8>,
}

pub fn assert(passkey: &Passkey, user_verified: bool) -> Assertion {
    Assertion {
        credential_id: passkey.credential_id.clone(),
        user_handle: passkey.user_handle.clone(),
        authenticator_data: authenticator_data(&passkey.rp_id, user_verified, None),
        key_pkcs8: passkey.key.clone(),
    }
}

/// `authenticator_data || client_data_hash`, the message ES256 signs.
pub fn signed_message(authenticator_data: &[u8], client_data_hash: &[u8]) -> Vec<u8> {
    let mut m = authenticator_data.to_vec();
    m.extend_from_slice(client_data_hash);
    m
}

// --- entries ----------------------------------------------------------------

/// Every readable passkey in an entry, in line order; damaged lines are
/// skipped (they stay in the entry untouched).
pub fn entry_passkeys(entry: &Entry) -> Vec<Passkey> {
    crate::passkey::passkeys(entry)
        .into_iter()
        .filter_map(Result::ok)
        .collect()
}

/// Add a passkey line to an entry. A brand-new entry (empty content) gets an
/// empty password line first, so the passkey never becomes the password.
pub fn entry_add_passkey(entry: &mut Entry, value: &str) {
    if entry.to_bytes().is_empty() {
        *entry = Entry::from_bytes(b"\n".to_vec());
    }
    entry.append_field(FIELD_KEY, value);
}

/// Remove the passkey with `credential_id`; false when the entry has none.
pub fn entry_remove_passkey(entry: &mut Entry, credential_id: &[u8]) -> bool {
    entry.remove_field_where(FIELD_KEY, |v| {
        Passkey::from_value(v).is_ok_and(|p| p.credential_id == credential_id)
    })
}

// --- Android request and response JSON ------------------------------------

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn unb64(text: &str) -> Result<Vec<u8>, WebAuthnError> {
    URL_SAFE_NO_PAD
        .decode(text.trim_end_matches('='))
        .map_err(|_| WebAuthnError::BadRequest("bad base64url".into()))
}

fn str_at<'a>(v: &'a Value, path: &[&str]) -> Option<&'a str> {
    let mut cur = v;
    for p in path {
        cur = cur.get(p)?;
    }
    cur.as_str()
}

fn credential_ids(list: Option<&Value>) -> Result<Vec<Vec<u8>>, WebAuthnError> {
    let Some(items) = list.and_then(Value::as_array) else {
        return Ok(Vec::new());
    };
    items
        .iter()
        .filter_map(|c| c.get("id").and_then(Value::as_str))
        .map(unb64)
        .collect()
}

/// PublicKeyCredentialCreationOptions, as Credential Manager passes them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateOptions {
    pub rp_id: String,
    pub rp_name: String,
    pub user_handle: Vec<u8>,
    pub user_name: String,
    pub user_display_name: String,
    pub exclude_credentials: Vec<Vec<u8>>,
    /// `required`, `preferred` or `discouraged`.
    pub user_verification: String,
}

pub fn parse_create_options(json: &str) -> Result<CreateOptions, WebAuthnError> {
    let v: Value =
        serde_json::from_str(json).map_err(|e| WebAuthnError::BadRequest(e.to_string()))?;
    let rp_id = str_at(&v, &["rp", "id"])
        .filter(|s| !s.is_empty())
        .ok_or_else(|| WebAuthnError::BadRequest("rp.id missing".into()))?
        .to_owned();
    let user_handle = unb64(
        str_at(&v, &["user", "id"])
            .ok_or_else(|| WebAuthnError::BadRequest("user.id missing".into()))?,
    )?;
    if user_handle.is_empty() || user_handle.len() > crate::passkey::MAX_USER_HANDLE {
        return Err(WebAuthnError::BadRequest(
            "user.id must be 1 to 64 bytes".into(),
        ));
    }
    let params = v.get("pubKeyCredParams").and_then(Value::as_array);
    let es256 = params.is_none_or(|ps| {
        ps.iter()
            .any(|p| p.get("alg").and_then(Value::as_i64) == Some(ES256))
    });
    if !es256 {
        return Err(WebAuthnError::NoSupportedAlgorithm);
    }
    Ok(CreateOptions {
        rp_name: str_at(&v, &["rp", "name"]).unwrap_or(&rp_id).to_owned(),
        rp_id,
        user_handle,
        user_name: str_at(&v, &["user", "name"]).unwrap_or("").to_owned(),
        user_display_name: str_at(&v, &["user", "displayName"])
            .unwrap_or("")
            .to_owned(),
        exclude_credentials: credential_ids(v.get("excludeCredentials"))?,
        user_verification: str_at(&v, &["authenticatorSelection", "userVerification"])
            .unwrap_or("preferred")
            .to_owned(),
    })
}

/// PublicKeyCredentialRequestOptions, as Credential Manager passes them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetOptions {
    /// Empty when the request left it out; the caller falls back to the
    /// origin's host.
    pub rp_id: String,
    pub allow_credentials: Vec<Vec<u8>>,
    pub user_verification: String,
}

pub fn parse_get_options(json: &str) -> Result<GetOptions, WebAuthnError> {
    let v: Value =
        serde_json::from_str(json).map_err(|e| WebAuthnError::BadRequest(e.to_string()))?;
    Ok(GetOptions {
        rp_id: str_at(&v, &["rpId"]).unwrap_or("").to_owned(),
        allow_credentials: credential_ids(v.get("allowCredentials"))?,
        user_verification: str_at(&v, &["userVerification"])
            .unwrap_or("preferred")
            .to_owned(),
    })
}

/// When the browser supplies `clientDataHash` it builds clientDataJSON
/// itself and ignores this field; Credential Manager still wants a value.
const CLIENT_DATA_PLACEHOLDER: &[u8] = b"{}";

/// The registration response JSON (a PublicKeyCredential with an
/// AuthenticatorAttestationResponse). `client_data_json` is None when the
/// caller supplied the clientDataHash.
pub fn registration_response_json(reg: &Registration, client_data_json: Option<&[u8]>) -> String {
    let id = b64(&reg.credential_id);
    json!({
        "id": id,
        "rawId": id,
        "type": "public-key",
        "authenticatorAttachment": "platform",
        "response": {
            "clientDataJSON": b64(client_data_json.unwrap_or(CLIENT_DATA_PLACEHOLDER)),
            "attestationObject": b64(&reg.attestation_object),
            "authenticatorData": b64(&reg.authenticator_data),
            "publicKey": b64(&reg.public_key_spki),
            "publicKeyAlgorithm": ES256,
            "transports": ["internal", "hybrid"],
        },
        "clientExtensionResults": { "credProps": { "rk": true } },
    })
    .to_string()
}

/// The sign-in response JSON (a PublicKeyCredential with an
/// AuthenticatorAssertionResponse).
pub fn assertion_response_json(
    assertion: &Assertion,
    signature: &[u8],
    client_data_json: Option<&[u8]>,
) -> String {
    let id = b64(&assertion.credential_id);
    json!({
        "id": id,
        "rawId": id,
        "type": "public-key",
        "authenticatorAttachment": "platform",
        "response": {
            "clientDataJSON": b64(client_data_json.unwrap_or(CLIENT_DATA_PLACEHOLDER)),
            "authenticatorData": b64(&assertion.authenticator_data),
            "signature": b64(signature),
            "userHandle": b64(&assertion.user_handle),
        },
        "clientExtensionResults": {},
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::{Signer, Verifier};
    use p256::ecdsa::{DerSignature, SigningKey, VerifyingKey};
    use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey};

    /// Stands in for the platform: generate a key, export PKCS#8 and x, y.
    fn platform_key() -> (SigningKey, Vec<u8>, Vec<u8>, Vec<u8>) {
        let sk = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let pkcs8 = sk.to_pkcs8_der().unwrap().as_bytes().to_vec();
        let point = sk.verifying_key().to_encoded_point(false);
        (
            sk,
            pkcs8,
            point.x().unwrap().to_vec(),
            point.y().unwrap().to_vec(),
        )
    }

    #[test]
    fn registration_bytes_have_the_webauthn_layout() {
        let (_, pkcs8, x, y) = platform_key();
        let reg = register(
            "webauthn.io",
            b"user-handle",
            "kevin",
            "Kevin",
            &pkcs8,
            &x,
            &y,
            true,
        )
        .unwrap();
        let ad = &reg.authenticator_data;
        assert_eq!(&ad[..32], Sha256::digest(b"webauthn.io").as_slice());
        assert_eq!(ad[32], 0x5d, "UP UV BE BS AT");
        assert_eq!(&ad[33..37], &[0, 0, 0, 0]);
        assert_eq!(&ad[37..53], &[0; 16]);
        assert_eq!(&ad[53..55], &[0, 16]);
        assert_eq!(&ad[55..71], reg.credential_id.as_slice());
        let cose = &ad[71..];
        assert_eq!(cose.len(), 77);
        assert_eq!(
            &cose[..10],
            &[0xa5, 1, 2, 3, 0x26, 0x20, 1, 0x21, 0x58, 0x20]
        );
        assert_eq!(&cose[10..42], x.as_slice());
        assert_eq!(&cose[45..], y.as_slice());

        let att = &reg.attestation_object;
        assert!(att.starts_with(b"\xa3\x63fmt\x64none\x67attStmt\xa0\x68authData\x58"));
        assert_eq!(att[att.len() - ad.len() - 1] as usize, ad.len());
        assert!(att.ends_with(ad));

        // The SPKI is a real P-256 public key for the same point.
        let spki = VerifyingKey::from_sec1_bytes(&reg.public_key_spki[26..]).unwrap();
        assert_eq!(
            spki.to_encoded_point(false).x().unwrap().as_slice(),
            x.as_slice()
        );

        // The stored line reads back as the same credential.
        let back = Passkey::from_value(&reg.value).unwrap();
        assert_eq!(back.credential_id, reg.credential_id);
        assert_eq!(back.rp_id, "webauthn.io");
        assert_eq!(back.user_handle, b"user-handle");
        assert_eq!(back.key, pkcs8);
    }

    #[test]
    fn assertion_signature_verifies_against_the_registered_key() {
        let (_, pkcs8, x, y) = platform_key();
        let reg = register("example.com", b"uh", "u", "", &pkcs8, &x, &y, false).unwrap();
        let passkey = Passkey::from_value(&reg.value).unwrap();
        let a = assert(&passkey, true);
        assert_eq!(a.authenticator_data.len(), 37);
        assert_eq!(a.authenticator_data[32], 0x1d, "UP UV BE BS, no AT");
        assert_eq!(&a.authenticator_data[..32], &reg.authenticator_data[..32]);

        // The platform side: import PKCS#8 and sign authData || clientDataHash.
        let client_data_hash = Sha256::digest(b"{\"type\":\"webauthn.get\"}");
        let message = signed_message(&a.authenticator_data, &client_data_hash);
        let signer = SigningKey::from_pkcs8_der(&a.key_pkcs8).unwrap();
        let sig: DerSignature = signer.sign(&message);

        // The relying party side: verify with the public key from the
        // registration's COSE key.
        let ad = &reg.authenticator_data;
        let mut sec1 = vec![0x04];
        sec1.extend_from_slice(&ad[81..113]);
        sec1.extend_from_slice(&ad[116..148]);
        let vk = VerifyingKey::from_sec1_bytes(&sec1).unwrap();
        vk.verify(&message, &sig).unwrap();

        let json: Value =
            serde_json::from_str(&assertion_response_json(&a, sig.as_bytes(), None)).unwrap();
        assert_eq!(json["type"], "public-key");
        assert_eq!(json["id"], b64(&reg.credential_id));
        assert_eq!(json["response"]["userHandle"], b64(b"uh"));
        assert_eq!(json["response"]["signature"], b64(sig.as_bytes()));
        assert_eq!(json["response"]["clientDataJSON"], "e30");
    }

    #[test]
    fn create_options_parse_like_credential_manager_sends_them() {
        let req = r#"{
          "challenge":"Y2hhbGxlbmdl",
          "rp":{"name":"WebAuthn.io","id":"webauthn.io"},
          "user":{"id":"dXNlcjE","name":"kevin","displayName":"Kevin S"},
          "pubKeyCredParams":[{"type":"public-key","alg":-8},{"type":"public-key","alg":-7}],
          "excludeCredentials":[{"type":"public-key","id":"AQID"}],
          "authenticatorSelection":{"residentKey":"required","userVerification":"required"}
        }"#;
        let o = parse_create_options(req).unwrap();
        assert_eq!(o.rp_id, "webauthn.io");
        assert_eq!(o.rp_name, "WebAuthn.io");
        assert_eq!(o.user_handle, b"user1");
        assert_eq!(o.user_name, "kevin");
        assert_eq!(o.exclude_credentials, vec![vec![1, 2, 3]]);
        assert_eq!(o.user_verification, "required");

        let rsa_only = req.replace("\"alg\":-7", "\"alg\":-257");
        assert_eq!(
            parse_create_options(&rsa_only).unwrap_err(),
            WebAuthnError::NoSupportedAlgorithm
        );
        assert!(parse_create_options("{\"rp\":{}}").is_err());
    }

    #[test]
    fn get_options_parse() {
        let o = parse_get_options(
            r#"{"challenge":"x","rpId":"webauthn.io","allowCredentials":[{"type":"public-key","id":"BAUG"}],"userVerification":"required"}"#,
        )
        .unwrap();
        assert_eq!(o.rp_id, "webauthn.io");
        assert_eq!(o.allow_credentials, vec![vec![4, 5, 6]]);
        assert_eq!(o.user_verification, "required");
        let bare = parse_get_options(r#"{"challenge":"x"}"#).unwrap();
        assert_eq!(bare.rp_id, "");
        assert!(bare.allow_credentials.is_empty());
        assert_eq!(bare.user_verification, "preferred");
    }

    #[test]
    fn registration_json_carries_every_field() {
        let (_, pkcs8, x, y) = platform_key();
        let reg = register("a.example", b"h", "n", "d", &pkcs8, &x, &y, true).unwrap();
        let json: Value = serde_json::from_str(&registration_response_json(&reg, None)).unwrap();
        assert_eq!(json["rawId"], json["id"]);
        assert_eq!(json["response"]["publicKeyAlgorithm"], -7);
        assert_eq!(
            json["response"]["attestationObject"],
            b64(&reg.attestation_object)
        );
        assert_eq!(json["response"]["publicKey"], b64(&reg.public_key_spki));
        assert_eq!(json["clientExtensionResults"]["credProps"]["rk"], true);
    }

    #[test]
    fn entries_hold_several_passkeys_and_lose_one_cleanly() {
        let (_, pkcs8, x, y) = platform_key();
        let one = register("a.example", b"h1", "", "", &pkcs8, &x, &y, true).unwrap();
        let two = register("b.example", b"h2", "", "", &pkcs8, &x, &y, true).unwrap();
        let mut e = Entry::from_bytes(Vec::new());
        entry_add_passkey(&mut e, &one.value);
        entry_add_passkey(&mut e, &two.value);
        assert_eq!(e.password(), b"");
        let found = entry_passkeys(&e);
        assert_eq!(found.len(), 2);
        assert_eq!(found[1].rp_id, "b.example");
        assert!(entry_remove_passkey(&mut e, &one.credential_id));
        assert!(!entry_remove_passkey(&mut e, &one.credential_id));
        assert_eq!(entry_passkeys(&e).len(), 1);
        assert_eq!(
            e.to_bytes(),
            format!("\npasskey: {}\n", two.value).as_bytes()
        );
    }

    #[test]
    fn short_coordinates_are_refused() {
        assert_eq!(
            cose_es256_key(&[0; 31], &[0; 32]).unwrap_err(),
            WebAuthnError::BadPublicKey
        );
    }

    #[test]
    fn cbor_lengths_switch_encoding_at_the_right_sizes() {
        let mut out = Vec::new();
        cbor_bytes(&mut out, &[0; 23]);
        assert_eq!(out[0], 0x57);
        out.clear();
        cbor_bytes(&mut out, &[0; 24]);
        assert_eq!(&out[..2], &[0x58, 24]);
        out.clear();
        cbor_bytes(&mut out, &[0; 300]);
        assert_eq!(&out[..3], &[0x59, 0x01, 0x2c]);
    }
}
