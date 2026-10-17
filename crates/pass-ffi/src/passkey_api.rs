//! Passkeys (2.0 rc3): the FFI surface over `pass_core::passkey` and
//! `pass_core::webauthn`. Key generation and ES256 signing stay platform
//! side; everything here is byte building, JSON, and entry editing.

use pass_core::entry::Entry;
use pass_core::passkey::Passkey;
use pass_core::webauthn;

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum PasskeyError {
    #[error("request JSON is not valid: {reason}")]
    BadRequest { reason: String },
    #[error("the relying party doesn't accept ES256 keys")]
    NoSupportedAlgorithm,
    #[error("public key coordinates must be 32 bytes each")]
    BadPublicKey,
    #[error("passkey line: {reason}")]
    BadPasskey { reason: String },
    #[error("no random source: {reason}")]
    Random { reason: String },
}

impl From<webauthn::WebAuthnError> for PasskeyError {
    fn from(e: webauthn::WebAuthnError) -> Self {
        use webauthn::WebAuthnError as E;
        match e {
            E::BadRequest(reason) => PasskeyError::BadRequest { reason },
            E::NoSupportedAlgorithm => PasskeyError::NoSupportedAlgorithm,
            E::BadPublicKey => PasskeyError::BadPublicKey,
            E::Passkey(reason) => PasskeyError::BadPasskey { reason },
            E::Random(reason) => PasskeyError::Random { reason },
        }
    }
}

/// A stored passkey without its private key, for lists and the entry view.
#[derive(Debug, Clone, uniffi::Record)]
pub struct PasskeyInfo {
    /// The entry line value; pass it to `passkey_assert`.
    pub value: String,
    pub credential_id: Vec<u8>,
    pub rp_id: String,
    pub username: String,
    pub user_display_name: String,
    pub user_handle: Vec<u8>,
}

fn info(p: &Passkey) -> PasskeyInfo {
    PasskeyInfo {
        value: p.to_value(),
        credential_id: p.credential_id.clone(),
        rp_id: p.rp_id.clone(),
        username: p.username.clone(),
        user_display_name: p.user_display_name.clone(),
        user_handle: p.user_handle.clone(),
    }
}

/// Every readable passkey in decrypted entry content, in line order.
#[uniffi::export]
pub fn entry_passkeys(content: Vec<u8>) -> Vec<PasskeyInfo> {
    webauthn::entry_passkeys(&Entry::from_bytes(content))
        .iter()
        .map(info)
        .collect()
}

/// Content with one more passkey line. Empty content becomes a new entry
/// with an empty password line first.
#[uniffi::export]
pub fn entry_add_passkey(content: Vec<u8>, value: String) -> Vec<u8> {
    let mut entry = Entry::from_bytes(content);
    webauthn::entry_add_passkey(&mut entry, &value);
    entry.to_bytes().to_vec()
}

/// Content without the passkey `credential_id`; unchanged when absent.
#[uniffi::export]
pub fn entry_remove_passkey(content: Vec<u8>, credential_id: Vec<u8>) -> Vec<u8> {
    let mut entry = Entry::from_bytes(content);
    webauthn::entry_remove_passkey(&mut entry, &credential_id);
    entry.to_bytes().to_vec()
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct PasskeyRegistration {
    /// Store as `passkey: <value>` with `entry_add_passkey`.
    pub value: String,
    pub credential_id: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub attestation_object: Vec<u8>,
    pub public_key_spki: Vec<u8>,
}

/// A new passkey around a platform-generated P-256 key: `key_pkcs8` is
/// the private key as PKCS#8 DER, `x` and `y` the public coordinates.
#[allow(clippy::too_many_arguments)]
#[uniffi::export]
pub fn passkey_register(
    rp_id: String,
    user_handle: Vec<u8>,
    username: String,
    user_display_name: String,
    key_pkcs8: Vec<u8>,
    x: Vec<u8>,
    y: Vec<u8>,
    user_verified: bool,
) -> Result<PasskeyRegistration, PasskeyError> {
    let r = webauthn::register(
        &rp_id,
        &user_handle,
        &username,
        &user_display_name,
        &key_pkcs8,
        &x,
        &y,
        user_verified,
    )?;
    Ok(PasskeyRegistration {
        value: r.value,
        credential_id: r.credential_id,
        authenticator_data: r.authenticator_data,
        attestation_object: r.attestation_object,
        public_key_spki: r.public_key_spki,
    })
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct PasskeyAssertion {
    pub credential_id: Vec<u8>,
    pub user_handle: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    /// Sign `passkey_signed_message(authenticator_data, client_data_hash)`
    /// with this key (ES256), then drop it.
    pub key_pkcs8: Vec<u8>,
}

#[uniffi::export]
pub fn passkey_assert(
    value: String,
    user_verified: bool,
) -> Result<PasskeyAssertion, PasskeyError> {
    let p = Passkey::from_value(&value).map_err(|e| PasskeyError::BadPasskey {
        reason: e.to_string(),
    })?;
    let a = webauthn::assert(&p, user_verified);
    Ok(PasskeyAssertion {
        credential_id: a.credential_id,
        user_handle: a.user_handle,
        authenticator_data: a.authenticator_data,
        key_pkcs8: a.key_pkcs8,
    })
}

#[uniffi::export]
pub fn passkey_signed_message(authenticator_data: Vec<u8>, client_data_hash: Vec<u8>) -> Vec<u8> {
    webauthn::signed_message(&authenticator_data, &client_data_hash)
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct WebAuthnCreateOptions {
    pub rp_id: String,
    pub rp_name: String,
    pub user_handle: Vec<u8>,
    pub user_name: String,
    pub user_display_name: String,
    pub exclude_credentials: Vec<Vec<u8>>,
    pub user_verification: String,
}

#[uniffi::export]
pub fn webauthn_parse_create_options(json: String) -> Result<WebAuthnCreateOptions, PasskeyError> {
    let o = webauthn::parse_create_options(&json)?;
    Ok(WebAuthnCreateOptions {
        rp_id: o.rp_id,
        rp_name: o.rp_name,
        user_handle: o.user_handle,
        user_name: o.user_name,
        user_display_name: o.user_display_name,
        exclude_credentials: o.exclude_credentials,
        user_verification: o.user_verification,
    })
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct WebAuthnGetOptions {
    /// Empty when the request left it out: use the origin's host.
    pub rp_id: String,
    pub allow_credentials: Vec<Vec<u8>>,
    pub user_verification: String,
}

#[uniffi::export]
pub fn webauthn_parse_get_options(json: String) -> Result<WebAuthnGetOptions, PasskeyError> {
    let o = webauthn::parse_get_options(&json)?;
    Ok(WebAuthnGetOptions {
        rp_id: o.rp_id,
        allow_credentials: o.allow_credentials,
        user_verification: o.user_verification,
    })
}

/// Android's registration response JSON. `client_data_json` is None when
/// the caller (a browser) supplied the clientDataHash.
#[uniffi::export]
pub fn webauthn_registration_json(
    registration: PasskeyRegistration,
    client_data_json: Option<Vec<u8>>,
) -> String {
    let r = webauthn::Registration {
        value: registration.value,
        credential_id: registration.credential_id,
        authenticator_data: registration.authenticator_data,
        attestation_object: registration.attestation_object,
        public_key_spki: registration.public_key_spki,
    };
    webauthn::registration_response_json(&r, client_data_json.as_deref())
}

/// Android's sign-in response JSON.
#[uniffi::export]
pub fn webauthn_assertion_json(
    credential_id: Vec<u8>,
    user_handle: Vec<u8>,
    authenticator_data: Vec<u8>,
    signature: Vec<u8>,
    client_data_json: Option<Vec<u8>>,
) -> String {
    let a = webauthn::Assertion {
        credential_id,
        user_handle,
        authenticator_data,
        key_pkcs8: Vec::new(),
    };
    webauthn::assertion_response_json(&a, &signature, client_data_json.as_deref())
}

#[uniffi::export]
pub fn commit_message_passkey_add(name: String) -> String {
    pass_core::git::messages::passkey_add(&name)
}

#[uniffi::export]
pub fn commit_message_passkey_remove(name: String) -> String {
    pass_core::git::messages::passkey_remove(&name)
}
