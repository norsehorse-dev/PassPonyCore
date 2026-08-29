//! Passkey line format, the 1.1 design spike (PassPonyAndroid P21). One
//! `passkey:` field per credential, carrying a FIDO Credential Exchange
//! Format (CXF) passkey object as base64url-encoded compact JSON. Behind
//! the `passkey` feature and wired to nothing: no FFI export, no store
//! integration. The format and the go/no-go memo are in
//! `docs/passkeys-format.md`; this module is the proof that the format
//! round-trips and the parser the later release starts from.
//!
//! Why one line and not a block: the entry codec is line-based and
//! byte-faithful, `pass edit` users see one opaque `key: value` line they
//! can leave alone, and a second passkey is simply a second line.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::entry::Entry;

/// The field key on the entry line.
pub const FIELD_KEY: &str = "passkey";
/// CXF's credential type identifier, carried in the object as `type`.
pub const CXF_TYPE: &str = "passkey";
/// WebAuthn user handle bounds (user.id is 1 to 64 bytes).
pub const MAX_USER_HANDLE: usize = 64;

/// A stored WebAuthn credential, field for field the CXF passkey object.
/// `key` is the private key as PKCS#8 DER, exactly what CXF carries and
/// what `java.security.KeyFactory` and CryptoKit import directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Passkey {
    pub credential_id: Vec<u8>,
    pub rp_id: String,
    pub username: String,
    pub user_display_name: String,
    pub user_handle: Vec<u8>,
    pub key: Vec<u8>,
    /// CXF `fido2Extensions`, kept opaque: whatever it holds is stored and
    /// returned untouched.
    pub fido2_extensions: Option<serde_json::Value>,
}

#[derive(Debug, thiserror::Error)]
pub enum PasskeyError {
    #[error("value is not base64url")]
    BadBase64,
    #[error("value is not a CXF passkey object: {0}")]
    BadJson(String),
    #[error("credential type is {0}, not passkey")]
    WrongType(String),
    #[error("{0} is missing or empty")]
    Missing(&'static str),
    #[error("user handle is longer than {MAX_USER_HANDLE} bytes")]
    UserHandleTooLong,
    #[error("key is not PKCS#8 DER")]
    BadKey,
}

/// The JSON shape: CXF's field names verbatim, in a fixed order, bytes as
/// unpadded base64url. Unknown fields are ignored on read and therefore
/// dropped on rewrite; the format doc records that as a known limit.
#[derive(Serialize, Deserialize)]
struct Wire {
    #[serde(rename = "type")]
    kind: String,
    #[serde(rename = "credentialId")]
    credential_id: String,
    #[serde(rename = "rpId")]
    rp_id: String,
    username: String,
    #[serde(rename = "userDisplayName")]
    user_display_name: String,
    #[serde(rename = "userHandle")]
    user_handle: String,
    key: String,
    #[serde(
        rename = "fido2Extensions",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    fido2_extensions: Option<serde_json::Value>,
}

impl Passkey {
    /// The compact CXF JSON object, which is also the CXF export form.
    pub fn to_cxf_json(&self) -> String {
        let wire = Wire {
            kind: CXF_TYPE.to_owned(),
            credential_id: URL_SAFE_NO_PAD.encode(&self.credential_id),
            rp_id: self.rp_id.clone(),
            username: self.username.clone(),
            user_display_name: self.user_display_name.clone(),
            user_handle: URL_SAFE_NO_PAD.encode(&self.user_handle),
            key: URL_SAFE_NO_PAD.encode(&self.key),
            fido2_extensions: self.fido2_extensions.clone(),
        };
        serde_json::to_string(&wire).expect("serializing a plain struct cannot fail")
    }

    /// Parse the CXF JSON object (import form), validating what WebAuthn
    /// needs: the type, a non-empty credential id and rpId, a user handle
    /// of 1 to 64 bytes, and a key that at least starts like DER.
    pub fn from_cxf_json(json: &str) -> Result<Self, PasskeyError> {
        let wire: Wire =
            serde_json::from_str(json).map_err(|e| PasskeyError::BadJson(e.to_string()))?;
        if wire.kind != CXF_TYPE {
            return Err(PasskeyError::WrongType(wire.kind));
        }
        let credential_id = decode(&wire.credential_id)?;
        if credential_id.is_empty() {
            return Err(PasskeyError::Missing("credentialId"));
        }
        if wire.rp_id.is_empty() {
            return Err(PasskeyError::Missing("rpId"));
        }
        let user_handle = decode(&wire.user_handle)?;
        if user_handle.is_empty() {
            return Err(PasskeyError::Missing("userHandle"));
        }
        if user_handle.len() > MAX_USER_HANDLE {
            return Err(PasskeyError::UserHandleTooLong);
        }
        let key = decode(&wire.key)?;
        // PKCS#8 PrivateKeyInfo is a DER SEQUENCE; a real parse is the
        // signer's job on each platform, this only catches the wrong field.
        if key.len() < 2 || key[0] != 0x30 {
            return Err(PasskeyError::BadKey);
        }
        Ok(Passkey {
            credential_id,
            rp_id: wire.rp_id,
            username: wire.username,
            user_display_name: wire.user_display_name,
            user_handle,
            key,
            fido2_extensions: wire.fido2_extensions,
        })
    }

    /// The field value: base64url (unpadded) of [`to_cxf_json`].
    pub fn to_value(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.to_cxf_json())
    }

    /// The whole entry line, ready for `Entry::set_field(FIELD_KEY, ..)`.
    pub fn to_line(&self) -> String {
        format!("{FIELD_KEY}: {}", self.to_value())
    }

    /// Parse a field value as read back from an entry.
    pub fn from_value(value: &str) -> Result<Self, PasskeyError> {
        let json = decode(value.trim())?;
        let json = String::from_utf8(json).map_err(|e| PasskeyError::BadJson(e.to_string()))?;
        Self::from_cxf_json(&json)
    }
}

/// Every `passkey:` field in an entry, in line order. Each line parses on
/// its own, so one damaged line never hides the others.
pub fn passkeys(entry: &Entry) -> Vec<Result<Passkey, PasskeyError>> {
    entry
        .fields()
        .into_iter()
        .filter(|f| f.key == FIELD_KEY)
        .map(|f| Passkey::from_value(f.value))
        .collect()
}

fn decode(text: &str) -> Result<Vec<u8>, PasskeyError> {
    URL_SAFE_NO_PAD
        .decode(text.trim_end_matches('='))
        .map_err(|_| PasskeyError::BadBase64)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stand-in PKCS#8 body: a DER SEQUENCE header and a few bytes. The
    /// spike checks the shape of the field, not the key inside it.
    const FAKE_PKCS8: &[u8] = &[
        0x30, 0x0b, 0x02, 0x01, 0x00, 0x30, 0x06, 0x06, 0x04, 0x2a, 0x86, 0x48, 0xce,
    ];

    fn sample() -> Passkey {
        Passkey {
            credential_id: vec![0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04],
            rp_id: "example.com".to_owned(),
            username: "kevin@example.com".to_owned(),
            user_display_name: "Kevin".to_owned(),
            user_handle: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            key: FAKE_PKCS8.to_vec(),
            fido2_extensions: None,
        }
    }

    #[test]
    fn cxf_json_is_compact_with_cxf_field_names() {
        let json = sample().to_cxf_json();
        assert_eq!(
            json,
            "{\"type\":\"passkey\",\"credentialId\":\"3q2-7wECAwQ\",\"rpId\":\"example.com\",\
             \"username\":\"kevin@example.com\",\"userDisplayName\":\"Kevin\",\
             \"userHandle\":\"AQIDBAUGBwgJCgsMDQ4PEA\",\"key\":\"MAsCAQAwBgYEKoZIzg\"}"
        );
        assert!(!json.contains(' '));
        assert_eq!(Passkey::from_cxf_json(&json).unwrap(), sample());
    }

    #[test]
    fn line_round_trips_byte_identically() {
        let line = sample().to_line();
        assert!(line.starts_with("passkey: "));
        assert!(!line.contains('='), "unpadded base64url only");
        assert!(!line.contains('\n'));
        let value = line.strip_prefix("passkey: ").unwrap();
        let back = Passkey::from_value(value).unwrap();
        assert_eq!(back, sample());
        assert_eq!(back.to_line(), line);
    }

    #[test]
    fn entry_integration_through_the_field_codec() {
        let mut entry = Entry::from_bytes(b"pw\nusername: kevin\nurl: example.com\n".to_vec());
        entry.set_field(FIELD_KEY, &sample().to_value());
        let found = passkeys(&entry);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].as_ref().unwrap(), &sample());
        // The rest of the entry is untouched and still parses.
        assert_eq!(entry.password(), b"pw");
        assert_eq!(entry.fields().len(), 3);
        // A second line is a second credential, in order; a damaged line
        // reports its own error without hiding the good one.
        let mut second = sample();
        second.rp_id = "other.example".to_owned();
        let mut raw = entry.to_bytes().to_vec();
        raw.extend_from_slice(b"passkey: not base64!\n");
        raw.extend_from_slice(second.to_line().as_bytes());
        raw.push(b'\n');
        let entry = Entry::from_bytes(raw);
        let found = passkeys(&entry);
        assert_eq!(found.len(), 3);
        assert!(found[0].is_ok());
        assert!(matches!(found[1], Err(PasskeyError::BadBase64)));
        assert_eq!(found[2].as_ref().unwrap().rp_id, "other.example");
    }

    #[test]
    fn extensions_pass_through_opaquely() {
        let mut with = sample();
        with.fido2_extensions = Some(serde_json::json!({
            "hmacCredentials": {"algorithm": "HS256", "credWithUV": "AAAA"},
            "payments": true
        }));
        let back = Passkey::from_value(&with.to_value()).unwrap();
        assert_eq!(back, with);
        assert!(with.to_cxf_json().contains("\"fido2Extensions\":{"));
        assert!(!sample().to_cxf_json().contains("fido2Extensions"));
    }

    #[test]
    fn rejections() {
        assert!(matches!(
            Passkey::from_value("not base64!"),
            Err(PasskeyError::BadBase64)
        ));
        assert!(matches!(
            Passkey::from_value(&URL_SAFE_NO_PAD.encode("{\"type\":\"passkey\"")),
            Err(PasskeyError::BadJson(_))
        ));
        let mut json = sample().to_cxf_json();
        json = json.replace("\"type\":\"passkey\"", "\"type\":\"totp\"");
        assert!(
            matches!(Passkey::from_cxf_json(&json), Err(PasskeyError::WrongType(t)) if t == "totp")
        );

        let json = sample()
            .to_cxf_json()
            .replace("\"rpId\":\"example.com\"", "\"rpId\":\"\"");
        assert!(matches!(
            Passkey::from_cxf_json(&json),
            Err(PasskeyError::Missing("rpId"))
        ));

        let json = sample()
            .to_cxf_json()
            .replace("\"credentialId\":\"3q2-7wECAwQ\"", "\"credentialId\":\"\"");
        assert!(matches!(
            Passkey::from_cxf_json(&json),
            Err(PasskeyError::Missing("credentialId"))
        ));

        let mut long_handle = sample();
        long_handle.user_handle = vec![7u8; 65];
        assert!(matches!(
            Passkey::from_value(&long_handle.to_value()),
            Err(PasskeyError::UserHandleTooLong)
        ));

        let mut bad_key = sample();
        bad_key.key = vec![0x04, 0x01, 0x02];
        assert!(matches!(
            Passkey::from_value(&bad_key.to_value()),
            Err(PasskeyError::BadKey)
        ));
    }

    #[test]
    fn unknown_fields_are_ignored_on_read() {
        let json = sample()
            .to_cxf_json()
            .replace("\"key\":", "\"note\":\"future field\",\"key\":");
        assert_eq!(Passkey::from_cxf_json(&json).unwrap(), sample());
    }

    #[test]
    fn padded_input_is_tolerated() {
        // A hand-pasted value might carry padding; the writer never emits it.
        let value = format!("{}==", sample().to_value());
        assert_eq!(Passkey::from_value(&value).unwrap(), sample());
    }
}
