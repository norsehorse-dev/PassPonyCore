//! FFI for the 2.0 rc1 core additions: HOTP entries, Google Authenticator
//! export import, age identities merge and detection, and the `.passpony`
//! backup container with its recovery codes. None of this is behind a
//! feature: iOS and Android call the same functions.

use crate::{TotpAlgorithm, TotpError};

// --- HOTP ---------------------------------------------------------------------

/// Which kind of `otpauth://` line an entry or URI carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum OtpKind {
    Totp,
    Hotp,
}

impl From<pass_core::hotp::OtpKind> for OtpKind {
    fn from(k: pass_core::hotp::OtpKind) -> Self {
        match k {
            pass_core::hotp::OtpKind::Totp => OtpKind::Totp,
            pass_core::hotp::OtpKind::Hotp => OtpKind::Hotp,
        }
    }
}

/// The kind of the entry's first `otpauth://` line, if it has one.
#[uniffi::export]
pub fn entry_otp_kind(content: Vec<u8>) -> Option<OtpKind> {
    let entry = pass_core::entry::Entry::from_bytes(content);
    pass_core::hotp::otp_kind(entry.otpauth()?).map(Into::into)
}

/// The kind of a pasted or scanned `otpauth://` URI.
#[uniffi::export]
pub fn otp_uri_kind(uri: String) -> Option<OtpKind> {
    pass_core::hotp::otp_kind(uri.trim()).map(Into::into)
}

/// An HOTP configuration without its secret. `counter` is the last counter
/// used (pass-otp's convention); the next code is computed at counter + 1.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct HotpSummary {
    pub label: String,
    pub issuer: Option<String>,
    pub algorithm: TotpAlgorithm,
    pub digits: u32,
    pub counter: u64,
}

impl From<&pass_core::hotp::Hotp> for HotpSummary {
    fn from(h: &pass_core::hotp::Hotp) -> Self {
        HotpSummary {
            label: h.label.clone(),
            issuer: h.issuer.clone(),
            algorithm: h.algorithm.into(),
            digits: h.digits,
            counter: h.counter,
        }
    }
}

#[uniffi::export]
pub fn entry_hotp_summary(content: Vec<u8>) -> Option<HotpSummary> {
    let entry = pass_core::entry::Entry::from_bytes(content);
    let hotp = pass_core::hotp::Hotp::from_uri(entry.otpauth()?).ok()?;
    Some((&hotp).into())
}

/// Validate a pasted or scanned `otpauth://hotp/` URI and describe it.
#[uniffi::export]
pub fn hotp_describe(uri: String) -> Result<HotpSummary, TotpError> {
    let hotp = pass_core::hotp::Hotp::from_uri(uri.trim())?;
    Ok((&hotp).into())
}

/// Canonical `otpauth://hotp/` URI from the manual form.
#[uniffi::export]
pub fn hotp_build_uri(
    secret: String,
    account: String,
    issuer: Option<String>,
    algorithm: TotpAlgorithm,
    digits: u32,
    counter: u64,
) -> Result<String, TotpError> {
    let hotp = pass_core::hotp::Hotp::new(
        &secret,
        &account,
        issuer.as_deref(),
        algorithm.into(),
        digits,
        counter,
    )?;
    Ok(hotp.to_uri())
}

/// The next HOTP code and the entry rewritten with the advanced counter.
/// The caller writes `content` back, then commits with
/// `commit_message_hotp_increment`, before showing `code`: a code shown
/// before its counter is saved could be shown again.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct HotpAdvance {
    pub code: String,
    pub counter: u64,
    pub content: Vec<u8>,
}

#[uniffi::export]
pub fn entry_hotp_next(content: Vec<u8>) -> Result<HotpAdvance, TotpError> {
    let mut entry = pass_core::entry::Entry::from_bytes(content);
    let step = pass_core::hotp::advance_entry(&mut entry)?;
    Ok(HotpAdvance {
        code: step.code,
        counter: step.counter,
        content: entry.to_bytes().to_vec(),
    })
}

#[uniffi::export]
pub fn commit_message_hotp_increment(name: String) -> String {
    pass_core::git::messages::hotp_increment(&name)
}

#[uniffi::export]
pub fn commit_message_otp_add(name: String) -> String {
    pass_core::git::messages::otp_add(&name)
}

// --- Google Authenticator export ------------------------------------------------

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum MigrationError {
    #[error("not an otpauth-migration:// URI")]
    NotMigrationUri,
    #[error("missing data parameter")]
    MissingData,
    #[error("data is not valid base64")]
    BadBase64,
    #[error("data is not a valid export payload")]
    BadPayload,
}

impl From<pass_core::migration::MigrationError> for MigrationError {
    fn from(e: pass_core::migration::MigrationError) -> Self {
        use pass_core::migration::MigrationError as E;
        match e {
            E::NotMigrationUri => MigrationError::NotMigrationUri,
            E::MissingData => MigrationError::MissingData,
            E::BadBase64 => MigrationError::BadBase64,
            E::BadPayload => MigrationError::BadPayload,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum MigrationSkipReason {
    Md5,
    EmptySecret,
    UnknownAlgorithm,
    UnknownDigits,
    UnknownType,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MigrationAccount {
    pub account: String,
    pub issuer: Option<String>,
    pub kind: OtpKind,
    /// Canonical otpauth line to store; carries the secret.
    pub uri: String,
    pub suggested_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MigrationSkipped {
    pub label: String,
    pub reason: MigrationSkipReason,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MigrationBatch {
    pub accounts: Vec<MigrationAccount>,
    pub skipped: Vec<MigrationSkipped>,
    pub batch_size: u32,
    pub batch_index: u32,
    pub batch_id: i64,
}

/// Parse one Google Authenticator export QR code. A multi-code export
/// shares `batch_id`; the scanner collects indexes 0..batch_size.
#[uniffi::export]
pub fn migration_parse(uri: String) -> Result<MigrationBatch, MigrationError> {
    use pass_core::migration::SkipReason as R;
    let b = pass_core::migration::parse_migration_uri(&uri)?;
    Ok(MigrationBatch {
        accounts: b
            .accounts
            .into_iter()
            .map(|a| MigrationAccount {
                account: a.account,
                issuer: a.issuer,
                kind: a.kind.into(),
                uri: a.uri,
                suggested_name: a.suggested_name,
            })
            .collect(),
        skipped: b
            .skipped
            .into_iter()
            .map(|s| MigrationSkipped {
                label: s.label,
                reason: match s.reason {
                    R::Md5 => MigrationSkipReason::Md5,
                    R::EmptySecret => MigrationSkipReason::EmptySecret,
                    R::UnknownAlgorithm => MigrationSkipReason::UnknownAlgorithm,
                    R::UnknownDigits => MigrationSkipReason::UnknownDigits,
                    R::UnknownType => MigrationSkipReason::UnknownType,
                },
            })
            .collect(),
        batch_size: b.batch_size,
        batch_index: b.batch_index,
        batch_id: b.batch_id,
    })
}

// --- age identities -------------------------------------------------------------

/// True when `data` starts (after whitespace) with an age header, binary or
/// armored: a passphrase-protected identities file. Same rule on both
/// platforms; decrypting is the platform engine's job.
#[uniffi::export]
pub fn age_is_encrypted_identities_file(data: Vec<u8>) -> bool {
    pass_core::identities::is_age_encrypted(&data)
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MergedIdentities {
    pub text: String,
    pub added: u32,
    pub already_present: u32,
}

/// Append the identities in `imported` that `existing` lacks, keeping each
/// one's comment lines. Never removes or reorders an existing identity.
#[uniffi::export]
pub fn identities_merge(existing: String, imported: String) -> MergedIdentities {
    let m = pass_core::identities::merge_identities(&existing, &imported);
    MergedIdentities {
        text: m.text,
        added: m.added,
        already_present: m.already_present,
    }
}

/// One identity in a file, described without its secret.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct IdentityInfo {
    /// From the `# public key:` comment, when the file has one.
    pub public_key_hint: Option<String>,
}

#[uniffi::export]
pub fn identities_describe(text: String) -> Vec<IdentityInfo> {
    pass_core::identities::parse_identities(&text)
        .iter()
        .map(|b| IdentityInfo {
            public_key_hint: b.public_key_hint().map(str::to_owned),
        })
        .collect()
}

// --- backup ---------------------------------------------------------------------

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum BackupError {
    #[error("not a PassPony backup")]
    NotABackup,
    #[error("backup was made by a newer version of PassPony")]
    NewerVersion,
    #[error("backup is truncated or damaged")]
    Damaged,
    #[error("recovery code has the wrong length")]
    CodeLength,
    #[error("recovery code has a character that is not used in codes")]
    CodeCharacter,
    #[error("recovery code has a typo")]
    CodeChecksum,
    #[error("system random source unavailable")]
    RandomUnavailable,
}

impl From<pass_core::backup::BackupError> for BackupError {
    fn from(e: pass_core::backup::BackupError) -> Self {
        use pass_core::backup::BackupError as E;
        match e {
            E::NotABackup => BackupError::NotABackup,
            E::NewerVersion => BackupError::NewerVersion,
            E::Damaged => BackupError::Damaged,
            E::CodeLength => BackupError::CodeLength,
            E::CodeCharacter => BackupError::CodeCharacter,
            E::CodeChecksum => BackupError::CodeChecksum,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct BackupSection {
    /// `backup_kind_age_identities()`, `backup_kind_pgp_secret_key()`, or a
    /// kind from a newer version, which the app should leave alone.
    pub kind: String,
    pub name: String,
    pub data: Vec<u8>,
}

#[uniffi::export]
pub fn backup_kind_age_identities() -> String {
    pass_core::backup::KIND_AGE_IDENTITIES.to_owned()
}

#[uniffi::export]
pub fn backup_kind_pgp_secret_key() -> String {
    pass_core::backup::KIND_PGP_SECRET_KEY.to_owned()
}

/// Container plaintext for a backup; encrypt it with the recovery code
/// (`age_encrypt_with_passphrase` on Android, AgePonyCore on iOS).
#[uniffi::export]
pub fn backup_encode(sections: Vec<BackupSection>) -> Vec<u8> {
    let sections: Vec<pass_core::backup::Section> = sections
        .into_iter()
        .map(|s| pass_core::backup::Section {
            kind: s.kind,
            name: s.name,
            data: s.data,
        })
        .collect();
    pass_core::backup::encode(&sections)
}

#[uniffi::export]
pub fn backup_decode(plaintext: Vec<u8>) -> Result<Vec<BackupSection>, BackupError> {
    Ok(pass_core::backup::decode(&plaintext)?
        .into_iter()
        .map(|s| BackupSection {
            kind: s.kind,
            name: s.name,
            data: s.data,
        })
        .collect())
}

#[uniffi::export]
pub fn backup_generate_recovery_code() -> Result<String, BackupError> {
    pass_core::backup::generate_recovery_code().map_err(|_| BackupError::RandomUnavailable)
}

/// The canonical code (the exact passphrase) for what the user typed, or
/// why it cannot be one. Run before any decrypt so a typo fails instantly.
#[uniffi::export]
pub fn backup_normalize_recovery_code(input: String) -> Result<String, BackupError> {
    Ok(pass_core::backup::normalize_recovery_code(&input)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hotp_over_ffi() {
        let content = b"otpauth://hotp/X?secret=JBSWY3DPEHPK3PXP&counter=0\n".to_vec();
        assert_eq!(entry_otp_kind(content.clone()), Some(OtpKind::Hotp));
        assert_eq!(entry_hotp_summary(content.clone()).unwrap().counter, 0);
        let adv = entry_hotp_next(content).unwrap();
        assert_eq!(adv.counter, 1);
        assert_eq!(
            adv.content,
            b"otpauth://hotp/X?secret=JBSWY3DPEHPK3PXP&counter=1\n"
        );
        assert!(matches!(
            entry_hotp_next(b"pw\n".to_vec()),
            Err(TotpError::NotHotpUri)
        ));
        assert_eq!(
            commit_message_hotp_increment("a/b".into()),
            "Increment HOTP counter for a/b."
        );
        assert!(hotp_describe("otpauth://hotp/X?secret=JBSWY3DPEHPK3PXP".into()).is_err());
    }

    #[test]
    fn backup_over_ffi() {
        let code = backup_generate_recovery_code().unwrap();
        assert_eq!(
            backup_normalize_recovery_code(code.to_lowercase()).unwrap(),
            code
        );
        let sections = vec![BackupSection {
            kind: backup_kind_age_identities(),
            name: String::new(),
            data: b"AGE-SECRET-KEY-1X\n".to_vec(),
        }];
        assert_eq!(
            backup_decode(backup_encode(sections.clone())).unwrap(),
            sections
        );
        assert!(matches!(
            backup_decode(b"x".to_vec()),
            Err(BackupError::NotABackup)
        ));
    }

    #[test]
    fn identities_over_ffi() {
        let m = identities_merge(
            "# public key: age1a\nAGE-SECRET-KEY-1A\n".into(),
            "# public key: age1b\nAGE-SECRET-KEY-1B\n".into(),
        );
        assert_eq!(m.added, 1);
        let info = identities_describe(m.text);
        assert_eq!(info.len(), 2);
        assert_eq!(info[1].public_key_hint.as_deref(), Some("age1b"));
        assert!(age_is_encrypted_identities_file(
            b" age-encryption.org/v1".to_vec()
        ));
    }
}
