//! SSH remotes (2.0 rc2): the app's SSH key and the hosts it trusts. See
//! `pass_core::ssh` for the rules; this is the FFI surface over it.

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum SshKeyError {
    #[error("this SSH key is protected with a passphrase")]
    NeedsPassphrase,
    #[error("wrong passphrase for this SSH key")]
    WrongPassphrase,
    #[error("older PEM key; convert with ssh-keygen -p -f <file>")]
    LegacyPem,
    #[error("public key, not a private key")]
    PublicKey,
    #[error("not an OpenSSH private key")]
    NotAKey,
    #[error("unsupported SSH key type: {algorithm}")]
    Unsupported { algorithm: String },
    #[error("couldn't generate an SSH key: {reason}")]
    Random { reason: String },
}

impl From<pass_core::ssh::SshKeyError> for SshKeyError {
    fn from(e: pass_core::ssh::SshKeyError) -> Self {
        use pass_core::ssh::SshKeyError as E;
        match e {
            E::NeedsPassphrase => SshKeyError::NeedsPassphrase,
            E::WrongPassphrase => SshKeyError::WrongPassphrase,
            E::LegacyPem => SshKeyError::LegacyPem,
            E::PublicKey => SshKeyError::PublicKey,
            E::NotAKey => SshKeyError::NotAKey,
            E::Unsupported(algorithm) => SshKeyError::Unsupported { algorithm },
            E::Random(reason) => SshKeyError::Random { reason },
        }
    }
}

/// The app's SSH key. `private_key` is unencrypted OpenSSH text: store it
/// wrapped with a hardware-backed key, never in plain files or logs.
#[derive(Clone, uniffi::Record)]
pub struct SshKey {
    pub private_key: String,
    /// `ssh-ed25519 AAAA… comment`, for pasting into a git host.
    pub public_key: String,
    /// `SHA256:…`
    pub fingerprint: String,
    pub algorithm: String,
    pub comment: String,
}

impl std::fmt::Debug for SshKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshKey")
            .field("algorithm", &self.algorithm)
            .field("fingerprint", &self.fingerprint)
            .finish_non_exhaustive()
    }
}

impl From<pass_core::ssh::SshKey> for SshKey {
    fn from(k: pass_core::ssh::SshKey) -> Self {
        SshKey {
            private_key: k.private_openssh.to_string(),
            public_key: k.public_openssh,
            fingerprint: k.fingerprint,
            algorithm: k.algorithm,
            comment: k.comment,
        }
    }
}

/// A new Ed25519 key; `comment` goes on the public key line.
#[uniffi::export]
pub fn ssh_generate_key(comment: String) -> Result<SshKey, SshKeyError> {
    Ok(pass_core::ssh::generate_ed25519(&comment)?.into())
}

/// Read an OpenSSH private key file (or the app's stored key, to show its
/// public half). `NeedsPassphrase` means ask and call again.
#[uniffi::export]
pub fn ssh_import_key(data: Vec<u8>, passphrase: Option<String>) -> Result<SshKey, SshKeyError> {
    Ok(pass_core::ssh::import_private_key(&data, passphrase.as_deref())?.into())
}

#[uniffi::export]
pub fn ssh_key_is_encrypted(data: Vec<u8>) -> bool {
    pass_core::ssh::is_encrypted(&data)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum RemoteScheme {
    Https,
    Http,
    Ssh,
    File,
    Other,
}

impl From<pass_core::ssh::RemoteScheme> for RemoteScheme {
    fn from(s: pass_core::ssh::RemoteScheme) -> Self {
        use pass_core::ssh::RemoteScheme as S;
        match s {
            S::Https => RemoteScheme::Https,
            S::Http => RemoteScheme::Http,
            S::Ssh => RemoteScheme::Ssh,
            S::File => RemoteScheme::File,
            S::Other => RemoteScheme::Other,
        }
    }
}

/// `https://…`, `ssh://…`, `git@host:path`, …
#[uniffi::export]
pub fn remote_scheme(url: String) -> RemoteScheme {
    pass_core::ssh::remote_scheme(&url).into()
}

/// The name an SSH remote's host has in known_hosts (`host`, or
/// `[host]:port` off port 22); None for other remotes.
#[uniffi::export]
pub fn ssh_known_hosts_name(url: String) -> Option<String> {
    pass_core::ssh::ssh_endpoint(&url).map(|e| e.known_hosts_name())
}

/// A host key as presented by a server or pinned in known_hosts.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct HostKey {
    pub key_type: String,
    pub key_base64: String,
    /// `SHA256:…`, to show the user.
    pub fingerprint: String,
}

impl From<pass_core::ssh::HostKey> for HostKey {
    fn from(k: pass_core::ssh::HostKey) -> Self {
        HostKey {
            key_type: k.key_type,
            key_base64: k.key_base64,
            fingerprint: k.fingerprint,
        }
    }
}

impl From<HostKey> for pass_core::ssh::HostKey {
    fn from(k: HostKey) -> Self {
        pass_core::ssh::HostKey {
            key_type: k.key_type,
            key_base64: k.key_base64,
            fingerprint: k.fingerprint,
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct KnownHost {
    pub host: String,
    pub key: HostKey,
}

#[uniffi::export]
pub fn known_hosts_list(text: String) -> Vec<KnownHost> {
    pass_core::ssh::known_hosts_list(&text)
        .into_iter()
        .map(|k| KnownHost {
            host: k.host,
            key: k.key.into(),
        })
        .collect()
}

/// Pin `key` for `host` (from `GitError::UnknownHostKey`); returns the new
/// file text to save.
#[uniffi::export]
pub fn known_hosts_add(text: String, host: String, key: HostKey) -> String {
    pass_core::ssh::known_hosts_add(&text, &host, &key.into())
}

/// Forget every key pinned for `host`; returns the new file text.
#[uniffi::export]
pub fn known_hosts_remove(text: String, host: String) -> String {
    pass_core::ssh::known_hosts_remove(&text, &host)
}

#[uniffi::export]
pub fn backup_kind_ssh_private_key() -> String {
    pass_core::backup::KIND_SSH_PRIVATE_KEY.to_owned()
}
