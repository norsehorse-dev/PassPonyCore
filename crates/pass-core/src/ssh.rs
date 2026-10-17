//! SSH remotes (2.0 rc2): the app's SSH key, the hosts it trusts, and the
//! remote URL forms that use them.
//!
//! One key per app. It is generated here (Ed25519) or imported from an
//! OpenSSH private key file, decrypted in memory when it has a passphrase,
//! and always handed back unencrypted in OpenSSH format: the apps wrap it
//! with a hardware-backed key at rest, and the git transport gives it to
//! libssh2 from memory, never from a file path.
//!
//! Host keys are trusted on first use. The apps keep a known-hosts file in
//! the OpenSSH format (`host type base64`, `[host]:port` for a port other
//! than 22); this module checks a presented key against it and edits it.
//! An unknown host is reported to the user with its fingerprint; a changed
//! key for a pinned host is a hard failure.

use sha2::{Digest, Sha256};
use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey};
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SshKeyError {
    #[error("this SSH key is protected with a passphrase")]
    NeedsPassphrase,
    #[error("wrong passphrase for this SSH key")]
    WrongPassphrase,
    #[error("this is an older PEM key; convert it with ssh-keygen -p -f <file>")]
    LegacyPem,
    #[error("this is a public key, not a private key")]
    PublicKey,
    #[error("not an OpenSSH private key")]
    NotAKey,
    #[error("unsupported SSH key type: {0}")]
    Unsupported(String),
    #[error("couldn't generate an SSH key: {0}")]
    Random(String),
}

/// The app's SSH key, unencrypted, plus what the UI shows about it.
#[derive(Clone)]
pub struct SshKey {
    /// OpenSSH private key file, unencrypted. Secret.
    pub private_openssh: Zeroizing<String>,
    /// `ssh-ed25519 AAAA… comment`, the line to paste into a git host.
    pub public_openssh: String,
    /// `SHA256:…`, as `ssh-keygen -l` prints it.
    pub fingerprint: String,
    /// `ssh-ed25519`, `ssh-rsa`, `ecdsa-sha2-nistp256`, …
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

fn describe_key(key: &PrivateKey) -> Result<SshKey, SshKeyError> {
    let private = key
        .to_openssh(LineEnding::LF)
        .map_err(|_| SshKeyError::NotAKey)?;
    let public = key.public_key();
    let public_openssh = public.to_openssh().map_err(|_| SshKeyError::NotAKey)?;
    Ok(SshKey {
        private_openssh: Zeroizing::new(private.to_string()),
        public_openssh,
        fingerprint: public.fingerprint(HashAlg::Sha256).to_string(),
        algorithm: key.algorithm().as_str().to_owned(),
        comment: key.comment().to_owned(),
    })
}

/// A new Ed25519 key. `comment` ends up on the public key line, so a git
/// host's key list shows which device it is.
pub fn generate_ed25519(comment: &str) -> Result<SshKey, SshKeyError> {
    let mut key = PrivateKey::random(&mut ssh_key::rand_core::OsRng, Algorithm::Ed25519)
        .map_err(|e| SshKeyError::Random(e.to_string()))?;
    key.set_comment(comment);
    describe_key(&key)
}

/// True for an OpenSSH private key file that needs a passphrase to open.
pub fn is_encrypted(data: &[u8]) -> bool {
    std::str::from_utf8(data)
        .ok()
        .and_then(|t| PrivateKey::from_openssh(t.trim()).ok())
        .is_some_and(|k| k.is_encrypted())
}

/// Read an OpenSSH private key file, decrypting it with `passphrase` when
/// it has one, and return it unencrypted.
pub fn import_private_key(data: &[u8], passphrase: Option<&str>) -> Result<SshKey, SshKeyError> {
    let text = std::str::from_utf8(data).map_err(|_| SshKeyError::NotAKey)?;
    let text = text.trim();
    if text.starts_with("-----BEGIN RSA PRIVATE KEY-----")
        || text.starts_with("-----BEGIN EC PRIVATE KEY-----")
        || text.starts_with("-----BEGIN DSA PRIVATE KEY-----")
        || text.starts_with("-----BEGIN PRIVATE KEY-----")
        || text.starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----")
    {
        return Err(SshKeyError::LegacyPem);
    }
    if text.starts_with("ssh-") || text.starts_with("ecdsa-") || text.starts_with("sk-") {
        return Err(SshKeyError::PublicKey);
    }
    let key = PrivateKey::from_openssh(text).map_err(|_| SshKeyError::NotAKey)?;
    let key = if key.is_encrypted() {
        let Some(pass) = passphrase else {
            return Err(SshKeyError::NeedsPassphrase);
        };
        key.decrypt(pass.as_bytes())
            .map_err(|_| SshKeyError::WrongPassphrase)?
    } else {
        key
    };
    match key.algorithm() {
        Algorithm::Ed25519 | Algorithm::Rsa { .. } | Algorithm::Ecdsa { .. } => {}
        other => return Err(SshKeyError::Unsupported(other.as_str().to_owned())),
    }
    describe_key(&key)
}

// --- remote URLs ------------------------------------------------------------

/// Which transport a remote URL uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteScheme {
    Https,
    Http,
    Ssh,
    File,
    Other,
}

/// `ssh://`, `git+ssh://`, `ssh+git://` and the scp-like `user@host:path`
/// are SSH; libgit2 treats them all the same way.
pub fn remote_scheme(url: &str) -> RemoteScheme {
    let url = url.trim();
    let lower = url.to_ascii_lowercase();
    if lower.starts_with("https://") {
        RemoteScheme::Https
    } else if lower.starts_with("http://") {
        RemoteScheme::Http
    } else if lower.starts_with("ssh://")
        || lower.starts_with("git+ssh://")
        || lower.starts_with("ssh+git://")
    {
        RemoteScheme::Ssh
    } else if lower.starts_with("file://") || url.starts_with('/') {
        RemoteScheme::File
    } else if scp_like(url).is_some() {
        RemoteScheme::Ssh
    } else {
        RemoteScheme::Other
    }
}

/// `user@host:path` with no scheme. The host part must not contain `/`
/// (that would be a relative path with a colon in it).
fn scp_like(url: &str) -> Option<(Option<&str>, &str, &str)> {
    if url.contains("://") {
        return None;
    }
    let (left, path) = url.split_once(':')?;
    if left.is_empty() || left.contains('/') || path.is_empty() {
        return None;
    }
    let (user, host) = match left.rsplit_once('@') {
        Some((u, h)) => (Some(u), h),
        None => (None, left),
    };
    if host.is_empty() {
        return None;
    }
    Some((user, host, path))
}

/// The SSH endpoint of a remote URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshEndpoint {
    pub user: Option<String>,
    pub host: String,
    pub port: u16,
}

impl SshEndpoint {
    /// The host's name in a known-hosts file: `host`, or `[host]:port`
    /// when the port is not 22 (the OpenSSH convention).
    pub fn known_hosts_name(&self) -> String {
        known_hosts_name(&self.host, self.port)
    }
}

pub fn known_hosts_name(host: &str, port: u16) -> String {
    let host = host.to_ascii_lowercase();
    if port == 22 {
        host
    } else {
        format!("[{host}]:{port}")
    }
}

pub fn ssh_endpoint(url: &str) -> Option<SshEndpoint> {
    let url = url.trim();
    if remote_scheme(url) != RemoteScheme::Ssh {
        return None;
    }
    if let Some((user, host, _)) = scp_like(url) {
        let host = host.trim_start_matches('[').trim_end_matches(']');
        return Some(SshEndpoint {
            user: user.map(str::to_owned),
            host: host.to_owned(),
            port: 22,
        });
    }
    let rest = url.split_once("://")?.1;
    let authority = rest.split('/').next()?;
    let (user, hostport) = match authority.rsplit_once('@') {
        Some((u, h)) => (Some(u.split(':').next().unwrap_or(u).to_owned()), h),
        None => (None, authority),
    };
    let (host, port) = if let Some(stripped) = hostport.strip_prefix('[') {
        let (h, after) = stripped.split_once(']')?;
        let port = match after.strip_prefix(':') {
            Some(p) => p.parse().ok()?,
            None => 22,
        };
        (h.to_owned(), port)
    } else {
        match hostport.rsplit_once(':') {
            Some((h, p)) if !p.is_empty() => (h.to_owned(), p.parse().ok()?),
            Some((h, _)) => (h.to_owned(), 22),
            None => (hostport.to_owned(), 22),
        }
    };
    if host.is_empty() {
        return None;
    }
    Some(SshEndpoint { user, host, port })
}

// --- known hosts ------------------------------------------------------------

/// A host key as the transport presents it: the SSH wire blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostKey {
    pub key_type: String,
    /// Standard base64 of the wire blob, as written in known_hosts.
    pub key_base64: String,
    /// `SHA256:…` without padding, as `ssh-keygen -l` and git hosts show it.
    pub fingerprint: String,
}

impl HostKey {
    /// From the raw wire blob; the key type is its first field.
    pub fn from_blob(blob: &[u8]) -> Option<Self> {
        let len = u32::from_be_bytes(blob.get(..4)?.try_into().ok()?) as usize;
        let key_type = std::str::from_utf8(blob.get(4..4 + len)?).ok()?.to_owned();
        if key_type.is_empty() {
            return None;
        }
        Some(HostKey {
            key_type,
            key_base64: base64_encode(blob, true),
            fingerprint: fingerprint_of_blob(blob),
        })
    }

    fn from_line_fields(key_type: &str, b64: &str) -> Option<Self> {
        let blob = base64_decode(b64)?;
        let parsed = HostKey::from_blob(&blob)?;
        (parsed.key_type == key_type).then_some(parsed)
    }
}

pub fn fingerprint_of_blob(blob: &[u8]) -> String {
    format!("SHA256:{}", base64_encode(&Sha256::digest(blob), false))
}

/// One pinned host, for the Settings list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownHost {
    /// `host` or `[host]:port`.
    pub host: String,
    pub key: HostKey,
}

/// What a presented host key means against the known-hosts file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostCheck {
    Trusted,
    /// No key of this type is pinned for the host yet.
    Unknown,
    /// A different key of the same type is pinned: refuse.
    Changed {
        pinned_fingerprint: String,
    },
}

/// Entries this module understands. Comments, markers (`@revoked`,
/// `@cert-authority`), hashed hosts and malformed lines are skipped; they
/// are kept verbatim when the file is edited.
pub fn known_hosts_list(text: &str) -> Vec<KnownHost> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('@') {
            continue;
        }
        let mut fields = line.split_whitespace();
        let (Some(hosts), Some(key_type), Some(b64)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let Some(key) = HostKey::from_line_fields(key_type, b64) else {
            continue;
        };
        for host in hosts.split(',') {
            if host.starts_with('|') || host.is_empty() {
                continue;
            }
            out.push(KnownHost {
                host: host.to_ascii_lowercase(),
                key: key.clone(),
            });
        }
    }
    out
}

pub fn known_hosts_check(text: &str, host_name: &str, presented: &HostKey) -> HostCheck {
    let host_name = host_name.to_ascii_lowercase();
    let pinned: Vec<KnownHost> = known_hosts_list(text)
        .into_iter()
        .filter(|k| k.host == host_name && k.key.key_type == presented.key_type)
        .collect();
    if pinned.is_empty() {
        HostCheck::Unknown
    } else if pinned
        .iter()
        .any(|k| k.key.key_base64 == presented.key_base64)
    {
        HostCheck::Trusted
    } else {
        HostCheck::Changed {
            pinned_fingerprint: pinned[0].key.fingerprint.clone(),
        }
    }
}

/// Pin `key` for `host_name`, replacing any key of the same type already
/// pinned for that host. Other lines are kept as they are.
pub fn known_hosts_add(text: &str, host_name: &str, key: &HostKey) -> String {
    let host_name = host_name.to_ascii_lowercase();
    let mut out = remove_lines(text, |h, t| h == host_name && t == key.key_type);
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(&format!(
        "{host_name} {} {}\n",
        key.key_type, key.key_base64
    ));
    out
}

/// Forget every key pinned for `host_name`.
pub fn known_hosts_remove(text: &str, host_name: &str) -> String {
    let host_name = host_name.to_ascii_lowercase();
    remove_lines(text, |h, _| h == host_name)
}

/// Drop single-host lines matching `drop(host, key_type)`; a line naming
/// several hosts loses only the matching name.
fn remove_lines(text: &str, drop: impl Fn(&str, &str) -> bool) -> String {
    let mut out = String::new();
    for line in text.lines() {
        let trimmed = line.trim();
        let mut fields = trimmed.split_whitespace();
        let parsed = if trimmed.starts_with('#') || trimmed.starts_with('@') {
            None
        } else {
            match (fields.next(), fields.next()) {
                (Some(hosts), Some(key_type)) => Some((hosts, key_type)),
                _ => None,
            }
        };
        let Some((hosts, key_type)) = parsed else {
            if !line.is_empty() {
                out.push_str(line);
                out.push('\n');
            }
            continue;
        };
        let names: Vec<&str> = hosts.split(',').collect();
        let kept: Vec<&str> = names
            .iter()
            .copied()
            .filter(|h| !drop(&h.to_ascii_lowercase(), key_type))
            .collect();
        if kept.len() == names.len() {
            out.push_str(line);
            out.push('\n');
        } else if !kept.is_empty() {
            let rest: Vec<&str> = trimmed.split_whitespace().skip(1).collect();
            out.push_str(&format!("{} {}\n", kept.join(","), rest.join(" ")));
        }
    }
    out
}

// --- base64 -----------------------------------------------------------------

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(data: &[u8], pad: bool) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let chars = [(n >> 18) & 63, (n >> 12) & 63, (n >> 6) & 63, n & 63];
        for (i, c) in chars.iter().enumerate() {
            if i <= chunk.len() {
                out.push(B64[*c as usize] as char);
            } else if pad {
                out.push('=');
            }
        }
    }
    out
}

fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let text = text.trim_end_matches('=');
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let mut acc = 0u32;
    let mut bits = 0;
    for c in text.bytes() {
        let v = B64.iter().position(|&b| b == c)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_key_round_trips_through_import() {
        let key = generate_ed25519("passpony@test").unwrap();
        assert_eq!(key.algorithm, "ssh-ed25519");
        assert!(key.public_openssh.starts_with("ssh-ed25519 "));
        assert!(key.public_openssh.ends_with(" passpony@test"));
        assert!(key.fingerprint.starts_with("SHA256:"));
        assert!(key
            .private_openssh
            .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));
        let again = import_private_key(key.private_openssh.as_bytes(), None).unwrap();
        assert_eq!(again.public_openssh, key.public_openssh);
        assert_eq!(again.fingerprint, key.fingerprint);
        assert!(!is_encrypted(key.private_openssh.as_bytes()));
    }

    fn fixture(name: &str) -> Vec<u8> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/ssh")
            .join(name);
        std::fs::read(path).unwrap()
    }

    #[test]
    fn imports_ssh_keygen_keys_with_and_without_passphrases() {
        for (name, algorithm) in [
            ("ed25519-protected", "ssh-ed25519"),
            ("rsa-protected", "ssh-rsa"),
            ("ecdsa-plain", "ecdsa-sha2-nistp256"),
        ] {
            let private = fixture(name);
            let public = String::from_utf8(fixture(&format!("{name}.pub"))).unwrap();
            let protected = name.ends_with("-protected");
            assert_eq!(is_encrypted(&private), protected, "{name}");
            if protected {
                assert_eq!(
                    import_private_key(&private, None).unwrap_err(),
                    SshKeyError::NeedsPassphrase
                );
                assert_eq!(
                    import_private_key(&private, Some("wrong")).unwrap_err(),
                    SshKeyError::WrongPassphrase
                );
            }
            let key = import_private_key(&private, protected.then_some("pony ssh test")).unwrap();
            assert_eq!(key.algorithm, algorithm, "{name}");
            assert_eq!(key.public_openssh, public.trim(), "{name}");
            assert!(!is_encrypted(key.private_openssh.as_bytes()), "{name}");
            let again = import_private_key(key.private_openssh.as_bytes(), None).unwrap();
            assert_eq!(again.fingerprint, key.fingerprint, "{name}");
        }
        assert_eq!(
            import_private_key(&fixture("rsa-legacy-pem"), None).unwrap_err(),
            SshKeyError::LegacyPem
        );
    }

    #[test]
    fn legacy_and_public_keys_are_explained() {
        assert_eq!(
            import_private_key(b"-----BEGIN RSA PRIVATE KEY-----\nabc\n", None).unwrap_err(),
            SshKeyError::LegacyPem
        );
        assert_eq!(
            import_private_key(b"ssh-ed25519 AAAAC3Nza me", None).unwrap_err(),
            SshKeyError::PublicKey
        );
        assert_eq!(
            import_private_key(b"hello", None).unwrap_err(),
            SshKeyError::NotAKey
        );
    }

    #[test]
    fn url_forms() {
        use RemoteScheme::*;
        assert_eq!(remote_scheme("https://github.com/a/b.git"), Https);
        assert_eq!(remote_scheme("git@github.com:a/b.git"), Ssh);
        assert_eq!(remote_scheme("ssh://git@host:2222/srv/store.git"), Ssh);
        assert_eq!(remote_scheme("git+ssh://host/x"), Ssh);
        assert_eq!(remote_scheme("/srv/store.git"), File);
        assert_eq!(remote_scheme("./a:b"), Other);
        assert_eq!(
            ssh_endpoint("git@github.com:a/b.git").unwrap(),
            SshEndpoint {
                user: Some("git".into()),
                host: "github.com".into(),
                port: 22
            }
        );
        let e = ssh_endpoint("ssh://git@Host.example:2222/srv/store.git").unwrap();
        assert_eq!((e.host.as_str(), e.port), ("Host.example", 2222));
        assert_eq!(e.known_hosts_name(), "[host.example]:2222");
        let e = ssh_endpoint("ssh://[::1]:2200/x").unwrap();
        assert_eq!((e.host.as_str(), e.port, e.user), ("::1", 2200, None));
        assert_eq!(
            ssh_endpoint("ssh://host/x").unwrap().known_hosts_name(),
            "host"
        );
        assert!(ssh_endpoint("https://host/x").is_none());
    }

    fn host_key() -> HostKey {
        let key = generate_ed25519("").unwrap();
        let b64 = key
            .public_openssh
            .split_whitespace()
            .nth(1)
            .unwrap()
            .to_owned();
        HostKey::from_blob(&base64_decode(&b64).unwrap()).unwrap()
    }

    #[test]
    fn host_key_fingerprint_matches_ssh_keygen_format() {
        let key = generate_ed25519("").unwrap();
        let b64 = key.public_openssh.split_whitespace().nth(1).unwrap();
        let hk = HostKey::from_blob(&base64_decode(b64).unwrap()).unwrap();
        assert_eq!(hk.key_type, "ssh-ed25519");
        assert_eq!(hk.key_base64, b64);
        assert_eq!(hk.fingerprint, key.fingerprint);
    }

    #[test]
    fn trust_on_first_use_then_pinned_then_changed() {
        let a = host_key();
        let b = host_key();
        let mut text =
            "# my hosts\n|1|hashed= ssh-ed25519 AAAA\nother ssh-rsa AAAAB3NzaC1yc2E=\n".to_string();
        assert_eq!(known_hosts_check(&text, "[h]:2222", &a), HostCheck::Unknown);
        text = known_hosts_add(&text, "[H]:2222", &a);
        assert!(text.starts_with("# my hosts\n|1|hashed="));
        assert_eq!(known_hosts_check(&text, "[h]:2222", &a), HostCheck::Trusted);
        assert_eq!(known_hosts_check(&text, "h", &a), HostCheck::Unknown);
        assert_eq!(
            known_hosts_check(&text, "[h]:2222", &b),
            HostCheck::Changed {
                pinned_fingerprint: a.fingerprint.clone()
            }
        );
        let pinned = |t: &str| {
            known_hosts_list(t)
                .into_iter()
                .filter(|k| k.host == "[h]:2222")
                .count()
        };
        let hosts: Vec<String> = known_hosts_list(&text)
            .into_iter()
            .map(|k| k.host)
            .collect();
        assert_eq!(hosts, ["other", "[h]:2222"]);
        let replaced = known_hosts_add(&text, "[h]:2222", &b);
        assert_eq!(
            known_hosts_check(&replaced, "[h]:2222", &b),
            HostCheck::Trusted
        );
        assert_eq!(pinned(&replaced), 1);
        let forgotten = known_hosts_remove(&replaced, "[h]:2222");
        assert_eq!(
            known_hosts_check(&forgotten, "[h]:2222", &b),
            HostCheck::Unknown
        );
        assert!(forgotten.contains("# my hosts"));
        assert!(forgotten.contains("other ssh-rsa"));
    }

    #[test]
    fn removing_one_name_from_a_shared_line_keeps_the_others() {
        let a = host_key();
        let text = format!("x,y {} {}\n", a.key_type, a.key_base64);
        let out = known_hosts_remove(&text, "x");
        assert_eq!(out, format!("y {} {}\n", a.key_type, a.key_base64));
    }

    #[test]
    fn base64_round_trip() {
        for n in 0..10 {
            let data: Vec<u8> = (0..n).map(|i| (i * 37) as u8).collect();
            assert_eq!(base64_decode(&base64_encode(&data, true)).unwrap(), data);
        }
        assert_eq!(base64_encode(b"hi", true), "aGk=");
        assert_eq!(base64_encode(b"hi", false), "aGk");
    }
}
