//! Dev-only crypto backends that shell out to the real CLIs. The point is
//! parity testing: when comparing our read path against golden outputs, the
//! decryption step should be the same one the reference CLI used. These are
//! never part of any shipped app (desktop 1.0 uses sequoia-openpgp and the
//! age crate in-process; mobile uses the platform engines).

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use pass_core::crypto::{CryptoBackend, CryptoError, Recipient};
use zeroize::Zeroizing;

fn run_filter(mut cmd: Command, input: &[u8]) -> Result<Vec<u8>, String> {
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| e.to_string())?;
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(input)
        .map_err(|e| e.to_string())?;
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(out.stdout)
    } else {
        Err(String::from_utf8_lossy(&out.stderr).into_owned())
    }
}

/// Shells out to `age`. Decryption uses the identities file, exactly as
/// passage does (`age -d -i identities`).
pub struct AgeCliBackend {
    pub identities_file: PathBuf,
    /// Recipients file for encryption, when resolution produced one
    /// (`age -R`); with `None`, encryption falls back to `-i identities`,
    /// mirroring passage's identities-fallback branch.
    pub recipients_file: Option<PathBuf>,
}

impl CryptoBackend for AgeCliBackend {
    fn encrypt(&self, plaintext: &[u8], recipients: &[Recipient]) -> Result<Vec<u8>, CryptoError> {
        let mut cmd = Command::new("age");
        cmd.arg("-e");
        if let Some(rf) = &self.recipients_file {
            cmd.arg("-R").arg(rf);
        } else if !recipients.is_empty() {
            for r in recipients {
                cmd.arg("-r").arg(r);
            }
        } else {
            cmd.arg("-i").arg(&self.identities_file);
        }
        run_filter(cmd, plaintext).map_err(|_| CryptoError::EncryptionFailed)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let mut cmd = Command::new("age");
        cmd.arg("-d").arg("-i").arg(&self.identities_file);
        run_filter(cmd, ciphertext)
            .map(Zeroizing::new)
            .map_err(|_| CryptoError::DecryptionFailed)
    }
}

/// Shells out to `gpg`, batch mode. Point `gnupghome` at a keyring holding
/// the fixture test keys.
pub struct GpgCliBackend {
    pub gnupghome: Option<PathBuf>,
}

impl GpgCliBackend {
    fn base(&self) -> Command {
        let mut cmd = Command::new("gpg");
        cmd.arg("--quiet").arg("--batch").arg("--yes");
        if let Some(home) = &self.gnupghome {
            cmd.env("GNUPGHOME", home);
        }
        cmd
    }
}

impl CryptoBackend for GpgCliBackend {
    fn encrypt(&self, plaintext: &[u8], recipients: &[Recipient]) -> Result<Vec<u8>, CryptoError> {
        if recipients.is_empty() {
            return Err(CryptoError::NoUsableKey);
        }
        let mut cmd = self.base();
        cmd.arg("--encrypt").arg("--trust-model").arg("always");
        for r in recipients {
            cmd.arg("-r").arg(r);
        }
        run_filter(cmd, plaintext).map_err(|_| CryptoError::EncryptionFailed)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let mut cmd = self.base();
        cmd.arg("--decrypt");
        run_filter(cmd, ciphertext)
            .map(Zeroizing::new)
            .map_err(|_| CryptoError::DecryptionFailed)
    }
}
