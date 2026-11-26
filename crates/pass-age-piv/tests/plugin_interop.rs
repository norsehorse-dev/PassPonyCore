//! Interop with the real age-plugin-yubikey, in both directions that need
//! no YubiKey: the plugin wraps for a software P-256 key (it never needs
//! the card to encrypt), and this crate's unwrap must open the result;
//! and a file this crate wraps must decrypt through the same unwrap via
//! the age crate's own header handling. Skipped, loudly, when `age` or
//! `age-plugin-yubikey` is not on PATH.

use std::io::{Read, Write};
use std::process::{Command, Stdio};

use age::secrecy::ExposeSecret;
use age_core::format::{FileKey, Stanza};
use p256::elliptic_curve::rand_core::OsRng;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use pass_age_piv::{PivRecipient, PivStanza, STANZA_TAG};

/// A software stand-in for the YubiKey: does the card's ECDH in memory.
struct SoftCard {
    sk: SecretKey,
    recipient: PivRecipient,
}

impl SoftCard {
    fn new() -> Self {
        let sk = SecretKey::random(&mut OsRng);
        let recipient =
            PivRecipient::from_compressed(sk.public_key().to_encoded_point(true).as_bytes())
                .unwrap();
        SoftCard { sk, recipient }
    }
}

impl age::Identity for SoftCard {
    fn unwrap_stanza(&self, stanza: &Stanza) -> Option<Result<FileKey, age::DecryptError>> {
        if stanza.tag != STANZA_TAG {
            return None;
        }
        let parsed = PivStanza::parse(&stanza.args, &stanza.body)?;
        if !parsed.is_for(&self.recipient) {
            return None;
        }
        let epk = PublicKey::from_sec1_bytes(&parsed.ephemeral_uncompressed()).unwrap();
        let shared = p256::ecdh::diffie_hellman(self.sk.to_nonzero_scalar(), epk.as_affine());
        Some(
            parsed
                .unwrap(&self.recipient, shared.raw_secret_bytes())
                .map(|fk| FileKey::new(Box::new(*fk)))
                .ok_or(age::DecryptError::DecryptionFailed),
        )
    }
}

struct Wrapper(PivRecipient);

impl age::Recipient for Wrapper {
    fn wrap_file_key(
        &self,
        file_key: &FileKey,
    ) -> Result<(Vec<Stanza>, std::collections::HashSet<String>), age::EncryptError> {
        let s = self.0.wrap(file_key.expose_secret());
        Ok((
            vec![Stanza {
                tag: STANZA_TAG.to_owned(),
                args: s.args(),
                body: s.body(),
            }],
            Default::default(),
        ))
    }
}

fn decrypt(card: &SoftCard, ciphertext: &[u8]) -> Vec<u8> {
    let d = age::Decryptor::new(ciphertext).unwrap();
    let mut r = d
        .decrypt(std::iter::once(card as &dyn age::Identity))
        .unwrap();
    let mut out = vec![];
    r.read_to_end(&mut out).unwrap();
    out
}

fn on_path(bin: &str) -> bool {
    Command::new("sh")
        .args(["-c", &format!("command -v {bin}")])
        .stdout(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[test]
fn plugin_wraps_and_we_unwrap() {
    if !(on_path("age") && on_path("age-plugin-yubikey")) {
        eprintln!("SKIPPED: age and age-plugin-yubikey must both be on PATH");
        return;
    }
    let card = SoftCard::new();
    let recipient = card.recipient.to_string();
    let plaintext = b"hunter2\nuser: deeplakes\n";

    let mut child = Command::new("age")
        .args(["-e", "-r", &recipient])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(plaintext).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "age -r {recipient} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let header = String::from_utf8_lossy(&out.stdout[..out.stdout.len().min(200)]).into_owned();
    assert!(header.contains("-> piv-p256 "), "header: {header}");

    assert_eq!(decrypt(&card, &out.stdout), plaintext);
}

#[test]
fn we_wrap_and_age_unwraps() {
    let card = SoftCard::new();
    let plaintext = b"correct horse battery staple";
    let other = age::x25519::Identity::generate().to_public();
    let recipients: Vec<Box<dyn age::Recipient>> =
        vec![Box::new(Wrapper(card.recipient.clone())), Box::new(other)];
    let e = age::Encryptor::with_recipients(recipients.iter().map(|r| r.as_ref())).unwrap();
    let mut ct = vec![];
    let mut w = e.wrap_output(&mut ct).unwrap();
    w.write_all(plaintext).unwrap();
    w.finish().unwrap();

    assert_eq!(decrypt(&card, &ct), plaintext);
}
