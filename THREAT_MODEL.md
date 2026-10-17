# PassPony threat model

Status: living document, present from P0. Expand as surfaces land.

## Assets

- Decrypted entry content (passwords, TOTP secrets, notes).
- Private key material: OpenPGP keys, age identities, SSH keys for git auth.
- Cached passphrases / unwrapped vault keys.
- Store structure and entry names (metadata; see honest limits below).

## Trust boundaries

- Crypto stays platform-native behind the `CryptoBackend` trait; pass-core
  never holds long-lived plaintext beyond the operation in flight.
- FFI boundary: minimal copies, zeroize on drop in core, no plaintext in
  logs or error messages; names and contents are never logged.
- Git remote is the user's own server; no other network endpoint exists.
  Storage modes without git perform no network I/O at all.

## Commitments

- No decrypted content at rest, ever. Index caches hold names and mtimes only.
- Clipboard auto-clear (default ~45 s); platform sensitive-content flags.
- Passphrase caching is per-backend, time-boxed, with visible policy.
- SSH keys encrypted at rest with an always-available encrypted export;
  hardware-backed wrapping is opt-in convenience, never the only copy.
  As built in 2.0: one key per app, generated (Ed25519) or imported from
  an OpenSSH file and decrypted once in memory at import. The apps keep it
  wrapped by a hardware-backed key (Android Keystore AES-GCM; iOS Keychain,
  this device only) and unwrap it per network operation; the core hands it
  to libssh2 from memory, never through a file path. The encrypted
  `.passpony` backup carries it, so the wrapping is never the only copy.
- SSH host keys are trusted on first use. The first connection to a host
  stops and shows its `SHA256:` fingerprint; nothing is fetched or pushed
  until the user confirms, and the confirmed key is pinned in the app's own
  known-hosts file. A pinned host that presents a different key of the
  same type is refused with no "connect anyway": the only way past it is to
  forget the host in Settings on purpose and confirm the new fingerprint,
  which is the moment to check it with the host's operator. A changed key
  means the server was rebuilt, rekeyed, or something is in the middle.
  Diagnostics reports only whether a remote is SSH and whether its host is
  pinned, never the key, the fingerprint, or the URL's user.
- FLAG_SECURE / screenshot suppression on reveal and passphrase screens.
- Panic-lock action clears all cached secrets immediately.
- An `otpauth://` URI is a secret like the password line: the core hands it
  out only as part of the plaintext or as a summary with the secret removed
  (`TotpSummary`), never logs it, and the apps hold it only for the life of
  the screen that sets it up. QR scanning decodes frames in memory and
  writes nothing.
- Generated passwords come from OS entropy through one uniform sampler in
  the core; there is no non-cryptographic fallback.
- No telemetry.

## Honest limits (out of scope)

- Entry names, directory structure, and edit timing are visible to the git
  host and anyone with repo access. Onboarding says so plainly.
- A compromised OS (keylogger, root malware, malicious keyboard) is out of
  scope on every platform.
- The clipboard is a shared surface; auto-clear narrows, not closes, the
  window.
- Trust on first use can't tell a real first connection from one that is
  already intercepted. A user who wants that closed compares the
  fingerprint with the one their git host publishes (GitHub, Codeberg and
  most hosts list theirs) before confirming.
