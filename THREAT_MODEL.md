# PassPony threat model

Status: living document, present from P0. Expand as surfaces land.

## Assets

- Decrypted entry content (passwords, TOTP secrets, notes).
- Private key material: OpenPGP keys, age identities, SSH keys for git auth.
- Cached passphrases / unwrapped vault keys.
- Store structure and entry names (metadata — see honest limits below).

## Trust boundaries

- Crypto stays platform-native behind the `CryptoBackend` trait; pass-core
  never holds long-lived plaintext beyond the operation in flight.
- FFI boundary: minimal copies, zeroize on drop in core, no plaintext in
  logs or error messages — names and contents are never logged.
- Git remote is the user's own server; no other network endpoint exists.
  Storage modes without git perform no network I/O at all.

## Commitments

- No decrypted content at rest, ever. Index caches hold names and mtimes only.
- Clipboard auto-clear (default ~45 s); platform sensitive-content flags.
- Passphrase caching is per-backend, time-boxed, with visible policy.
- SSH keys encrypted at rest with an always-available encrypted export —
  hardware-backed wrapping is opt-in convenience, never the only copy.
- FLAG_SECURE / screenshot suppression on reveal and passphrase screens.
- Panic-lock action clears all cached secrets immediately.
- No telemetry.

## Honest limits (out of scope)

- Entry names, directory structure, and edit timing are visible to the git
  host and anyone with repo access. Onboarding says so plainly.
- A compromised OS (keylogger, root malware, malicious keyboard) is out of
  scope on every platform.
- The clipboard is a shared surface; auto-clear narrows, not closes, the
  window.
