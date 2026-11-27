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
- Passkeys (2.0) live inside the encrypted entry as one `passkey:` line
  each, so they are covered by the same encryption, sync and backups as
  the password. They are software keys, never hardware bound: a key that
  could not leave the device could not follow the store to the next one.
  The signature counter is always 0. User verification is the app's unlock
  gate. On Android only browsers on the bundled privileged list are served;
  a native app's request is declined, because confirming an app's claim on
  a site would need a network fetch to that site.
- Post-quantum passage stores (3.0) use age's hybrid recipients
  (`age1pq1...`, ML-KEM-768 with X25519), so an entry recorded from the
  git host today is not opened by breaking X25519 alone later. A store is
  one kind or the other: age refuses to encrypt one file to post-quantum
  and classic recipients together, since the classic stanza would undo
  the point, and the core reports that state as its own error instead of
  writing anything. The store's kind is read from its recipients, never
  from a setting someone could change out from under it. This protects
  entry contents only. Git transport (SSH, TLS) and OpenPGP stores are as
  quantum-safe as their own keys.
- A classic key appearing in a post-quantum store is treated as an
  out-of-date device, asked about on every sync, and can only be removed.
  The apps never re-encrypt to it and never drop back to classic keys to
  accommodate it. Anyone who can push to the repo can still add a key of
  the right kind, which is why re-encrypting existing entries to a new key
  always asks the person first.
- Keys are compared by eye in one place, when another device's key shows
  up. A post-quantum recipient is too long to compare whole, so the apps
  show a fingerprint: the first 16 bytes of SHA-256 over the recipient as
  written. A short prefix or suffix of the key is not used for this,
  because its last characters are a checksum and the rest of a short
  slice could be matched on purpose.
- Device keys (iOS, 3.0) are age identities whose private half is a
  Secure Enclave key that needs the owner for each use. What that buys:
  the key cannot be copied off the phone, by a backup, a file-system
  dump, or malware that reads the app's files, and a locked or
  out-of-session phone cannot open entries addressed only to it. What it
  does not: entries are readable on the unlocked, authenticated phone like
  any other, and the store's other keys are unaffected. A cancelled or
  failed hardware operation ends the decrypt; it never falls back to a
  software identity for an entry addressed to the device key. Below
  iOS 26 the Enclave has no ML-KEM, so a post-quantum device key keeps
  that half's seed in the key file and only its P-256 half is
  hardware-bound; opening an entry needs both.
- A device key is never the only way in. It cannot be backed up, so the
  app creates one only when a backed-up software identity, another
  device's key, or a recovery key the person supplied can already open the
  store. Losing the phone then loses a key, not the store.
- Folder stores (3.0): a store can live in a folder the person picks
  instead of app storage, so a file-sync tool carries the encrypted files.
  On Android the app reaches that one folder through the Storage Access
  Framework and asks for no storage permission; it never sees a path. The
  core takes the file layer from the platform (`StoreFs`) and still checks
  entry names itself before any call reaches it. A folder store has no
  git, so it makes no network connection at all.
- A folder that cannot be reached is reported as exactly that
  (`FolderUnavailable`). The app never falls back to an empty store, which
  would look like every entry had been deleted.
- A save to a folder store never leaves a half-written entry: the bytes
  go to a temp file that is promoted only once it is complete, and what an
  interrupted save leaves behind is cleaned up, or finished, the next time
  that directory is read.
- Adding an entry never replaces one. The core's `add_entry` refuses a
  name that is taken; replacing is a separate, confirmed step.
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
- Post-quantum keys cover confidentiality of entry contents against a
  future quantum computer. They do not hide that an entry exists or
  changed, and they are no stronger than the weakest key listed: a store
  is only post-quantum while every recipient in it is.
- Anything that can write to a folder store's folder, including the sync
  tool and every device it syncs with, can add, change or delete entries
  and can add a key to `.age-recipients`. What it cannot do is read them:
  the app asks before re-encrypting existing entries to a key it has not
  been asked about, so a key slipped into the file is not handed the
  store. It can still make new saves go to that key until someone removes
  it, and it can roll an entry back to an older ciphertext. Entry names
  and the folder layout are visible to it, as they are to a git host.
- A sync tool's conflict copies are ordinary entries. The app labels the
  ones it recognises (Syncthing's naming); a conflicted `.age-recipients`
  becomes a dot file the app does not show.
- pass stores keyed to ElGamal or brainpool keys: the OpenPGP library
  (rpgp) reads those keys but has no arithmetic for them, so the engine
  does the public-key step itself in `pgp_legacy.rs`, with a general
  big-integer library. That code is written for PassPony, has had no
  outside review, and is not constant-time. It runs on the device that
  holds the key, on the person's own entries, and is tested both ways
  against GnuPG. The message format, the symmetric encryption and its
  integrity check are still rpgp's. RSA, Curve25519 and NIST-curve keys
  never touch it. ElGamal is weaker than a current key at the same size
  and is supported so old stores keep opening, not as a recommendation.
- A recovery key is trusted as given. The app checks that it is a usable
  recipient of the store's kind, not who holds its private half.
- The clipboard is a shared surface; auto-clear narrows, not closes, the
  window.
- Trust on first use can't tell a real first connection from one that is
  already intercepted. A user who wants that closed compares the
  fingerprint with the one their git host publishes (GitHub, Codeberg and
  most hosts list theirs) before confirming.
