# NorseHorsePGPCore public API proposal — PassPony as first external consumer

Status: proposal for review, 2026-08-02. Target repo: NorseHorsePGPCore
(the extracted shared core, Downloads checkout / norsehorse-dev remote).
Nothing here changes cryptography — only access levels, one or two thin
helpers, and documentation. Per the package's own README, the public surface
*is* the audit surface, so every promotion below is also a documentation
commitment.

## 1. Where the package already stands

Closer to consumable than expected. Already `public` today:

- `OpenPGPPacketParser.decryptMessageReturningInnerPackets(messageData:decryptionKeys:)`
  → `DecryptedMessageContents` (with public `literalData`) — the whole
  software decrypt path for Cv25519 v4 and v6 keys.
- `OpenPGPPacketBuilder.buildEncryptedMessage(plaintext:recipients:rsaRecipients:…:filename:armor:)`
  — the whole encrypt path, including software RSA *encryption* and the
  v6-vs-v4 PKESK/SEIPD selection.
- All seven key-extraction functions (v4 + v6): secret→`Cv25519DecryptionKey`,
  secret→`Ed25519SigningInfo`, public→`Cv25519Recipient`, with `passphrase:`
  parameters handling S2K unlock at extraction time.
- The `Pass` module (`PassEntryContent`, `PassField`) and `PassphraseBox`.

The four key structs are public *types* with internal members — that is
actually fine for PassPony's core flow: they work as opaque tokens
(extraction functions produce them, decrypt/build consume them, all across
the module boundary). No member promotion needed for v0.

## 2. Proposed promotions (v0 — the minimum PassPony needs)

1. `OpenPGPPacketParser.dearmor(_:) → public`
   Key import and many `.gpg-id`-adjacent workflows hand us armored text;
   there is currently no public path from armored anything to binary.
2. **Error surface**: the error enums thrown by extraction and decrypt
   (exact type names TBD during implementation) need public cases
   distinguishing at minimum: passphrase required, wrong passphrase,
   no matching key, malformed input. PassPony's unlock flow is
   throw-prompt-retry (the PGPony pattern) and cannot work against opaque
   `internal` errors.
3. `OpenPGPPacketParser.messageRecipientKeyIDs(_:) → public`
   Pre-flight "which key opens this file" — powers a good error message and
   avoids passphrase-prompting for keys that can't help. Cheap, read-only,
   already used by PGPony's pass viewer for exactly this.
4. Key inspection for keyring UX: either promote `parseAllPublicKeys` +
   a public read-only view of `ParsedPublicKeyInfo` (fingerprintHex,
   keyIDHex, algorithmName, isV6), or add a small public
   `KeyInspector.summary(of: Data) -> [KeySummary]`. PassPony needs this to
   show imported keys and to resolve `.gpg-id` strings to keys.

Deliberately *not* in v0: card entry points (`decryptMessageOnCard*` —
promote in the P3 smartcard pass, together with the transport-seam roadmap
item), `armorMessage` (PassPony writes binary `.gpg`; `buildEncryptedMessage`
already exposes `armor:` for the rest), and any member access on the token
structs.

## 3. PassPony adapter sketch (`PGPonyEngine: CryptoBackend`)

Keyring: an app-group `pgp-keys/` directory of key files (armored or
binary), plus a tiny index the app maintains: fingerprint / 16-hex key ID /
user-ID email → file. Import UX mirrors AgePony identities.

decrypt(ciphertext) → dearmor if `-----BEGIN`-prefixed → collect
`[Cv25519DecryptionKey]` from unlocked secret keys (try v4 extraction,
fall back to v6 per key) → `decryptMessageReturningInnerPackets` →
`literalData`. Passphrase model: S2K unlock happens at *extraction* time,
so "unlock" = extract once and hold the decryption keys in memory for the
UnlockGate grace window; on `passphraseRequired`, prompt and re-extract.
This is strictly better than PGPony's per-operation prompting and is why
the error-surface promotion matters.

encrypt(plaintext, recipients) → resolve each `.gpg-id` string against the
key index (normalize: uppercase hex, strip `0x`; try 40/64-hex fingerprint,
then 16-hex key ID, then email) → `cv25519Recipient(fromPublicKey:)` /
v6 equivalent → `buildEncryptedMessage(..., filename: leafName, armor: false)`
for binary `.gpg` output. Unresolvable ID → `CryptoError.NoUsableKey` with
the offending string surfaced — never silently encrypt to fewer recipients
than `.gpg-id` lists.

## 4. Honest limitations to document (both repos)

- **No software-RSA decrypt.** The package parses RSA PKESKs but only the
  card path consumes them. Consequence: existing pass stores keyed to
  RSA keys (common for long-lived pass users) decrypt on iOS **only with a
  smartcard**, not with an imported software RSA key. v0 ships with this
  documented; options later: card-assist (works today, and card users are
  the target persona), or an app-side ObjectivePGP shim (PGPony precedent —
  kept out of the auditable package by design).
- Encryption-subkey selection is structural (first matching algorithm), not
  key-flag-driven — fine for conventional keys, worth a note.
- v6 CFB-protected (254/255) secret keys and Argon2-protected v4 Ed25519
  primaries throw on extraction.

## 5. Verification plan

The PassPonyCore fixture corpus already uses ed25519/cv25519 GPG keys —
squarely in the package's native strength. So: export the fixture keys into
a PassPony test bundle; an XCTest suite decrypts every pass-fixture golden
through `PGPonyEngine` and byte-compares against `goldens/show/*.out`
(the same gate the Rust side passes). Write-side: entries encrypted by
`PGPonyEngine` in the simulator must decrypt under `gpg` on the Mac —
extending the house three-implementations-check-each-other story to four
(gpg, sequoia-desktop-later, pass-devtools, NorseHorsePGPCore).

## 6. Work plan (session-sized)

1. **NorseHorsePGPCore**: promotions §2 + doc comments on every promoted
   symbol + confirm its conformance tests still pass. Small, reviewable diff
   in the audit repo.
2. **PassPony**: `PGPonyEngine` adapter + minimal key import (file picker →
   `pgp-keys/`), wire into `EngineProvider` for `.pass` stores, retire the
   flip engine entirely.
3. **Parity**: fixture-key test bundle + the XCTest gate above.
4. **Later, with the P3 card work**: promote the card entry points behind
   the transport-seam protocol from the package roadmap.
