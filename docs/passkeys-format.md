# Passkeys in a pass entry: format and go/no-go memo

**Project:** PassPony (PassPonyCore, iOS, Android)
**Date:** 2026-08-29
**Status:** design spike, PassPony 1.1 packet P21. Built in 2.0 rc3; see
"What 2.0 built" at the end for where the release departs from this memo.
**Question:** How would a WebAuthn credential (a passkey) live inside a pass or
passage entry so both phones can use it, and what does a passkey release cost?

The parser for the format below is `crates/pass-core/src/passkey.rs`, built
only with the `passkey` cargo feature, exported over no FFI, and wired to no
store code. It exists to prove the format round-trips and to be the starting
point of the later release.

---

## Verdict

**Go, for the release after 1.2, on Android 14 and iOS 17 and later.** The
storage format is settled and cheap (one line per credential, CXF's own
object, so import and export need no translation). The expensive parts are
the two platform providers and the WebAuthn plumbing they share, roughly
seven session packets in total, and one of them has a policy cost: an
Android provider cannot verify a native app's claim on an rpId without
fetching that site's asset links, which would be PassPony's first network
endpoint that is not the user's own git remote. The recommendation is to
ship passkeys for browsers and iOS first, where the OS does the origin
checking, and decide the Android native-app case on its own.

Passkeys should not ship before 1.2 (identity export and backup). A passkey's
private key lives only inside the encrypted entry. Today a user who loses
the device and never exported the auto-generated age identity loses every
passage entry; with passkeys that is also every sign-in that no longer has a
password. 1.2 closes that first.

## 1. The line

One credential is one field line in the entry:

```
passkey: <base64url, unpadded, of the compact CXF passkey JSON object>
```

The example the tests pin (`passkey.rs`, `cxf_json_is_compact_with_cxf_field_names`):

```
{"type":"passkey","credentialId":"3q2-7wECAwQ","rpId":"example.com","username":"kevin@example.com","userDisplayName":"Kevin","userHandle":"AQIDBAUGBwgJCgsMDQ4PEA","key":"MAsCAQAwBgYEKoZIzg"}
```

encodes to

```
passkey: eyJ0eXBlIjoicGFzc2tleSIsImNyZWRlbnRpYWxJZCI6IjNxMi03d0VDQXdRIiwicnBJZCI6ImV4YW1wbGUuY29tIiwidXNlcm5hbWUiOiJrZXZpbkBleGFtcGxlLmNvbSIsInVzZXJEaXNwbGF5TmFtZSI6IktldmluIiwidXNlckhhbmRsZSI6IkFRSURCQVVHQndnSkNnc01EUTRQRUEiLCJrZXkiOiJNQXNDQVFBd0JnWUVLb1pJemcifQ
```

Why this shape:

- The entry codec is line based and byte faithful. A single `key: value`
  line rides through `fields()`, `set_field()`, and every other client
  untouched. A multi-line PEM block would be seen as junk lines by every
  pass tool, preserved but unreadable, and would break the one-field-per-line
  edit model.
- `pass edit` users see one opaque line and can leave it alone. The secret
  inside is no more exposed than the password on line 1: the whole entry is
  encrypted to the store's recipients.
- Multiple passkeys for one entry are multiple lines. Readers get them in
  line order.
- The passkey lives in the same entry as the site's password
  (`web/github.com` style), so autofill and the passkey share one record,
  one git history, and one set of recipients.

## 2. The object

The JSON object is a FIDO Credential Exchange Format (CXF) v1.0 passkey
credential (Proposed Standard, August 14, 2025; errata March 9, 2026), field
names verbatim, plus `type` so a reader can reject anything that is not a
passkey without guessing:

| Field             | Type   | Encoding                                           |
|-------------------|--------|----------------------------------------------------|
| `type`            | string | always `passkey`                                   |
| `credentialId`    | bytes  | base64url, unpadded; non-empty                     |
| `rpId`            | string | the relying party id, non-empty                    |
| `username`        | string | may be empty; some sites have none                 |
| `userDisplayName` | string | may be empty                                       |
| `userHandle`      | bytes  | base64url, unpadded; 1 to 64 bytes (WebAuthn user.id) |
| `key`             | bytes  | PKCS#8 PrivateKeyInfo, DER, base64url unpadded     |
| `fido2Extensions` | object | optional; stored and returned opaquely             |

Reading rules: the value is base64url, padding tolerated on input, never
written. The JSON must parse, `type` must be `passkey`, and the four
non-empty fields are checked. `key` is checked only for the DER SEQUENCE
byte; a real parse is the platform signer's job, since that is where the key
is used. Unknown fields are ignored on read and therefore dropped on
rewrite. That is a known limit of the spike: a later version that wants to
preserve foreign fields adds an opaque pass-through map.

Writing rules: compact JSON, fields in the order of the table, no
whitespace, so the same credential serializes to the same bytes on every
platform (the tests hold the encoder to the exact string above).

Using CXF's names is the point. Import from and export to any manager that
speaks CXF is a matter of unwrapping the base64url, not a translation layer,
and CXF is what the exchange protocol (CXP) carries between managers.

## 3. What the codec still needs

`Entry::set_field("passkey", value)` replaces the first `passkey:` line or
appends one. That covers one credential per entry. A second credential
needs an append-without-replace primitive (`append_field`, or an
index-aware `set_field`), and removing one needs a delete primitive like
the one the OTP line got in 1.1 (`remove_otpauth`). Both are small,
byte-faithful, and follow the OTP pattern exactly. The read side needs
nothing: `passkeys(&entry)` already returns every line in order, each
parsed on its own so one damaged line never hides the rest.

## 4. Security notes

- The private key is at rest only inside an encrypted entry. It is never
  hardware bound: an Android Keystore or Secure Enclave key cannot follow a
  git-synced store to the next device, and syncing is the product. This is
  the same trade-off every syncable-passkey manager makes; the doc says it
  out loud rather than implying otherwise.
- Signature counter is 0 on every assertion. A monotonic counter cannot be
  kept consistent across devices that sync through git, and WebAuthn
  permits 0 for exactly this case.
- ES256 (P-256) only. It is the algorithm every relying party accepts and
  the one both platforms sign natively.
- The credential id is 16 random bytes generated by the provider at
  registration; the user handle is whatever the relying party supplied in
  `user.id`, stored as given, never generated.
- User verification: the unlock gate (biometric or device credential, the
  same one autofill uses) is the UV step. The UV flag is set only after a
  fresh or in-grace unlock.
- No plaintext of any of this in logs, in navigation state, or in a
  ViewModel that outlives the screen, the same rules the OTP secret follows.

## 5. Findings

**Where signing lives.** The core is crypto-free by policy (everything goes
through `CryptoBackend`), so ES256 signing is platform work: `java.security`
(`KeyFactory("EC")` over the PKCS#8 DER, `Signature("SHA256withECDSA")`)
on Android, CryptoKit `P256.Signing.PrivateKey(derRepresentation:)` on
iOS. Both import PKCS#8 directly, which is why the CXF encoding was chosen
over SEC1 or JWK. Key generation is also platform work, with a software
`KeyPairGenerator("EC")` on Android (a Keystore key cannot be exported) and
CryptoKit on iOS, exported to PKCS#8 for storage. The core gets a foreign
callback trait like `CryptoBackend`: `WebAuthnSigner { public_key(pkcs8) ->
(x, y); sign_es256(pkcs8, message) -> DER signature }`.

**WebAuthn plumbing in the core.** Yes. Authenticator data (rpIdHash, flags,
counter, and for registration the attested credential data with the COSE
public key), the attestation object with `fmt: "none"` (CBOR), and the
assertion input (`authenticatorData || clientDataHash`) are pure byte
builders with test vectors. One implementation in the core, exposed over
the FFI, means the two providers cannot drift and the CBOR encoder is
written and tested once. Both platforms hand the provider a
`clientDataHash`; neither provider builds client data itself.

**Platform floors.** Android: a provider is a
`CredentialProviderService` (`androidx.credentials.provider`) with three
callbacks, `onBeginCreateCredentialRequest`, `onBeginGetCredentialRequest`,
`onClearCredentialStateRequest`, and a two-phase model where the entry the
user picks fires a `PendingIntent` into an Activity that answers through
`PendingIntentHandler`. The framework API exists from Android 14 (API 34);
below that it is Play services, which the foss flavor cannot rely on. The
provider is declared in the manifest with
`android.permission.BIND_CREDENTIAL_PROVIDER_SERVICE` and a provider XML.
iOS: `ASCredentialProviderViewController` with passkey registration and
assertion (iOS 17 and later), backed by `ASPasskeyCredentialIdentity`
entries in the credential identity store, the same store the password
identities already use.

**RP ID binding.** This is the finding that shapes the release. On iOS the
system verifies the relying party against associated domains before the
extension is asked to sign; the provider trusts the request. On Android the
provider is the verifier. For a browser request the system supplies the
origin and the provider checks that its host matches rpId or a registrable
suffix of it, which is local string work. For a native app request the
provider gets the calling package and its signing certificate and is
expected to confirm the app is listed in
`https://<rpId>/.well-known/assetlinks.json`. That is a network fetch to an
arbitrary site at registration and at sign-in, which would be PassPony's
first network endpoint that is not the user's own git remote, against the
threat model's current promise. The options are: browsers only on Android
at first; a cached, user-visible asset-links check with a plain explanation
in the threat model; or trusting the system's own Digital Asset Links cache
where a future androidx release exposes it. This is a product decision, not
a technical one, and the memo does not make it.

**Handles, ids, and UV.** Covered in section 4: provider-generated 16-byte
credential id, relying-party-supplied user handle stored as given, ES256
only, counter 0, unlock gate as UV. A resident-key request with
`userVerification: required` is honored only after a fresh or in-grace
unlock; otherwise the provider prompts for one.

## 6. Cost

Estimates in session packets of the size used for 1.1:

- Core: 1 to 2. The CBOR and COSE builders, authenticator data, the
  attestation object, the signer callback trait, `append_field` and
  `remove_field` for the codec, FFI exports, fixtures.
- Android: 3 to 4. Provider service and manifest, the create and get
  activities on the PendingIntent path, the WebAuthn request and response
  JSON, browser origin checking, the unlock gate as UV, entry selection UI,
  and whatever the asset-links decision costs.
- iOS: 2 to 3. Extension passkey registration and assertion, identity store
  sync of `ASPasskeyCredentialIdentity`, the same JSON and signer work in
  Swift.
- Docs and site: under 1. CXF import and export can ride along, since the
  object is already CXF.

Sequencing: 1.2 (backup) first, then this as the following release, with
the Android native-app decision made before its packets are cut.

## 7. Open items for that release

- The Android native-app rpId decision (section 5).
- Whether CXF import and export ship in the same release or the next.
- `fido2Extensions` handling beyond pass-through: `hmacCredentials` and
  `credBlob` are meaningful only if the provider implements those
  extensions, which the first release will not.
- Whether the desktop consumes the format read-only at first (show that an
  entry carries a passkey) or not at all.

## What 2.0 built

- The format above, unchanged, now compiled into every build (`passkey.rs`
  no longer sits behind a feature).
- `webauthn.rs`: authenticator data, the COSE key, the `none` attestation
  object, the SPKI Android wants, and Android's request and response JSON,
  with tests that verify real ES256 signatures over the built bytes.
- The codec gained `append_field` and `remove_field_where`; passkeys are
  added and removed one line at a time.
- Signing is platform side as recommended, but without a callback trait:
  a registration takes the platform's PKCS#8 key and public coordinates,
  and an assertion returns the bytes to sign. Nothing calls back into the
  app.
- Android native apps: declined (browsers only), decided in the 2.0 plan.
  A request counts as a browser request only when the calling app is on
  the bundled privileged-browser allowlist, which is what makes
  `CallingAppInfo.getOrigin()` return an origin. The provider does not add
  its own origin-to-rpId check on top: the browser has already enforced
  the WebAuthn rules, and Android's guidance is that a provider-side check
  breaks Related Origin Requests.

## Sources

- FIDO Alliance, Credential Exchange Format v1.0 Proposed Standard,
  errata 2026-03-09: https://fidoalliance.org/specs/cx/cxf-v1.0-ps-errata-20260309.html
- FIDO Alliance, Credential Exchange Specifications overview:
  https://fidoalliance.org/specifications-credential-exchange-specifications/
- Android Developers, Integrate Credential Manager with your credential
  provider solution: https://developer.android.com/identity/sign-in/credential-provider
- W3C, Web Authentication Level 3 (authenticator data, attestation, user
  handle bounds, signature counter): https://www.w3.org/TR/webauthn-3/
