# Testing YubiKey support with your own YubiKey

PassPony can use YubiKey keys made by
[age-plugin-yubikey](https://github.com/str4d/age-plugin-yubikey) in
passage stores. This page is for anyone who wants to check that against
their own YubiKey, using a throwaway store that has nothing to do with
their real passwords.

## What works where

| | Save an entry to `age1yubikey1…` recipients | Open an entry with the YubiKey |
|---|---|---|
| PassPonyCore (`pass-age-piv`, `pass-ffi` `age-engine`) | yes, natively | yes, through an app-provided `YubiKeyCard` |
| PassPony Desktop | yes | yes, through `age-plugin-yubikey` on PATH: PIN dialog, then a touch; the PIN is kept for five minutes |
| PassPony Android | yes | not yet (the app keeps its own key for reading) |
| PassPony iOS | not yet | not yet |

Saving to a YubiKey recipient needs only its public key, so no plugin and
no YubiKey are involved. Opening needs the YubiKey itself.

## What you need

- A YubiKey 5 series (or any YubiKey with the PIV applet).
- `age` 1.1 or later, `age-plugin-yubikey` 0.5 or later, and `git`.
- For Desktop: a build of the YubiKey branch (`cargo run`).
- For Android: a build of the YubiKey branch (`scripts/build-core.sh`
  then `./gradlew assembleFossDebug`), and a phone with USB debugging on.
- A private git repository for the test store, one the apps can reach
  (any host; the apps sync over HTTPS with a token, Android also over SSH).

## 1. Give the YubiKey an age identity

Skip this if `age-plugin-yubikey --list` already prints an `age1yubikey1…`
line with the YubiKey plugged in.

age-plugin-yubikey needs the PIV PIN, PUK and management key changed from
their factory defaults. If you've never done that (`ykman piv info` says
"Using default"):

```sh
ykman piv access change-pin
ykman piv access change-puk
ykman piv access change-management-key --generate --protect
```

Then make the identity, in a free retired slot (slot 1 here):

```sh
age-plugin-yubikey --generate --slot 1 --pin-policy once --touch-policy always --name "passpony test"
```

It asks for the PIN and a touch, and prints the identity stub
(`AGE-PLUGIN-YUBIKEY-1…`, not a secret) and the recipient (`age1yubikey1…`).

## 2. Make the test store

With the YubiKey plugged in:

```sh
tools/yubikey-test-store.sh init ~/passpony-yk-test
```

This writes a `.age-recipients` listing the recipient of every YubiKey
plugged in, plus a seed entry, `test/from-age`, written by the real `age`
and `age-plugin-yubikey`, and commits both. Add `--recipient <age1…>` to
include another key as well, such as a desktop's own key, so that
machine can read entries without the YubiKey.

Push it to your private repository:

```sh
git -C ~/passpony-yk-test remote add origin <url>
git -C ~/passpony-yk-test push -u origin main
```

## 3. PassPony Desktop

1. Give the app the YubiKey's identity stub (not a secret):

   ```sh
   age-plugin-yubikey --identity > /tmp/yubikey-identity.txt
   cargo run -- import-identities /tmp/yubikey-identity.txt
   ```

2. Run `cargo run`, choose passage, and clone or open the test store.
3. Open `test/from-age`. **Expect** a PIN dialog naming your YubiKey's
   serial, then "touch your YubiKey" in the entry pane, then
   `seed-password`. Enter in the PIN field unlocks.
4. Open it again within five minutes. **Expect** no PIN dialog, just the
   touch.
5. Add an entry, `test/desktop`, and save. **Expect** it to save and
   commit, and to open after a touch.
6. With two of your YubiKeys listed but only one plugged in, open an
   entry. **Expect** to be asked for the plugged-in one only.

The CLI does the same from a terminal: `cargo run -- show test/from-age
passage` asks for the PIN without echo (or reads `PASSPONY_PIV_PIN`).

## 4. PassPony Android

1. Install the debug build. If you already have PassPony installed from a
   store, the debug build won't install over it (different signing key);
   don't uninstall the store build to make room, since that deletes its
   keys.
2. Choose passage, let the app make its own age identity, and clone the
   test store from the first-run tour. **Expect** the app to add its own
   key to `.age-recipients` and commit that; that's how a phone shares a
   store.

   A debug build fills an empty passage store with fake demo entries
   (`DemoSeed`) once onboarding is done. If they land in the test store's
   folder, Sync stops with "The store has local changes that aren't
   committed yet". Remove them (they're all fake):
   `adb shell run-as com.passpony.android rm -r files/store/finance files/store/mail files/store/web files/store/wifi files/store/work files/store/dev`.
3. Add an entry, `test/phone`, and sync. **Expect** it to save and push.
   Before YubiKey support, this failed with an encryption error.
4. Open `test/phone` on the phone. **Expect** it to open with the phone's
   own key, without the YubiKey.

## 5. Check what the apps wrote

On a machine with `age` and `age-plugin-yubikey`:

```sh
git -C ~/passpony-yk-test pull
tools/yubikey-test-store.sh verify ~/passpony-yk-test --decrypt
```

**Expect** every entry to report one YubiKey stanza per YubiKey recipient
and to open; each asks for the PIN and a touch. `--show` prints what they
hold. Without `--decrypt`, only the headers are checked, which needs no
YubiKey.

## Reporting back

Please include:

- YubiKey model and firmware (`ykman info`), `age --version` and
  `age-plugin-yubikey --version`.
- The OS (and phone model, for Android).
- Which steps you ran, which expectations held, and the output of
  `verify` (without `--show`).

Never paste an identity file's `AGE-SECRET-KEY-1…` lines, a PIN, or
`--show` output from a real store.

## Cleaning up

Delete the test repository and `~/passpony-yk-test`. To drop the YubiKey's
identity from PassPony Desktop, remove its `AGE-PLUGIN-YUBIKEY-1…` line
from the identities file (`passpony keys` prints its path). The identity
on the YubiKey can stay. If you made it only for this, `ykman piv keys
delete 82` removes slot 1's key; that can't be undone, so check the slot
first.
