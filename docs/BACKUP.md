# The `.passpony` backup format

One format for every PassPony app (iOS, Android, desktop), defined once in
`crates/pass-core/src/backup.rs` and tested there. This document is the wire
format; the code is the reference implementation.

## Layers

A `.passpony` file is an **age v1 file with exactly one scrypt (passphrase)
recipient**. Nothing about it is PassPony-specific at this layer:

    age -d backup.passpony

asks for the passphrase and prints the container below. The apps write the
binary age format at age's default work factor (log2 N = 18, the same as
`age -p`) and read binary or armored files, refusing a work factor above 20
(1 GiB of scrypt memory) so a hostile file cannot exhaust a phone.

Encryption is done by each platform's age engine (the `age-engine` feature
of `pass-ffi` on Android, AgePonyCore on iOS, the age crate on desktop).
pass-core itself stays crypto-free and only builds and parses the container.

## The passphrase: a recovery code

The passphrase is always generated, never chosen by the user:

    DB6QT-DJ8HB-T87Z4-7D8JW-C11PC-M2TVD

- 30 characters from the Crockford base32 alphabet
  `0123456789ABCDEFGHJKMNPQRSTVWXYZ` (no I, L, O, U), shown as six groups of
  five joined by `-`.
- The first 29 are random (145 bits). The 30th is a check character: Luhn
  mod 32 over the first 29 values, which catches every single-character typo
  and most swapped neighbors before any scrypt work starts.
- **Canonical form is the passphrase.** What the user types is normalized
  first: case is ignored, spaces and dashes are dropped, `O` reads as `0`
  and `I`/`L` as `1`, then the code is re-grouped with dashes. The age
  passphrase is that canonical string, dashes included.
- The app makes the user type the code back before a backup counts as done.

## The container (age plaintext)

Line-based header, length-prefixed bodies, so key material can be any bytes:

    PassPony backup 1\n
    <kind> <length>[ <name>]\n
    <length bytes>\n
    ...
    end\n

- Line 1 is `PassPony backup <version>`. This document is version 1. A
  reader refuses a higher version ("made by a newer version of PassPony")
  rather than guessing.
- Each section header is the kind, a space, the body length in bytes as
  decimal, and optionally a space and a name (the original file name; never
  contains a newline). The body follows, then one `\n`.
- `end\n` closes the container and must be the last bytes. A missing
  trailer, a length that runs past the end, or bytes after the trailer make
  the whole backup "damaged"; nothing is restored from a damaged backup.

### Section kinds

| kind             | body                                                  | name                 |
|------------------|-------------------------------------------------------|----------------------|
| `age-identities` | the app's age identities file, verbatim               | empty                |
| `pgp-secret-key` | one imported OpenPGP secret key, armored or binary    | the key's file name  |

A reader keeps sections of kinds it does not know and reports them instead
of failing, so a backup from a newer version still restores everything an
older version understands. rc2 of 2.0 adds `ssh-private-key`.

## Restore rules

- Restored age identities are **merged** into the existing identities file
  (`identities_merge`): appended if new, skipped if already present, never
  replacing what is there.
- Restored PGP keys are imported the same way a picked key file is.
- Wrong recovery code and damaged backup both fail before anything is
  written.

## Tests

- `pass-core` `backup::tests`: container round trip with binary bodies,
  unknown kinds, truncation, newer versions, and every single-character
  recovery-code typo.
- `pass-ffi` (`age-engine`): passphrase encrypt and decrypt round trip; the
  output is a plain age file (also checked by hand with `age -d`).
- Cross-platform done-when for 2.0 rc1: a backup made on iOS restores on
  Android and the reverse.
