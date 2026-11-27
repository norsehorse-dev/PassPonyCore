#!/usr/bin/env bash
# Fixtures for crates/pass-ffi/src/pgp_legacy.rs: real GnuPG keys of the
# types rpgp parses but has no arithmetic for (ElGamal, brainpool ECDH),
# each with one pass entry encrypted to it by gpg.
# Regenerate with: bash fixtures/gen-pgp-legacy-fixtures.sh
# Requirements: gpg 2.4.

set -euo pipefail

FIX="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/pgp-legacy"
PASS="pony-pass"
PLAIN=$'correct horse battery staple\nusername: pony\n'

mkdir -p "$FIX"
GNUPGHOME="$(mktemp -d)"
export GNUPGHOME
trap 'gpgconf --kill all >/dev/null 2>&1 || true; rm -rf "$GNUPGHOME"' EXIT

printf '%s' "$PLAIN" >"$FIX/plaintext.txt"

gen() {
  local name="$1" sign="$2" encr="$3" pass="$4" fpr
  gpg --batch --quiet --pinentry-mode loopback --passphrase "$pass" \
    --quick-gen-key "$name <$name@example.com>" "$sign" sign,cert never
  fpr=$(gpg --batch --with-colons --list-keys "$name@example.com" | awk -F: '/^fpr:/ {print $10; exit}')
  gpg --batch --quiet --pinentry-mode loopback --passphrase "$pass" \
    --quick-add-key "$fpr" "$encr" encr never
  gpg --batch --pinentry-mode loopback --passphrase "$pass" \
    --export-secret-keys "$fpr" >"$FIX/$name.sec.gpg"
  echo "$fpr" >"$FIX/$name.fpr"
  printf '%s' "$PLAIN" | gpg --batch --yes --trust-model always \
    --recipient "$fpr" --encrypt --output "$FIX/$name.gpg"
}

gen dsa-elg dsa2048 elg2048 ""
gen dsa-elg-locked dsa2048 elg2048 "$PASS"
gen rsa-elg rsa3072 elg3072 ""
gen bp256 brainpoolP256r1 brainpoolP256r1 ""
gen bp384 brainpoolP384r1 brainpoolP384r1 ""
gen bp512 brainpoolP512r1 brainpoolP512r1 ""
