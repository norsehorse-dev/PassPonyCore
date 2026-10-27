#!/usr/bin/env bash
# Fixtures for the pgp-engine feature (crates/pass-ffi/src/pgp_engine.rs):
# real GnuPG keys and pass entries the iOS Swift engine can't read (RSA,
# a passphrase-locked RSA key, a secret-subkeys-only export, GnuPG's AEAD
# packets). Regenerate with: bash fixtures/gen-pgp-engine-fixtures.sh
# Requirements: gpg 2.4 (2.4 is what writes the AEAD/OCB packets).

set -euo pipefail

FIX="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/pgp-engine"
PASS="pony-test-passphrase"
PLAIN=$'correct horse battery staple\nusername: pony\nurl: https://example.com\n'

mkdir -p "$FIX"
GNUPGHOME="$(mktemp -d)"
export GNUPGHOME
trap 'gpgconf --kill all >/dev/null 2>&1 || true; rm -rf "$GNUPGHOME"' EXIT

# Primary for certify+sign, separate encryption subkey: the shape gpg's
# interactive --full-gen-key produces for both RSA and ECC.
gen() {
  local uid="$1" sign="$2" encr="$3" pass="$4" fpr
  gpg --batch --pinentry-mode loopback --passphrase "$pass" \
    --quick-gen-key "$uid" "$sign" sign,cert never
  fpr=$(gpg --batch --with-colons --list-keys "$uid" | awk -F: '/^fpr:/ {print $10; exit}')
  gpg --batch --pinentry-mode loopback --passphrase "$pass" \
    --quick-add-key "$fpr" "$encr" encr never
  echo "$fpr"
}

RSA=$(gen "RSA Pony <rsa@example.com>" rsa3072 rsa3072 "")
LOCKED=$(gen "Locked Pony <locked@example.com>" rsa3072 rsa3072 "$PASS")
ECC=$(gen "ECC Pony <ecc@example.com>" ed25519 cv25519 "")

gpg --batch --armor --export-secret-keys "$RSA" >"$FIX/rsa.sec.asc"
gpg --batch --pinentry-mode loopback --passphrase "$PASS" --armor \
  --export-secret-keys "$LOCKED" >"$FIX/rsa-locked.sec.asc"
gpg --batch --armor --export-secret-subkeys "$RSA" >"$FIX/rsa-subkeys-only.sec.asc"
gpg --batch --export-secret-keys "$ECC" >"$FIX/ecc.sec.gpg"
gpg --batch --armor --export "$RSA" >"$FIX/rsa.pub.asc"

echo "$RSA" >"$FIX/rsa.fpr"
echo "$LOCKED" >"$FIX/rsa-locked.fpr"
echo "$ECC" >"$FIX/ecc.fpr"
printf '%s' "$PLAIN" >"$FIX/plaintext.txt"

enc() {
  local out="$1"; shift
  local args=()
  for r in "$@"; do args+=(--recipient "$r"); done
  printf '%s' "$PLAIN" | gpg --batch --yes --trust-model always "${args[@]}" \
    --encrypt --output "$out"
}

enc "$FIX/rsa.gpg" "$RSA"
enc "$FIX/rsa-locked.gpg" "$LOCKED"
enc "$FIX/ecc-aead.gpg" "$ECC"
enc "$FIX/rsa-and-ecc.gpg" "$RSA" "$ECC"
printf '%s' "$PLAIN" | gpg --batch --yes --trust-model always --armor \
  --recipient "$RSA" --encrypt --output "$FIX/rsa-armored.gpg"

gpg --batch --list-packets "$FIX/ecc-aead.gpg" 2>/dev/null >"$FIX/ecc-aead.packets.txt" || true
