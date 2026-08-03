#!/usr/bin/env bash
# Fixture corpus generator. The real CLIs are the spec: everything under
# fixtures/{pass,passage}/ is produced by pass(1) and passage at the pinned
# commit below, and the goldens/ trees capture their stdout (canonicalized:
# ANSI stripped, NBSP normalized), stderr, and exit codes. Regenerate with: bash fixtures/gen-fixtures.sh
#
# Requirements: pass (1.7.x), age, age-keygen, gpg (2.x), tree, git.
# The passage script is fetched at the pinned commit into fixtures/.tools/
# (gitignored) unless PASSAGE_SCRIPT points at an existing copy.

set -euo pipefail

# Force one locale so tree(1)'s line drawing is byte-identical on every
# machine that regenerates the corpus. macOS has no C.UTF-8, so use
# en_US.UTF-8, which both macOS and the Ubuntu CI runners ship.
export LC_ALL=en_US.UTF-8
# Belt and braces: tree honors TREE_CHARSET regardless of which locales
# the machine has installed.
export TREE_CHARSET=utf-8

PASSAGE_COMMIT="4e4c5ae14be91833791d45608f50868175c1490f"
FIX="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLS="$FIX/.tools"
KEYS="$FIX/keys"

# --- tooling -----------------------------------------------------------------

if [[ -z "${PASSAGE_SCRIPT:-}" ]]; then
  if [[ ! -f "$TOOLS/passage-src/src/password-store.sh" ]]; then
    mkdir -p "$TOOLS"
    git clone -q https://github.com/FiloSottile/passage "$TOOLS/passage-src"
    git -C "$TOOLS/passage-src" checkout -q "$PASSAGE_COMMIT"
  fi
  PASSAGE_SCRIPT="$TOOLS/passage-src/src/password-store.sh"
fi

passage() { bash "$PASSAGE_SCRIPT" "$@"; }

strip_ansi() { sed -e $'s/\x1b\\[[0-9;]*[a-zA-Z]//g'; }

# Run a command, capturing stdout, stderr and exit code into a goldens dir.
# usage: golden <goldens-dir> <name> cmd args...
golden() {
  local dir="$1" name="$2"; shift 2
  mkdir -p "$dir"
  local rc=0
  "$@" >"$dir/$name.raw" 2>"$dir/$name.err" || rc=$?
  echo "$rc" >"$dir/$name.rc"
  # Canonicalize every capture: strip ANSI color and normalize
  # non-breaking spaces to regular ones. tree's raw color codes and
  # indent whitespace vary by version and platform, so committing raw
  # bytes can never be reproducible across machines. The .plain twin
  # stays for the test harness and is identical to .out.
  strip_ansi <"$dir/$name.raw" | LC_ALL=C sed $'s/\xc2\xa0/ /g' >"$dir/$name.out"
  rm -f "$dir/$name.raw"
  cp "$dir/$name.out" "$dir/$name.plain"
}

# --- keys (generated once, then reused from fixtures/keys) -------------------

mkdir -p "$KEYS"

if [[ ! -f "$KEYS/age-key-a.txt" ]]; then
  age-keygen -o "$KEYS/age-key-a.txt" 2>"$KEYS/age-key-a.pub.tmp"
  grep -o 'age1[a-z0-9]*' "$KEYS/age-key-a.pub.tmp" >"$KEYS/age-key-a.pub"
  rm "$KEYS/age-key-a.pub.tmp"
fi
if [[ ! -f "$KEYS/age-key-b.txt" ]]; then
  age-keygen -o "$KEYS/age-key-b.txt" 2>"$KEYS/age-key-b.pub.tmp"
  grep -o 'age1[a-z0-9]*' "$KEYS/age-key-b.pub.tmp" >"$KEYS/age-key-b.pub"
  rm "$KEYS/age-key-b.pub.tmp"
fi
AGE_PUB_A="$(cat "$KEYS/age-key-a.pub")"
AGE_PUB_B="$(cat "$KEYS/age-key-b.pub")"

export GNUPGHOME="$TOOLS/gnupghome"
if [[ ! -f "$KEYS/gpg-key-a.sec.asc" ]]; then
  rm -rf "$GNUPGHOME"; mkdir -p "$GNUPGHOME"; chmod 700 "$GNUPGHOME"
  gpg --batch --quiet --pinentry-mode loopback --passphrase '' \
      --quick-generate-key "PassPony Test A <a@passpony.test>" ed25519 cert never
  gpg --batch --quiet --pinentry-mode loopback --passphrase '' \
      --quick-generate-key "PassPony Test B <b@passpony.test>" ed25519 cert never
  for who in A B; do
    fpr=$(gpg --list-keys --with-colons "$who@passpony.test" 2>/dev/null \
          | awk -F: '/^fpr/{print $10; exit}' || true)
    fpr=$(gpg --list-keys --with-colons "$(echo $who | tr AB ab)@passpony.test" \
          | awk -F: '/^fpr/{print $10; exit}')
    gpg --batch --quiet --pinentry-mode loopback --passphrase '' \
        --quick-add-key "$fpr" cv25519 encr never
    lower=$(echo "$who" | tr AB ab)
    gpg --batch --pinentry-mode loopback --passphrase '' \
        --export-secret-keys --armor "$lower@passpony.test" \
        >"$KEYS/gpg-key-$lower.sec.asc"
    echo "$fpr" >"$KEYS/gpg-key-$lower.fpr"
  done
else
  rm -rf "$GNUPGHOME"; mkdir -p "$GNUPGHOME"; chmod 700 "$GNUPGHOME"
  gpg --batch --quiet --import "$KEYS/gpg-key-a.sec.asc" "$KEYS/gpg-key-b.sec.asc"
  for f in "$KEYS"/gpg-key-*.fpr; do
    echo -e "5\ny\n" | gpg --batch --command-fd 0 --expert --edit-key "$(cat "$f")" trust quit >/dev/null 2>&1 || true
  done
fi
GPG_FPR_A="$(cat "$KEYS/gpg-key-a.fpr")"
GPG_FPR_B="$(cat "$KEYS/gpg-key-b.fpr")"
# Fixture keys are trusted ultimately so pass encrypts without prompts.
for fpr in "$GPG_FPR_A" "$GPG_FPR_B"; do
  echo "$fpr:6:" | gpg --import-ownertrust >/dev/null 2>&1
done

# --- shared entry content -----------------------------------------------------

CONTENT="$TOOLS/content"; mkdir -p "$CONTENT"
printf 'alpha-password-1\n' >"$CONTENT/alpha"
printf 'beta-pw\nusername: kevin\nurl: example.com\n' >"$CONTENT/beta"
printf 'gamma-pw\nline two\n\nline four with trailing spaces  \nno trailing newline' >"$CONTENT/gamma"
printf 'hunter2\notpauth://totp/Example:kevin?secret=JBSWY3DPEHPK3PXP&issuer=Example\n' >"$CONTENT/otp"
printf 'café-pw\nnote: naïve unicode ✓\n' >"$CONTENT/unicode"
printf 'collision-file-pw\n' >"$CONTENT/collision"
printf 'hidden-pw\n' >"$CONTENT/hidden"

# --- passage fixtures ---------------------------------------------------------

passage_fixture() {
  local name="$1"
  export PASSAGE_DIR="$FIX/passage/$name/store"
  export PASSAGE_IDENTITIES_FILE="$FIX/passage/$name/identities"
  rm -rf "$FIX/passage/$name"
  mkdir -p "$PASSAGE_DIR"
}

passage_goldens() {
  local name="$1"; shift
  local G="$FIX/passage/$name/goldens"
  golden "$G" ls passage
  while [[ $# -gt 0 ]]; do
    local entry="$1"; shift
    local safe="${entry//\//__}"
    golden "$G/show" "$safe" passage show "$entry"
  done
}

# minimal: identities-fallback encryption, no .age-recipients anywhere
passage_fixture minimal
cp "$KEYS/age-key-a.txt" "$PASSAGE_IDENTITIES_FILE"
passage insert -m alpha <"$CONTENT/alpha" >/dev/null
passage insert -m beta  <"$CONTENT/beta"  >/dev/null
passage insert -m gamma <"$CONTENT/gamma" >/dev/null
passage_goldens minimal alpha beta gamma
golden "$FIX/passage/minimal/goldens" find-hit passage find al
golden "$FIX/passage/minimal/goldens" find-miss passage find zzz
golden "$FIX/passage/minimal/goldens" show-missing passage show nope

# recipients-root: single .age-recipients at root
passage_fixture recipients-root
cp "$KEYS/age-key-a.txt" "$PASSAGE_IDENTITIES_FILE"
echo "$AGE_PUB_A" >"$PASSAGE_DIR/.age-recipients"
passage insert -m alpha <"$CONTENT/alpha" >/dev/null
passage insert -m "web/github" <"$CONTENT/beta" >/dev/null
passage_goldens recipients-root alpha web/github

# recipients-nested: nearest-ancestor + multi-recipient with comments
passage_fixture recipients-nested
cat "$KEYS/age-key-a.txt" "$KEYS/age-key-b.txt" >"$PASSAGE_IDENTITIES_FILE"
echo "$AGE_PUB_A" >"$PASSAGE_DIR/.age-recipients"
mkdir -p "$PASSAGE_DIR/work"
{ echo "# team recipients"; echo ""; echo "$AGE_PUB_A"; echo "$AGE_PUB_B"; } >"$PASSAGE_DIR/work/.age-recipients"
passage insert -m rootentry <"$CONTENT/alpha" >/dev/null
passage insert -m "work/jira" <"$CONTENT/beta" >/dev/null
passage insert -m "work/deep/sub/vault" <"$CONTENT/gamma" >/dev/null
passage_goldens recipients-nested rootentry work/jira work/deep/sub/vault

# collision: entry `web` and directory `web/`
passage_fixture collision
cp "$KEYS/age-key-a.txt" "$PASSAGE_IDENTITIES_FILE"
passage insert -m web <"$CONTENT/collision" >/dev/null
passage insert -m "web/site" <"$CONTENT/alpha" >/dev/null
passage_goldens collision web web/site
golden "$FIX/passage/collision/goldens" show-dir passage show web/

# dotfiles: hidden entries — ls hides, show works
passage_fixture dotfiles
cp "$KEYS/age-key-a.txt" "$PASSAGE_IDENTITIES_FILE"
passage insert -m .hidden <"$CONTENT/hidden" >/dev/null
passage insert -m "dir/.secret" <"$CONTENT/hidden" >/dev/null
passage insert -m visible <"$CONTENT/alpha" >/dev/null
passage_goldens dotfiles .hidden dir/.secret visible

# names-hard: spaces, unicode, name ending in .age
passage_fixture names-hard
cp "$KEYS/age-key-a.txt" "$PASSAGE_IDENTITIES_FILE"
passage insert -m "web sites/my bank" <"$CONTENT/alpha" >/dev/null
passage insert -m "café/naïve" <"$CONTENT/unicode" >/dev/null
passage insert -m "weird.age" <"$CONTENT/beta" >/dev/null
passage insert -m "totp/gh" <"$CONTENT/otp" >/dev/null
passage_goldens names-hard "web sites/my bank" "café/naïve" weird.age totp/gh

# empty-dir vs no-store
passage_fixture empty-dir
cp "$KEYS/age-key-a.txt" "$PASSAGE_IDENTITIES_FILE"
golden "$FIX/passage/empty-dir/goldens" ls passage
( export PASSAGE_DIR="$FIX/passage/empty-dir/does-not-exist"
  golden "$FIX/passage/empty-dir/goldens" ls-no-store passage )

# sneaky paths
passage_fixture sneaky
cp "$KEYS/age-key-a.txt" "$PASSAGE_IDENTITIES_FILE"
golden "$FIX/passage/sneaky/goldens" show-dotdot passage show "../x"
golden "$FIX/passage/sneaky/goldens" show-mid passage show "a/../b"

# --- pass fixtures ------------------------------------------------------------

pass_fixture() {
  local name="$1"
  export PASSWORD_STORE_DIR="$FIX/pass/$name/store"
  rm -rf "$FIX/pass/$name"
  mkdir -p "$PASSWORD_STORE_DIR"
}

pass_goldens() {
  local name="$1"; shift
  local G="$FIX/pass/$name/goldens"
  golden "$G" ls pass
  while [[ $# -gt 0 ]]; do
    local entry="$1"; shift
    local safe="${entry//\//__}"
    golden "$G/show" "$safe" pass show "$entry"
  done
}

# minimal: root .gpg-id key A
pass_fixture minimal
pass init "$GPG_FPR_A" >/dev/null
pass insert -m alpha <"$CONTENT/alpha" >/dev/null
pass insert -m beta  <"$CONTENT/beta"  >/dev/null
pass insert -m gamma <"$CONTENT/gamma" >/dev/null
pass_goldens minimal alpha beta gamma
golden "$FIX/pass/minimal/goldens" find-hit pass find al
golden "$FIX/pass/minimal/goldens" show-missing pass show nope

# nested: subdir re-keyed to A+B via pass init -p (multi-recipient + comment line)
pass_fixture nested
pass init "$GPG_FPR_A" >/dev/null
pass insert -m rootentry <"$CONTENT/alpha" >/dev/null
pass insert -m "work/jira" <"$CONTENT/beta" >/dev/null
pass insert -m "work/deep/sub/vault" <"$CONTENT/gamma" >/dev/null
pass init -p work "$GPG_FPR_A" "$GPG_FPR_B" >/dev/null
pass_goldens nested rootentry work/jira work/deep/sub/vault

# collision
pass_fixture collision
pass init "$GPG_FPR_A" >/dev/null
pass insert -m web <"$CONTENT/collision" >/dev/null
pass insert -m "web/site" <"$CONTENT/alpha" >/dev/null
pass_goldens collision web web/site
golden "$FIX/pass/collision/goldens" show-dir pass show web/

# dotfiles
pass_fixture dotfiles
pass init "$GPG_FPR_A" >/dev/null
pass insert -m .hidden <"$CONTENT/hidden" >/dev/null
pass insert -m "dir/.secret" <"$CONTENT/hidden" >/dev/null
pass insert -m visible <"$CONTENT/alpha" >/dev/null
pass_goldens dotfiles .hidden dir/.secret visible

# names-hard
pass_fixture names-hard
pass init "$GPG_FPR_A" >/dev/null
pass insert -m "web sites/my bank" <"$CONTENT/alpha" >/dev/null
pass insert -m "café/naïve" <"$CONTENT/unicode" >/dev/null
pass insert -m "weird.gpg" <"$CONTENT/beta" >/dev/null
pass_goldens names-hard "web sites/my bank" "café/naïve" weird.gpg

echo "Corpus generated under $FIX"
find "$FIX/pass" "$FIX/passage" -name "*.gpg" -o -name "*.age" | wc -l
