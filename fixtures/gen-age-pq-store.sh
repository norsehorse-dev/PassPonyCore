#!/usr/bin/env bash
# The post-quantum passage fixture (fixtures/passage/post-quantum), written
# by the real tools: age-keygen -pq makes the key, and passage at the
# commit pinned in gen-fixtures.sh inserts the entries, which makes age
# itself write the mlkem768x25519 stanzas. The pass-ffi age-pq tests then
# decrypt this store with the Rust engine and compare against the goldens.
# Regenerate with: bash fixtures/gen-age-pq-store.sh
#
# Kept apart from gen-fixtures.sh because it needs age 1.3.0 or later, and
# the age in Ubuntu's archive (what CI installs) is older. CI therefore
# tests against the committed store and does not regenerate it.
# Requirements: age and age-keygen 1.3.0 or later, git, bash.

set -euo pipefail

FIX="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLS="$FIX/.tools"
KEYS="$FIX/keys"
NAME="post-quantum"

if ! age-keygen -pq >/dev/null 2>&1; then
  echo "age-keygen here cannot make post-quantum keys; age 1.3.0 or later is needed (found: $(age --version 2>&1))"
  exit 1
fi

PASSAGE_COMMIT="$(sed -n 's/^PASSAGE_COMMIT="\(.*\)"$/\1/p' "$FIX/gen-fixtures.sh")"
[[ -n "$PASSAGE_COMMIT" ]] || { echo "could not read PASSAGE_COMMIT from gen-fixtures.sh"; exit 1; }
if [[ -z "${PASSAGE_SCRIPT:-}" ]]; then
  if [[ ! -f "$TOOLS/passage-src/src/password-store.sh" ]]; then
    mkdir -p "$TOOLS"
    git clone -q https://github.com/FiloSottile/passage "$TOOLS/passage-src"
  fi
  git -C "$TOOLS/passage-src" checkout -q "$PASSAGE_COMMIT"
  PASSAGE_SCRIPT="$TOOLS/passage-src/src/password-store.sh"
fi
passage() { bash "$PASSAGE_SCRIPT" "$@"; }

# The key is generated once and then reused, like the other fixture keys.
mkdir -p "$KEYS"
if [[ ! -f "$KEYS/age-key-pq.txt" ]]; then
  age-keygen -pq -o "$KEYS/age-key-pq.txt" 2>/dev/null
fi
age-keygen -y "$KEYS/age-key-pq.txt" >"$KEYS/age-key-pq.pub"
AGE_PUB_PQ="$(cat "$KEYS/age-key-pq.pub")"

export PASSAGE_DIR="$FIX/passage/$NAME/store"
export PASSAGE_IDENTITIES_FILE="$FIX/passage/$NAME/identities"
rm -rf "$FIX/passage/$NAME"
mkdir -p "$PASSAGE_DIR"
cp "$KEYS/age-key-pq.txt" "$PASSAGE_IDENTITIES_FILE"
echo "$AGE_PUB_PQ" >"$PASSAGE_DIR/.age-recipients"

# Same plaintexts gen-fixtures.sh uses for alpha and beta.
printf 'alpha-password-1\n' | passage insert -m alpha >/dev/null
printf 'beta-pw\nusername: kevin\nurl: example.com\n' | passage insert -m "web/github" >/dev/null

G="$FIX/passage/$NAME/goldens/show"
mkdir -p "$G"
passage show alpha >"$G/alpha.out"
passage show "web/github" >"$G/web__github.out"

echo "Wrote $FIX/passage/$NAME with $(age --version)"
