#!/usr/bin/env bash
# A throwaway passage store for testing YubiKey (age-plugin-yubikey)
# support in the PassPony apps against your own YubiKey. See
# docs/yubikey-testing.md for the whole procedure.
#
#   tools/yubikey-test-store.sh init <dir> [--recipient <age1...>]...
#       Make <dir> a git repo holding a passage store whose .age-recipients
#       lists the age-plugin-yubikey recipients of every YubiKey plugged in
#       (plus any --recipient: a phone's or a desktop's own key), and one
#       seed entry, test/from-age, written by the real age and
#       age-plugin-yubikey. Needs no PIN or touch.
#
#   tools/yubikey-test-store.sh verify <dir> [--decrypt] [--show]
#       Check that every entry's header holds one piv-p256 (YubiKey) stanza
#       per YubiKey recipient in .age-recipients; no key needed. With
#       --decrypt, also open each entry through age-plugin-yubikey (the PIV
#       PIN and a touch for each, with a YubiKey plugged in); --show prints
#       what they hold. Exits 1 if any entry fails.
#
# Requirements: age (1.1+), age-plugin-yubikey (0.5+), git. Nothing here
# reads or writes a secret key: recipients and YubiKey identity stubs are
# public.

set -euo pipefail

die() {
  echo "yubikey-test-store: $*" >&2
  exit 1
}

need() {
  command -v "$1" >/dev/null 2>&1 || die "$1 is not installed (see docs/yubikey-testing.md)"
}

usage() {
  sed -n '2,/^$/s/^# \{0,1\}//p' "${BASH_SOURCE[0]}" >&2
  exit 2
}

# The YubiKey recipients in a recipients file, one per line.
yubikey_recipients() {
  grep -E '^[[:space:]]*age1yubikey1' "$1" | sed 's/[[:space:]]//g' || true
}

init() {
  local dir="" extra=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --recipient)
        [[ $# -ge 2 ]] || usage
        extra+=("$2")
        shift 2
        ;;
      -*) usage ;;
      *)
        [[ -z "$dir" ]] || usage
        dir="$1"
        shift
        ;;
    esac
  done
  [[ -n "$dir" ]] || usage
  need age
  need age-plugin-yubikey
  need git

  if [[ -e "$dir" && -n "$(ls -A "$dir" 2>/dev/null)" ]]; then
    die "$dir exists and is not empty"
  fi

  local yubikeys
  yubikeys="$(age-plugin-yubikey --list 2>/dev/null | grep -E '^age1yubikey1' || true)"
  if [[ -z "$yubikeys" ]]; then
    die "no age-plugin-yubikey identity on a plugged-in YubiKey (make one: docs/yubikey-testing.md, step 1)"
  fi
  for r in "${extra[@]+"${extra[@]}"}"; do
    [[ "$r" == age1* ]] || die "not an age recipient: $r"
  done

  mkdir -p "$dir/test"
  {
    echo "# PassPony YubiKey test store: every YubiKey plugged in when it was made"
    echo "$yubikeys"
    for r in "${extra[@]+"${extra[@]}"}"; do
      echo "# added with --recipient"
      echo "$r"
    done
  } >"$dir/.age-recipients"

  printf 'seed-password\nnote: written by age and age-plugin-yubikey\n' |
    age -e -R "$dir/.age-recipients" -o "$dir/test/from-age.age"

  git -C "$dir" init -q -b main
  git -C "$dir" add .age-recipients test/from-age.age
  local who=()
  if [[ -z "$(git -C "$dir" config user.email || true)" ]]; then
    who=(-c user.name="PassPony YubiKey test" -c user.email="yubikey-test@invalid")
  fi
  git -C "$dir" "${who[@]+"${who[@]}"}" commit -q -m "YubiKey test store: recipients and a seed entry"

  local n
  n="$(printf '%s\n' "$yubikeys" | wc -l | tr -d ' ')"
  cat <<EOF
Made $dir: $n YubiKey recipient(s)${extra:+ and ${#extra[@]} more}, one seed entry (test/from-age).

Next:
  1. Push it to a new private git repository you can reach from the apps:
       git -C "$dir" remote add origin <url> && git -C "$dir" push -u origin main
  2. Follow docs/yubikey-testing.md, step 3 on: open and add entries in the apps.
  3. Pull, then check what the apps wrote:
       $0 verify "$dir" --decrypt
EOF
}

# How many piv-p256 stanzas an age file's header holds.
piv_stanzas() {
  LC_ALL=C sed -n '/^---/q;p' "$1" | grep -c '^-> piv-p256 ' || true
}

verify() {
  local dir="" decrypt=0 show=0
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --decrypt) decrypt=1 ;;
      --show) show=1 ;;
      -*) usage ;;
      *)
        [[ -z "$dir" ]] || usage
        dir="$1"
        ;;
    esac
    shift
  done
  [[ -n "$dir" ]] || usage
  [[ -f "$dir/.age-recipients" ]] || die "$dir has no .age-recipients"
  need age

  local want
  want="$(yubikey_recipients "$dir/.age-recipients" | wc -l | tr -d ' ')"
  [[ "$want" -gt 0 ]] || die "$dir/.age-recipients lists no age1yubikey1 recipient"

  local ids=""
  if [[ "$decrypt" -eq 1 ]]; then
    need age-plugin-yubikey
    ids="$(mktemp)"
    # Expanded now: $ids is local, and gone by the time EXIT fires.
    # shellcheck disable=SC2064
    trap "rm -f -- $(printf '%q' "$ids")" EXIT
    age-plugin-yubikey --identity 2>/dev/null >"$ids" || true
    grep -q '^AGE-PLUGIN-YUBIKEY-' "$ids" || die "--decrypt needs a YubiKey with an age identity plugged in"
  fi

  local failed=0 count=0 file name got
  while IFS= read -r -d '' file; do
    name="${file#"$dir"/}"
    name="${name%.age}"
    count=$((count + 1))
    got="$(piv_stanzas "$file")"
    if [[ "$got" -ne "$want" ]]; then
      echo "FAIL $name: $got YubiKey stanza(s), want $want"
      failed=1
      continue
    fi
    if [[ "$decrypt" -eq 0 ]]; then
      echo "ok   $name: $got YubiKey stanza(s)"
      continue
    fi
    echo "     $name: opening (PIV PIN and touch)..."
    local plain
    if plain="$(age -d -i "$ids" "$file")"; then
      if [[ "$show" -eq 1 ]]; then
        echo "ok   $name: $got YubiKey stanza(s), opens:"
        printf '%s\n' "$plain" | sed 's/^/       /'
      else
        echo "ok   $name: $got YubiKey stanza(s), opens (${#plain} bytes)"
      fi
    else
      echo "FAIL $name: does not open with the plugged-in YubiKey"
      failed=1
    fi
  done < <(find "$dir" -path "$dir/.git" -prune -o -type f -name '*.age' -print0 | sort -z)

  [[ "$count" -gt 0 ]] || die "$dir holds no entries"
  if [[ "$failed" -eq 0 ]]; then
    echo "All $count entries are encrypted to the $want YubiKey recipient(s)$([[ "$decrypt" -eq 1 ]] && echo " and open")."
  fi
  return "$failed"
}

case "${1:-}" in
  init)
    shift
    init "$@"
    ;;
  verify)
    shift
    verify "$@"
    ;;
  *) usage ;;
esac
