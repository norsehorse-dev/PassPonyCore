# passage store semantics — source read-through notes

**Source read:** `src/password-store.sh` from `FiloSottile/passage`, branch `main`, fetched 2026-08-02 via raw.githubusercontent.com. The script self-reports **v1.7.4** (`cmd_version`, line 224), i.e. it is a patched fork of pass 1.7.4's script (663 lines vs upstream's 721). Pin by SHA-256 of the script read: `1a6394cb946fe469c2a6c4442cbaa2d0d144e09a43ea3d98ad92d482685cbb29` (README: `86b31bb1…196c16`; note the README is at repo path `README`, not `README.md`). Compared line-by-line against upstream pass master (`zx2c4/password-store`, `src/password-store.sh`, 721 lines). Line numbers below refer to the passage script. **Re-verify against the pinned commit when generating fixtures — the corpus, not this document, is the spec.**

---

## 1. Store location and environment variables

All defaults, lines 6–22:

| Variable | Default / effect | Line |
|---|---|---|
| `PASSAGE_DIR` | store root `PREFIX`; default `$HOME/.passage/store` | 12 |
| `PASSAGE_IDENTITIES_FILE` | `IDENTITIES_FILE`; default `$HOME/.passage/identities` | 13 |
| `PASSAGE_AGE` | age binary; default `age` (rage works too) | 9 |
| `PASSAGE_EXTENSIONS_DIR` | default `$HOME/.passage/extensions` — **not documented in the README's env-var table**, but real | 14 |
| `PASSAGE_RECIPIENTS_FILE` | if set, overrides all recipient resolution; passed as `age -R <file>` | 58–61 |
| `PASSAGE_RECIPIENTS` | space-separated recipients, each passed as `-r`; checked only if `PASSAGE_RECIPIENTS_FILE` unset | 63–68 |
| `PASSWORD_STORE_UMASK` | umask, default `077` | 6 |
| `PASSWORD_STORE_X_SELECTION`, `PASSWORD_STORE_CLIP_TIME` (45), `PASSWORD_STORE_GENERATED_LENGTH` (25), `PASSWORD_STORE_CHARACTER_SET`(`_NO_SYMBOLS`), `PASSWORD_STORE_ENABLE_EXTENSIONS` | retained from pass with pass's names | 15–19, 615 |

Removed vs pass: `PASSWORD_STORE_DIR`, `PASSWORD_STORE_KEY`, `PASSWORD_STORE_GPG_OPTS`, `PASSWORD_STORE_SIGNING_KEY`, `GPG_TTY` handling. Also `PASSAGE="1"` is set (line 10, not exported) so sourced extensions can detect passage; `GIT_CEILING_DIRECTORIES="$PREFIX/.."` is exported (line 22), so a git repo above the store's parent is never used.

**Hard gate:** lines 635–644 — if `IDENTITIES_FILE` does not exist, *every* invocation (including `help`, `version`, `ls`, `git`) prints `Error: You must place an age identity at …` + usage and exits 1. This runs before command dispatch. Fixture-relevant: a store is unusable without the identities file even for read-only listing (the gate precedes the `case`).

## 2. File extension, recipients files, resolution rules

- Entries are `<name>.age`; every command builds `passfile="$PREFIX/$path.age"` (e.g. show line 314, insert 381, generate 465, rm 511, mv/cp 547/553).
- Recipients file is **`.age-recipients`** (plural, dotfile), one per directory, contents in age's `-R` format — age itself handles per-line recipients, blank lines and `#` comments. Unlike pass, the script never parses the file (pass parses `.gpg-id` line-by-line and strips comments itself); passage just hands the path to `age -R` (line 81).
- Resolution (`set_age_recipients`, lines 55–82), in priority order:
  1. `PASSAGE_RECIPIENTS_FILE` → `-R $file`, done.
  2. `PASSAGE_RECIPIENTS` → `-r` per word, done.
  3. **Nearest-ancestor walk**: start at `$PREFIX/<dir-of-entry>`, climb with `${current%/*}` while `current != PREFIX` and no `.age-recipients` present (lines 70–73); the walk cannot escape the store root. First `.age-recipients` found → `-R` it.
  4. No `.age-recipients` anywhere up to the root → **fallback to the identities file**: `age -e -i "$IDENTITIES_FILE"` (line 77) — age derives the recipient(s) from the identities. This is why a bare store with only an identities file "just works" without any init.
- Multi-recipient: purely a property of the `.age-recipients` file contents (multiple lines) or `PASSAGE_RECIPIENTS` (multiple words). No group expansion (pass's gpg-group logic is gone).

## 3. Identities file and decryption

- Every decryption is `$AGE -d -i "$IDENTITIES_FILE" <file>` (show 318/322, grep 355, edit 431/436, generate-in-place 476, reencrypt 97). No agent, no caching in the script.
- Passphrase-protected identities: the identities file may itself be an age `-p`-encrypted file (README setup 2: `age-keygen | age -p -a >> identities`); age natively prompts for the passphrase when given an encrypted identities file. Consequence for fixtures: with encrypted identities and **no** `.age-recipients`, *encryption* also prompts (fallback branch passes `-i`); with `.age-recipients` present, only decryption prompts. `grep` decrypts every file → one passphrase prompt per file unless age caches (it doesn't).
- Plugin identities (e.g. `age-plugin-yubikey`) are supported implicitly — the identities file just contains plugin identity lines.

## 4. init and reencryption

- **`passage init` does not exist — and is arguably broken, not just removed.** The dispatch table still routes `init` → `cmd_init` (line 647), but no `cmd_init` function is defined anywhere in the script. Running `passage init` (with identities present) yields bash's `cmd_init: command not found` on stderr, and then the trailing `exit 0` (line 663) makes the **exit status 0**. The README says "the init command is not currently available"; the source shows it as a dangling dispatch entry. Fixture-worthy quirk.
- Its replacement is **`passage reencrypt [--path=subfolder,-p]`** (lines 279–297, dispatch 656; not in upstream pass): validates that `--path` (if given) is a directory, then `reencrypt_path "$PREFIX/$path"` and auto-commits `"Reencrypted $path."`.
- `reencrypt_path` (lines 84–100): `find "$1" -path '*/.git' -prune -o -iname '*.age' -print0`; per file: skip symlinks (`-L` check, line 87), resolve recipients for the file's directory, print `"<name>: reencrypting with: age <args>"`, decrypt-with-identities | encrypt-to-recipients into a `*.tmp.$RANDOM…--` temp file, `mv` over the original (rm temp on failure). Divergences from pass: **unconditional** re-encrypt (pass compares current key set vs target and skips up-to-date files); no `.extensions` prune in this find (upstream prunes it; harmless since passage's extensions dir defaults outside the store).

## 5. Command semantics and divergences from pass

- **show / ls / list** (`cmd_show`, 299–342): file beats directory — `-f $PREFIX/$path.age` checked first (line 316), so an entry name colliding with a directory shows the entry; append `/` to force the directory branch (`$PREFIX/foo/.age` is not a file). Plain show pipes plaintext through base64 and back (318–319) to preserve exact bytes; output is the exact decrypted plaintext. `-c[N]`/`-q[N]` select line N via `tail -n +N | head -n 1` (322); empty line at N → `die "There is no password to put on the clipboard at line N."`. Directory listing prints header `Passage` for the root (line 332; pass prints `Password Store`) or the path sans trailing slash, then `tree -N -C -l --noreport` minus first line, with `.age` suffixes stripped by sed (line 336). Passage dropped upstream's `3>&-` on the tree calls (tree ≥2.0 fd workaround). Nonexistent path → `Error: $path is not in the password store.`; no args + no store dir → `Error: password store is empty.` (no "Try pass init" hint).
- **find / search** (344–349): prints `Search Terms: a,b`, then `tree -P '*a*|*b*' --prune --matchdirs --ignore-case` with the same `.age`-stripping sed.
- **grep** (351–365): `find -L` (follows symlinks) pruning `.git` and `.extensions`, decrypts each `*.age`, greps with user options, prints colorized `dir/name:` header per hit. Includes dot-named entries (find has no dotfile filter), which `ls` hides (tree without `-a`).
- **insert / add** (367–414): `--echo`/`--multiline`/`--force` as in pass; strips one trailing `/` from name; overwrite prompt unless forced (skipped when stdin is not a tty — `yesno` returns 0, line 46); `mkdir -p -v` parents; encrypts via resolved recipients. Commit: `Add given password for $path to store.`
- **edit** (416–441): decrypts to tmpfile in `/dev/shm` if available (else warns + shred on exit), `$EDITOR`, dies `Password unchanged.` on identical content, retry loop on `Age encryption failed.`. Commit: `Add|Edit password for $path using ${EDITOR:-vi}.`
- **generate** (443–494): length arg default 25; charsets via `tr -dc` from `/dev/urandom`; `--in-place` replaces line 1 keeping `tail -n +2` of old content via temp-file dance; `-f` and `-i` mutually exclusive. Commits: `Add generated password for X.` / `Replace generated password for X.`
- **rm / delete / remove** (496–526): trailing-`/` and file-vs-dir disambiguation at line 512 (file exists AND dir exists AND arg ends in `/` → dir; file missing → dir); confirmation unless `-f`; `rm $recursive -f -v`; `git rm -qr` + commit `Remove $path from store.`; `rmdir -p` prunes now-empty parents.
- **mv / cp** (`cmd_copy_move`, 528–581): source resolution mirrors rm (line 545); dest gets `.age` appended unless it's an existing dir / ends with `/` / source is a dir (line 553); interactive `-i` on `mv`/`cp` unless forced or stdin not a tty. **Key divergence: after a successful move or copy, `reencrypt_path "$new_path"` always runs** (lines 561, 578) — pass only re-encrypts when the destination's key set differs; passage re-encrypts unconditionally (README: "moving or copying a secret always re-encrypts it"), so mv/cp produce new ciphertext bytes every time. Commits: `Rename ${1} to ${2}.` / `Copy ${1} to ${2}.` (plus a possible separate `Remove ${1}.` when old and new paths live in different inner git repos). Quirk: line 549 `echo "$old_path"` prints the resolved absolute source path as the first line of output (a debug leftover also present in upstream master) — capture it in goldens.
- **git** (583–601): `passage git init` initializes the repo at `$PREFIX`, commits everything (`Add current contents of password store.`), writes `.gitattributes` containing `*.age diff=age` (commit `Configure git repository for age file diff.`), and sets local config `diff.age.binary=true`, `diff.age.textconv="$AGE -d -i $IDENTITIES_FILE"`. Other git subcommands run with `TMPDIR` pointed at a secure tmpdir. Auto-commit for all mutating commands is via `git_add_file`/`git_commit` (no-op when the store isn't a repo); **commit signing removed** — pass's `pass.signcommits` check is gone (lines 41–44).

## 6. Removed / changed relative to pass 1.7.x

- `init` command gone (dangling dispatch, see §4); no `.gpg-id` files, no per-subfolder key scoping via init — the closest analog is manually placing `.age-recipients` files + `passage reencrypt -p sub`.
- All signing machinery removed: `verify_file`, `PASSWORD_STORE_SIGNING_KEY`, `.gpg-id.sig`, signed-extension verification, signed git commits.
- Extensions retained (dispatch fall-through line 661, `cmd_extension` 611–626) but user extensions live at `~/.passage/extensions` (not `$PREFIX/.extensions`) and are **not** signature-verified; still gated on `PASSWORD_STORE_ENABLE_EXTENSIONS=true`; `SYSTEM_EXTENSION_DIR` is empty in-source (set at install time).
- Reencrypt is unconditional (no key-diff optimization), and prints its age args.
- gpg group expansion, `--list-only` key introspection: gone (age has no equivalent).
- Unknown first argument still falls through to extension-then-`show` (line 661), so `passage some/entry` works like `passage show some/entry`.

## 7. Edge cases worth fixtures (source-derived)

- `check_sneaky_paths` (101–106): rejects any argument matching `^\.\.$`, `^\.\./`, `/\.\.$`, `/\.\./` with `…sneaky path to passage. Go home.` — but allows `.` components, leading-dot names; absolute-looking names are not blocked (only `..`).
- Dot-named entries (`.hidden.age`): insert/show/grep work; `ls`/`find` hide them (tree lacks `-a`). `.age-recipients` itself never appears in listings.
- Name/directory collision: show prefers the file; `show dir/` hits the dir branch; rm/mv disambiguate by trailing slash (lines 512, 545).
- Symlinks: `reencrypt_path` skips symlinked `.age` files (line 87) and — since `find` defaults to `-P` — a **symlinked store root or symlinked subdirectory is not descended by reencrypt/mv/cp re-encryption** (silent no-op), while `grep` (find `-L`) and `ls` (tree `-l`) do follow them. Verify empirically; this asymmetry is a prime fixture.
- Empty store: no `$PREFIX` dir → `ls` dies "password store is empty." (exit 1); existing-but-empty dir → prints `Passage` and nothing else (exit 0).
- Non-tty stdin: `yesno` auto-confirms (line 46) and mv/cp switch `-i`→`-f` (line 556) — batch-mode fixture generation therefore never prompts for overwrite.
- `.age` matching is `-iname` — a file named `foo.AGE` is found by grep/reencrypt but `show foo` looks for the literal `foo.age`; case-mismatch fixture is cheap insurance.
- Multiline/binary content survives show byte-exactly (base64 round-trip); no trailing-newline normalization.

## 8. P0 fixture list

Generate each with the real `passage` CLI + `age`/`age-keygen` (set `PASSAGE_DIR`, `PASSAGE_IDENTITIES_FILE` per fixture; pipe stdin from files to exploit non-tty auto-confirm). For each, capture goldens: full `ls` output (`passage`), `show` of every entry (exact bytes + exit code), `find` for a term that matches and one that doesn't, plus stderr and exit codes where noted.

1. **`minimal`** — plain-keyfile identities, no `.age-recipients`, three root entries (`alpha`, `beta`, `gamma` with multiline content). Purpose: identities-fallback encryption path (§2.3-4). Goldens: `ls`, `show alpha` (single line), `show gamma` (multiline, exact bytes, one entry with no trailing newline), `find al`.
2. **`empty-dir` / `no-store`** — (a) `$PREFIX` exists empty; (b) `$PREFIX` absent. Goldens: `ls` output `Passage` + exit 0 vs `Error: password store is empty.` + exit 1; `show nope` error text.
3. **`no-identities`** — valid store, identities file missing. Goldens: stderr gate message + usage, exit 1, for `ls`, `version`, and `help` alike.
4. **`recipients-root`** — root `.age-recipients` with a single recipient (identity's own pubkey). Purpose: `-R` root resolution; `.age-recipients` invisible in `ls`. Goldens: `ls`, `show`, `find`.
5. **`recipients-nested`** — root `.age-recipients` (key A) + `work/.age-recipients` (keys A+B, multi-line with a `#` comment and blank line) + entries at root, `work/`, and `work/deep/sub/`. Purpose: nearest-ancestor resolution and multi-recipient; verify `work/deep/sub` entry decrypts with B alone. Goldens: `ls`, `show` each, age header recipient counts (stanza count per file).
6. **`passphrase-identities`** — identities file age-`-p`-encrypted, root `.age-recipients` carrying the pubkey (README setup 2). Purpose: decrypt-prompts-only flow. Goldens: `show` under scripted passphrase (e.g. expect/`AGE` shim), `ls` (no prompt).
7. **`env-overrides`** — same store read with `PASSAGE_RECIPIENTS_FILE` and separately `PASSAGE_RECIPIENTS="key1 key2"` during an `insert`. Purpose: override precedence over on-disk `.age-recipients`. Goldens: resulting file's recipient stanzas; `reencrypt` output lines showing chosen age args.
8. **`collision`** — entry `web.age` AND directory `web/` containing `web/site.age`. Purpose: file-over-dir precedence. Goldens: `show web` (file), `show web/` (tree), `ls web`, `rm web/` vs `rm web` behavior, `find web`.
9. **`dotfiles`** — entries `.hidden` and `dir/.secret`. Purpose: ls-hides / grep-finds asymmetry. Goldens: `ls` (absent), `show .hidden` (works), `grep -i` hit output format, `find hidden` (absent).
10. **`sneaky`** — no files; just invocations `show ../x`, `insert a/../b`, `rm ..`. Goldens: exact `Go home.` stderr + exit 1 for each.
11. **`git-store`** — store under `passage git init`, then one `insert`, `generate`, `edit` (scripted `EDITOR`), `rm`, `mv a b`, `cp b c`, `reencrypt`. Purpose: full auto-commit message corpus + `.gitattributes` + `diff.age.*` config. Goldens: `git log --format=%s` (expected messages: `Add current contents…`, `Configure git repository for age file diff.`, `Add given password for X to store.`, `Add generated password for X.`, `Edit password for X using …`, `Remove X from store.`, `Rename a to b.`, `Copy b to c.`, `Reencrypted .`), `.gitattributes` bytes, `git config --local --list` subset.
12. **`mv-reencrypts`** — two sibling dirs with different `.age-recipients` (A-only and B-only, identities holding both); `mv dirA/entry dirB/entry`. Purpose: unconditional re-encrypt on move, ciphertext changes, recipient set switches to B; capture the stray `echo "$old_path"` first line and the `…: reencrypting with: age -R …` line. Goldens: full stdout, before/after age recipient stanzas.
13. **`symlinks`** — (a) store root is a symlink; (b) a symlinked subdir inside a real store; (c) a symlinked `.age` file. Purpose: pin the find `-P` vs `-L` vs tree `-l` asymmetry (§7): `ls`/`grep` see them, `reencrypt` skips (c) explicitly and silently no-ops on (a)/(b) subtrees. Goldens: `ls`, `grep` hits, `reencrypt` stdout (empty vs per-file lines).
14. **`names-hard`** — entries with spaces (`web sites/my bank`), unicode (`café/naïve`), deep nesting, name ending in `.age` (`weird.age` → file `weird.age.age`), and an uppercase `FOO.AGE` file planted manually. Purpose: quoting, `-N` tree flag, extension stripping in ls/find, `-iname` case behavior. Goldens: `ls`, `find`, `show` each, `show weird.age`.
15. **`show-line-clip`** — one entry with 5 known lines including an empty line 3. Purpose: `-c2`/`-q4` line selection and the empty-line error. Goldens: clip-shim capture of line 2, error text + exit 1 for `-c3`, `Clip location 'x' is not a number.` for `-cx`.
16. **`init-dangler`** — any valid store; run `passage init`, `passage init somekey`. Purpose: pin the undefined-`cmd_init` behavior (stderr `cmd_init: command not found`, **exit 0**) so PassPony can decide to implement/refuse `init` deliberately. Goldens: stderr pattern, exit code.

Cross-cutting golden rule: capture stdout and stderr separately, byte-exact (ANSI colors included — tree/grep output is colorized; also record `TERM`-stripped variants), plus exit codes; for every store also archive the raw tree (`find $PREFIX -printf '%y %p\n'`) and per-file age recipient-stanza counts so PassPony can validate both semantics and on-disk shape.
