# Conflict and recovery UX

Status: P2 gate artifact. Approved behavior for every non-happy-path git
state. The engine (pass-core `git.rs`) enforces the invariants; this doc
fixes the flows the apps build. Nothing here is improvised at beta time —
that is the point (plan §6, §13.2).

## Invariants (engine-enforced)

1. Sync is fetch + rebase. PassPony never creates merge commits and never
   attempts a content merge of encrypted blobs.
2. A conflict is always surfaced per file, by entry name, and always requires
   an explicit choice. There is no "auto-resolve" default. The three choices:
   keep mine, keep theirs, keep both.
3. "Keep both" preserves the remote version under the entry's name and the
   local version as `<name>.conflict` — a completely ordinary entry: listed,
   decryptable, pushable, so the other device sees it too and nothing is ever
   lost silently.
4. Local commits accumulate offline; nothing about being unreachable blocks
   editing. The unpushed count is always visible (badge), never hidden.
5. A dirty working tree blocks sync (engine refuses); app flows always commit
   before syncing, so users only hit this via external tampering — the fix-it
   screen offers "commit everything as-is" (one tap) before retrying.

## Flow: entry conflict during sync

Trigger: sync rebases local commits and a file both sides changed conflicts.

Sheet per conflicted entry (sequentially, count shown "1 of 3"):

    Sync conflict: web/github
    This entry was changed on this device and on another device.
    [ Keep this device's version ]
    [ Keep the other version ]
    [ Keep both ]              <- explanation line: the other version keeps
                                  the name; this device's copy becomes
                                  web/github.conflict

- No preview of decrypted contents on this sheet by default (it would force
  a decrypt prompt mid-sync); a "compare…" affordance decrypts both versions
  on demand for users who want to look before choosing.
- Cancel is allowed: it aborts the whole sync (rebase aborted, local state
  exactly as before sync started). Partial resolution is never persisted.
- After resolution the sync completes and pushes if auto-push-on-save is on.
- `.conflict` entries get a distinct row badge in lists until renamed or
  deleted; the diagnostics screen counts them.

## Flow: push rejected (non-fast-forward)

Trigger: `push` returns NonFastForward (someone else pushed first).

No dialog. The app runs sync automatically (which may surface the conflict
flow above), then pushes again. Only if that second push also fails does the
user see an error sheet with the diagnostics snapshot. Rationale: this is the
single most common "git error" for multi-device users and it has a mechanical
fix; asking the user to understand it is APS-issue-tracker territory.

## Flow: upstream history rewritten (force-push)

Trigger: fetch shows the remote tracking ref is not an ancestor of the new
remote head *and* local commits exist that were based on the old history
(detected before any rebase attempt).

This is the one genuinely dangerous state, and the only flow with a scary
screen:

    The server's history was rewritten.
    Your copy is based on history that no longer exists on the server.
    Nothing has been changed locally.
    [ Keep my copy: create backup branch and re-apply ]   (recommended)
    [ Take the server's version, archive mine ]
    [ Do nothing / decide later ]

- Option 1: tag current local head as `passpony-backup/<date>`, then rebase
  local commits onto the new remote head (conflict flow applies per file).
  The backup ref is listed in diagnostics and pushable on request.
- Option 2: tag local head the same way, hard-reset to the remote head. The
  backup tag means "archive mine", never "discard mine".
- Option 3: store keeps working locally; sync badge shows a persistent
  warning state.
- In no case does PassPony force-push as a resolution. Force-pushing *out*
  is not offered in UI at all; power users have the CLI.

## Flow: shallow-clone limitations

Shallow-cloned stores (huge-store option) may be unable to rebase across the
truncation boundary. If that state is hit, the app offers one-tap "deepen
history and retry" (unshallow fetch) rather than failing cryptically.

## Diagnostics screen (support-load countermeasure, plan §11)

One screen, one screenshot: current branch; remote URL (scheme+host only by
default, full on tap); last successful fetch/push timestamps; ahead/behind
counts; dirty flag; `.conflict` entry count; backup tags; backend versions;
storage mode. Every error sheet above links to it.

## Test coverage map

| Scenario | Where tested |
|---|---|
| Fast-forward, clean rebase | `git_matrix.rs` (local remotes) + CI server matrix |
| Keep local / remote / both | `git_matrix.rs`, incl. `.conflict` entry visibility and propagation |
| Non-FF push → sync → push | `git_matrix.rs` |
| Offline badge counts | `git_matrix.rs` |
| Force-push recovery | engine detection + flows land with the app work (P3); scenario scripted in CI matrix before beta — gate item, not optional |
| SSH auth/TOFU edge cases | CI matrix (bare-over-SSH container), P2 continuation |
