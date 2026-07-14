# Plan: Fable review M6 — `--update-config` silently erases an explicitly-empty `allow_fail = []`

Source: `docs/2026-07-02-fable-review.md`, finding M6. Verified still present
on main @ 4152307.

## Current state

- `internal/config/update.go` round-trips the user's TOML through structs
  whose allow-fail fields are tagged `toml:"allow_fail,omitempty"` —
  `updateFile` (:83), `updateProvider` (:92), `updatePolicy` (:97). An
  explicitly-empty list (`allow_fail = []`, meaning "enforce ALL factors")
  serializes as *absent*.
- The load path distinguishes the two correctly: `meta.IsDefined` per
  provider (`internal/config/config.go:330-335`) and top level (:358-370);
  `MergedAllowFail` honors explicit-empty via `!= nil` (:459-461). So after
  a rewrite, the dropped key silently reverts the user to the weaker Go
  defaults (the H1/M1 lists) — a security downgrade caused by a maintenance
  command.
- Related: `update.go:48` uses non-strict `toml.Decode` and discards
  `meta` — no `meta.Undecoded()` check (contrast strict load at
  `config.go:306-308`), so unknown/future keys and all comments are dropped
  on rewrite (documented at update.go:78-79; the `.bak` is the only
  mitigation).

## Design

### 1. Preserve absent-vs-empty (the core fix)

Change the update structs' allow-fail fields from `[]string` +
`omitempty` to `*[]string` (no omitempty):

- Decode: TOML key absent → nil pointer; `allow_fail = []` → pointer to
  empty slice.
- Encode: nil pointer → key omitted; empty slice → `allow_fail = []`
  emitted.
- Verify the TOML library round-trips `*[]string` this way; if its encoder
  won't emit an empty array for a non-nil pointer, implement
  `MarshalTOML`/post-process the emitted bytes for these three fields.
  Add an explicit round-trip test either way.

Apply to all three sites (file, provider, policy structs). Audit
`update.go` for any *other* `omitempty` on a semantically-meaningful-empty
field (same bug class) — e.g. empty tables/arrays used as "explicitly
none" — and fix in the same pass.

### 2. Strict decode on the update path

Replace `toml.Decode(string(data), &f)` (:48) with the same strict pattern
as `config.go:306-308`: capture `meta`, and fail the update if
`meta.Undecoded()` is non-empty. Rationale (fail closed): `--update-config`
rewrites the file; proceeding while not understanding parts of it means
destroying those parts. A user with unknown keys gets an error telling them
to update teep or remove the key — never a silent rewrite-and-drop.

### 3. Comment loss: warn loudly

Comment preservation is a large change (would need a lossless TOML
editor). Short term: before rewriting, detect `#` comment lines in the
original; if present, print a prominent notice that comments are not
preserved and the original is at `<file>.bak`. Longer term (optional
follow-up): switch the update path to targeted textual edits or a
comment-preserving TOML library.

## Files

- `internal/config/update.go` — pointer fields, strict decode, comment
  notice.
- `internal/config/update_test.go` — round-trip matrix.

## Tests

Round-trip matrix (regression for the finding):

- `allow_fail = []` at top level / per provider / per policy → survives
  `--update-config` byte-for-byte as an empty array; reloading yields
  "enforce all factors" (`MergedAllowFail` returns empty, not defaults).
- `allow_fail` absent → stays absent; defaults still apply after reload.
- Non-empty list → preserved verbatim.
- Config containing an unknown key → update refuses with the key named;
  file untouched; `.bak` not created.
- Config with comments → update proceeds with the loud notice (assert the
  notice output), `.bak` contains the comments.
- End-to-end: harden config with `allow_fail = []`, run
  `teep verify <provider> --update-config` against a fixture, reload, and
  assert every factor is still enforced (`Blocked()` semantics unchanged).

## Verification

- `make check`; `go test -race ./internal/config/...`; `make integration`
  (update-config fixture flow if present); manual round-trip on a real
  config.

## Constraints (AGENTS.md)

- Unknown config keys MUST be rejected (step 2 extends the startup rule to
  the rewrite path).
- Fail loudly: refusal messages name the offending key; comment-loss
  notice is unmissable.
- Coordinate with fable-review M1's `--update-config` pinning refusal —
  both change `update.go`; sequence M6 first (smaller, self-contained).
