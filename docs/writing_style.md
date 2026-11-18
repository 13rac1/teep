# Approved terms

Terms of art permitted as exceptions to the ASD-STE100 dictionary. SEE: `AGENTS.md` § Writing
Style for the rule that decides whether a word belongs here.

Each of these is the name of a thing rather than a decoration on a name that already exists.
Removing one costs the reader the link to a definition they can look up.

## Project

- `fail closed` / `fail-closed` — reject or block when validation cannot complete.
- `allow_fail` / `allow-fail` — the factor allowlist config field.
- `nil-safe` — a method that accepts a nil receiver.
- `org` — a GitHub organization, for example `tinfoilsh`.

## Security

- `trust root` — the root of a verification chain. Use it in place of `trust anchor`.
- `trust boundary` — the line between code that is verified and code that is not.
- `attack surface` — the set of entry points an attacker can reach.
- `defense in depth` — a check of a different kind that still provides security when another
  check or process fails. Example: Certificate Transparency verification of the CA-issued
  certificates on the NVIDIA and Intel endpoints. Not `double enforcement` — the same property
  re-checked in a second place, which drifts from the first check and is not wanted. Check each
  property in one place with clear ownership, then treat it as an invariant downstream.
- `cache poisoning` — writing an attacker-chosen value into a cache that other requests read.
- `front-running` — inserting a record into a transparency log before the legitimate one.
- `security theater` — a measure that produces the appearance of security and no security.
  Use it only where the measure has no effect. A measure that helps an attacker is worse than
  theater and must be described directly.

## Systems

- `source of truth` — the single authoritative location for a piece of data.
- `fast path` / `slow path` — the branch taken when a cache or precondition is satisfied, and
  the branch taken when it is not.
- `happy path` — the execution route where no error branch is taken.
- `thundering herd` — many waiters proceeding at once when one shared result expires.
- `fan out` — starting one unit of work per item concurrently.
- `thrashing` — repeated eviction and refetch of the same cache entry.
- `sticky` routing / sessions — sending related requests to the same backend.
- `stale` / `fresh` — outside or inside a cache TTL.
- `graceful shutdown`, `drain`, `in-flight` — the `http.Server.Shutdown` vocabulary: stop
  accepting connections, then finish the requests already started.

## Formats and protocols

- `handshake` — the TLS protocol exchange.
- `magic bytes` — the leading bytes that identify a file format.
- `checkpoint` — the signed statement of a transparency log's size and root hash
  ([C2SP tlog-checkpoint](https://github.com/C2SP/C2SP/blob/main/tlog-checkpoint.md)).
- `tile` — a fixed-size block of hashes from a transparency log's Merkle tree, served as a static file
  ([C2SP tlog-tiles](https://github.com/C2SP/C2SP/blob/main/tlog-tiles.md)).
- `shard` — one of the independent trees into which a transparency log is split over time.
- `keyless signing` — Sigstore signing with a short-lived certificate that Fulcio issues to an
  OIDC identity, with no long-lived signing key.

## Adding a term

Show that the term is a name under the rule in `AGENTS.md`: it has a definition shared outside
this project, a reader can look it up, and no plain word carries the same meaning. Add it to this
file in the same change that first uses it, so the reviewer decides both together.
