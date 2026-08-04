# CISS security review — 2026-08-03

Findings of record from the security audit of CISS as deployed live at
`https://ciss.croft.ing`. Three axes were reviewed: **access/authorization**,
**integrity / untrusted-input handling**, and **availability / resource safety**.
Remediation is sequenced in [`plans/2026-08-03-hardening-and-auth.md`](plans/2026-08-03-hardening-and-auth.md);
the auth-model decision is [`adr/0001-auth-and-access-control-model.md`](adr/0001-auth-and-access-control-model.md).

Every "live-confirmed" finding was reproduced against the production host with
read-only probes or a clearly-labelled audit namespace; every "proven" finding
was reproduced against the real server via the `tests/common` harness.

## Severity summary

| ID | Sev | Axis | Finding | Status |
|----|-----|------|---------|--------|
| A1 | CRITICAL | access | S3 plane fully unauthenticated: anonymous cross-tenant read/write/enumerate/meter | live-confirmed |
| A2 | CRITICAL | access+integrity | atproto bearer is non-verifying; token string *is* the acting DID → write into any DID's repo and make the provider sign false receipts against a third party | live-confirmed |
| V1 | CRITICAL | availability | A single ~40-byte GET drives `fs::read` on an attacker-selected path → unbounded allocation → OOM/SIGKILL | proven |
| V2 | CRITICAL | availability | Synchronous fs/SQLite I/O inside async handlers; N concurrent blocking requests freeze the whole runtime incl. `/healthz` | proven |
| A3 | HIGH | access | Path traversal: `did`/`cid` joined straight into a filesystem path, escapes the data dir | proven (local) |
| I1 | HIGH | integrity | Manifest `total_bytes` is not bound by the signature and never recomputed — the rent base is forgeable | proven |
| I2 | HIGH | integrity | Merkle root uses duplicate-last padding (CVE-2012-2459 shape) — one signature validates multiple leaf sets | proven |
| I3 | HIGH | integrity | journald log forging via unvalidated path segments (newline/ANSI injection into `tracing` lines) | proven |
| V3 | HIGH | availability | Per-request work is O(ledger depth); total O(n²); the shared `Mutex<Store>` turns one deep ledger into whole-server starvation | proven |
| I4 | MEDIUM | integrity | Error bodies reflect internal state — a content-hash oracle, io-error text, raw SQLite/serde errors | proven |
| I5 | MEDIUM | integrity | No manifest replay protection — an old signed manifest re-PUTs and rolls state back | proven |
| I6 | MEDIUM | integrity | Small-order keys accepted, non-strict `verify`, and the DID is a function of the key *encoding* not the key | proven |
| I7 | MEDIUM | integrity | `derive_id` truncates SHA-256 to 64 bits — the whole key↔identity binding | analysis |
| I8 | MEDIUM | integrity | Provider signing seed stored plaintext in SQLite, slated to replicate off-box to R2 | analysis |
| V4 | MEDIUM | availability | No request/body timeouts, no concurrency limit (slowloris, connection pressure) | analysis |
| V5 | MEDIUM | availability | Unbounded disk / SQLite row growth, no quota anywhere | analysis |
| I9 | MED/LOW | integrity | Served blobs carry no `nosniff`/`Content-Disposition`/CSP — script execution + same-origin hosting surface on `ciss.croft.ing` | proven |
| I10 | LOW/MED | integrity | `did` accepts empty/control/unbounded strings; FS↔SQLite namespace split-brain (latent on ext4) | proven |
| I11 | LOW | integrity | No domain separation between signed message types | analysis |
| I12 | LOW | integrity | Manifest leaves never cross-checked against storage; hostile leaf strings stored and reflected | proven |
| I13 | LOW | integrity | `Content-Type` reflected unvalidated; `x-croft-pubkey` case-insensitive | proven |

## Remediation status (updated 2026-08-04)

All findings are remediated in the codebase (phases in
[`plans/2026-08-03-hardening-and-auth.md`](plans/2026-08-03-hardening-and-auth.md)),
except two that are intentionally partial/deferred with rationale below. **Note:**
these are code fixes on `main`; the running deployment is unchanged until a new
release is built and croft-stack is converged.

| Finding | Status | Where |
|---|---|---|
| A1, A2 | **closed** | Phase 3 — verified sessions + owner authorization |
| A3 | **closed** | Phase 1 (identifier validation) + Phase 2 (backend path safety) |
| I1, I2, I5, I11, I12 | **closed** | Phase 4a — bound signed preimage, Merkle fix, seq, leaf validation |
| I3, I10 | **closed** | Phase 1 — `parse_did`/`parse_cid` newtypes, escaped logging |
| I4 | **closed** | Phase 5a — generic 5xx bodies |
| I6 | **closed** | Phase 4b — weak-key rejection + `verify_strict` |
| I7 | **closed** | Phase 4c — full 64-hex DID |
| I9, I13 | **closed** | Phase 5a — blob response headers + media-type validation |
| V1, V2, V4 | **closed** | Phase 2 — size cap, non-regular refusal, `spawn_blocking`, tower limits |
| V3 | **closed** | Phase 5b — O(1) per-DID ledger totals cache |
| **I8** | **partial** | Phase 5b zeroizes the in-memory seed; the at-rest relocation off the canonical SQLite (KMS / `0600` file outside the backup set) is a **deployment decision** that rotates the live signing identity — documented, not changed inline. |
| **V5** | **partial / tracked** | The Phase-2 concurrency cap bounds burst memory, and the E4 statement rollup bounds ledger-row growth, but a **per-DID storage/row quota** is not yet enforced. It needs a quota-policy product decision (what the limit means and its value); tracked as the remaining hardening item. |

## The criticals, in one paragraph each

**A1 — no auth on the S3 plane.** `PUT`/`GET /{did}/objects`, `/manifest`, and
`/meter` accept anonymous requests. Anyone can write into, read from, enumerate
(`listBlobs`), and read the billing meter of any tenant's namespace. Confirmed
live by PUT/GET/meter against an audit namespace on the production host.

**A2 — the atproto "auth" is a formality (audit F4).** `authed_did`
(`src/pds_api.rs:53`) returns `401` only for an empty bearer; any non-empty
string authenticates and is used *verbatim* as the acting DID. So
`Authorization: Bearer did:plc:victim` writes into the victim's repo, and because
the provider signs a receipt naming that DID (`src/server.rs:398`), CISS emits a
**provider-signed false billing statement against a third party** the victim
cannot repudiate. Confirmed live.

**V1 — one tiny GET OOM-kills the process.** `FsBlobStore::get`
(`src/blobstore.rs:180`) `fs::read`s the whole file into a `Vec` with no size
check. A ~40-byte `GET` whose path resolves (via A3) to `/dev/zero` SIGKILLed the
process in under 500 ms; a 512 MiB file was fully buffered in RAM. `MemoryMax=384M`
means a single unauthenticated request restarts the unit at will. The 2 MiB body
limit guards the request path only, not the response path.

**V2 — synchronous I/O freezes the runtime.** Every handler does synchronous
`fs`/SQLite work inside `async fn` with no `spawn_blocking`. On an N-worker
tokio runtime, N concurrent requests that block in `fs::read` (a FIFO with no
writer, a stalled path) park every worker; a 2-worker runtime stopped answering
`/healthz` entirely. `Restart=always` does not help — the process is alive but
scheduling nothing.

## Cross-cutting fixes (one change closes several findings)

- **`parse_did` / `parse_cid` newtypes at the extractor boundary** (non-empty,
  length-capped, charset-constrained) close I3 and I10, and shrink the attack
  reach of A3, V1, and V2 (a validated `id:`/`did:`/hex identifier cannot select
  `/dev/zero`, a FIFO, or a traversal path). **Highest leverage, smallest change.**
- **Real requester authentication (ADR 0001)** closes A1 and A2, and gates the
  read/write/meter amplification behind a verified identity.
- **`spawn_blocking` + per-object size cap + streamed responses + refuse
  non-regular files** close V1 and V2 and blunt the V3 tail.
- **A versioned, structured signed preimage** binding the leaf multiset,
  `total_bytes`, and a monotonic `seq` closes I1, I2, I5, and I11 together.
- **A tower middleware stack** (`TimeoutLayer` + `ConcurrencyLimitLayer`) closes
  V4 and further blunts V2.
- **Per-DID quota + a running-total cache / pagination** close V3 and V5.

## Verified NOT vulnerable (recorded so these are not re-chased)

- **Request-body memory is bounded** — axum `DefaultBodyLimit` (2 MiB) is in
  force; `413` above it on every body-taking route.
- **No JSON recursion bomb** — a 60 000-deep nested body is rejected `400` by
  `serde_json`'s 128-deep limit; no stack overflow.
- **No attacker-reachable panic** — every `unwrap`/`expect`/`panic!`/index on an
  HTTP-reachable path was traced; each is gated by a prior check (hex/length/type)
  or is infallible on 64-bit. Even a hypothetical handler panic resets one
  connection (tokio unwind boundary), not the process, and the store mutex is
  poison-safe (`PoisonError::into_inner`).
- **No reachable integer overflow** — byte totals are `usize`/`u64` on 64-bit and
  bounded by the body limit; 2⁶⁴ bytes is unreachable. (Release overflow-checks
  are off — add `checked_add` as correctness hygiene, not an availability fix.)
- **No SQL injection** — every statement in `persist.rs` uses positional binds.
- **No timing-sensitive comparison** — there is no shared secret / MAC compared
  anywhere on the request path.
- **No `ETag`/response-header injection** — the `cid` reaching a header has
  already passed the `sha256_hex == cid` gate, so it is always lowercase hex;
  `HeaderValue::from_str` rejects CR/LF regardless.
- **No canonical-serialization collision** — `canonical.rs` sorts keys and relies
  on `serde_json`'s injective escaping.

## Immediate operational note

The host is live and public. DEPLOYMENT.md §6 already says to "treat the
deployment as test/dogfood, not durable-of-record" (R2 backup is set aside).
Until the auth and availability phases land, consider gating `ciss.croft.ing` at
the Caddy front (IP allowlist or basic-auth) or disabling the vhost — an
independent, reversible mitigation that does not wait on the code changes. The
levers are documented in DEPLOYMENT.md §9.
