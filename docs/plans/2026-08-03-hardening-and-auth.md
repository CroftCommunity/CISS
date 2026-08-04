# CISS hardening + authentication — phased plan

- **Date:** 2026-08-03
- **Companion docs:** [`../SECURITY-REVIEW-2026-08-03.md`](../SECURITY-REVIEW-2026-08-03.md)
  (findings + remediation status), [`../adr/0001-auth-and-access-control-model.md`](../adr/0001-auth-and-access-control-model.md)
  (auth-model decision), [`../TESTING-STRATEGY.md`](../TESTING-STRATEGY.md)
  (the workflow test tier).
- **Status (2026-08-04):** Phases 0–5 landed on `main` (TDD-first, one commit per
  phase). All findings closed except I8 (at-rest seed relocation — deployment
  decision) and V5 (per-DID quota — quota-policy decision), both documented in the
  security review. Outstanding feature work: the atproto-identity increment
  (OAuth/DPoP + DID resolution, see the Phase 3 follow-on below). Code only — no
  redeploy yet.

## Problem statement

CISS is live and public (`https://ciss.croft.ing`) and the audit found it is
trivially breakable on all three axes at once:

- **Access:** no real authentication. Anyone reads/writes/enumerates/meters any
  tenant (A1); the atproto bearer is a formality that lets a caller make the
  provider sign false receipts against third parties (A2).
- **Availability:** a single ~40-byte request OOM-kills the process (V1); N
  concurrent blocking requests freeze the runtime including `/healthz` (V2).
- **Integrity:** the manifest that the whole billing story rests on is forgeable
  (I1/I2), and untrusted identifiers reach logs and filesystem paths unvalidated
  (I3/I10/A3).

These must be fixed together and **test-first**: every fix lands as a workflow
flow that fails against today's server (RED) and passes once the fix is in, then
stays as a permanent regression guard.

## Approach

Six phases, each RED-first. Ordering is deliberate: build the harness that makes
TDD possible, then reduce blast radius cheaply, then stop the process-kills, then
the biggest correctness rock (auth), then billing integrity, then the remainder.

```
  Phase 0  Workflow harness (World/Actor)      enables TDD for everything after
     │
  Phase 1  Input scoping (parse_did/parse_cid)  closes I3,I10; shrinks A3,V1,V2
     │
  Phase 2  Availability hardening               closes V1,V2,V4; blunts V3
     │
  Phase 3  Auth + authorization (ADR 0001)      closes A1,A2
     │
  Phase 4  Manifest / billing integrity         closes I1,I2,I5,I6,I7,I11,I12
     │
  Phase 5  Remaining hardening                  closes I4,I8,I9,I13,V3,V5
```

Each phase leaves the crate green and the binary runnable. **Independent of this
plan**, gate or disable `ciss.croft.ing` at the Caddy front now (DEPLOYMENT.md §9)
— a reversible operational mitigation that does not wait on code.

## Reasoning

- **Harness before fixes.** The remediation is relational (multi-actor auth,
  gated reads). Without the `World`/`Actor` tier there is no way to write the RED
  test that defines "done" for the security work, so it comes first.
- **Input scoping before the criticals.** A `parse_did`/`parse_cid` newtype is the
  smallest change with the widest blast-radius reduction: it closes the log-forging
  and identifier-junk findings outright and removes the attacker's ability to
  select `/dev/zero`, a FIFO, or a traversal path — shrinking V1, V2, and A3
  before they are fixed head-on.
- **Availability before auth.** V1/V2 are single-request, unauthenticated process
  kills on a live box; they are the most urgent operational risk and do not depend
  on the auth design.
- **Auth as one rock, not scattered.** Per ADR 0001, authentication (a `ciss-auth`
  crate + tower layer) and authorization (namespace mode bits at `dispatch`) land
  together so there is never a token-present-implies-authorized gap.
- **Integrity with the billing story.** I1/I2/I5 all break the same claim ("rent
  is a pure function of the customer's signed document"); they share one fix — a
  versioned structured signed preimage — so they land together.

---

## Phase 0 — Workflow harness foundation

**Problem:** the test suite has no vocabulary for multi-actor, multi-step,
stateful stories (TESTING-STRATEGY).

**Done means (RED):** the audit PoCs are re-expressed as workflow flows using the
new harness and **fail against today's server** for the right reason —
- anonymous cross-tenant write returns `200` (must become refused) — A1
- `Bearer did:plc:victim` writes into the victim's repo — A2
- a percent-encoded absolute path escapes the data dir — A3
- a single GET of a large/device file exhausts memory — V1
- N concurrent blocking GETs wedge `/healthz` — V2

**Build (GREEN):**
- Extend `tests/common` into `World` (owns a `TestServer` + named namespaces) and
  `Actor` (identity + credential + high-level ops returning typed outcomes:
  `.ok()`, `.refused(status)`, `.returns(bytes)`, `.omits(cid)`).
- `world.anonymous()` for the no-credential caller.
- Port the deleted PoC scenarios into `tests/flows/` as the first flows. They stay
  RED until the phase that fixes each; that is expected and correct.

**Validation:** the flows compile and fail with the documented statuses. No
production code changes in this phase.

## Phase 1 — Input scoping at the boundary

**Problem:** I3 (log forging), I10 (empty/control/unbounded `did`, FS↔SQLite
split-brain); enables A3/V1/V2.

**Done means (RED):** flows asserting that a `did`/`cid`/object-key containing a
newline, NUL, control char, ANSI escape, empty string, over-length value, or path
separator is rejected with `400` **before** it reaches a log line, a filesystem
path, or a SQL bind; and a flow asserting log lines carry no un-escaped untrusted
bytes.

**Build (GREEN):**
- `Did` and `Cid` newtypes with `parse` constructors — non-empty, length-capped,
  charset-constrained (`^(id:[0-9a-f]{16}|did:[a-z]+:[A-Za-z0-9._:%-]+)$` for did;
  hex/CIDv1 for cid). Reject at the axum extractor, before `dispatch`.
- Record untrusted values in `tracing` with `?` (Debug/escaped), never `%`.

**Validation:** the I3/I10 flows go green; the A3/V1/V2 flows still fail (their
head-on fixes are Phases 2–3) but their *reach* is now narrowed — add a flow
asserting a validated identifier can no longer name `/dev/zero` or a traversal
path.

## Phase 2 — Availability hardening

**Problem:** V1 (unbounded `fs::read`), V2 (sync I/O freezes the runtime), V4 (no
timeouts/concurrency limit); blunts V3.

**Done means (RED):** flows asserting —
- a GET of an oversized or non-regular file is refused, not buffered, and RSS stays
  bounded (V1);
- with a small worker count, many concurrent slow/blocking requests do **not**
  stop `/healthz` from answering promptly (V2);
- a request exceeding the timeout is dropped, not held (V4).

**Build (GREEN):**
- Move all `blobstore`/`persist` calls onto `tokio::task::spawn_blocking` (or a
  dedicated blocking pool); never hold an async task on sync fs/SQLite.
- `FsBlobStore::get`: `stat` first, refuse non-regular files, enforce a per-object
  size cap, and stream the response body instead of buffering.
- Harden path construction defensively (reject non-hex `cid`, constrain the join)
  as defense-in-depth behind Phase 1's boundary check — this closes A3 at the
  backend too.
- Add `tower_http::timeout::TimeoutLayer` and `tower::limit::ConcurrencyLimitLayer`
  to the router; add `[profile.release]` with a decision on `overflow-checks`.

**Validation:** the V1/V2/V4 and A3 flows go green; re-run the memory/wedge PoCs.

## Phase 3 — Authentication + authorization (ADR 0001)

**Problem:** A1 (no auth) and A2 (formality auth + forged receipts).

**Done means (RED):** the security-regression and gated-namespace flows —
- anonymous cross-tenant write refused (A1);
- an unverifiable bearer refused; no DID spoofable; no receipt names an unconsented
  DID (A2);
- gated read → `404` to unauthorized, `listBlobs` omits gated CIDs, grant enables,
  revoke disables;
- `read: world` namespaces remain publicly readable (PDS-compat unbroken).

**Build (GREEN):**
- Convert to a Cargo workspace; add the `ciss-auth` crate — authentication only:
  verify DPoP-bound tokens / service-auth JWTs against the DID's resolved signing
  key (cribbed from rsky-pds), return a `Principal`.
- DID resolution: TTL cache, async, hard-timeout, **fail-closed**; a pinned
  admin-DID set resolved locally (poisoning-resistant break-glass).
- Wire `ciss-auth` as a tower layer that attaches `Principal =
  Authenticated(did) | Anonymous`.
- Namespace mode bits `{read_class, write_class}` in the `Store`; enforce
  `authorize(principal, mode, op)` at the `dispatch` boundary. `404` for gated
  denials (no existence oracle).
- Separate the `id:<hex>` and `did:*` identity spaces by type (part of A2).

**Validation:** all Phase-3 flows green; PDS-compat lifecycle flow still green.

### Phase 3 status & tracked follow-on (atproto identity)

**Done (increments 1–2):** the `ciss-auth` crate + a verified signed session over
the **`id:` identity space**, owner authorization at `dispatch`, findings A1/A2
closed. The `id:` space needs no resolution (the DID is the hash of the presented
key).

**OUTSTANDING — atproto identity increment (OAuth/DPoP + DID resolution).** Not
yet built; the `did:plc` / `did:web` spaces and their token verification land
together. Requirements are specified in
[`../adr/0001-auth-and-access-control-model.md`](../adr/0001-auth-and-access-control-model.md)
§5 and repeated here as the tracked checklist so they are not lost:

- handle→DID and DID→signing-key resolution (`did:plc` via plc.directory,
  `did:web` via HTTPS);
- a **runtime TTL cache**; async; **hard-timeout-bounded**; **fail-closed**
  (unresolvable/timed-out ⇒ reject, never fall through);
- a **pinned admin-DID set resolved locally** — break-glass: a poisoned or
  unreachable plc.directory/DNS cannot rotate an admin key, and admin auth still
  works when the resolver is down;
- (later) verify the `did:plc` signed operation log so a poisoned directory
  cannot forge current state.

This is caught inline with the OAuth/DPoP work; until then the interim session is
`id:`-only and replay-limited (no server nonce), as noted above.

## Phase 4 — Manifest / billing integrity

**Problem:** I1 (`total_bytes` unbound), I2 (Merkle padding ambiguous), I5 (replay),
I6 (weak keys / non-strict verify), I7 (64-bit id truncation), I11 (no domain
separation), I12 (unvalidated leaves).

**Done means (RED):** billing-integrity flows —
- declared rent base must equal the recomputed leaf sum, else refused (I1);
- a duplicate-leaf inflation with the same signed root is refused (I2);
- an older signed manifest re-PUT is refused (I5);
- a small-order / non-canonical key is refused (I6);
- two encodings of one key do not yield two identities (I6/I7).

**Build (GREEN):**
- Sign a versioned structured preimage `{version, signer_id, leaf_count,
  total_bytes, root}` (domain-separated, closes I11); recompute `total_bytes` and
  reject mismatch; reject duplicate cids and replace duplicate-last Merkle padding
  with a tagged odd-node rule.
- Add a monotonic `seq`/`epoch` inside the signed preimage; reject `new.seq <=
  stored.seq` (I5).
- `public_key_from_hex`: reject non-canonical encodings and small-order points;
  use `verify_strict` (I6). Use the full digest or a `did:key` encoding (I7).
- Validate leaf `cid` (hex/CIDv1) and cap `size`; `#[serde(deny_unknown_fields)]`
  (I12).

**Validation:** billing-integrity flows green; the README billing claim is true.

## Phase 5 — Remaining hardening

**Problem:** I4 (error-body disclosure), I8 (plaintext provider seed), I9 (blob
response headers), I13 (content-type reflection), V3 (quadratic ledger + mutex
starvation), V5 (unbounded growth).

**Done means (RED):** flows asserting —
- 5xx bodies carry a fixed public string, never a content hash / io / SQLite text
  (I4);
- blob responses carry `X-Content-Type-Options: nosniff` +
  `Content-Disposition: attachment` + a restrictive CSP (I9);
- an oversized/invalid `Content-Type` is rejected or normalized (I13);
- per-request latency does not grow with ledger depth (V3);
- writes past a per-DID quota are refused (V5).

**Build (GREEN):**
- Split internal vs external error representation: log `self` at full fidelity,
  return an enumerated public string per status (I4).
- Move the provider seed off the canonical DB (a `0600` file outside the backup
  set, or the KMS route); wrap in `Zeroize`/`ZeroizeOnDrop` (I8).
- Add blob response headers on both surfaces + the Caddy vhost (I9); validate
  `Content-Type` against a media-type grammar and cap length (I13).
- Cache the per-DID running total (O(1)) or compute via SQL aggregate + index;
  paginate `listBlobs`/`meter`; add per-DID storage/row quotas and a ledger
  rollup/reaper (V3, V5).

**Validation:** full crate suite + all workflow flows green; re-run the audit
PoCs — every one now refused/contained.

---

## Definition of done (whole plan)

- Every finding in the security review has a permanent workflow guard that is
  green.
- `cargo test` (all tiers) and the mutation gate pass.
- The live host answers PDS-compat traffic unbroken and refuses every audit PoC.
- SECURITY-REVIEW, ADR 0001, and this plan are consistent with the shipped code.
