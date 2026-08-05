# Plan — gated reads (the authorization layer)

- **Date:** 2026-08-05 · **Status:** Pass 1 complete (phase-plan skill) · **TDD-first**
- **Owns:** ADR 0001 §2 (namespace mode bits) + its grain reopening; closes the
  standing gap `SECURITY-POSTURE.md` §14.1. **Contract:** `docs/spec/gated-reads.md`.

---

## Problem Statement

Authentication is complete (`id:` session + `did:` service-auth JWT). Read
**authorization** is still flat: every object/blob read and `listBlobs` is
world-readable (invariant Z1) — exact PDS-compat, but CISS needs *private* reads
for two use cases with no enforcement today (posture §14.1): the
**history-convergence** backend (range/repo readable only by grantees) and
**private-PDS per-object sharing** (a blob shared with a named DID list). The
load-bearing risk is **leakage**: a denied read must not become an existence
oracle, and `listBlobs` must not enumerate hidden objects.

## Reasoning

- **Both grains, composed** (namespace default + per-object override). The two use
  cases differ in grain; one grain forces either bloated namespace exceptions or a
  full ACL per object. Namespace + object override is the minimal composition (Unix
  dir-mode + per-file ACL). *Rejected:* namespace-only (can't share one blob),
  object-only (bloats every object for a whole-repo gate).
- **Owner-signed policy record, dedicated (not on the manifest).** CISS trusts
  owner-signed artifacts (the manifest, Z3) for durable authority. A dedicated
  record keeps the **billing** signature (manifest, B-tier) and the **authz**
  signature distinct — a grant/revoke never re-signs the rent base — and makes
  per-object policy first-class. *Rejected:* a manifest field (couples billing +
  authz; per-object bloats a whole-namespace doc). *Rejected:* a session-set flag
  (provenance is "whoever held a session," not a durable verifiable artifact).
- **404-on-deny + `listBlobs` omission.** A gate that 403s or lists hidden CIDs
  leaks what it protects. Oracle-free denial (ADR 0001 §2).
- **Reads only in v1.** Writes are already owner-only (Z2) and safe; read-gating is
  the missing capability. Delegated writes add a consent model — deferred.
- **Two owner-authorization forms in v1 (Model A + Model C).** Who may *set* policy
  depends on whether the owner holds a signing key locally:
  - **Model A — owner-signed (`id:` owners).** A Croft-native owner holds its
    ed25519 key (the DID is its hash), so it signs the policy record itself — a
    durable, self-contained, content-binding proof (like the manifest, Z3). Serves
    provider/native owners (e.g. the history-convergence backend).
  - **Model C — provider-attested (external-provider / `did:` owners).** An owner
    whose key lives at an **external identity provider** (offloaded auth — today
    bsky via `account.croft.ing`, but the mechanism is the atproto service-auth path,
    not bsky-specific) cannot self-sign. It instead presents a **service-auth JWT**
    (`iss`=owner DID, `aud`=CISS, `lxm`=the set-policy method, ~60s) — the provider
    vouches, via the owner's repo key, that the owner authorized a set-policy *action*.
    CISS verifies that JWT (reusing the Model-R path already built), then
    **counter-signs the resulting policy record with the provider key** (domain-
    separated preimage) so the stored record is durably verifiable on later reads.
  - *Why both, now (vs deferring C):* the two use cases split across the two owner
    populations — history-convergence is `id:`-owned (A), private-PDS per-object
    sharing is external-provider-owned (C) — so shipping only A would leave the
    second use case unbuilt. C reuses the service-auth verification we already have;
    the only new crypto is the provider counter-sign. *Rejected:* Model B (JWT-
    authorized but **not** re-signed) — the record would then have only transient
    (session) provenance; C's counter-sign restores durable provenance at write time.
    The residual property (the JWT authorizes the *action*, not the *bytes*; content
    integrity in transit rests on TLS + short `exp` + single-use `jti`) is **identical
    to how `uploadBlob` already works**, so C is no weaker than what CISS ships today.

## Verified Assumptions

Confirmed firsthand against the code (2026-08-05):

- **The authz choke point is `server::authorize(principal, op)`** (`src/server.rs:731`),
  called by `dispatch(state, principal, op)`. Today `GetObject | ListBlobs => Ok(())`.
  **`authorize` is pure — it has no `Store`/state access.** Policy resolution needs
  the `Store`, so the policy gate lands in **`dispatch`** (which holds `state`) after
  the base `authorize`, or `authorize` gains `&AppState`. Chosen: gate in `dispatch`
  (keeps the single choke point; `authorize` stays a pure policy function fed the
  resolved policy). *Evidence:* `src/server.rs:731-745`, `dispatch` sig.
- **`ServerError::NotFound → 404`** (`src/server.rs:1230,1302`); `Forbidden → 403`,
  `Unauthorized → 401`. Deny maps to `NotFound`. *Evidence:* `src/server.rs:1299-1308`.
- **`Op::GetObject { did, cid }`** carries the cid; `Op::ListBlobs { did }`. Handlers
  `op_get_object(state, did, cid)` (`:878`), `op_list_blobs(state, did)` (`:1027`).
  *Evidence:* `src/server.rs:463-492,878,1027`.
- **Owner-signed record pattern = the manifest**, and it is **`id:`-space / ed25519**:
  domain `"ciss/v1/manifest"`, `signing_preimage(signer_id, seq, leaf_count,
  total_bytes, root)` (`src/manifest.rs:115`), `Manifest::verify(customer_key:
  &VerifyingKey)` (`:168`, ed25519-dalek), `Manifest::seq()` (`:152`). The policy
  record mirrors this shape with domain `"ciss/v1/policy"`. *Evidence:*
  `src/manifest.rs:32,115,152,168`.
- **A `did:` owner does not hold a repo signing key client-side** (their atproto key
  lives at their PDS; they authenticate to CISS via a service-auth JWT, not by
  signing arbitrary records). So the owner-**signed**-record model verifies cleanly
  only for **`id:` owners** (ed25519, like the manifest). This drives Open Question 1.
- **Persistence pattern:** `CREATE TABLE IF NOT EXISTS` in the init block
  (`src/persist.rs:160+`), defensive `ALTER TABLE … ADD COLUMN` (`:199`), upsert
  `save_manifest` (`:245`) / `load_manifest` (`:259`). Policy tables mirror this.
  *Evidence:* `src/persist.rs:160-262`.
- **Flow harness** supports owner-signed writes and the assertions we need: the
  forged/replayed manifest is guarded in `tests/flow_billing_integrity.rs`, and
  `Outcome` has `.ok/.refused/.returns/.omits/.discloses` (`tests/common/mod.rs`).
  Gated-read flows + a policy `PUT` mirror the manifest flow. *Evidence:*
  `tests/flow_billing_integrity.rs`, `tests/common/mod.rs` `Outcome`.

## Documentation Impact

- `docs/spec/gated-reads.md` — flip `[PLANNED build]` sections to live as they land:
  §3/§5 in **Phase 3–4**, §6 wire in **Phase 5**; change log each time.
- `docs/SECURITY-POSTURE.md` — new invariants + close §14.1 gap in **Phase 7**.
- `docs/adr/0001-auth-and-access-control-model.md` — record the resolved §2 grain
  decision + policy-record shape in **Phase 7**.
- `README.md` / `docs/ARCHITECTURE.md` — grepped: describe reads as "world-readable"
  (README security summary, ARCH §5). Add the gated-read capability line in
  **Phase 7** (search terms: `world-readable`, `listBlobs`, `Z1`).
- No croft-stack doc impact (additive, in-repo schema; no deploy/unit change).

## Concurrency Map

**All phases sequential** (8 phases): record(1) → storage(2) → dispatch gate(3) →
listBlobs(4) → id:-owner write(5) → did:-owner write + attestation(6) → corpus(7) →
docs(8). Each reads what the prior wrote, and Phases 3–6 all write `src/server.rs`,
so their write-sets overlap. No parallelism.

## Phases (TDD-first — RED before GREEN, commit per phase)

**Testing doctrine (cross-cutting):** every phase tests the **should-NOT** path, not
just the happy path — a gate is only as trustworthy as its denials. Each phase's
`Done when` pairs an *allow* case with its *deny* case (Phase 1: verify vs
refuse-forgery/replay; Phase 3: grantee-reads vs non-grantee-404; Phase 4:
grantee-sees vs non-grantee-omitted; Phase 5: grant-works vs wrong-signer-refused),
and Phase 6 is the comprehensive matrix. A regression that opens the gate must break
a test, by construction.

### Phase 1 — The signed policy record (pure)

- **Goal:** a `PolicyRecord` that verifies under **either** authorization form
  (owner-signed A, or provider-attested C) with a monotonic `seq`.
- **Changes:**
  - [ ] `src/policy.rs` — `PolicyRecord { target, read_class, readers, seq,
    authorization }` where `authorization = OwnerSigned{signer, sig} |
    ProviderAttested{owner_did, authorizing_jti, provider_sig}`;
    `ReadClass{World,Grantees,Owner}`; `verify_policy(record, prior_seq,
    provider_pubkey)`:
    - `OwnerSigned` → verify ed25519 `sig` over `ciss/v1/policy:<target>:<seq>:…`
      and `derive_id(signer) == target-DID` (Model A, `id:` owner);
    - `ProviderAttested` → verify the **provider** `sig` over
      `ciss/v1/policy-attest:<owner_did>:<target>:<seq>:…` under `provider_pubkey`
      (Model C — CISS's durable attestation that it checked a valid owner JWT).
  - [ ] `src/lib.rs` — `pub mod policy;`.
- **Call chain:** (none yet — pure module; wired at Phase 2 `put_policy` / Phase 3
  `dispatch`). Named here so it is not left dangling: `dispatch → resolve_policy →
  {policy record}` and `PUT /policy handler → verify_policy → save_policy`.
- **Wiring test:** deferred to Phase 2 (first consumer); Phase 1 is unit-only by
  nature (a pure verifier), noted so it is not mistaken for dead code.
- **Depends on:** none.
- **Read-set:** `src/manifest.rs` (preimage pattern), `src/canonical.rs`, `src/crypto.rs`.
- **Write-set:** `src/policy.rs`, `src/lib.rs`.
- **Shared-state contract:** none beyond the file write-set (pure).
- **Risks:** ed25519-only signer (Open Q1) — v1 verifies `id:`/ed25519 owners.
- **Done when:**
  1. *Behavioral:* a policy record signed by the owner ed25519 key that derives the
     target DID verifies; a forged signer, wrong-DID signer, replayed/lower `seq`,
     malformed `readers[]`, or post-sign tamper is refused.
  2. *Verification:* `cargo test -p ciss --lib policy::`.
- **Validation:** narrow — unit tests sufficient; add a preimage round-trip prop test.

### Phase 2 — Policy storage + resolution (`persist::Store`)

- **Goal:** persist verified policy per target; `resolve_policy` with finest-grain-wins,
  monotonic supersede, fail-closed.
- **Changes:**
  - [ ] `src/persist.rs` — `namespace_policy(did PK,…)` + `object_policy((did,cid) PK,…)`
    tables (in the init block); `save_policy(verified)` (seq-monotonic guard in-txn);
    `resolve_policy(did, cid) -> ResolvedPolicy`.
- **Call chain:** `server::dispatch → Store::resolve_policy` (Phase 3);
  `PUT /policy handler → Store::save_policy` (Phase 5).
- **Wiring test:** `tests/wiring_persist.rs` (or a new `wiring_policy`) proves
  `save_policy`→`resolve_policy` round-trips through a real `Store`.
- **Depends on:** Phase 1 (`verify_policy`, `PolicyRecord`).
- **Read-set:** `src/policy.rs`.
- **Write-set:** `src/persist.rs`.
- **Shared-state contract:** the SQLite `Store` (in-process, `Arc<Mutex>`); additive
  schema, no migration of existing rows.
- **Risks:** a malformed stored row must fail closed (never widen); test explicitly.
- **Done when:**
  1. *Behavioral:* an object policy overrides a namespace policy which overrides the
     `world` default; a higher `seq` supersedes, equal/lower is rejected; an
     unparseable row resolves to the tighter of {stored, default}, never permissive.
  2. *Verification:* `cargo test -p ciss --lib persist::` + the wiring test.
- **Validation:** moderate — unit + wiring; confirm the existing `persist`/quota
  suites stay green (additive schema).

### Phase 3 — Authorize reads at `dispatch` (the choke point)

- **Goal:** gate `getBlob`/object GET by policy; deny → 404; `world` unchanged.
- **Changes:**
  - [ ] `src/server.rs` — in `dispatch`, for read ops resolve
    `state.store.resolve_policy(did, cid)` and evaluate membership against the
    `Principal`; deny → `ServerError::NotFound`. Keep `authorize` a pure fn fed the
    resolved policy (world → allow fast path when no row).
- **Call chain:** `get_object_handler / pds getBlob → dispatch → resolve_policy →
  authorize(policy, principal) → op_get_object | NotFound`.
- **Wiring test:** `tests/wiring_s3_metered.rs` / `wiring_pds_blob.rs` extended (or a
  new gated case) — a gated object GET through the real handler returns 404 to a
  non-grantee and bytes to a grantee.
- **Depends on:** Phase 2.
- **Read-set:** `src/policy.rs`, `src/persist.rs`.
- **Write-set:** `src/server.rs`.
- **Shared-state contract:** none beyond the `Store` read; no route changes.
- **Risks:** the world fast-path must add ≤1 indexed lookup on the hot path; a
  regression that 404s a public read is a PDS-compat break — guarded explicitly.
- **Done when:**
  1. *Behavioral:* `world`/default → allow (public read unbroken); `grantees`/`owner`
     → allow iff caller is owner or in `readers`; a non-grantee/anon gated GET → 404;
     the owner always reads its own gated object.
  2. *Verification:* `cargo test --test wiring_pds_blob --test wiring_s3_metered` +
     `--lib server::` gated cases.
- **Validation:** moderate — wiring + the pre-existing read flows still green.

### Phase 4 — `listBlobs` omission (no CID leak)

- **Goal:** `listBlobs` returns only objects the caller may read.
- **Changes:**
  - [ ] `src/server.rs` — `op_list_blobs` filters each cid through `resolve_policy` +
    the Phase-3 membership check for the requesting `Principal`; batch per DID.
- **Call chain:** `pds listBlobs → dispatch → op_list_blobs → per-cid resolve_policy
  + membership → filtered cids`.
- **Wiring test:** `tests/wiring_pds_blob.rs` — listBlobs over a DID with mixed
  public/gated objects returns only the caller-visible cids through the real handler.
- **Depends on:** Phase 3 (membership), Phase 2.
- **Read-set:** `src/policy.rs`, `src/persist.rs`.
- **Write-set:** `src/server.rs`.
- **Shared-state contract:** `Store` reads only.
- **Risks:** N+1 policy lookups on large namespaces — batch the lookups per DID
  (validate).
- **Done when:**
  1. *Behavioral:* anon sees only `world` cids; a grantee sees `world` + granted; the
     owner sees all; hidden cids are neither listed nor counted.
  2. *Verification:* `cargo test --test wiring_pds_blob -k listBlobs`.
- **Validation:** moderate — wiring; ungated DIDs' listBlobs unchanged.

### Phase 5 — `id:`-owner policy write over HTTP (Model A)

- **Goal:** an `id:` owner sets/changes policy by submitting a self-signed record;
  reads honor it live.
- **Changes:**
  - [ ] `src/server.rs` — `put_policy_handler` (namespace) + object variant:
    `verify_policy` (`OwnerSigned`) → `save_policy`; read-back `GET`; error mappings
    (bad-sig/lower-seq → distinct 4xx).
  - [ ] router — `PUT/GET /{did}/policy` and `/{did}/objects/{cid}/policy` (mirror the
    manifest handler shape).
- **Call chain:** `PUT /{did}/policy → put_policy_handler → verify_policy(OwnerSigned)
  → Store::save_policy`; subsequent `getBlob/listBlobs` reflect it via Phase 3–4.
- **Wiring test:** the first `flow_gated_reads` step — an `id:` owner sets
  `grantees:[alice]` over HTTP, then alice reads / bob 404s.
- **Depends on:** Phases 1–4.
- **Read-set:** `src/policy.rs`, `src/persist.rs`, `src/pds_api.rs` (handler shape).
- **Write-set:** `src/server.rs`.
- **Shared-state contract:** `Store` writes (policy tables); no other unit/route.
- **Risks:** wrong-signer / lower-seq must be refused (no un-revoke) — tested.
- **Done when:**
  1. *Behavioral:* over HTTP — `id:` owner sets grantees→alice reads/bob 404; grant
     bob (higher seq)→bob reads; revoke (higher seq)→bob 404; per-object `world`
     override makes one blob public; wrong-signer/lower-seq refused; owner read-back.
  2. *Verification:* `cargo test --test flow_gated_reads` (the id:-owner lifecycle).
- **Validation:** broad — the lifecycle over real HTTP; manifest/quota unaffected.

### Phase 6 — `did:`-owner policy write via service-auth JWT + provider attestation (Model C)

- **Goal:** an external-provider (`did:`) owner sets policy by presenting a service-
  auth JWT; CISS verifies it and counter-signs the resulting record for durability.
- **Changes:**
  - [ ] Define the set-policy lexicon method id (proposed `ing.croft.ciss.setPolicy`)
    as a constant; the JWT's `lxm` must equal it, `aud` == CISS service DID, `iss` ==
    the target-owning DID.
  - [ ] `src/server.rs` — the policy handlers accept an alternate authorization: a
    `Bearer` service-auth JWT + a **policy body** (readers/read_class/seq). Verify the
    JWT via `ciss_auth::verify_service_auth_jwt` (reused, with `lxm`=set-policy); on
    success, construct the `PolicyRecord`, **provider-attest** it (sign
    `ciss/v1/policy-attest:…` with the provider key), and `save_policy`.
  - [ ] `src/server.rs` / provider — a `provider.attest_policy(record)` signing helper
    (domain-separated preimage; provider key). The stored record is `ProviderAttested`.
- **Call chain:** `PUT /{did}/policy (Bearer jwt + body) → put_policy_handler →
  verify_service_auth_jwt(lxm=setPolicy, aud=CISS) → provider.attest_policy →
  Store::save_policy`; reads verify the provider attestation (Phase 3).
- **Wiring test:** a `did:` (AtprotoActor) owner sets `grantees:[alice]` with a
  service-auth JWT; the stored record is `ProviderAttested`; alice reads / bob 404s;
  a JWT with the wrong `lxm`/`aud`, expired, or a replayed `jti` → refused, no write.
- **Depends on:** Phases 1–5, and the built atproto-identity path (`ciss-auth`).
- **Read-set:** `src/policy.rs`, `src/persist.rs`, `crates/ciss-auth` (verify),
  `src/receipts.rs`/`src/crypto.rs` (provider signing).
- **Write-set:** `src/server.rs` (+ a small provider signing helper).
- **Shared-state contract:** `Store` writes; the provider key (read for attestation —
  never logged). Reuses the `ReplayGuard` for the set-policy `jti`.
- **Risks:** the JWT authorizes the *action*, not the *bytes* — content integrity in
  transit rests on TLS + short `exp` + single-use `jti` (identical to `uploadBlob`);
  the provider attestation makes the *result* durable. Do not reuse a bare provider
  key without domain separation (Open Q: attestation key).
- **Done when:**
  1. *Behavioral:* a `did:` owner sets policy over HTTP via a valid service-auth JWT;
     the record persists as `ProviderAttested` and gates reads exactly as Model A; a
     wrong-`lxm`/`aud`/expired/replayed JWT is refused with no policy change.
  2. *Verification:* `cargo test --test flow_gated_reads` (the did:-owner lifecycle).
- **Validation:** broad — real HTTP with a minted service-auth JWT (harness
  `AtprotoActor`); confirm the attestation verifies on read and the JWT is single-use.

### Phase 7 — Flow corpus (permanent regression guards)

- **Goal:** the relational stories as permanent guards — **comprehensive on both
  sides**: every *should-work* and every *should-NOT-work* is its own flow, so the
  gate can never silently regress open. The should-NOT cases are the point.
- **Changes:**
  - [ ] `tests/flow_gated_reads.rs` — the full matrix:
    - **Positive (should work):** owner reads own gated object; a grantee reads a
      granted object; grant→read; revoke→re-grant→read; a per-object `world` override
      exposes just that blob; a `world`/ungated object stays publicly readable
      (PDS-compat regression guard — the gate never over-reaches).
    - **Negative (should NOT — access denied):** anon → gated object = 404 (not the
      bytes); a non-grantee `did:` → 404; a **revoked** grantee → 404 (revocation
      actually bites); a gated object under a `world` namespace is still gated (the
      default does not leak an object); cross-DID — alice's grant on *her* namespace
      does not admit her to bob's gated namespace.
    - **Negative (should NOT — leakage):** `listBlobs` omits every hidden cid for
      anon/non-grantee (neither listed **nor** counted); a 404 is indistinguishable
      from not-found (no existence oracle); a grantee's policy read-back does not
      disclose the full `readers[]` (Open Q2).
    - **Adversarial (should NOT — forgery/rollback):** a **forged** policy (attacker
      signs a policy naming a victim's target) → refused, access unchanged; a
      **replayed lower-`seq`** policy (an old permissive policy re-submitted to
      un-revoke) → refused; a **tampered** policy (fields changed after signing) →
      refused; a policy signed by a key that does not derive the target DID →
      refused; **setting policy without owner authority** (anon/another DID) →
      refused, no policy change.
    - **Both owner forms (Model A + C):** repeat the grant/revoke/override + the
      adversarial cases for an **`id:` owner** (self-signed) *and* a **`did:` owner**
      (service-auth JWT + provider attestation) — the gate behaves identically on
      read regardless of how the policy was authored; a `did:`-owner set with a
      wrong-`lxm`/`aud`/expired/replayed JWT is refused with no write.
  - Each flow uses the intent-named `Outcome` asserts (`.refused(404)`, `.omits(cid)`,
    `.returns(bytes)`); a should-NOT flow that *passes as allowed* fails loudly.
- **Call chain:** the harness drives the real server end-to-end (World/Actor +
  AtprotoActor as readers).
- **Wiring test:** the file *is* the wiring corpus.
- **Depends on:** Phases 1–6.
- **Read-set:** `tests/common/mod.rs`.
- **Write-set:** `tests/flow_gated_reads.rs` (+ small `tests/common/mod.rs` helpers
  for a policy-PUT/Actor if needed).
- **Shared-state contract:** ephemeral test servers (loopback), `Drop` cleanup.
- **Risks:** none beyond harness flakiness; keep each flow hermetic.
- **Done when:**
  1. *Behavioral:* every listed story passes; a forged/replayed policy cannot widen
     access.
  2. *Verification:* `cargo test --test flow_gated_reads` (all green) + the 26
     pre-existing flow tests still green.
- **Validation:** broad — the corpus is the end-to-end proof.

### Phase 8 — Posture + ADR + spec/README (docs finalization)

- **Goal:** record the design intent as invariants and close the tracked gap.
- **Changes:**
  - [ ] `docs/SECURITY-POSTURE.md` — invariants: owner-signed policy, authorize-read-
    at-dispatch, 404-on-deny, listBlobs omission, monotonic-seq anti-rollback; close
    §14.1.
  - [ ] `docs/adr/0001-…md` — resolved §2 grain decision + policy-record shape.
  - [ ] `docs/spec/gated-reads.md` — flip settled sections to live; change log.
  - [ ] `README.md` / `docs/ARCHITECTURE.md` — add the gated-read capability line.
- **Call chain:** n/a (docs).
- **Wiring test:** n/a.
- **Depends on:** Phases 1–7 (documents what is now true + green).
- **Read-set:** the built code (to describe it accurately).
- **Write-set:** the four doc files.
- **Shared-state contract:** none.
- **Risks:** doc/code drift — write after green so claims are true.
- **Done when:**
  1. *Behavioral:* posture/ADR/spec/README agree with the shipped behavior; §14.1
     gated-read gap is closed.
  2. *Verification:* manual review; `cargo test --workspace` + `clippy` clean.
- **Validation:** narrow — prose accuracy against the green suite.

## Rollout / risk

- **Additive + reads-only.** No write path or existing read changes until an owner
  writes a non-`world` policy, so the increment merges and deploys **dark**; gating a
  namespace is then a reversible data op (a higher-`seq` `world` policy un-gates).
  Low blast radius.
- **Perf.** One indexed policy lookup per read (short-circuited for the `world`
  default); `listBlobs` batches per DID (Phase 4 validation watches fan-out).
- **Deploy.** Normal CISS release; additive schema created on `Store` open. No
  croft-stack change.

## Open Questions

- **[RESOLVED 2026-08-05] Who may *set* policy in v1?** **Both** `id:` owners
  (Model A, self-signed) **and** external-provider `did:` owners (Model C, service-
  auth JWT + CISS provider counter-sign). Readers/grantees may be any DID. See the
  Reasoning "Two owner-authorization forms" note; the phases below build both.
- **[RECOMMENDED: ADVISORY] The set-policy lexicon method name.** Model C's JWT must
  be `lxm`-bound to a CISS-defined method (proposed `ing.croft.ciss.setPolicy`).
  *Recommendation:* pick the name in Phase 6; any non-atproto-protected string works
  (the provider signs an arbitrary `lxm`). *Rationale: a naming detail, not a blocker.*
- **[RECOMMENDED: ADVISORY] Provider attestation key: domain-separation vs a sub-key.**
  Model C counter-signs with the provider key over a domain-separated preimage
  (`ciss/v1/policy-attest`), safe to share the receipt-signing key. *Recommendation:*
  domain-separation in v1; a dedicated attestation sub-key (independent rotation) is
  the upgrade. *Rationale: blast-radius nicety, not a v1 blocker.*
- **[RECOMMENDED: PHASE-GATED (Phase 5)] Grantee visibility of `readers[]`.** On
  policy read-back, does a grantee see the full reader list, or only that it may
  read? *Recommendation:* owner-only full visibility (a grantee learns only its own
  access), to avoid leaking the grantee set. *Rationale: a disclosure choice, safe to
  fix at the wire phase; spec §6 flagged it.*

## Review Log

- **2026-08-05 — Pass 1 (phase-plan skill).** Built the base: problem, reasoning
  (+rejected alternatives), Verified Assumptions (grounded firsthand in
  `server.rs`/`manifest.rs`/`persist.rs`), Documentation Impact, Concurrency Map
  (all sequential), seven phases with Call-chain/Wiring-test/Read-Write-sets/Done-when,
  Rollout/risk. **Grounding surfaced two open questions** (id:-vs-did: policy-setting
  authority; grantee readers[] visibility) and one design fact (the policy gate lands
  in `dispatch`, not the pure `authorize`). Split the docs finalization into its own
  Phase 7 (4-file rule). Pending: Pass 2 (gap analysis), Pass 3 (quality gates).
- **2026-08-05 — Pass 1 addendum (user).** Made comprehensive **should-NOT**
  coverage a first-class, cross-cutting requirement (regression protection): added a
  Testing-doctrine note (every phase pairs allow+deny) and expanded the corpus into
  the full positive/negative/leakage/adversarial matrix.
- **2026-08-05 — Q1 resolved: Model A + C in v1 (user).** Decided to build *both*
  owner-authorization paths now, not defer the external-provider (`did:`) owner.
  Reframed the axis as "offloaded auth to an external identity provider (today bsky,
  not bsky-bound)." Changes: added the "Two owner-authorization forms" reasoning; the
  `PolicyRecord` now carries `OwnerSigned | ProviderAttested` (Phase 1); **split the
  write into Phase 5 (`id:` self-signed) + new Phase 6 (`did:` service-auth JWT +
  provider counter-sign, reusing `ciss-auth::verify_service_auth_jwt`)**; renumbered
  corpus→7 (now covers both owner forms) and docs→8; two new ADVISORY questions (the
  set-policy `lxm` name; attestation-key domain-sep vs sub-key). Grew 7→8 phases.
  **Scope change is material — warrants a Pass 2 gap analysis before execution.**
