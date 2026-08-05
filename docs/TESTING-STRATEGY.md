# CISS testing strategy

How CISS is tested, and specifically the **workflow test tier** that sits
alongside the pointwise suites. The existing suites are not replaced — this is a
layer above them (the atproto-identity flows, `tests/flow_atproto_identity.rs`, and
the security/quota/hardening flows are live).

## Why a new tier

The current tests are strong but **pointwise**: one server, one implicit actor, a
short linear sequence, one property asserted (see `tests/e86_abuse.rs`,
`tests/wiring_pds_blob.rs`, the `e0`–`e9` suites). That shape is right for pinning
a unit, killing a mutant, or gating dead code.

Authentication is the first feature whose correctness is **relational**, not
pointwise — it lives in the interaction between actors over time:

```
  pointwise (what we have)           relational (what auth needs)
  ─────────────────────────          ────────────────────────────
  "a forged manifest is 400"         owner grants delegate → delegate reads →
  "tamper-at-rest is 500"            owner revokes → delegate now refused →
  "a missing object is 404"          attacker replays the old token → still refused
```

No single-property test expresses that chain. The audit failures are relational
too: "make the provider sign a receipt against a *third party*" is a two-actor
story. So the workflow tier is not optional alongside auth — the workflow tests
**are the RED specification** for the auth build.

## The test tiers

| Tier | Location | Scope | Purpose |
|------|----------|-------|---------|
| Unit / behavior | `#[cfg(test)]` in `src/*.rs` | one function/type | pin behavior, mutation resistance |
| Wiring | `tests/wiring_*.rs` | one feature, end to end | anti-dead-code gate (the feature is really reached) |
| E-suite | `tests/e0..e9.rs`, `e86_abuse.rs` | one protocol property over HTTP | protocol conformance + adversarial single properties |
| **Workflow** | `tests/flow_*.rs` | **multi-actor, multi-step, stateful** | the relational stories: lifecycles, gating, revocation, and every security finding as a permanent guard |

Keep the lower tiers as-is. The workflow tier consumes the same real server over
real HTTP; it adds a persona vocabulary on top, nothing more.

## The harness: `World` + `Actor`

Extend `tests/common` into a small persona layer. An `Actor` holds an identity
and its credential and exposes high-level operations that return typed,
assertable results, so a flow reads as a story rather than URL boilerplate.

Target ergonomics (illustrative — the assertions underneath are the same reqwest
calls the E-suite already makes):

```rust
let world    = World::spawn().await;                      // server + named namespaces
let owner     = world.actor("owner").await;               // holds a DID + a verifiable session
let delegate  = world.actor("delegate").await;
let attacker  = world.anonymous();

world.namespace("owner").set_read(ReadClass::Grantees);   // ADR 0001 mode bits

let cid = owner.upload_blob(b"private").await.ok();
attacker.get_blob("owner", &cid).await.refused(404);      // gated read → 404, no oracle
world.list_blobs("owner").as(&attacker).omits(&cid);      // the gate does not leak CIDs
owner.grant_read("owner", delegate.did()).await;
delegate.get_blob("owner", &cid).await.returns(b"private");
owner.revoke_read("owner", delegate.did()).await;
delegate.get_blob("owner", &cid).await.refused(404);      // revocation takes effect
```

Harness principles:

- **Deterministic.** Identities derive from seeds (as the crypto layer already
  does); no wall-clock, no randomness in assertions. A flow is reproducible.
- **Real server, real HTTP.** `World` owns a `TestServer` on an ephemeral port and
  shuts it down cleanly (port-leak stays observable).
- **Typed outcomes.** `.ok()`, `.refused(status)`, `.returns(bytes)`,
  `.omits(cid)` — a flow asserts intent, not raw status codes scattered inline.
- **Actors carry credentials, not the test.** An `Actor` holds its `id:` session;
  an `AtprotoActor` mints a `did:` service-auth JWT; `world.anonymous()` holds
  none. Swapping who performs a step is a persona choice, so multi-actor
  interaction is first-class.

## Flow catalog (first set)

Each security finding gets a **permanent workflow guard** — a flow that fails
against today's server (RED) and passes once the fix lands, then stays as a
regression wall.

1. **PDS-compat lifecycle** — public read + authenticated write across both the
   S3 and atproto surfaces; upload → meter → manifest → statement close →
   independent rent recompute matches. The happy path, end to end.
2. **Gated-namespace multi-actor** — the snippet above: owner / delegate /
   attacker, grant and revoke, `404` semantics, `listBlobs` omission. Exercises
   ADR 0001's three archetypes (`world`, `grantees`, `owner`).
3. **Security-regression guards** (RED today, promoted from the audit PoCs):
   - anonymous cross-tenant write is refused (A1)
   - a bearer that does not verify is refused; no DID is spoofable (A2)
   - no provider receipt ever names an unconsented DID (A2)
   - a validated identifier cannot select a device/FIFO/traversal path (A3, V1, V2)
   - a single request cannot exhaust memory or wedge the runtime (V1, V2)
4. **Billing-integrity lifecycle** — declared rent base must equal the recomputed
   leaf sum (I1); duplicate-leaf inflation refused (I2); a replayed older manifest
   refused (I5). The billing story, as a flow.
5. **Storage quota** (`tests/flow_storage_quota.rs`, V5) — each quota case as a
   flow: a new store over the store ceiling → `507`; over a configured per-DID cap
   → `507` (distinct body); a dedup write allowed even when full; opportunistic
   fill with no per-DID cap; DIDs share the store opportunistically (multi-actor);
   reads and metering never blocked by a full store.

## TDD mandate

Everything in the remediation plan is **test-driven, RED first**. A phase does not
begin implementation until its workflow flows (and any unit tests) exist and fail
for the right reason. The workflow is the failing test; the implementation is the
minimum code that makes the story pass. This is the cleanest expression of the
project's TDD discipline: the flows in tier 4 above are literally the acceptance
criteria for each phase in
[`plans/2026-08-03-hardening-and-auth.md`](plans/2026-08-03-hardening-and-auth.md).
