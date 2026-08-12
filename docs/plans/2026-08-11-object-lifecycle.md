# Object lifecycle — reclamation (A) and declared retention (B)

date: 2026-08-11
status: **planned, not started.** Scoped from the meer Phase-0 spike (discovery `E95`).
origin: `discovery/alpha/experiments/meer-queue/TEST-LOG.md` (S5), `discovery/alpha/ROADMAP_TODO.md` E95

---

## Problem statement

**CISS cannot delete anything.** The object plane is `PUT` and `GET`; there is no `DELETE`, no
expiry, and no reclamation of any kind. Nothing that is stored ever stops being stored.

This was measured, not inferred — the meer spike swept an expired queue entry, confirmed the queue
served nothing afterwards, and confirmed the object was **still on disk**
(`meer-queue/tests/s5_expiry_watermark.rs`).

Two independent problems follow, and they need different fixes.

### Problem A — nothing ever becomes unreferenced (atproto compatibility)

CISS ships a PDS-compatible blob surface — `uploadBlob`, `getBlob`, `listBlobs` — and **no record
surface**. In atproto, blobs are reclaimed once the records referencing them are deleted. CISS has no
mechanism by which anything ever *becomes* unreferenced, so the compat claim is structurally
incomplete: a caller can put blobs in and never take them out.

This is owed regardless of the meer.

### Problem B — a retention promise the substrate cannot honour

The meer promises mail is held "14 days or until drained." It can stop *serving* an expired entry.
It cannot cause the bytes to go away. Three consequences:

1. **The promise is false as worded.** "Here is what is gone" is not true; "we stopped serving it"
   is. That is the kind of claim that is fine until someone relies on it.
2. **Storage grows monotonically.** The queue-mode deployment profile — *"high write rate / tiny
   objects / 14-day churn / no backup"* — assumes a churn that does not happen. Its sizing follows
   from a false premise.
3. **Ciphertext outlives its window.** Sealed and unreadable today; a harvest-now-decrypt-later
   surface and a durable metadata surface (sizes, timing, counts) that retention was meant to bound.

**Owner decision (2026-08-11): build both.** They are different jobs and neither substitutes for the
other.

## Approach

**Neither half needs a new authenticated destructive endpoint.** That is the point of the design —
a `DELETE` route would be a new destructive path requiring its own authorization story and its own
anti-rollback proof. Both halves instead ride authority CISS already has.

### A — reclamation driven by the signed manifest

The manifest is *already* the owner's signed statement of what should exist. It binds every leaf
(invariant **B1**) and carries a monotonic `seq` refused on rollback (**B3**, enforced at
`src/server.rs:1299`).

So: **an owner signing manifest `N+1` without a leaf has said "I no longer claim this."** That is
authenticated, replay-proof, and already expressible. Reclamation collects objects no manifest
references.

Billing needs no change — byte-days already stop when a leaf leaves the manifest.

### B — a retention dial on the assertion surface

**The mechanism already exists.** CISS has a typed, owner-signed, `seq`-monotonic assertion surface
(`PUT /{did}/assertion/{kind}[/{subkey}]`) whose `kind_fold` **refuses unknown kinds** — *"kinds are
code, not data"* (`src/server.rs:1440`). `POLICY_KIND`, `CEILING_DIAL_KIND` and `PERIOD_DIAL_KIND`
already ride it.

A **retention dial** is one more kind on that surface, following `CeilingDialBody` exactly:

```rust
pub struct RetentionDialBody {
    /// Objects in this namespace are served for at most this many days.
    /// `None` = indefinite (today's behaviour, and the default).
    pub max_age_days: Option<u32>,
}
```

The owner declares it **once**. The server enforces it thereafter **without the owner present** —
which is the whole point, because the meer exists precisely for when the owner is asleep.

Security properties come for free from the surface it rides: the declaration is owner-signed,
`seq`-monotonic (so it cannot be rolled back), and a custodian never sets it, so the party it
constrains cannot weaken it.

### Why B is not blocked on the meer lane

The original E95 sketch assumed retention would live in the typed-chain substrate's *slot
declaration* — meer-lane Phase 1, unbuilt. **It does not need to.** The assertion surface provides
the same guarantees today. B can ship independently and the substrate can adopt it later.

## Reasoning

**Why not a `DELETE` endpoint.** It is the obvious design and the worst one available. It adds an
authenticated destructive path to a service whose security posture is built on *"the customer's
signed manifest is what we owe them"*; it needs its own anti-rollback argument (what stops a replayed
delete?); and it invites exactly the confused-deputy question custodial write was carefully designed
to avoid. Both halves here derive authority from documents the owner already signs.

**Why A and B are not the same mechanism.** A needs the owner **online** to sign a new manifest. B
must work while the owner is **offline** — that is its entire purpose. A mechanism that required
presence could not serve the meer; a mechanism that expired things without a per-item signature
could not be the general-purpose deletion path without becoming a policy engine. Two problems, two
shapes.

**Why the default must be "indefinite".** `max_age_days: None` preserves today's behaviour exactly.
A retention dial that defaulted to *any* finite value would silently start deleting existing
customers' data on upgrade. The dangerous direction is opt-out; this is opt-in.

**What is deliberately not in scope.** Raising `MAX_OBJECT_BYTES`. It is tempting because the server
is ours, but the cap came from the 2026-08-03 security review — a 512 MiB upload buffered entirely in
RAM against a `MemoryMax=384M` unit, so one unauthenticated request could restart the service. Moving
it re-opens that unless streaming replaces buffering first, which is a different piece of work
(**"build streaming uploads"**, not "change a constant").

## Verified assumptions

Confirmed by reading source on 2026-08-11, not from memory:

- **No delete exists.** Object-plane routes are `PUT`/`GET` only — `src/server.rs:373–396`. No
  `DELETE` on objects, manifest, assertion, or the PDS surface. No GC, reclamation, or
  unreferenced-object sweep anywhere in `src/`.
- **The manifest is signed, binds its leaves, and is `seq`-monotonic.** `src/manifest.rs` (I1, I5);
  rollback refused at `src/server.rs:1299` (`manifest.seq() <= existing.seq()`).
- **The assertion surface is typed and fails closed on unknown kinds.** `kind_fold` at
  `src/server.rs:1440` — *"An unknown kind is refused — kinds are code, not data."* Existing kinds:
  `POLICY_KIND`, `CEILING_DIAL_KIND`, `PERIOD_DIAL_KIND`. Assertion rollback refused at
  `src/server.rs:1585`.
- **`CeilingDialBody`** (`src/dials.rs:24`) is the pattern to copy — an owner-asserted dial with
  `Option` fields, a canonical fold, and server-side enforcement.
- **Objects are laid out per namespace:** `blocks/{did}/{cid}` — so reclamation is scoped to a
  namespace and never crosses one.

## Open questions

- **[BLOCKING — Phase 0 resolves]** *Can an object be `PUT` and never appear in a manifest?* If yes,
  A cannot treat "absent from the manifest" as "unwanted" without destroying the normal
  put-then-manifest window. Likely needs a grace period, or reclamation restricted to objects that
  were manifested at least once. **This decides whether A is safe at all**, so it is Phase 0's first
  probe.
- **[PHASE-GATED — Phase 3]** *Is retention per namespace, or per object?* The dial above is
  namespace-wide. A queue wants namespace-wide; a general customer might want per-object. The
  assertion surface supports a `subkey`, so per-object is expressible — but it is more state and more
  enforcement surface. Start namespace-wide.
- **[ADVISORY]** *Does reclamation need a tombstone, or is silence enough?* A reader fetching a
  reclaimed cid currently gets a 404. The meer's watermark already carries the "you missed something"
  story at the queue layer, so a storage-layer tombstone may be redundant.

## Phases

Each leaves the system working. TDD throughout: RED first, mutation-check the load-bearing
assertions, commit the green state before mutating.

### Phase 0 — Discovery (blocking)

- [ ] **D1: Can an object be PUT and never manifested?** Probe: PUT an object, never manifest it,
      read `du` and the blob directory. **Decides whether A is safe as specified.**
- [ ] **D2: What is the manifest→object relationship at read time?** Does `GET /{did}/objects/{cid}`
      consult the manifest at all, or only the blobstore? Determines where a reclamation check lives.
- [ ] **D3: Confirm the assertion surface accepts a new kind cleanly.** Add a throwaway kind, PUT and
      GET it, confirm `kind_fold` refuses a malformed body and an unknown kind.
- [ ] **D4: Does anything already read `deposited_at` / object age?** The meter tracks byte-days, so
      a per-object timestamp may already exist. If it does, B's enforcement is a read, not a new
      column.

**Done when:** the manifest/object coupling is understood well enough that A cannot delete live data.

### Phase 1 — The retention dial (B, declaration half)

**Goal:** an owner can declare a retention window; it round-trips and is refused when malformed.
**Changes:** `src/dials.rs` (`RetentionDialBody` + fold), `src/server.rs` (`RETENTION_DIAL_KIND` in
`kind_fold`), `tests/` a new assertion wiring test.
**Wiring test:** `PUT /{did}/assertion/retention` with a valid body round-trips via `GET`; a
malformed body is refused; a stale `seq` is refused; **an unknown kind is still refused** (the
fail-closed property must not regress).
**Done when:** the dial is declarable and readable end to end over HTTP. Nothing expires yet.

### Phase 2 — Enforcement (B, expiry half)

**Goal:** objects past the declared window stop being served.
**Changes:** the read path consults the resolved retention dial; a sweep reclaims expired objects.
**Wiring test:** with `max_age_days = 14`, an object aged 14 days is **served**, one aged 15 is
**not** — both edges, since this is a comparison and an off-by-one would otherwise survive. With no
dial declared, nothing ever expires (the default must be inert).
**Risk:** the default. A bug here deletes customer data on upgrade. `None` must mean indefinite, and
the test asserting that is the most important one in this plan.

### Phase 3 — Manifest-driven reclamation (A)

**Goal:** an object no manifest references becomes reclaimable.
**Changes:** reclamation pass keyed on the current manifest per namespace, honouring whatever grace
rule D1 forces.
**Wiring test:** manifest `N` lists an object; manifest `N+1` omits it; after reclamation the object
is gone and `du` reflects it. **And the negative:** an object still listed is never touched, and an
object never manifested is not destroyed inside the put-then-manifest window.
**Done when:** signing a manifest without a leaf actually reclaims the bytes.

### Phase 4 — Close the atproto half and document

**Goal:** the PDS-compat claim is true, and the promise language matches the mechanism.
**Changes:** `docs/` — record that reclamation is manifest-driven; update `SECURITY-POSTURE.md` with
the new reclamation path and its authority argument; note the retention dial in the API surface docs.
**Done when:** a reader can see how an object stops existing, and by whose signature.

## Documentation impact

- `docs/SECURITY-POSTURE.md` — reclamation is a new state transition; its authority (B1/B3 via the
  manifest, `seq`-monotonic assertion for the dial) belongs beside the existing invariants. Phase 4.
- `docs/` API surface — the new assertion kind. Phase 1.
- `CHANGELOG.md` — both halves. Phases 2 and 3.
- `discovery/alpha/ROADMAP_TODO.md` **E95** — status transitions as phases land. Ongoing.
- `discovery/alpha/thinking/meer-as-custodian-queue.md` — the S5 correction can be softened once B
  ships, because the retention promise becomes true. **Not before.** Phase 2.
