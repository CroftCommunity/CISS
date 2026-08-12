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

> **CORRECTED 2026-08-11, before any code was written.** The first draft of this section said
> *"reclamation collects objects no manifest references."* **That would have deleted nearly
> everything.** See "The manifest is not an index" below.

The manifest is the owner's signed statement of what they **claim to be keeping**. It binds every
leaf (invariant **B1**) and carries a monotonic `seq` refused on rollback (**B3**,
`src/server.rs:1299`). So an owner signing manifest `N+1` **without** a leaf that manifest `N`
**did** carry is an authenticated, replay-proof *"I no longer claim this."*

**That is the only safe signal, and it is narrower than "absent from the manifest."**

#### The manifest is not an index of what exists

Verified in source, and it invalidates the obvious design:

- **`op_put_object` never touches the manifest** (`src/server.rs:1030`). It gates on quota and the
  spend ceiling, writes to the blobstore, and records a receipt. Nothing more.
- **`op_du` reads receipts, not the manifest** (`src/server.rs:1399`, `:1414`).
- The Phase-0 meer probe corroborates it empirically: `d2_ciss_put.rs` PUTs four objects, never
  writes a manifest, and all four store, serve, and appear in `du`.

The manifest and the receipts are **two different ledgers** — the customer's claim, and the
provider's record of what actually moved. An object that was never manifested is not *unwanted*; it
is *never claimed*, which is the ordinary case.

**Consequence for A:** reclamation must be keyed on a **transition** — an object that *was* carried
by some manifest and is *no longer* carried by the current one — never on mere absence. This
requires tracking "was this cid ever manifested for this did," which is new state. It is small, but
it is not free, and pretending the manifest was already an index would have been a data-loss bug.

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

#### The one place B must NOT copy the ceiling dial: the failure direction

`at_rest_dial` fails **closed to a cap of 0** when a stored dial will not parse
(`src/persist.rs:424–443`) — documented as *"new stores refuse loudly rather than silently dropping
the customer's protection."* For a **ceiling**, that is right: the dial is a *protection*, so
failing closed means refusing writes, which is the safe direction.

**A retention dial is destructive, so the safe direction inverts.** An unparseable retention dial
that "failed closed" to 0 days would **delete the namespace immediately**. For anything whose effect
is deletion, failing safe means **retain indefinitely**:

| dial | effect | unparseable ⇒ |
|---|---|---|
| ceiling (`at_rest_bytes`) | protective — refuses writes | cap `0` — refuse loudly ✅ |
| **retention (`max_age_days`)** | **destructive — deletes** | **`None` — retain forever, and warn loudly** |

"Follow `CeilingDialBody` exactly" is correct for the shape, the fold, the signing and the
`seq` handling — and **wrong on precisely this point.** Same for the enforcement hook:
set-time validation (`src/server.rs:1584`) checks the ceiling against a provider bound; a retention
dial's set-time check should reject an implausibly short window rather than accept it.

### Time: one stamping authority, and a counter rather than a clock

**Owner's posture (2026-08-11), and it decides this design:** we do not rely on wall clocks. A clock
assertion is trustworthy locally and never *between* nodes. The usable version is **seconds since
epoch stamped by a single authority** — then time is monotonic *within the system*, and what remains
is **drift over an interval**, not clock synchronisation between machines.

For retention that collapses the problem, because **the storer and the deleter are the same party.**
CISS stamps an object on arrival and CISS decides it has expired. Both readings come from one clock,
so nothing is ever compared across a trust boundary and no stamp has to be believed from elsewhere.
Drift against real-world time only decides whether "14 days" is 13.9 or 14.1 — it cannot make the
decision *wrong*.

**Starting position is good:** the server's only wall-clock read today is `now_unix_s()` for JWT
`exp` (`src/server.rs:828`), which atproto imposes because JWTs carry absolute expiry. Nothing else
in the server's correctness path reads a clock.

#### What the design already says, and why retention still fits

Searched before designing (2026-08-11). **There is no seconds-since-epoch mechanism anywhere in the
corpus, and that is deliberate.** Every monotonic counter that exists counts *events*, not time:

| mechanism | what it counts | where |
|---|---|---|
| per-client `lamport` | facts authored by that client | Drystone Part 2 §4.5.1 |
| `seq` (manifest / assertion / kv / chain) | writes to that slot | CISS `manifest.rs`, `assertion.rs` |
| `chain.counter` | owner-signed delta entries (the running total, tamper-evident) | CISS `chain_kind.rs` |

Part 2 §4.5.1 is explicit: *"the logical clock is per client and **strictly logical, never a
wall-clock** … a wall-clock is never consulted because it is an **uncorroborable assertion** that
could not order what must converge."* Part 1 §2.0.1 states the principle — *time is not a fact*.

**So a logical clock cannot serve retention**, because retention is a claim about **duration** and a
Lamport counter only supplies **order**. No amount of event-counting yields "14 days."

**T7 is what makes this tractable, and its wording is narrower than a blanket ban:**

> **T7** — Not require a wall-clock **for any authority-bearing decision** (§10.3, grounding Part 1 §2.0.1)

The rule is about *authority*, not about ever reading a clock. Retention splits cleanly along that
line:

| | what it is | corroborable? | T7 |
|---|---|---|---|
| **the policy** — `max_age_days = 14` | an owner-**signed** assertion, `seq`-monotonic | yes — it is a signed fact | bears the authority |
| **the measurement** — "this object is now 15 days old" | CISS's own local elapsed count | no, and it never needs to be | bears **no** authority |

**The signature carries the authority; the counter only executes a policy that was authorized
without it.** Nothing converges, nothing is ordered, no fact is attributed, no quorum is counted,
and the count is never compared against another node's.

**The constraint this places on the implementation, and it is the load-bearing one:** the elapsed
counter **must never become a fact.** Never signed, never written into the fold, never carried on the
wire, never compared across nodes. The moment a retention timestamp is signed into a fact, it stops
being a local operational measurement and becomes exactly the uncorroborable assertion §4.5.1
excludes. Keep it in server-local state (the `meta` table, not a manifest or an assertion body).

Recorded because a later reader seeing "CISS reads a clock for retention" would reasonably suspect a
T7 violation, and the answer is not obvious without this split.

#### Prefer a monotonic day counter over a wall-clock comparison

Two formulations, and the second is safer:

1. **Store absolute seconds, compare to `SystemTime::now()`.** Simple, but `SystemTime` can jump. A
   *backward* jump is harmless here (age computes negative, clamp to zero, retain). A **forward jump
   deletes early** — the dangerous direction, and the one no clamp catches.
2. **Store a day index; advance it deliberately.** Correctness depends only on the counter being
   monotonic. Wall clock decides *when* to advance it, which sets granularity, not correctness.

**Take (2), because its failure mode is the safe one.** If the advancer stalls, the counter stops,
ages stop growing, and **nothing is deleted**. A stalled component causes retention, not data loss —
which is the same direction the unparseable-dial rule takes, and for the same reason.

**`SimClock` is already this shape.** `src/clock.rs` is a day counter that only moves when told
(`advance_days`), written for reproducible byte-day rent — *"no wall-clock reads"*. It has **zero
callers**. It was built as a test type and it is the right production shape; retention would be its
first consumer.

#### Two clocks, one authority per question

The meer already stamps queue entries with its own `deposited_day`. That does **not** need to agree
with CISS's counter, because they answer different questions: the meer's clock drives the
**watermark** ("you missed 3 things between day 0 and day 2"), CISS's drives **deletion**. Neither
stamp is ever read by the other party, so there is no cross-node time trust — which is the whole
point. Worth stating explicitly so a later reader does not try to reconcile them.

**Open, and it is a coupling not a contradiction:** if CISS deletes on its own counter, the meer
learns what was swept only by asking. Whether the watermark is derived from CISS's sweep or kept
independently by the meer is a Phase-3 question.

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

- **[RESOLVED 2026-08-11 — and the answer is worse than a grace period]** *Can an object be `PUT`
  and never appear in a manifest?* **Yes, and that is the ordinary case.** `op_put_object` never
  touches the manifest; `op_du` reads receipts; the meer probe PUTs four objects with no manifest at
  all and every one stores, serves and meters. So "absent from the manifest" is not a weak signal
  needing a grace window — **it is the normal state of almost every object.** A must key on the
  *transition* (was manifested, now is not), which needs new state: a record of which cids have ever
  been manifested per did. Folded into Phase 3.
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

- [ ] **D0: Correct the README so it stops asserting more than the boundary does.** Not discovery —
      it is here because it is independent of everything else, costs an hour, and is the specific
      inaccuracy that led us to plan against machinery that was not running. Mark the library-only
      layer as such in the architecture diagram.

- [x] **D1: Can an object be PUT and never manifested?** **ANSWERED 2026-08-11: yes, and it is the
      ordinary case.** `op_put_object` (`src/server.rs:1030`) never touches the manifest; `op_du`
      (`:1399`) reads receipts. Corroborated by `meer-queue/src/bin/d2_ciss_put.rs`. **A is not safe
      as originally specified** — corrected above.
- [ ] **D2: What is the manifest→object relationship at read time?** Does `GET /{did}/objects/{cid}`
      consult the manifest at all, or only the blobstore? Determines where a reclamation check lives.
- [ ] **D3: Confirm the assertion surface accepts a new kind cleanly.** Add a throwaway kind, PUT and
      GET it, confirm `kind_fold` refuses a malformed body and an unknown kind.
- [x] **D4: Where does per-object age come from?** **ANSWERED 2026-08-11: nowhere. It does not
      exist, and neither does the machinery I assumed would supply it.**
      - `BlobStore` is `put`/`get`/`has` with no metadata (`src/blobstore.rs:80–92`); the `receipt`
        table is `(id, did, json)` with no age column.
      - **Byte-day accounting is not running.** `Timeline` / `set_bytes_at_rest` / `byte_days` have
        **no callers outside `src/statements.rs`**. `persist.rs` can `append_statement` and
        `load_statements`, but **nothing in the server ever constructs a `Statement`** — no period
        ever closes.
      - Even fully wired it would not help: the `Timeline` is a **namespace-level** step function of
        total bytes at rest per day. It never knew when an individual object arrived.
      - **There is no day clock running.** `src/clock.rs` has zero callers.
      - Same state for the lifecycle machinery generally: **`seal.rs` and `grace.rs` have zero
        callers** and are unreachable from the HTTP boundary and the CLI.

      **Consequence:** B must introduce its own arrival stamp and its own counter. The dial half
      stays cheap; the enforcement half is new construction, not a read. See "Time" above.

      *Recorded plainly because the corpus reads otherwise:* "the E0–E9 ledger core is complete" is
      true **of the library**, and its tests are real. What is not true is the implicit next step —
      that the boundary exposes it. Phase 7 wired the metered byte-path; the periodic and lifecycle
      halves stayed behind the library wall.

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

- **`README.md` — the architecture diagram overstates what the service does.** It lists
  *"statements · audit · seal · grace"* as part of the running system and calls the E0–E9 core
  *"proven"*. All four are **library-only with zero callers**
  (`docs/notes/2026-08-11-reachability-audit.md`). "Proven" is true of the library; the diagram
  invites the false next clause. **This is the smallest and most urgent item in this plan** — it
  costs an hour, it is the thing that misled us, and it does not depend on any other phase.
  **Do it first, in Phase 0.**
- `docs/SECURITY-POSTURE.md` — reclamation is a new state transition; its authority (B1/B3 via the
  manifest, `seq`-monotonic assertion for the dial) belongs beside the existing invariants. Phase 4.
- `docs/` API surface — the new assertion kind. Phase 1.
- `CHANGELOG.md` — both halves. Phases 2 and 3.
- `discovery/alpha/ROADMAP_TODO.md` **E95** — status transitions as phases land. Ongoing.
- `discovery/alpha/thinking/meer-as-custodian-queue.md` — the S5 correction can be softened once B
  ships, because the retention promise becomes true. **Not before.** Phase 2.
