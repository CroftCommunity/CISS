# Reachability audit — what is built, tested, and unreachable

date: 2026-08-11
found by: scoping `docs/plans/2026-08-11-object-lifecycle.md` (from the meer Phase-0 spike)

---

## The finding

**Five modules have no caller anywhere outside themselves.** They are real code with real tests, and
nothing in the running service can reach them.

| module | lines | inline tests | dedicated suite | reachable from the boundary |
|---|---:|---:|---|---|
| `seal.rs` — seal / tombstone tiers | 414 | 5 | `e7_seal.rs`, `e8_tombstone.rs` | **no** |
| `grace.rs` — the grace ledger | 171 | 2 | `e9_grace.rs` | **no** |
| `dial.rs` — audit-tier assurance dial | 144 | 4 | `e6_dial.rs` | **no** |
| `audit.rs` — k-sample spot check | 104 | 4 | `e5_audit.rs` | **no** |
| `clock.rs` — deterministic day clock | 46 | 1 | — | **no** |

Plus a sixth, half-wired: **`statements.rs`**. `persist.rs` can `append_statement` and
`load_statements`, but **nothing in the server ever constructs a `Statement`** — so no period ever
closes, and `Timeline` / `set_bytes_at_rest` / `byte_days` have no runtime driver. The byte-day rent
integral is unit-tested library code that never runs.

**Nothing here is broken.** Every one of these is tested and, as far as its tests go, correct. The
problem is that a reader — including us, last week — reasonably concludes from the README's
architecture diagram (*"statements · audit · seal · grace"*) and from *"the E0–E9 ledger core
(proven)"* that the service does these things. It does not. It stores bytes, meters them, and serves
policy, ceiling, period and account-mode dials.

"Proven" is true **of the library**. The implicit next clause — that the boundary exposes it — is
what is false.

## Why the test suite did not catch it

The suite is in two halves that never meet.

```
   tests/e0..e9_*.rs          10 files        tests/wiring_*.rs, flow_*.rs      30 files
   ────────────────────       ─────────       ──────────────────────────        ─────────
   import ciss::seal,                         spin the real axum router,
   ciss::grace, ciss::audit                   drive it over real HTTP
   directly                                   
   construct NO server ◄──── nothing ────►    reach only what the router
                             asserts a        actually routes
                             path between
```

Every `e0`–`e9` test is **server-driven: 0** — it imports the library module and exercises it in
isolation. Every `wiring_*` / `flow_*` test drives the boundary. **No test asserts that a capability
tested in the first half is reachable from the second.**

So `seal.rs` can have five inline tests, a dedicated suite, and a mutation gate — and be unreachable.
**Coverage measures whether code is executed by tests. It says nothing about whether it is reachable
from the entry point.** A thoroughly-tested orphan has excellent coverage and zero reachability, and
no amount of coverage tooling will tell you which one you have.

## Why the guardrail did not fire

This project already carries the rule, in `coding-agents/CLAUDE.md`:

> **Built means wired, and wired means tested.** Code that exists but isn't reachable from the entry
> point is dead code, not progress.

And the phase-plan skill has a required **Wiring test** field for exactly this.

It was applied, and it still missed — because it was applied **per phase, forward only.**

E0–E9 were built as *library* phases, before any HTTP boundary existed. At that time the library API
**was** the entry point, so their wiring tests were correct: `e7_seal.rs` genuinely exercised seal
through its public interface. Phase 7 then added the metered byte-path, Phase 8 the atproto blob
surface — and each wired **what that phase introduced**. Nothing re-examined the earlier phases
against the new entry point.

**The generalizable lesson: a new entry point invalidates every prior "wired" claim.** When a project
grows a boundary — an HTTP surface, a CLI, a daemon — every capability built before it needs
re-testing *against that boundary*, not just against the API that was current when it was written.
Otherwise the codebase accumulates modules that were correctly wired to an entry point that no longer
matters.

## The harness gap, and the fix

What was missing is a **reachability inventory**: an explicit list of capabilities and, for each, the
boundary path that exposes it — asserted, not assumed.

`tests/wiring_reachability.rs` implements it. The shape matters:

- It computes the caller-count for every `src/*.rs` module.
- It carries an **explicit allowlist of known-unreachable modules**, each with a reason and a tracking
  reference.
- **A module not on the allowlist with zero callers fails the test.** That stops *new* drift
  immediately, without blocking on a cleanup that is its own project.
- **A module on the allowlist that becomes reachable also fails**, with a message to remove it from
  the list. The allowlist cannot silently rot into a permanent excuse.

The allowlist is the honest artifact here: it turns "we thought this was live" into a list somebody
has to look at and shorten.

## What to do about the five

Not decided here. The options differ per module:

- **`clock.rs`** — wire it. `docs/plans/2026-08-11-object-lifecycle.md` needs a monotonic day counter
  and this is already the right shape. Retention would be its first consumer.
- **`statements.rs` / `dial.rs`** — these are the billing period machinery. Wiring them is the
  "close a period and issue a statement" feature, which is a real product decision, not a gap to
  patch quietly.
- **`audit.rs`** — the spot-check needs a boundary verb (a customer asking the provider to prove it
  still holds a sample). Small, and it is the mechanism behind a claim the README makes.
- **`seal.rs` / `grace.rs`** — the largest and the least urgent. Both are policy features with real
  design questions attached (who signs a seal ceremony; who co-signs a grace event).

The immediate obligation is smaller than any of that: **stop the docs asserting more than the
boundary does.** See the README task in the object-lifecycle plan.
