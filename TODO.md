# CISS — repo open items

> Known work only — items whose shape is already decided, and which may therefore be
> proposed as work. Anything still an open question (decide / verify / investigate /
> reconcile) belongs in the backlog of record, `discovery/alpha/ROADMAP_TODO.md`,
> however small or operational it is. Tracking scheme: `CroftC/.claude/TRACKING.md`;
> the two piles and why: its § "Two piles". Cross-reference E-numbers where an item
> here implements a backlog row.

Work local to this repo. Dated plans live in `docs/plans/`; decisions in `docs/adr/`.

## Open

- [ ] **Bump `h2` — RUSTSEC-2026-0258, fix available.** Found by the workspace
  supply-chain sweep, 2026-08-29 (`CroftC/.claude/SUPPLY-CHAIN.md`). `h2` 0.4.15 is in
  the **normal** dependency path — confirmed, not assumed — via both `axum` and
  `reqwest`:

  ```
  h2 v0.4.15
  ├── hyper v1.11.0 └── axum v0.8.9 └── ciss v0.9.0
  └── reqwest v0.13.4
  ```

  Fixed in 0.4.16. Likely a `cargo update -p h2` rather than a manifest change, since
  it is transitive. Re-run `osv-scanner scan source -L Cargo.lock` after.

  Note the deployment coupling before bumping: `ciss-admit` on the box is pinned to
  **v0.8.0** (the admit crate's kind-semantics pin), while the public tenant versions
  independently at v0.9.0. A fix that only lands on the v0.9.x line does not reach the
  deployed admit service — check which line needs it, and whether the pin moves.

- [ ] **Record the `rsa` advisory as a dated exception — it has no upstream fix.**
  `rsa` 0.9.10 carries RUSTSEC-2023-0071 (the Marvin timing attack) with **no fixed
  version available**, which is exactly the shape `SUPPLY-CHAIN.md` rule 9 exists for:
  an undated ignore is indistinguishable from a decision nobody made. It needs an
  entry in `osv-scanner.toml` with the reason and an expiry, not a silenced check.

  **Reachability is unproven** — `rsa` did not resolve in the default-target normal
  tree. Run `cargo tree -i rsa --edges normal --target all` first; the exception's
  wording depends on the answer, and "not in the default tree" is not "not shipped".

- [ ] **Wire the SCA gate (audit check 31).** CISS is one of the three enforcing
  surfaces slated to get the blocking gate first, ahead of the static sites — rollout
  step 4 in `CroftC/.claude/SUPPLY-CHAIN.md` § Current state.
