# CISS — repo open items

> Known work only — items whose shape is already decided, and which may therefore be
> proposed as work. Anything still an open question (decide / verify / investigate /
> reconcile) belongs in the backlog of record, `discovery/alpha/ROADMAP_TODO.md`,
> however small or operational it is. Tracking scheme: `CroftC/.claude/TRACKING.md`;
> the two piles and why: its § "Two piles". Cross-reference E-numbers where an item
> here implements a backlog row.

Work local to this repo. Dated plans live in `docs/plans/`; decisions in `docs/adr/`.

## Open

(nothing — every item below closed; new known work starts a fresh bullet here)

## Closed

- [x] **Bump `h2` — RUSTSEC-2026-0258.** Shipped in v0.10.0 (2026-08-29): `h2` 0.4.15 → 0.4.19
  via `cargo update`, in the production path through `axum` and `reqwest`. The deployed
  `ciss-admit` (pinned to the v0.8.0 rev by `croft-stack`'s admit crate) did NOT carry it
  until that pin moved — tracked in `croft-stack`, not here (the pin's bump PR is where the
  admit gate proves compatibility). Closed on the record 2026-09-14; the TODO had outlived
  the changelog entry.
- [x] **Record the `rsa` advisory as a dated exception.** Done 2026-08-29 in
  `osv-scanner.toml` (RUSTSEC-2023-0071, `ignoreUntil` 2026-11-29): rung 1 clears it — an
  unenabled optional dependency in no resolved tree on any target, verified per shipped
  artifact — with the invalidation condition written down (any feature that activates an
  RSA-backed path). Closed on the record 2026-09-14.
- [x] **Wire the SCA gate (audit check 31).** Done 2026-08-29: `.github/workflows/security.yml`
  calls croft-pwa's `security-reusable.yml` on every PR, push to main, weekly, and by hand
  (secrets AND dependencies; blocking). Audit check 31 no longer flags this repo. Closed on
  the record 2026-09-14.
