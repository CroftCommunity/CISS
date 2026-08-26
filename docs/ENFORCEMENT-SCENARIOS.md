# Enforcement scenarios — every MUST-ADMIT and MUST-REFUSE, pinned

CISS's positive AND negative space, enumerated — not what runs have happened to
exercise, but what the design promises to admit or refuse, each row naming the test
that pins it. Gated by `tests/enforcement_matrix.rs` (in `cargo test`): a PIN naming a
nonexistent test fails, an unresolved gap row fails, and a `JwtError` variant with no row here
fails the gate. Workspace method: `CroftC/.claude/ENFORCEMENT.md`; the reference matrix
is croft-stack's. Levels: rows pin in-proc HTTP tests (real axum server on loopback —
`green-model` for the deployed surface) unless marked LIVE (`tests/live_refusals.rs`,
`CISS_LIVE=1`, skip-guarded — `green-real`). The deep manual walkthrough stays
`docs/CLIENT-TESTING.md`.

## Service-auth JWT (crates/ciss-auth) — every `JwtError` variant

| Scenario | Outcome | Variant / observable | Pinned by |
|---|---|---|---|
| Valid service-auth JWT | MUST ADMIT | issuer authenticated | PIN:service_jwt.rs::a_valid_service_auth_jwt_authenticates_the_issuer |
| Malformed did:key / unsupported curve | MUST REFUSE | BadDidKey · UnsupportedKeyType | PIN:did_key.rs::rejects_a_non_did_key_and_unsupported_curve |
| Malformed signature bytes | MUST REFUSE | BadSignature | PIN:did_key.rs::rejects_malformed_signature_bytes |
| High-S (malleable) signature | MUST REFUSE | MalleableSignature | PIN:did_key.rs::rejects_a_high_s_malleable_signature |
| Signature by a different key | MUST REFUSE | SignatureInvalid | PIN:did_key.rs::rejects_a_signature_from_a_different_key |
| Attacker signs a token naming a victim `iss` | MUST REFUSE | SignatureInvalid — no receipt signed | PIN:service_jwt.rs::a_forged_token_naming_a_victim_iss_but_signed_by_the_attacker_is_refused · HTTP: PIN:flow_atproto_identity.rs::a_forged_token_naming_a_victim_is_refused_and_signs_no_receipt |
| Not three base64url segments | MUST REFUSE | BadJwtStructure | PIN:service_jwt.rs::a_structurally_broken_jwt_is_refused |
| Forged / `alg:none` header | MUST REFUSE | BadHeader | PIN:service_jwt.rs::a_forged_alg_none_header_is_refused |
| Claim edges (missing/mistyped) | MUST REFUSE | BadClaims | PIN:service_jwt.rs::promoted_mint_helper_round_trips_and_rejects_claim_edges |
| `iss` does not match the resolved DID | MUST REFUSE | WrongIssuer | PIN:service_jwt.rs::a_token_whose_iss_does_not_match_the_resolved_did_is_refused |
| Token for another service | MUST REFUSE | WrongAudience | PIN:service_jwt.rs::a_token_for_another_service_is_refused · HTTP: PIN:flow_atproto_identity.rs::a_token_for_another_service_is_refused |
| Token bound to a different / no method | MUST REFUSE | WrongMethod | PIN:service_jwt.rs::a_token_bound_to_a_different_method_is_refused · PIN:service_jwt.rs::a_method_less_token_is_refused |
| Expired token | MUST REFUSE | Expired | PIN:service_jwt.rs::an_expired_token_is_refused · HTTP: PIN:flow_atproto_identity.rs::an_expired_token_is_refused |
| Replayed `jti` within window | MUST REFUSE | Replayed | PIN:replay.rs::a_replayed_jti_within_its_window_is_refused · HTTP: PIN:flow_atproto_identity.rs::a_replayed_token_is_refused_the_second_time |
| Fresh / post-window / distinct jtis | MUST ADMIT | replay window mechanics | PIN:replay.rs::a_fresh_jti_is_accepted · PIN:replay.rs::a_jti_is_reusable_once_its_window_has_passed · PIN:replay.rs::distinct_jtis_are_independent |
| Resolver down, non-admin | MUST REFUSE (fail closed) | no identity, no admission | PIN:flow_atproto_identity.rs::when_the_resolver_is_down_a_non_admin_fails_closed |

## Session auth (signed challenge)

| Scenario | Outcome | Observable | Pinned by |
|---|---|---|---|
| Valid session | MUST ADMIT | owner authenticated | PIN:ciss-auth/src/lib.rs::a_valid_session_authenticates_the_owner |
| Impostor: victim's public key, attacker's signature | MUST REFUSE | DidMismatch/Unverified | PIN:ciss-auth/src/lib.rs::an_impostor_presenting_the_victims_public_key_cannot_sign_for_it · PIN:ciss-auth/src/lib.rs::an_impostor_presenting_their_own_key_for_a_victim_did_is_refused |
| Signature over different bytes/challenge | MUST REFUSE | Unverified | PIN:ciss-auth/src/lib.rs::a_signature_over_a_different_challenge_does_not_verify · PIN:did_key.rs::rejects_a_signature_over_different_bytes |
| Malformed inputs | MUST REFUSE (no panic) | rejected, never panicked | PIN:ciss-auth/src/lib.rs::malformed_inputs_are_rejected_not_panicked |

## HTTP surface (in-proc server; tests/common TestServer)

| Scenario | Outcome | Observable | Pinned by |
|---|---|---|---|
| Unauthenticated write | MUST REFUSE | 401 | PIN:flow_security_regression.rs (suite of 6 refusals) — see file |
| Foreign-namespace write / foreign meter read | MUST REFUSE | isolation holds | PIN:flow_security_regression.rs — see file |
| Control bytes / path separators / empty / overlong DID | MUST REFUSE | 400 before auth | PIN:flow_input_scoping.rs (5 refusal tests) — see file |
| Over spend ceiling | MUST REFUSE with quote | structured 402, comparison-before-serving (ADR 0004) | PIN:flow_dial_spend.rs · PIN:flow_kind_ceiling.rs::an_over_ceiling_body_is_refused_and_an_ordinary_one_is_kept |
| Sync over ceiling; exit exempt (B6) | MUST REFUSE / MUST ADMIT exit | defer-whole; exit stays exempt | PIN:flow_sync_ceiling.rs::over_ceiling_defers_whole_and_exit_stays_exempt |
| Replayed dial seq; provider DID cap | MUST REFUSE / cap supersedes | ADR 0004 dial rules | PIN:flow_dial_ceiling.rs — see file |
| New store over store ceiling / per-DID cap | MUST REFUSE | quota refusals; reads not blocked when full | PIN:flow_storage_quota.rs::a_new_store_over_the_store_ceiling_is_refused · PIN:flow_storage_quota.rs::a_new_store_over_the_per_did_cap_is_refused |
| Replayed older manifest | MUST REFUSE | anti-rollback (F1/F2, I5) | PIN:flow_billing_integrity.rs::a_replayed_older_manifest_is_refused |
| Compaction without checkpoint; misstated total; forged head | MUST REFUSE | the irreversible act is guarded | PIN:flow_chain_checkpoint.rs::compaction_without_a_checkpoint_is_refused · PIN:flow_chain_checkpoint.rs::a_checkpoint_that_misstates_the_total_is_refused · PIN:flow_chain_checkpoint.rs::a_checkpoint_with_a_forged_head_is_refused |

## Gated reads (docs/spec/gated-reads.md)

| Scenario | Outcome | Observable | Pinned by |
|---|---|---|---|
| Non-grantee / anonymous reads gated object | MUST REFUSE invisibly | 404 never 403 — no existence oracle; grant→read→revoke→404 lifecycle | PIN:flow_gated_reads.rs — full lifecycle suite, see file |
| Forged policy | MUST REFUSE | 403 | PIN:flow_gated_reads.rs — see file |
| Stale / rolled-back policy seq | MUST REFUSE | 409 | PIN:flow_gated_reads.rs — see file |
| Cross-namespace grant | MUST REFUSE | grants do not cross namespaces | PIN:flow_gated_reads.rs::did_reader_reads_gated_blob_and_grants_do_not_cross_namespaces |

## Live rungs (deployed surface — `ciss.croft.ing`; `CISS_LIVE=1`, skip-guarded)

| Scenario | Outcome | Observable | Pinned by |
|---|---|---|---|
| Service identity served | MUST ADMIT | `/.well-known/did.json` → did:web:ciss.croft.ing | PIN:live_refusals.rs::live_identity_is_served |
| Unauthenticated write, well-formed unowned DID | MUST REFUSE | 401 | PIN:live_refusals.rs::live_unauthenticated_write_is_refused_401 |
| Malformed DID, before auth | MUST REFUSE | 400 | PIN:live_refusals.rs::live_malformed_did_is_refused_400_before_auth |

Deeper live refusals (gated-read 404/409, journald refusal words) remain the manual
walkthrough `docs/CLIENT-TESTING.md` — some paths have no CLI surface yet (its noted
gaps). Promote rows here as they gain automation.