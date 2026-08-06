# Plan — `ciss-ctl`, the CISS client CLI

- **Date:** 2026-08-06 · **Status:** ✅ **READY FOR EXECUTION — Passes 1/2/3 complete; Phase 0 (D1–D4) executed incl. live bsky probe; one ADVISORY open question (non-gating)** · **TDD-first**
- **Owns:** a new workspace member `crates/ciss-cli` producing the `ciss-ctl`
  binary. Homebrew-installable from the same tap as the server.
- **Contracts spoken to:** `README.md` API surface, `docs/spec/gated-reads.md`
  (Model A/C policy), `docs/notes/atproto-integration-model.md` (service-auth),
  ADR 0001 (auth model).

---

## Problem Statement

CISS is a server with a rich, security-load-bearing wire surface (S3 metering
plane + atproto blob plane + gated-reads policy), but **the only client today is
`curl` plus hand-built signatures**. Every capability the server guarantees —
content-addressed metered upload, a signed transfer receipt per byte-crossing, an
owner-signed read ACL on a private object, oracle-free denial — is currently
demonstrable only by a human assembling ed25519 signatures, session challenges,
CIDv1 bridging, and policy preimages by hand. That is error-prone, undemoable, and
undistributable.

We need **one self-contained, homebrew-installable local client** that:

1. Owns a client identity keypair (generate natively **or** import an existing
   ssh-keygen ed25519 key) and derives its `id:` DID from it.
2. Uploads an item over **either** the S3 plane **or** the atproto `uploadBlob`
   plane — interchangeably, landing at the same backend digest — and shows the
   **bytes transferred** (the server's signed receipt + the running meter).
3. Sets and reads a **read ACL on a private object** (gated reads, Model A/C).
4. **Fetches a stored object by id** (cid) back from the server.

The load-bearing risk is **fidelity**: a client that reconstructs preimages or
signatures *approximately* will silently authenticate-then-fail, or worse, pass
against a permissive path and mask a real gap. The client must reproduce the
server's crypto exactly — which is why it lives in-repo and links the server's own
crates rather than re-implementing the wire.

**Constraints / decisions already made (from the intake Q&A):**
- Binary name **`ciss-ctl`**, in-repo workspace crate.
- Native ed25519 keygen **plus** import of ssh-keygen ed25519 keys.
- **Both** `id:` and `did:` identity paths in v1.
- v1 **shows the server's receipt/meter**; no client-side ledger, and bilateral
  (client co-signed) receipts stay a labeled SEAM (server returns
  `BilateralUnsupported`).

## Reasoning

- **In-repo crate, links the server's crates.** *Chosen* over a separate repo
  because the client's whole job is to reproduce server crypto byte-for-byte — the
  session challenge, the CIDv1 bridge, the Model-A policy preimage. Sharing the
  source makes drift a compile error, not a silent 403. Pass-2 verification found
  the client-facing helpers already exist and are `pub`: `identity::derive_id`,
  `crypto::Keypair::sign_message`, `cidv1::{from,to}_sha256_hex`,
  `policy::PolicyRecord::sign_owner`, `policy::PolicyIntent`. The CLI is largely a
  *composition* of existing library surface, not new crypto. *Rejected:* separate
  repo depending on `ciss` as a git dep (drift, version skew) or re-declaring wire
  shapes (guaranteed drift).
- **`ciss-ctl` name.** Distinct from the `ciss` server binary; one tap ships both.
  "ctl" reads as a control client, not a second server.
- **ed25519 native, with OpenSSH import.** ed25519 *is* the identity primitive —
  `derive_id` hashes the raw pubkey — so generating natively needs zero format
  translation and matches the server exactly. Importing via the `ssh-key` crate
  (not shelling to `ssh-keygen`, not a hand-rolled OpenSSH parser) satisfies "reuse
  ssh-keygen keys" with a maintained, audited parser. *Rejected:* shelling to
  `ssh-keygen` (still must decode the OpenSSH wrapper) and persisting in OpenSSH
  format (a parse on every load for no gain).
- **Both identity planes; `did:` via the standard `getServiceAuth` relay (Model R),
  not self-mint.** *Corrected 2026-08-06 (see Review Log).* CISS is a verify-only
  resource provider; the `did:` identity is the user's atproto account (a bsky
  `did:plc`) whose signing key stays **at the PDS**. The CLI logs in (app password)
  and relays a short-lived, `aud`/`lxm`-scoped JWT that **bsky** signs with the
  user's repo key — the exact flow `atproto-integration-model.md` specifies. The
  CLI holds a *credential*, never a key; no `did:web` hosting. *Rejected:* the CLI
  self-minting from a locally-held secp256k1 key (would make the CLI an issuer,
  contradicting the verify-only tenet, and require hosting a `did:web` doc). The
  promoted mint helper (Phase 6) survives only as the **test stand-in** for the PDS,
  since in-process tests can't call bsky.
- **Show the server receipt; bilateral is a SEAM.** Matches the server's actual
  capability (unilateral only). Faking a co-signed receipt client-side would
  misrepresent the trust model the receipts doc is precise about.
- **`clap` in the CLI crate only.** The server's hand-rolled parser is fine for two
  subcommands; a client with ~10 needs real help/validation. Scoped so the server
  binary gains no dependency.
- **Async reqwest + `#[tokio::main]`.** The workspace already uses tokio + reqwest
  (rustls). The CLI adds the `json` feature (dev-tests already rely on it) rather
  than introduce `reqwest/blocking` and a second HTTP style.

## Verified Assumptions

Confirmed firsthand against the code at plan time:

- **Session auth** — headers `x-croft-pubkey` (pubkey hex) + `x-croft-session`
  (ed25519 sig over the UTF-8 string `ciss-session/v1/<did>`); the acting DID is
  `derive_id(pubkey)`. `src/server.rs:625-641`, `SESSION_CHALLENGE_PREFIX` at
  `:66`. The CLI builds the sig with `crypto::Keypair::sign_message`
  (`src/crypto.rs:75`).
- **DID derivation** — `"id:" + SHA-256(raw pubkey)`, full 64 hex.
  `src/identity.rs:25-28`.
- **atproto uploadBlob accepts the `x-croft-*` session** as a fallback when no
  Bearer is present. `authenticate_atproto` at `src/server.rs:650-655`. So an
  `id:` identity drives both planes → the interchangeability demo works from one
  key.
- **CIDv1 bridge** — `cidv1::from_sha256_hex` (hex→`$link`) and `to_sha256_hex`
  (`$link`→hex), used by `src/pds_api.rs:105,135`. Same backend digest under both
  addressings.
- **Model-A policy client API** — `policy::PolicyRecord::sign_owner(did,
  cid: Option<&str>, read_class, readers: &[String], seq, owner_key: &Keypair)`,
  `src/policy.rs:189`. `PolicyIntent` (Model-C body) at `:118`.
- **Policy wire** — `PUT/GET /{did}/policy` and `/{did}/objects/{cid}/policy`;
  Model-A body = signed `PolicyRecord`; Model-C = `PolicyIntent` + Bearer JWT with
  `lxm=ing.croft.ciss.setPolicy` (getPolicy `lxm=ing.croft.ciss.getPolicy`).
  `docs/spec/gated-reads.md` §6; router at `src/server.rs:338-345`.
- **Service DID** — defaults to `did:web:ciss.croft.ing`, override via
  `CISS_SERVICE_DID`; served at `/.well-known/did.json`. `src/server.rs:761-762`,
  `:363`. This is the JWT `aud` the CLI must target.
- **Test harness** — integration tests bind `TcpListener::bind("127.0.0.1:0")`,
  build `App`, inject a resolver via `App::with_did_resolver(Arc<StaticResolver>,
  service_did)`, and drive with `reqwest`. `StaticResolver::default().with(did,
  "did:key:z…")` maps a caller DID to its signing key. `tests/wiring_checkpoint.rs`,
  `crates/ciss-resolve/src/static_resolver.rs:29`.
- **`Did::parse` accepts `did:key`** (`method=key`). `src/identifiers.rs`
  `is_valid_did`.
- **S3 response shapes** — `PUT /{did}/objects/{key}` → `{"cid","bytes",
  "receipt_mode"}` with an `etag` header; `receipt_mode` ∈ `{"unilateral",
  "bilateral"}`. `GET` returns the raw bytes + `etag` + the blob security headers.
  `GET /{did}/meter` → `{receipt_count, upload_bytes, download_bytes,
  running_total_bytes, postage_cents}`. `src/server.rs:1584-1606`, `op_get_meter`.
  (Pins Phase 4 — no shape is left to confirm at wiring time.)

Verified by Phase 0 discovery (2026-08-06 — see the Review Log; probe under
`$SCRATCH/sshkey-spike`):

- **D1 — `ssh-key` v0.6 (feature `ed25519`) extracts a raw ed25519 seed.**
  `PrivateKey::from_openssh(pem)` → `.key_data().ed25519()` → `Ed25519Keypair`;
  `kp.private.to_bytes(): [u8;32]` is the seed and `kp.public.0: [u8;32]` the
  pubkey. Reconstructing via `ed25519_dalek::SigningKey::from_bytes(&seed)` yields
  the **same** public bytes, and `"id:"+sha256(pubkey)` is byte-identical between
  the imported and native paths (probe asserted parity, exit 0).
  `PrivateKey::is_encrypted()` flags a passphrase-protected key → the CLI errors
  clearly (encrypted keys are out of v1). `key.algorithm()` == `ssh-ed25519`.
- **D2 — the service-auth JWS shape.** Compact JWS
  `base64url(header).base64url(claims).base64url(sig)`. Header
  `{"typ":"JWT","alg":"ES256K"}` (secp256k1) or `ES256` (P-256). Claims
  `{"iss","aud","lxm","exp","jti"}` — **`lxm` is mandatory** (a method-less token
  is refused `WrongMethod`); `jti` recommended (replay). Signature = raw 64-byte
  `r‖s` ECDSA over the ASCII `header.payload`, base64url. **The verify path derives
  the algorithm from the resolved key's curve, not the header `alg`**
  (`service_jwt.rs:102-103`). Source: the `#[cfg(test)]` `mint`/`did_key_of` at
  `service_jwt.rs:171-198`.
- **D2 corollary — `did:` repo keys are secp256k1 or P-256, NOT ed25519.**
  `did_key.rs` decodes only the `0xe7 01` (secp256k1) and P-256 multicodec
  prefixes (`:16-47`). **This curve lives at the PDS, not in the CLI** (see the
  Model-R correction below) — it matters to the CLI only inside the test harness,
  which mints an ES256K JWT to stand in for bsky.
- **D3 — the deployed resolver resolves `did:plc` and `did:web` only.**
  `PlcWebResolver` routes `did:plc` via `plc.directory` and `did:web` via the
  host's `/.well-known/did.json`; **`did:key` is refused before any fetch**
  (`fetch.rs:26-39`). A real atproto account is a `did:plc` — resolvable by the
  deployed resolver — so the live `did:` demo needs **no `did:web` hosting**;
  `did:key` remains the in-process test vehicle via `StaticResolver`.

**Model-R correction (2026-08-06, from `docs/notes/atproto-integration-model.md`
+ `atproto-token-shape.md`).** CISS is a **verify-only resource provider**; it
issues no token and the caller's signing key is **never held by the client**. The
`did:` identity is the user's **atproto account** (a bsky `did:plc`), and the token
is obtained by the standard flow, **not self-minted**:

```
  client --app password--> user's PDS: com.atproto.server.createSession  -> accessJwt
  client --accessJwt-->     user's PDS: com.atproto.server.getServiceAuth
                              (aud=did:web:ciss.croft.ing, lxm=<method>, exp<=now+60s..1h)
                            <- { token: <service-auth JWT, signed by the user's repo key> }
  client --Bearer <that JWT>--> CISS  -> resolves iss did:plc via plc.directory -> verify
```

Consequences that reshape the `did:` track:
- **The CLI holds a *credential* (a bsky app password), not a signing key.** No
  local secp256k1 key, no `did:web` hosting, no self-mint in the production path.
- `did:web:ciss.croft.ing` is **CISS's** service DID (the `aud`), already served at
  `/.well-known/did.json` — the client only needs to know it (discover or `--aud`).
- The mint helper (Phase 6) is a **test-only** stand-in for the PDS's
  `getServiceAuth`, so in-process tests (which cannot call bsky) can produce a JWT
  CISS accepts via `StaticResolver`. It is not a CLI production path.
- The live `did:` demo needs **throwaway bsky test credentials** (per the workspace
  convention "drive live logins with throwaway test credentials the owner
  supplies") and network to bsky + plc.directory.

**D4 — the live `getServiceAuth` flow, verified against `bsky.social` (2026-08-06,
disposable account in `.env`; External-APIs rule satisfied by a live probe):**
- `POST /xrpc/com.atproto.server.createSession`, body `{"identifier","password"}`
  → `{accessJwt, refreshJwt, did, handle, didDoc, active, email, …}`. The test
  account is `handle=ngvalidation2112.bsky.social`, `did:plc:xyfhcaweaeyew3zrgk6jaln7`.
- `GET /xrpc/com.atproto.server.getServiceAuth?aud=<CISS did>&lxm=<method>&exp=<unix>`
  with `Authorization: Bearer <accessJwt>` → `{"token": "<jwt>"}`.
- The `token` is a compact `ES256K` JWS with claims `{iss=<account did:plc>, aud,
  lxm, exp, iat, jti}`, `exp-iat = 60s`. This is exactly the shape `service_jwt.rs`
  verifies (D2), signed by the account's repo key at bsky, resolvable via
  `plc.directory` (D3). **The live `did:` path is fully specified — no inference
  remains.** The account password lives only in `.env` (gitignored); the CLI reads
  the credential from there / its config, never logs it.

## Documentation Impact

- `README.md` — add a **Client (`ciss-ctl`)** section with the capability
  walkthrough; handled in **Phase 9** (the phase that makes the README stale by
  shipping the demo).
- `docs/CLIENT.md` (new) — the end-to-end walkthrough doc; created in **Phase 9**.
- `docs/spec/gated-reads.md` — add a one-line note that `ciss-ctl acl` is the
  reference Model-A/C integrator; **Phase 8b**.
- `Cargo.toml` (root, workspace `members`) — build config, not a doc; edited in
  **Phase 1**.
- Homebrew tap: **`CroftCommunity/homebrew-tap`**, cloned at
  `/Users/cpettet/git/chasemp/CroftC/homebrew-tap` (currently `LICENSE` + `README`
  only). The `ciss-ctl` formula lands there in **Phase 10** (cross-repo; not a
  CISS-repo source change).
- Grep for existing `ciss-ctl` references: none (new name) — `grep -rn "ciss-ctl"`
  returns only this plan. Nothing else to update.

## Concurrency Map

```
Sequential spine (║ = may run concurrently with the spine):
  Phase 0 → 1 → 2 → 3 → 4 → 5 → 7 → 8b → 9 → 10
                            └→ 8a ┐  (8a depends only on Phase 5)
  Phase 6 ║ (any time after Phase 0/D2, before Phase 7)
```

Default is **sequential** — each CLI phase builds on the scaffolding (config,
client, command dispatch) the previous one created, so read-sets overlap. Two
structural notes from Pass 3: **Phase 8a** (Model-A ACL) depends only on Phase 5,
so it can land before Phase 7; **Phase 8b** (Model-C ACL) depends on Phase 7.

One genuine parallel candidate, surfaced in Pass 2:

Parallel set {6, (2 or 3)}:
- **Phase 6** (promote the JWT mint helper) lives entirely in
  `crates/ciss-auth/` — a **disjoint write-set** from the `crates/ciss-cli/` work
  in Phases 2–3. It is a prerequisite only for Phase 7, so it can be done any time
  before then, including concurrently with the `id:`-track CLI phases.
- Shared-state contract: both touch the workspace `Cargo.lock` on `cargo build`,
  but not the same source files; no git-HEAD/port/daemon mutation (both are
  library+unit-test work, no server bind). Disjoint tmp paths (unit tests only).
- Re-entry verification (if run in parallel worktrees): parent-repo HEAD ==
  pre-dispatch SHA; `git worktree list` shows only the expected worktrees;
  `cargo test -p ciss-auth` and `cargo test -p ciss-cli` both green after merge.

**Recommendation:** keep sequential unless the executor wants the speedup — the
change is small and the workspace build is the only shared surface. Flagged so the
option is explicit, per the Concurrency Map rule.

## Phases

**TDD discipline (applies to every implementation phase, 1–10; Phase 0 is exempt
under the Discovery Exemption).** Each phase's **Wiring test is written first and
watched fail (RED)** against the absent/incomplete production code — a failure that
is seen, not assumed — then the minimum production code makes it GREEN, then
refactor only if it adds value. No production line lands without a failing test
that demanded it, data/config/constants included. Security-shaped guards (the
`401` on an unauthenticated `put`, the `404`-on-deny in Phase 8) must be RED
against the permissive path before they are GREEN, then stay as regression walls.
Keep `cargo test --workspace` and `cargo clippy --all-targets --workspace` clean at
every phase boundary; commit only at a green boundary, one commit per phase.

**Observability & error UX (cross-cutting, applies to every HTTP-touching phase).**
The CLI is a debugging tool as much as a client, so:
- **`-v/--verbose`** logs each request/response line (method, URL, **status**) and,
  for the `did:` path, the **decoded JWT claims** (`iss/aud/lxm/exp`) — never the
  signature. Off by default; single line per call at `-v`, bodies at `-vv`.
- **Never log secrets:** the ed25519 seed, the `x-croft-session` signature, the
  bsky app password, `accessJwt`, or the raw service-auth JWT. Redact in all paths.
- **Actionable error mapping:** the server returns *distinct* codes and the CLI
  must translate them, not print "request failed". At minimum: `401` → "no/'invalid
  session — run under an authenticated profile"; `403` → "forbidden (bad signature
  or wrong signer)"; `404` on a read → "not found **or** not visible to you (gated)"
  (name the oracle-free ambiguity); `409` on `acl set` → "policy seq not newer;
  current seq=<n>". A connect failure → "server unreachable at <url>". This mapping
  is introduced in Phase 4 (first HTTP surface) and reused by every later phase.
- **`--json`** switches human output to machine JSON for scripting/tests.

**Test-harness convention.** CLI integration tests follow the repo's in-process
pattern (`docs/TESTING-STRATEGY.md`): build `App`, bind `127.0.0.1:0`, drive via the
CLI's own client functions — not mocked HTTP. The multi-actor stories (Phase 7 `did:`,
Phase 8 owner/grantee/stranger) are **workflow-tier** in spirit; reuse the
`World`/`Actor` harness (`tests/common`) if it lifts cleanly into the `ciss-cli`
crate, else a CLI-local analog with the same persona shape. Decide at Phase 4 (the
first integration test) and keep it consistent.

### Phase 0: Discovery ✅ EXECUTED (2026-08-06)

**Goal:** Resolve the unverified unknowns before sizing the key-import and
`did:` phases, so an assumption error doesn't cascade. **All four (D1–D4) resolved
— see Verified Assumptions and the Review Log. Findings folded into Phases 3, 6, 7
below.**

- [x] **D1: How does `ssh-key` expose a raw ed25519 seed?** → **RESOLVED.**
  `ssh-key` v0.6 + feature `ed25519`: `PrivateKey::from_openssh` →
  `.key_data().ed25519()` → `kp.private.to_bytes()`. DID parity proven by a
  compile+run probe (`$SCRATCH/sshkey-spike`, exit 0). Encrypted keys flagged by
  `is_encrypted()`. Disposition honored: probe code `throwaway`; a passphrase-less
  ed25519 key becomes a committed fixture in Phase 3.
- [x] **D2: What compact-JWS does `verify_service_auth_jwt` accept?** → **RESOLVED.**
  Header `{"typ":"JWT","alg":"ES256K"}`; claims `{iss,aud,lxm,exp,jti}` (`lxm`
  mandatory); sig = raw 64-byte `r‖s` base64url; curve secp256k1/P-256 (**not
  ed25519**). Verify reads the curve from the resolved key. `promote` target for
  Phase 6 identified: `service_jwt.rs:171-198`.
- [x] **D3: Which `did:` method, and can CISS resolve it?** → **RESOLVED.**
  Deployed resolver = `did:plc` + `did:web` only; `did:key` refused pre-fetch.
  A real atproto account is a `did:plc` (resolvable) — so the live demo needs no
  `did:web` hosting. Tests use `StaticResolver` + `did:key`.
- [x] **D4: the `getServiceAuth` flow shape.** → **RESOLVED** (live probe against
  `bsky.social`, 2026-08-06, disposable test account in `.env`). Confirmed:
  `createSession` POST `{identifier, password}` → `{accessJwt, did, handle,
  refreshJwt, didDoc, active, email…}`; `getServiceAuth` GET `?aud=&lxm=&exp=` +
  `Bearer accessJwt` → `{token}`. The token is a real `ES256K` service-auth JWT
  with claims `{iss, aud, lxm, exp, iat, jti}` — a byte-for-byte match to CISS's
  verify contract. Disposition honored: probe `throwaway`, findings below.

**Done:** all four D-items (D1–D4) answered with firsthand evidence, including a
live bsky probe; Verified Assumptions updated. Phase 0 restructured Phases 3/6/7
(the secp256k1 `did:`-key finding and the Model-R correction) — logged in the
Review Log.

**Read-set:** `crates/ciss-auth/src/service_jwt.rs`, `crates/ciss-resolve/src/fetch.rs`, `static_resolver.rs`.
**Write-set:** throwaway spike under `$TMPDIR/`; no committed source.
**Shared-state contract:** no shared mutable state; probes are unit-level, bind no ports.
**Validation:** Discovery Exemption — evidence recorded, no TDD on spike code.

---

### Phase 1: Crate skeleton ✅ COMPLETE (2026-08-06)

**Goal:** `crates/ciss-cli` exists as a workspace member; `ciss-ctl --version` and
`--help` work.
**Changes:**
- [x] `crates/ciss-cli/Cargo.toml` — new crate; deps `ciss` (path), `clap`
  (derive), `tokio`, `anyhow`/`thiserror`; `[[bin]] name = "ciss-ctl"`.
- [x] `crates/ciss-cli/src/main.rs` — `clap` root parser with the **global flags**
  (`--server <url>`, `--profile <name>`, `--identity id|did`, `--json`,
  `-v/--verbose`), `--version`, and subcommand enum stubs that return "not yet
  implemented" errors (not silent stubs — explicit `unimplemented`-style error
  text, replaced phase by phase). Actionable error-code mapping arrives in Phase 4.
- [x] `Cargo.toml` (root) — add `crates/ciss-cli` to `workspace.members`.

**Executed:** RED-first `tests/cli_smoke.rs` (bare `main` → empty `--version`/`--help`,
2/3 failing), then GREEN with the clap parser (3/3). `cargo build --workspace` +
`cargo clippy --all-targets --workspace` clean; full workspace suite unaffected.
Subcommand surface wired as stubs: `key {gen,show,import}`, `whoami`, `put`, `get`,
`meter`, `ls`, `acl {set,get}`, each returning a loud not-yet-implemented error.
**Call chain:** `main()` → `clap::Parser::parse()` → subcommand dispatch (stubs
error explicitly until their phase lands).
**Wiring test:** `tests/cli_smoke.rs` runs the built binary with `--version` and
asserts it prints the crate version; runs `--help` and asserts each subcommand
name appears.
**Depends on:** Phase 0 (dep choices confirmed).
**Read-set:** root `Cargo.toml`.
**Write-set:** `crates/ciss-cli/Cargo.toml`, `crates/ciss-cli/src/main.rs`, root `Cargo.toml`.
**Shared-state contract:** no shared mutable state beyond the workspace build.
**Risks:** clap version drift with the workspace; pin explicitly.
**Done when:**
1. **Behavioral:** `ciss-ctl --version` prints the version and `--help` lists all
   planned subcommands.
2. **Verification:** `cargo test -p ciss-cli --test cli_smoke` green; `cargo build
   --workspace` green.
**Validation:** Narrow — wiring test + build.

---

### Phase 2: Identity — `key gen` / `key show` / `whoami` ✅ COMPLETE (2026-08-06)

**Goal:** Generate a native ed25519 identity, persist it, and report the derived
`id:` DID.
**Changes:**
- [x] `crates/ciss-cli/src/config.rs` — profile/paths (`$XDG_CONFIG_HOME/ciss-ctl/`),
  key file read/write at mode `0600`, stores only the raw seed hex.
- [x] `crates/ciss-cli/src/identity.rs` — `key gen` (random ed25519 via the in-tree
  primitive), `key show`, `whoami`; DID via `ciss::identity::derive_id`.
- [x] wire the `key`/`whoami` subcommands in `main.rs`.

**Library addition (TDD'd in `ciss`, RED→GREEN):** `ciss::crypto::Keypair::from_seed(&[u8;32], label)`
— the crate had **no public seed constructor** (only `derive_keypair`, which
*hashes* a master seed). The CLI must persist a raw seed and reconstruct the exact
keypair to call the server's own `sign_message` (Phase 4), so this small
constructor is the fidelity hinge; its RED test asserts reload parity (same pubkey
+ same signature). Randomness for `key gen` is `getrandom` (OS CSPRNG) — **not**
`ciss::rng`, which is a deterministic mulberry32 sim PRNG, unfit for a real key.

**Executed:** RED-first `tests/cli_identity.rs` (4 edges: DID == independent
`derive_id` over the stored seed; key file `0600` + seed-only, no pubkey/DID
leak; `key gen` refuses to clobber; `whoami` with no key fails loud pointing at
`key gen`) → GREEN. Manually validated: file `-rw-------`, dir `drwx------`,
re-gen exits 1. Config layout fixed as `$XDG_CONFIG_HOME/ciss-ctl/profiles/<profile>/identity.key`
(seed hex, `create_new`+`mode(0600)` so the secret is never briefly world-readable).
**Call chain:** `main` → `Key::Gen` → `identity::gen()` → writes key file →
`identity::show()`/`whoami()` → `derive_id`.
**Wiring test:** `tests/cli_identity.rs` — `key gen` then `whoami` prints an `id:`
DID equal to `derive_id` over the stored key's public half; the key file is `0600`
and contains no pubkey/DID (seed only).
**Depends on:** Phase 1.
**Read-set:** `src/main.rs`, `ciss::{crypto,identity}`.
**Write-set:** `crates/ciss-cli/src/config.rs`, `crates/ciss-cli/src/identity.rs`, `crates/ciss-cli/src/main.rs`.
**Shared-state contract:** writes only under a test-scoped `$XDG_CONFIG_HOME`
(`tmp_path`); reads/sets no ambient env beyond that; binds no ports.
**Risks:** secret leaking to logs — assert the key material is never printed.
**Done when:**
1. **Behavioral:** a fresh `key gen` + `whoami` yields a stable `id:` DID; the
   secret is on disk only, `0600`.
2. **Verification:** `cargo test -p ciss-cli --test cli_identity` green.
**Validation:** Moderate — wiring test + run `ciss-ctl key gen && ciss-ctl whoami`
by hand, inspect file mode.

---

### Phase 3: Key import (OpenSSH ed25519) ✅ COMPLETE (2026-08-06)

**Goal:** Import an ssh-keygen ed25519 key as a first-class CISS identity.
**Changes:**
- [x] `crates/ciss-cli/Cargo.toml` — add `ssh-key = { version = "0.6", features =
  ["ed25519"] }` (per D1).
- [x] `crates/ciss-cli/src/identity.rs` — `key import <path>`:
  `PrivateKey::from_openssh` → guard `is_encrypted()` (error: passphrase keys out
  of v1) → `.key_data().ed25519().kp.private.to_bytes()` → store like a native key.
- [x] test fixtures: committed passphrase-less **and** encrypted ed25519 OpenSSH
  keys at `crates/ciss-cli/tests/fixtures/`.

**Executed:** RED-first (3 edges on top of Phase 2's `cli_identity.rs`): import
parity against a **golden `id:` DID** computed independently of the CLI and the
`ssh-key` crate (decode `.pub`, sha256 the trailing raw 32-byte pubkey); an
encrypted key is refused with a clear message and leaves **no** key file; import
refuses to clobber. GREEN; the imported seed is stored identically to a native
key so it re-derives the same DID. Manually validated against a fresh real
`ssh-keygen` key (parity) and an encrypted key (exit 1). Clippy clean; full
workspace suite green.
**Call chain:** `main` → `Key::Import{path}` → `identity::import()` → `ssh-key`
parse → store seed → `derive_id`.
**Wiring test:** `tests/cli_identity.rs` (extend) — importing the fixture yields
the **same** `id:` DID as loading its raw seed natively (round-trip parity).
**Depends on:** Phase 2, Phase 0/D1.
**Read-set:** `src/identity.rs`, the fixture key.
**Write-set:** `crates/ciss-cli/src/identity.rs`, `crates/ciss-cli/Cargo.toml`, `crates/ciss-cli/tests/fixtures/…`.
**Shared-state contract:** test-scoped `$XDG_CONFIG_HOME`; no ambient state.
**Risks:** `ssh-key` may pull a large dep tree or require features — confirm in D1;
passphrase-protected keys are out of v1 (error clearly).
**Done when:**
1. **Behavioral:** `ciss-ctl key import ~/.ssh/id_ed25519` produces a usable CISS
   identity with a deterministic `id:` DID.
2. **Verification:** `cargo test -p ciss-cli --test cli_identity -k import` green.
**Validation:** Moderate — wiring test + import a real `ssh-keygen` key by hand.

---

### Phase 4: S3 plane — `put` / `get` / `meter` (`id:` session) ✅ COMPLETE (2026-08-06)

**Goal:** Upload/fetch/meter over the S3 plane with a signed session; show bytes
transferred.
**Changes:**
- [x] `crates/ciss-cli/src/client.rs` — async reqwest client; session-header
  builder (sign `ciss-session/v1/<did>` via `Keypair::sign_message`, set
  `x-croft-pubkey`/`x-croft-session`); base-URL/profile plumbing.
- [x] `crates/ciss-cli/src/commands/object.rs` — `put <file>` (S3 `PUT
  /{did}/objects/{key}` → print `{cid, bytes, receipt_mode}` — shape pinned in
  Verified Assumptions), `get <cid>` (S3 GET, write bytes to `-o`, re-verify
  `sha256(bytes)==cid`), `meter` (GET `/{did}/meter`).
- [x] `crates/ciss-cli/src/client.rs` — the **error-code→message mapping** from the
  Observability note (401/403/404/409/connect-fail → actionable text). *(Distinct
  process exit codes deferred; every error exits 1 with actionable text — the
  load-bearing part. Noted as a minor follow-on.)*
- [x] wire subcommands.

**Structural:** `ciss-cli` became **lib+bin** (`src/lib.rs` exposes
`client`/`commands`/`config`/`identity`; `main.rs` is parse+dispatch) so
integration tests drive the CLI's own `Client` against an in-process `App`, per
the harness convention. `main` dispatch is now async.

**Executed:** RED-first pure guards in `client.rs` unit tests — `verify_cid`
(flipped byte **and** truncation fail) and `status_hint` (401→session,
403→signer, 404→oracle-free "not found/not visible", 409→seq) — then GREEN.
Integration `tests/cli_s3.rs` (in-process `ciss` App): metered put→get→meter
round-trip (cid==sha256, bytes==len, receipt unilateral, ETag echoes cid,
receipts=2, running_total=2×len); **tampered session → 401** (distinct from a
good one, which still works); missing object → **oracle-free 404**; dead server →
"unreachable". Manually validated against a locally-launched `ciss` server:
identical round-trip, meter increments, 404 message. Clippy clean; full suite green.
**Call chain:** `main` → `Put` → `client::put_s3()` (session header) → server
`put_object_handler` → prints receipt; `Get` → `client::get_s3()` → re-verify.
**Wiring test:** `tests/cli_s3.rs` — against an in-process `App` on an ephemeral
port. Name the edges (mutation-resistant, not single happy-path points):
- `put` a temp file → `cid == sha256_hex(bytes)`, `bytes` == the file length,
  `receipt_mode == "unilateral"`; `get <cid>` returns byte-identical content and an
  `etag`.
- **missing** session → `401`; **present-but-invalid** session (valid pubkey header,
  wrong/garbage signature) → **also `401`/Anonymous**, not accepted — distinguishes
  "no credential" from "bad credential" (guards the auth boundary against a mutation
  that treats any header as valid).
- `get` re-verify: a corrupted response body (one flipped byte) → the CLI **errors**
  (does not write a file that mismatches its cid).
- `meter` after one upload → `upload_bytes == len`, `receipt_count == 1`.
**Depends on:** Phase 2.
**Read-set:** `src/identity.rs`, `ciss::{crypto,cidv1,receipts}`, server test setup.
**Write-set:** `crates/ciss-cli/src/client.rs`, `crates/ciss-cli/src/commands/object.rs`, `crates/ciss-cli/src/main.rs`.
**Shared-state contract:** the test binds an ephemeral loopback port (`:0`) and a
`tmp_path` data dir; no fixed port, no ambient env beyond a test-scoped config.
**Risks:** the `get` re-verify must run **before** the file is written to `-o` (or
to a temp then rename), so a mismatch never leaves a corrupt file on disk.
**Done when:**
1. **Behavioral:** `ciss-ctl put note.txt` prints the cid + bytes + receipt mode;
   `ciss-ctl get <cid> -o out` reproduces the file; `ciss-ctl meter` shows totals.
2. **Verification:** `cargo test -p ciss-cli --test cli_s3` green.
**Validation:** Broad — wiring test + run against a locally-launched `ciss` server,
confirm the meter increments and bytes round-trip.

---

### Phase 5: atproto plane + interchangeability — `put/get --via pds`, `ls` ✅ COMPLETE (2026-08-06)

**Goal:** The same identity uploads/fetches over `uploadBlob`/`getBlob`
interchangeably with S3, via the CIDv1 bridge; `ls` lists blobs.
**Changes:**
- [x] `crates/ciss-cli/src/client.rs` — `uploadBlob` (POST, `x-croft-*` session),
  `getBlob?did=&cid=`, `listBlobs?did=`; CIDv1↔hex via `ciss::cidv1`. `Plane` enum
  moved into the lib (clap `ValueEnum`); a query-value percent-encoder for the
  `did`/`cid` params.
- [x] `crates/ciss-cli/src/commands/object.rs` — `--via s3|pds` on put/get; `ls`.

**Executed:** RED-first `tests/cli_atproto.rs` drives the library `Client` against
an in-process App and proves the load-bearing property — **cross-plane fetch**:
`put_s3` then `get_blob` is byte-identical, and `upload_blob` then `get_s3` is
byte-identical, with `uploadBlob`'s CIDv1 bridging back to the *same* sha256 hex
the S3 plane reports; `list_blobs` returns both cids as hex. GREEN. `get_blob`
takes the hex cid, bridges to CIDv1, and re-verifies bytes against the hex cid
(same guard as `get_s3`). The `id:` `x-croft-*` session drives both planes, so one
key demonstrates interchangeability. Manually validated against a local server
(S3→PDS and PDS→S3 both identical; `ls` lists both). Clippy clean; full suite green.
**Call chain:** `main` → `Put{via:pds}` → `client::upload_blob()` → server
`upload_blob` → `$link`; `Get{via:pds}` → `client::get_blob()`.
**Wiring test:** `tests/cli_atproto.rs` — a file `put --via s3` is fetchable via
`get --via pds <cid>` (and vice-versa), proving one digest under two addressings;
`ls` reflects the uploaded cids.
**Depends on:** Phase 4.
**Read-set:** `src/client.rs`, `ciss::cidv1`, `src/pds_api.rs` (shape reference).
**Write-set:** `crates/ciss-cli/src/client.rs`, `crates/ciss-cli/src/commands/object.rs`.
**Shared-state contract:** ephemeral loopback port + `tmp_path`; as Phase 4.
**Risks:** CIDv1↔hex mismatch — the test asserts cross-plane fetch, which is the
exact guard.
**Done when:**
1. **Behavioral:** `put --via s3` then `get --via pds` (and the reverse) return the
   same bytes; `ls` lists them.
2. **Verification:** `cargo test -p ciss-cli --test cli_atproto` green.
**Validation:** Broad — wiring test + manual cross-plane round-trip against a local
server.

---

### Phase 6: Promote the service-auth JWT mint helper (`ciss-auth`) — test-side stand-in for the PDS ✅ COMPLETE (2026-08-06)

**Goal:** A public `ciss-auth` function mints a service-auth JWT CISS's verify path
accepts, so **in-process tests can simulate a PDS's `getServiceAuth`** (they cannot
call bsky). This is a test/dev helper, **not** the CLI's production path (the CLI
fetches its JWT from the real PDS — Phase 7).
**Changes:**
- [x] `crates/ciss-auth/src/service_jwt.rs` — promoted `mint_service_auth_jwt(sk:
  &k256::ecdsa::SigningKey, iss, aud, lxm, exp_unix_s, jti: Option<&str>) -> String`
  and `did_key_secp256k1(vk: &k256::ecdsa::VerifyingKey) -> String`. Exact verify
  shape: header `{"typ":"JWT","alg":"ES256K"}`, claims `{iss,aud,lxm,exp[,jti]}`,
  sig = raw 64-byte `r‖s` base64url over `header.payload`. secp256k1 (`k256`), not
  ed25519 (D2 corollary). Doc-commented as a **test/dev stand-in, not an issuer**.
- [x] `crates/ciss-auth/src/lib.rs` — export both. No new deps (`k256`/`base64`/
  `multibase` already present).

**Executed:** RED-first (`promoted_mint_helper_round_trips_and_rejects_claim_edges`
referenced the absent public fns → compile fail) → GREEN. The new test mints via
the public helper and asserts valid→`Authenticated(iss)` plus each edge with its
distinct error (wrong aud→`WrongAudience`, wrong lxm→`WrongMethod`,
expired→`Expired`, forged→`SignatureInvalid`). The existing `#[cfg(test)]`
`did_key_of` now delegates to `did_key_secp256k1`, so all prior edge tests exercise
the promoted encoding. Chosen **plain `pub`** over a `testing` feature so
`cargo test --workspace` keeps the guard active without extra feature plumbing.
28 ciss-auth tests green; clippy clean.

*Note for Phase 7:* `ciss` does not re-export `ciss-auth`, so ciss-cli's `did:`
offline test will add `ciss-auth` (+ `k256`) as dev-deps to mint the stand-in JWT.
**Call chain:** (library, test path) test harness → `ciss_auth::mint_service_auth_jwt`
→ compact JWS; server `verify_service_auth_jwt` accepts it against a
`StaticResolver`-provided `did:key`.
**Wiring test:** `crates/ciss-auth` unit test — a minted token round-trips through
`verify_service_auth_jwt` against a `StaticResolver`-provided `did:key` (**valid →
`Authenticated(iss)`**), and each failure edge is refused with its distinct error
(RED-first per case): **wrong `aud`** → `WrongAudience`; **wrong `lxm`** and
**missing `lxm`** → `WrongMethod`; **expired `exp`** → `Expired`; **forged** (token
names the victim `iss` but is signed by another key) → signature failure. These
mirror the existing `service_jwt.rs` cases so the promoted helper cannot regress
the verify contract.
**Depends on:** Phase 0/D2. (Independent of Phases 2–5, and of the live-account
D4 — this is the offline test vehicle. See Concurrency Map.)
**Read-set:** `crates/ciss-auth/src/service_jwt.rs`, `did_key.rs`.
**Write-set:** `crates/ciss-auth/src/service_jwt.rs`, `crates/ciss-auth/src/lib.rs`.
**Shared-state contract:** unit-test only; no ports, no ambient state.
**Risks:** the promoted signature must match the verify path exactly — the
round-trip test is the guard; keep the mint's key type zeroized.
**Done when:**
1. **Behavioral:** external callers can mint a token that `verify_service_auth_jwt`
   accepts; invalid variants are refused.
2. **Verification:** `cargo test -p ciss-auth` green (new mint/verify cases).
**Validation:** Moderate — unit round-trip + confirm no other crate regressed.

---

### Phase 7: `did:` service-auth path in the CLI — the `getServiceAuth` relay (Model R)

**Goal:** The CLI acts as a `did:` caller by **relaying a PDS-minted service-auth
JWT** (not self-minting): log in to the user's atproto account, fetch a
method-scoped JWT via `getServiceAuth`, and drive `uploadBlob`/`getBlob` with it.
**Changes:**
- [ ] `crates/ciss-cli/src/atproto.rs` — the PDS client: `createSession`
  (identifier + app password → `accessJwt` + the account `did`) and
  `getServiceAuth(aud, lxm, exp)` → the service-auth JWT (`token`). Shapes per D4.
- [ ] `crates/ciss-cli/src/client.rs` — Bearer-JWT auth mode against CISS; `--aud`
  (default the CISS service DID, discovered via `/.well-known/did.json`), `lxm` per
  method.
- [ ] `crates/ciss-cli/src/config.rs` — a `did:` **credential** profile (PDS host +
  handle/identifier + app password at `0600`); **no signing key** is stored.
**Call chain:** `main` → `Put{identity:did}` → `atproto::get_service_auth()` (login
+ getServiceAuth against the PDS) → `client` sends `Authorization: Bearer <jwt>` to
CISS `uploadBlob` → server resolves the `iss` `did:plc` → verifies.
**Wiring test (offline, authoritative for the code path):** `tests/cli_did.rs` —
build `App` with a `StaticResolver` mapping a test DID → its `did:key`; a JWT minted
by the Phase-6 helper (standing in for the PDS) drives `put --via pds` successfully;
`get --via pds` reads it back; an expired/wrong-`aud`/wrong-`lxm` token is `401`.
The **live** `getServiceAuth` round-trip is exercised separately in Phase 9's demo
(gated on D4 + creds), not in this unit test.
**Depends on:** Phase 5, Phase 6, and **D4** (live path only; the offline wiring
test does not).
**Read-set:** `src/client.rs`, `src/atproto.rs`, `src/config.rs`, `ciss_auth`, `ciss-resolve` testutil.
**Write-set:** `crates/ciss-cli/src/atproto.rs`, `crates/ciss-cli/src/client.rs`, `crates/ciss-cli/src/config.rs`.
**Shared-state contract:** ephemeral loopback port + `tmp_path`; the resolver is
injected into the in-process `App`, not global. The live path talks to bsky +
plc.directory (external) — exercised only in the Phase 9 demo, never in the unit
test (which is hermetic).
**Risks:** **the CLI never holds the repo key** — a credential leak is a bsky
app-password leak (revocable at bsky), not a key compromise; store the app password
`0600` and never log it. The `id:` and `did:` profiles are different kinds (local
key vs. remote credential) — a `put --via s3` under a `did:` profile must fail
loudly (no `id:` session key present), not silently mis-sign. External-APIs
discipline: do not code `createSession`/`getServiceAuth` until D4 confirms the
field names.
**Done when:**
1. **Behavioral (offline):** `ciss-ctl --identity did:… put --via pds` uploads and
   reads back under a service-auth JWT verified via the injected resolver.
2. **Verification:** `cargo test -p ciss-cli --test cli_did` green.
**Validation:** Broad — the hermetic wiring test proves the Bearer/verify path; the
**live** getServiceAuth round-trip is validated in Phase 9 against bsky with
throwaway creds (D4).

---

### Phase 8a: Object ACL — Model A (`id:` owner, self-signed)

**Goal:** An `id:` owner sets/reads a per-object read policy and the gate proves
**oracle-free denial**. (Model C `did:` owner is Phase 8b — split from the original
Phase 8 to respect the 4-file rule and because Model A has **no `did:`
dependency**.)
**Changes:**
- [ ] `crates/ciss-cli/src/commands/acl.rs` — `acl set <cid> --class
  world|grantees|owner [--readers did,…]` (Model A: build via
  `PolicyRecord::sign_owner`, PUT the signed record); `acl get <cid>` (GET).
- [ ] `crates/ciss-cli/src/client.rs` — policy PUT/GET methods; on `set`, read the
  current policy first to choose `seq = current+1` (else the server `409`s), and
  map `409` to the actionable message from the Observability note.
- [ ] wire the `acl` subcommand in `main.rs`.
**Call chain:** `main` → `Acl::Set` → (`client::get_object_policy` for current
`seq`) → `PolicyRecord::sign_owner` → `client::put_object_policy()` → server
`put_object_policy_handler`.
**Wiring test:** `tests/cli_acl.rs` — three-party story with `id:` actors (owner,
grantee, stranger). Name the edges:
- owner sets `grantees` with the grantee DID → `{seq}` returned.
- **owner** `get <cid>` → bytes; **grantee** `get <cid>` → bytes; **stranger**
  (other `id:`) `get <cid>` → **`404`**; **anonymous** `get <cid>` → **`404`**
  (never `403` — the oracle-free rule, the load-bearing security edge).
- `ls`: owner and grantee see the cid; stranger and anonymous **omit** it.
- `acl get`: **owner** sees the full record incl. `readers[]`; **grantee** sees only
  `{read_class, may_read:true}` (no reader-set leak); **stranger** → `404`.
- **anti-rollback:** a second `acl set` with a **stale/equal `seq`** → `409` (the
  CLI's auto-`seq` prevents this in the happy path; the test forces a low `seq` to
  prove the guard).
**Depends on:** Phase 5 (S3 + atproto reads, `id:` grantee recognized).
**Read-set:** `src/client.rs`, `ciss::policy`.
**Write-set:** `crates/ciss-cli/src/commands/acl.rs`, `crates/ciss-cli/src/client.rs`, `crates/ciss-cli/src/main.rs` (3 files).
**Shared-state contract:** ephemeral loopback port + `tmp_path`.
**Risks:** the `may_read`-only view for a grantee is a leakage boundary — assert the
grantee response does **not** contain `readers`.
**Done when:**
1. **Behavioral:** `acl set <cid> --class grantees --readers <id-did>` then stranger
   `get` → 404, grantee → bytes, owner `acl get` shows readers.
2. **Verification:** `cargo test -p ciss-cli --test cli_acl` green.
**Validation:** Broad — wiring test asserting 404-on-deny + `ls` omission + no
reader-leak; manual three-party run against a local server.

---

### Phase 8b: Object ACL — Model C (`did:` owner, provider-attested)

**Goal:** A `did:` owner sets/reads policy via a service-auth JWT (the atproto
authorization form), reusing the 8a command surface.
**Changes:**
- [ ] `crates/ciss-cli/src/commands/acl.rs` (extend) — for a `did:` profile, PUT a
  `PolicyIntent` with a `Bearer` service-auth JWT (`lxm=ing.croft.ciss.setPolicy`);
  `acl get` uses `lxm=ing.croft.ciss.getPolicy`. The JWT comes from Phase 7's
  `atproto::get_service_auth` (or the Phase-6 mint in-process).
- [ ] `docs/spec/gated-reads.md` — one-line note: `ciss-ctl acl` is the reference
  Model-A/C integrator.
**Call chain:** `main` → `Acl::Set{profile:did}` → `atproto::get_service_auth(lxm=
setPolicy)` → `client::put_object_policy_intent(Bearer)` → server
`put_object_policy_handler` (Model C branch → provider-attest).
**Wiring test:** `tests/cli_acl.rs` (extend) — `did:` owner (StaticResolver +
Phase-6 mint) sets `grantees`; a granted `did:` reader `get`s the blob; an
ungranted caller → `404`. A **present-but-invalid** JWT on `acl set` → **`403`**
(the spec's hard-fail for a bad Model-C credential), distinct from the `401` a read
gives an anonymous caller.
**Depends on:** Phase 7 (the `did:` service-auth client), Phase 8a (the command).
**Read-set:** `src/client.rs`, `src/atproto.rs`, `ciss::policy`, `docs/spec/gated-reads.md`.
**Write-set:** `crates/ciss-cli/src/commands/acl.rs`, `docs/spec/gated-reads.md` (2 files).
**Shared-state contract:** ephemeral loopback port + `tmp_path`.
**Risks:** verify bsky's `getServiceAuth` accepts a **non-`com.atproto` `lxm`**
(`ing.croft.ciss.setPolicy`) — `lxm` is an opaque NSID string, expected to work, but
confirm on the first live run (the offline test uses the Phase-6 mint, which is
unconstrained). If bsky rejects custom `lxm`, Model-C-over-live-bsky is a documented
SEAM and the offline test still proves the CISS-side path.
**Done when:**
1. **Behavioral:** a `did:` owner `acl set`s a policy CISS honors; a bad JWT → 403.
2. **Verification:** `cargo test -p ciss-cli --test cli_acl -k model_c` green.
**Validation:** Broad — offline wiring test; live Model-C set exercised in Phase 9
if the custom-`lxm` risk clears.

---

### Phase 9: End-to-end demo + docs

**Goal:** A repeatable capability tour and user-facing docs.
**Changes:**
- [ ] `scripts/demo.sh` (or a `just demo`) — launches a local `ciss`, runs the full
  tour (keygen → put both planes → meter → acl set → 3-party read → get).
- [ ] `docs/CLIENT.md` — the walkthrough (below).
- [ ] `README.md` — a **Client** section linking `ciss-ctl`.
**Call chain:** n/a (docs + orchestration script).
**Wiring test:** `tests/cli_demo.rs` (preferred over a bare shell script so it is a
real, asserting test) runs the tour end-to-end against an in-process server and
**asserts each step** — not just exit 0: keygen yields an `id:` DID; `put`
returns a cid; cross-plane `get` matches; `meter` increments; `acl set` then
stranger `get` → 404. The live `did:` `getServiceAuth` round-trip against bsky
(with the `.env` account) is a **separate, opt-in** target (`-k live`, network-gated)
so the default suite stays hermetic.
**Depends on:** Phases 4–8b.
**Read-set:** all CLI command modules.
**Write-set:** `scripts/demo.sh`, `docs/CLIENT.md`, `README.md`.
**Shared-state contract:** the demo script launches a server on a chosen port and
tears it down; document the port and cleanup.
**Risks:** a demo that drifts from the code — prefer the `tests/cli_demo.rs` form
so it is a real test, not prose.
**Done when:**
1. **Behavioral:** a new user runs one script and sees every capability
   demonstrated with real output.
2. **Verification:** `cargo test -p ciss-cli --test cli_demo` (or the script's
   own exit code in CI) green.
**Validation:** Broad — run the whole tour on a clean checkout.

---

### Phase 10: Homebrew distribution

**Goal:** `brew install` yields a working `ciss-ctl`.
**Changes:**
- [ ] `CroftCommunity/homebrew-tap` (cloned at
  `/Users/cpettet/git/chasemp/CroftC/homebrew-tap`) — add `Formula/ciss-ctl.rb`
  building `ciss-ctl`; push tag on `ciss`, verify SHA256 against the uploaded
  release asset (per the Homebrew workflow rules in CLAUDE.md and the
  `cli-distribution` skill). Git identity: `chasemp` / `github-personal`.
**Call chain:** n/a (packaging).
**Wiring test:** `brew install` from the tap on a clean machine → `ciss-ctl
--version` works; `brew test` runs `key gen` + `whoami`.
**Depends on:** Phase 9 (a tagged, demoable release).
**Read-set:** the release tarball.
**Write-set:** tap formula (external repo).
**Shared-state contract:** cross-repo; no CISS-repo source mutation.
**Risks:** pure-Rust here (no native .so relocation issue), so the standard
`cargo install` recipe applies — but confirm `ssh-key`/`k256` don't pull a C dep.
**Done when:**
1. **Behavioral:** `brew install …/ciss-ctl && ciss-ctl --version` on a clean box.
2. **Verification:** `brew test` green; SHA256 matches the release asset.
**Validation:** Broad — install on a machine without the toolchain preinstalled.

---

## The capability walkthrough (what the demo proves)

```
┌─ identity ────────────────────────────────────────────────┐
│ ciss-ctl key gen              → id:8a1f…  (or key import)  │
└───────────────────────────────────────────────────────────┘
        │
        ▼
┌─ metered upload, two surfaces, one digest ────────────────┐
│ ciss-ctl put note.txt --via s3   → {cid, bytes, receipt}  │
│ ciss-ctl get <cid>  --via pds    → exact bytes (bridged)  │
│ ciss-ctl meter                   → running_total_bytes ↑  │
└───────────────────────────────────────────────────────────┘
        │
        ▼
┌─ gate a private object, prove oracle-free denial ─────────┐
│ ciss-ctl acl set <cid> --class grantees --readers did:…   │
│   owner   get <cid> → bytes                                │
│   grantee get <cid> → bytes                                │
│   stranger get <cid> → 404  (not 403; ls omits it)        │
│ ciss-ctl acl get <cid> → owner sees readers[]             │
└───────────────────────────────────────────────────────────┘
```

## SEAMs / deferred (explicit, so nobody relies on them)

- **Bilateral (client co-signed) receipts** — server returns `BilateralUnsupported`;
  a `--bilateral` flag surfaces the boundary, does not fake it.
- **OAuth login for the `did:` path** — v1 uses an **app password** for
  `createSession` (the simplest CLI login). Full atproto OAuth (PAR/DPoP/PKCE) and
  the `account.croft.ing` broker relay are tracked follow-ons; the app-password
  floor reaches the same `getServiceAuth` JWT.
- **Manifest signing** (`PUT /{did}/manifest`, the rent base) — not in the client
  demo v1; the meter already shows transferred bytes. Tracked add-on.
- **S3 DELETE/LIST/HEAD/multipart** — server-side `501` SEAMs; the client won't
  expose verbs the server doesn't implement.

## Open Questions

**Resolved by Phase 0 (2026-08-06):**
- ~~[PHASE-GATED (Phase 3)] Does `ssh-key` yield a raw ed25519 seed with DID
  parity?~~ → **RESOLVED (D1):** yes, `ssh-key` v0.6 + `ed25519`; parity proven.
- ~~[PHASE-GATED (Phase 6)] Exact JWS header/claim/curve?~~ → **RESOLVED (D2):**
  `ES256K` header, `{iss,aud,lxm,exp,jti}`, secp256k1/P-256 (not ed25519).
- ~~[PHASE-GATED (Phase 7)] Which `did:` method can the deployed resolver
  resolve?~~ → **RESOLVED (D3):** `did:plc`/`did:web` only; live demo uses
  `did:web`, tests use `StaticResolver`+`did:key`.

**Resolved in discussion (2026-08-06):**
- ~~[ADVISORY] Homebrew home.~~ → **RESOLVED:** `CroftCommunity/homebrew-tap`,
  cloned at `/Users/cpettet/git/chasemp/CroftC/homebrew-tap`.
- ~~[PHASE-GATED (Phase 7)] `did:web` host for the live demo.~~ → **DISSOLVED:** the
  Model-R correction means the live `did:` identity is a bsky `did:plc` account,
  not a hosted `did:web`. Replaced by the credential question below.

- ~~[BLOCKING] throwaway bsky creds for D4 / the live demo.~~ → **RESOLVED:** the
  owner supplied a disposable account in `.env` (gitignored); D4 ran live and
  passed. The Phase 9 demo can exercise the real `getServiceAuth` round-trip.

**Resolved during execution (2026-08-06):**
- ~~[ADVISORY] Config layout.~~ → **RESOLVED (Phase 2):** proceeded with the
  recommendation — `$XDG_CONFIG_HOME/ciss-ctl/profiles/<profile>/` (fallback
  `$HOME/.config`), `identity.key` = raw seed hex at `0600`; default `--via s3`.
  The `did:` credential moves **into the profile** (a `pds` credential file
  alongside `identity.key`) in Phase 7 — not a repo-root `.env`, which was only the
  D4 probe vehicle. No `config.toml` yet (nothing needs it until multi-field
  profiles land); revisit if profile config grows beyond per-file secrets.

**Still open:** none blocking. (Phase 7 will confirm the `did:` credential file
shape when it lands.)

## Review Log

### Pass 1: Plan development — 2026-08-06
Built the base: problem, reasoning, phases 0–10, concurrency map, docs impact,
open questions. Grounded every wire claim in `src/`/`crates/` at plan time.

### Pass 2: Gap analysis — 2026-08-06
**Found:**
- **No public JWT-mint helper.** Minting exists only in `ciss-auth`'s
  `#[cfg(test)]` block (`service_jwt.rs:181`). The original draft assumed the CLI
  could "self-mint" without noting the missing library surface. **Added Phase 6**
  (promote the mint helper) as an explicit prerequisite for the `did:` path.
- **Policy signing is already public** (`PolicyRecord::sign_owner`,
  `policy.rs:189`) — the draft implied the CLI would build the preimage. Corrected
  the Reasoning and Phase 8 to *call the existing API*, shrinking that phase.
- **`did:key` is parseable but its live resolution is unconfirmed.** Split the
  `did:` concern into an in-process-testable path (StaticResolver, authoritative)
  and a live-demo path (Open Question 3 / D3). The path lands green regardless of
  the live-resolver answer.
- **Phase 8 touches 4 files** — at the hard limit; added an explicit split-to-8b
  trigger and the `seq` anti-rollback handling the draft omitted.
- **Missing `did:` `seq`/`aud` mechanics** — Phase 8 now reads current policy to
  pick the next `seq` (or handles the server 409).
**Concurrency:**
- Surfaced one parallel candidate: Phase 6 (`crates/ciss-auth/`) has a disjoint
  write-set from Phases 2–3 (`crates/ciss-cli/`) and gates only Phase 7. Added it
  to the Concurrency Map with re-entry checks; recommended sequential (small change).
**Changed:**
- Reformatted the initial sketch into the phase-plan template; added Verified
  Assumptions, Documentation Impact, Concurrency Map, per-phase Call chain / Wiring
  test / Read-Write-set / Shared-state / two-tier Done-when / Validation, and
  severity-tagged Open Questions.
- Split the old single "did: + JWT" idea into Phase 6 (library mint) + Phase 7
  (CLI usage).
**Confirmed:**
- The in-repo-crate decision holds and is stronger than first argued — the CLI is
  mostly composition of existing `pub` surface (`derive_id`, `sign_message`,
  `cidv1`, `sign_owner`), so drift risk is even lower than the draft claimed.
- `id:` drives both S3 and atproto planes (`authenticate_atproto` fallback),
  so the interchangeability demo needs only one native key.
**Added (user emphasis, 2026-08-06):**
- A cross-cutting **TDD discipline** note at the head of the Phases section —
  RED-first wiring test per phase, security guards RED against the permissive path
  before GREEN, green+clippy-clean at every commit boundary. Reinforces the
  per-phase wiring tests already present; no phase content changed.

### Phase 0: Discovery executed — 2026-08-06
**Ran** all three D-items (Discovery Exemption: throwaway spike, no TDD on spike
code; evidence recorded).
**Found:**
- **D1 (compile+run probe, `$SCRATCH/sshkey-spike`, exit 0):** `ssh-key` v0.6 +
  feature `ed25519` extracts the raw seed via
  `PrivateKey::from_openssh(...).key_data().ed25519().private.to_bytes()`;
  reconstructing through `ed25519_dalek` matches the public bytes and the `id:` DID
  is byte-identical. `is_encrypted()` guards passphrase keys.
- **D2 (code read, `service_jwt.rs:160-279`):** JWS = `ES256K` header,
  `{iss,aud,lxm,exp,jti}` claims (`lxm` mandatory), 64-byte `r‖s` base64url sig;
  verify uses the resolved key's curve.
- **D2 corollary (code read, `did_key.rs:16-47`):** `did:` repo keys are
  **secp256k1/P-256, not ed25519** — the deployed verify path decodes only those
  two multicodecs. This is the one finding that changed later phases.
- **D3 (code read, `fetch.rs:26-39` + tests):** deployed resolver = `did:plc` +
  `did:web`; `did:key` refused pre-fetch.
**Changed:**
- **Phase 3:** pinned `ssh-key = "0.6"` + `ed25519`, the exact extraction call, and
  an `is_encrypted()` guard.
- **Phase 6:** pinned the promoted mint's header/claims/curve and named the
  secp256k1/P-256 signing-key type; noted `k256`/`p256`/`base64`/`multibase` are
  already deps (no new crate).
- **Phase 7:** the `did:` profile now holds a **secp256k1** key (distinct from the
  ed25519 `id:` key); live demo uses `did:web`, tests use `StaticResolver`+`did:key`;
  added `k256` to the CLI deps and a risk note about keeping the two key types
  from crossing planes.
- **Open Questions:** the three PHASE-GATED items are resolved; one new
  PHASE-GATED (Phase 7) question surfaced — whether the live demo needs a real
  `did:web` host or stays in-process — because D3 closed the `did:key` shortcut.
**Confirmed:**
- The `id:` track (Phases 1–5, 8-Model-A) is unaffected by the discovery — it is
  pure ed25519 and needs no external resolution. Only the `did:` track (6, 7,
  8-Model-C) absorbed the secp256k1 finding.

### Discussion: Model-R correction + tap — 2026-08-06
**Found (user challenge: "why did:web rather than just a bsky account?"):** the
draft `did:` path had the CLI self-minting from a locally-held secp256k1 key and/or
hosting a `did:web` doc. Re-reading `docs/notes/atproto-integration-model.md` and
`atproto-token-shape.md` confirmed this is wrong: CISS is **verify-only (Model R)**,
and the standard path is **the client relays a bsky-signed `getServiceAuth` JWT**
for its `did:plc` account. `did:web:ciss.croft.ing` is **CISS's** `aud`, not a
client artifact.
**Changed:**
- **Verified Assumptions:** added the Model-R correction block (token taxonomy,
  the `createSession`→`getServiceAuth`→Bearer flow, curve-lives-at-PDS).
- **Phase 6:** reframed as a **test-only** mint stand-in for the PDS (in-process
  tests can't call bsky), not the CLI's production path.
- **Phase 7:** rewritten to the **`getServiceAuth` relay** — `createSession` (app
  password) + `getServiceAuth` against the user's PDS, Bearer to CISS; the CLI
  holds a **credential, not a key**; `did:plc`, no `did:web` hosting. New module
  `src/atproto.rs`. Offline wiring test via `StaticResolver` + the Phase-6 mint;
  live round-trip moved to the Phase 9 demo.
- **Added D4** (deferred, gated on throwaway bsky creds): verify the
  `createSession`/`getServiceAuth` lexicon shapes before coding the live path.
- **Reasoning / SEAMs / Open Questions:** updated to app-password login (OAuth +
  broker relay tracked); the `did:web`-host question dissolved; a new BLOCKING
  question (throwaway bsky creds) added.
- **Homebrew:** resolved to `CroftCommunity/homebrew-tap`, cloned at
  `/Users/cpettet/git/chasemp/CroftC/homebrew-tap`; Phase 10 + Documentation Impact
  point at it.
**Confirmed:**
- The two-key-type worry is smaller than first stated: in production the CLI holds
  one ed25519 `id:` key **and a bsky app-password credential** — the secp256k1 key
  lives at bsky and surfaces in the CLI only inside the Phase-6 test mint.

### D4 executed (live bsky probe) — 2026-08-06
**Ran** the live `getServiceAuth` flow against `bsky.social` with the disposable
account the owner placed in `.env` (gitignored). **All confirmed firsthand:**
`createSession {identifier,password}→{accessJwt,did,handle,…}`;
`getServiceAuth ?aud=&lxm=&exp= +Bearer→{token}`; the `token` is an `ES256K` JWS
with `{iss,aud,lxm,exp,iat,jti}`, 60s window, `iss=did:plc:xyfhcaweaeyew3zrgk6jaln7`
— an exact match to CISS's verify contract.
**Changed:**
- Verified Assumptions: replaced the D4 "to verify" note with the confirmed
  `createSession`/`getServiceAuth` shapes and the account identity.
- Phase 0: D4 flipped to resolved.
- Open Questions: the BLOCKING creds question resolved; the config advisory now
  also asks whether the `did:` credential stays in `.env` or moves into profile
  config.
**Confirmed:**
- The full `did:` track (Phases 6–8 Model-C) now rests entirely on firsthand
  evidence — offline (mint helper + StaticResolver) and live (real bsky JWT). No
  API shape in the plan is inferred.

### Pass 3: Quality Gates — 2026-08-06
**TDD ordering:**
- Wiring test present in every implementation phase; all Verification commands run
  through the entry point (the built binary / the CLI client), not isolated modules.
- Strengthened mutation-resistance by naming **edges**, not happy-path points:
  Phase 4 (missing vs present-but-invalid session both → 401; corrupt-body → error;
  `meter` counts), Phase 6 (wrong-`aud`/`lxm`/missing-`lxm`/expired/forged each with
  its distinct error), Phase 8a (owner/grantee/stranger/anonymous read outcomes,
  `ls` omission, grantee sees `may_read` only, stale-`seq` → 409), Phase 8b
  (bad JWT → 403 vs anonymous 404).
**Observability:**
- Added a cross-cutting **Observability & error-UX** note: `-v/--verbose`
  request/response + decoded JWT claims (never the signature), a hard **never-log**
  list for all secrets, and an **actionable error-code mapping** (401/403/404/409/
  connect-fail) introduced in Phase 4 and reused everywhere. Wired the global flags
  into Phase 1 and the mapping into Phase 4.
**Debugging readiness:**
- Each phase commits at a green boundary (checkpoint). The 404-message names the
  oracle-free ambiguity so a debugger doesn't misread "gated" as "gone".
**Validation calibration:**
- Confirmed every phase's Validation matches scope (Narrow→Broad). Resolved the one
  deferred verification **now**: pinned the S3 PUT/GET/meter response shapes from
  `src/server.rs:1584-1606` into Verified Assumptions, removing Phase 4's "confirm
  at wiring" hedge.
**Concurrency honesty:**
- Map re-checked after the 8a/8b split; the {6 ∥ ciss-cli} parallel set's write-sets
  are still disjoint (`crates/ciss-auth` vs `crates/ciss-cli`); shared-state is
  stated as invariants (no git-HEAD/port mutation, disjoint tmp) with concrete
  re-entry checks. Surfaced the new structural fact that **Phase 8a depends only on
  Phase 5** (can precede Phase 7) and corrected the spine notation.
**Discovery:**
- Phase 0 D1–D4 all concrete, answered, and dispositioned (`throwaway`/
  `keep-as-fixture`/`promote`); fixed the stale "three D-items" wording to four.
**Coherence:**
- Plan still solves the four original asks; no scope creep. **Split Phase 8 → 8a
  (Model A, `id:`, 3 files) + 8b (Model C, `did:`, 2 files)** to honor the 4-file
  hard rule and separate the `did:`-independent Model-A ACL.
**Documentation impact:**
- Each doc update sits in the phase that makes it stale (gated-reads note → 8b;
  README/CLIENT → 9). Noted that per-phase `--help` text is self-documenting, so no
  doc debt accrues between phases; the consolidated Phase 9 docs describe the
  assembled whole (defensible, not an end-of-plan dumping ground).
**Confirmed ready:** yes — one ADVISORY open question remains (config layout /
`.env`-vs-profile credential), non-gating.
