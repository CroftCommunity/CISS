# `ciss-ctl` — the CISS client CLI

`ciss-ctl` is the reference client for CISS. It lives in-repo
(`crates/ciss-cli`) and **links the server's own crates**, so its crypto — the
session challenge, the DID derivation, the CIDv1↔hex bridge, the gated-read
policy preimage — is byte-identical to the wire. Drift is a compile error, not a
silent `403`.

It is the reference integrator for every capability CISS guarantees:

- a client identity keypair (generated natively **or** imported from an existing
  `ssh-keygen` ed25519 key);
- metered upload over **either** the S3 plane **or** the atproto `uploadBlob`
  plane — interchangeably, landing at one backend digest — showing the bytes
  transferred;
- an owner-controlled **read ACL** on a private object (gated reads, Model A/C)
  with **oracle-free denial**;
- fetching a stored object by its content id.

## Install

From the tap (see `Formula/ciss-ctl.rb` in `CroftCommunity/homebrew-tap`):

```bash
brew install croftcommunity/tap/ciss-ctl
ciss-ctl --version
```

Or from source in this workspace:

```bash
cargo build -p ciss-cli --release   # target/release/ciss-ctl
```

A man page is installed by the formula (`man ciss-ctl`); from source it can be
generated with `ciss-ctl man > ciss-ctl.1`.

## Identity

`ciss-ctl` keeps a raw ed25519 seed per profile at
`$XDG_CONFIG_HOME/ciss-ctl/profiles/<profile>/identity.key` (mode `0600`,
seed-only — the public key and DID are derived). The `id:` DID is
`"id:" + sha256(pubkey)`.

```bash
ciss-ctl key gen                       # generate a native identity
ciss-ctl key import ~/.ssh/id_ed25519  # or import an OpenSSH ed25519 key
ciss-ctl whoami                        # print the id: DID
ciss-ctl key show                      # DID + public key
```

Import extracts the raw seed via the `ssh-key` parser and stores it identically
to a native key, so an imported identity re-derives the same DID. Encrypted
(passphrase-protected) keys are refused — decrypt first with `ssh-keygen -p`.

## Two planes, one digest

Every command takes `--server <url>` (default `http://127.0.0.1:8080`). Upload
and fetch work over the S3 plane (`--via s3`, the default) or the atproto blob
plane (`--via pds`); both address the same content id.

```bash
ciss-ctl put note.txt                       # S3 plane → {cid, bytes, receipt}
ciss-ctl put note.txt --via pds             # atproto uploadBlob → same cid
ciss-ctl get <cid> -o out.txt               # fetch (re-verified against the cid)
ciss-ctl get <cid> --via pds -o out.txt     # fetch the other way — same bytes
ciss-ctl ls                                 # cids stored under your identity
ciss-ctl meter                              # receipts + bytes + postage
```

`get` verifies `sha256(bytes) == cid` **before** writing (temp-then-rename), so
a corrupted or substituted body never lands on disk.

## Gated reads (a read ACL on a private object)

An owner sets a per-object policy; a non-grantee read is a `404` — never a `403`
— so the gate is not an existence oracle, and `ls` omits objects the caller may
not read.

```bash
# Owner gates an object to a specific reader:
ciss-ctl acl set <cid> --class grantees --readers id:<grantee-did>
ciss-ctl acl get <cid>          # owner sees the full record incl. readers[]

# A grantee fetches it from the owner's namespace:
ciss-ctl --profile grantee get <cid> --owner id:<owner-did> -o out.txt

# A stranger gets 404 (and their `ls` omits the cid).
```

- `--class` is `world` (public), `grantees` (owner + the `--readers` list), or
  `owner` (owner-only).
- `acl set` reads the current policy first and submits `seq = current + 1`, so
  the happy path never trips the server's anti-rollback (`409`).
- A grantee's `acl get` returns only `{read_class, may_read: true}` — never the
  reader set.

## The `did:` identity (atproto account, Model R)

A `did:` identity is your **atproto account** (a bsky `did:plc`); its signing key
stays at your PDS. `ciss-ctl` holds a **credential** (an app password), not a
key. On each `did:` action it logs in and relays a short-lived, method-scoped
service-auth JWT that your PDS mints — CISS is verify-only.

Log in once with a bsky **app password** (revocable; create it in Settings → App
Passwords). `login` verifies it, then stores it in the profile's `pds.json` at
`0600`:

```bash
ciss-ctl login --pds https://bsky.social --identifier you.bsky.social
# app password: ****   (prompted without echo; or set CISS_PDS_APP_PASSWORD)

ciss-ctl --identity did put photo.jpg --via pds    # upload under a service-auth JWT
ciss-ctl --identity did get <cid> --via pds -o out
ciss-ctl --identity did acl set <cid> --class grantees --readers did:plc:…  # Model C
```

`CISS_PDS_HOST`/`CISS_PDS_IDENTIFIER`/`CISS_PDS_APP_PASSWORD` also work without
`login` (useful in CI).

Under a `did:` identity, `--via s3` is refused (there is no local signing key) —
the atproto plane is the `did:` path.

## Output & diagnostics

- `--json` switches any command's output to machine-readable JSON.
- `-v`/`-vv` raise verbosity. Secrets — the seed, the session signature, the app
  password, the access/service-auth JWTs — are **never** logged.
- Errors are actionable and map the server's status: `401` (no/invalid session),
  `403` (bad signature / wrong signer / bad Model-C credential), `404` (not
  found, **or** not visible to you — the gated-read ambiguity), `409` (policy
  `seq` not newer), and a clear "server unreachable" on a connect failure.

## What is not in v1 (explicit)

- **Bilateral (client co-signed) receipts** — the server is unilateral only; a
  `--bilateral` flag would surface the boundary, not fake it.
- **Manifest signing** (the rent base) — the meter already shows bytes
  transferred.
- **S3 DELETE/LIST/HEAD/multipart** — the client does not expose verbs the server
  answers with `501`.
- Full atproto **OAuth** for the `did:` path — v1 uses an app password for
  `createSession`; both reach the same `getServiceAuth` JWT.
