# Testing `ciss-ctl` against the live server — a both-sides guide

This walks the whole surface of the CISS client, `ciss-ctl`, against the
**deployed VPS** at `https://ciss.croft.ing`, and then shows the **server side** of
each action (the metering ledger, the signed receipts, the stored blobs, the
logs) so you can see both halves of every exchange.

Everything below was run against the live server with `ciss-ctl 0.5.0`; the
outputs are representative (your DIDs/cids differ). The last section lists what
CISS does that is **not yet reachable from the CLI**.

> These commands write small test objects to the production store under
> throwaway identities. There is no delete verb, so the bytes persist (a few
> hundred at most). That is inherent to testing against a live server.

---

## 0. Setup

### Install the client

```bash
brew install croftcommunity/tap/ciss-ctl
ciss-ctl --version          # ciss-ctl 0.5.0
man ciss-ctl                # the man page ships with the formula
```

### Point it at the VPS

`ciss-ctl` takes `--server` (default `http://127.0.0.1:8080`). Rather than repeat
the flag, define a small wrapper for this session, and a throwaway config dir so
nothing touches your real `~/.config`:

```bash
cctl() { ciss-ctl --server https://ciss.croft.ing "$@"; }
export XDG_CONFIG_HOME="$(mktemp -d)/cfg"
```

Confirm the server is reachable and serving its identity:

```bash
curl -s https://ciss.croft.ing/.well-known/did.json
# {"@context":[…],"id":"did:web:ciss.croft.ing","service":[{…"serviceEndpoint":"https://ciss.croft.ing"…}]}
```

The server enforces auth — an unauthenticated write is refused:

```bash
curl -s -o /dev/null -w '%{http_code}\n' -X PUT \
  https://ciss.croft.ing/id:0000…0000/objects/x --data-binary probe
# 401
```

---

## 1. Identity

`ciss-ctl` holds a raw ed25519 seed per **profile** at
`$XDG_CONFIG_HOME/ciss-ctl/profiles/<profile>/identity.key` (mode `0600`,
seed-only). The `id:` DID is `"id:" + sha256(pubkey)`.

```bash
cctl key gen
# id:b8c1ecda…

cctl whoami          # same DID — a pure function of the key
cctl key show        # DID + public key
cctl --json whoami   # {"did":"id:b8c1ecda…"}
```

Import an existing OpenSSH ed25519 key (passphrase-less) as its own profile:

```bash
ssh-keygen -t ed25519 -N "" -f /tmp/demo_key -q
cctl --profile imported key import /tmp/demo_key
# id:0da99fa5…      (deterministic; encrypted keys are refused)
```

---

## 2. Metered upload — two planes, one digest

CISS exposes an S3-compatible plane and an atproto blob plane over one metered
byte-path. `put`/`get` take `--via s3` (default) or `--via pds`; both address the
same content id.

```bash
echo "hello from ciss-ctl" > note.txt

cctl put note.txt
# uploaded via s3
#   cid:     f2c13d14…        (= sha256 of the file)
#   bytes:   29               (bytes transferred — the metered quantity)
#   receipt: unilateral       (provider-signed receipt; see §7)
#   etag:    "f2c13d14…"

CID=$(cctl --json put note.txt | python3 -c 'import sys,json;print(json.load(sys.stdin)["cid"])')
```

Cross-plane fetch — store one way, read the other, identical bytes (the client
bridges the S3 hex cid ↔ the atproto CIDv1):

```bash
cctl get "$CID" -o out_s3.txt              # via s3 (default)
cctl get "$CID" --via pds -o out_pds.txt   # via the atproto plane
diff out_s3.txt out_pds.txt && echo "identical across planes"
```

The client-side meter — receipts and bytes transferred (this is the aggregate the
server keeps for you):

```bash
cctl meter
# receipts:            4
# upload bytes:        58
# download bytes:      58
# running total bytes: 116
# postage (cents):     0

cctl ls          # content ids stored under your identity
# f2c13d14…
```

---

## 3. Content integrity

`get` re-computes `sha256(bytes)` and checks it against the cid **before** writing
(temp-then-rename), so a corrupt or substituted body never lands on disk — you see
`(cid verified)` on every fetch:

```bash
cctl get "$CID" -o out.txt
# wrote 29 bytes to out.txt (cid verified)
```

A cid that does not exist is an oracle-free `404` (see §4 for why "not found" and
"not visible" are deliberately indistinguishable):

```bash
cctl get "$(python3 -c 'print("0"*64)')" -o missing.txt; echo "exit=$?"
# Error: download failed: HTTP 404 — not found, or not visible to you …
# exit=1
```

---

## 4. Gated reads — a read ACL on a private object (Model A)

The headline security property. An owner sets a per-object policy; a non-grantee's
read is **404, never 403** (not an existence oracle), and `ls` omits objects you
may not read.

```bash
OWNER=$(cctl --profile owner key gen)
GRANTEE=$(cctl --profile grantee key gen)
cctl --profile stranger key gen >/dev/null

echo "the secret memo" > secret.txt
CID=$(cctl --profile owner --json put secret.txt \
      | python3 -c 'import sys,json;print(json.load(sys.stdin)["cid"])')

cctl --profile owner acl set "$CID" --class grantees --readers "$GRANTEE"
# policy set: 22855e9e… class=grantees seq=1
```

`--class` is validated (`world` | `grantees` | `owner`); an invalid value is
rejected before any request. Now the three-party read matrix — `--owner <did>`
reads from another identity's namespace:

```bash
cctl --profile grantee  get "$CID" --owner "$OWNER" -o got.txt   # wrote 17 bytes … (cid verified)
cctl --profile stranger get "$CID" --owner "$OWNER" -o s.txt; echo "exit=$?"
# Error: download failed: HTTP 404 …    exit=1

cctl --profile owner    ls    # 22855e9e…
cctl --profile stranger ls    # (no objects stored)   ← the gated cid is omitted
```

Reading the policy back respects visibility — the **owner** sees the full signed
record incl. `readers[]`; a **grantee** sees only `{read_class, may_read}`; a
**stranger** gets 404:

```bash
cctl --profile owner acl get "$CID"
# { "authorization": { "OwnerSigned": { "sig": "…", "signer": "…" } },
#   "cid": "22855e9e…", "did": "id:…", "read_class": "grantees",
#   "readers": [ "id:d87c60aa…" ], "seq": 1 }
```

Revoke / re-grant is just another `acl set` (the client picks the next `seq`, so
you never trip the anti-rollback `409`).

---

## 5. The `did:` identity — the full e2e with your own atproto account (Model R)

This is the real end-to-end most worth exercising: you log in with **your own bsky
app password**, and CISS treats your **atproto account** (`did:plc`) as the
identity. Your account's signing key never leaves your PDS; `ciss-ctl` holds only
the app-password credential and, on each `did:` action, relays a short-lived,
method-scoped service-auth JWT that **bsky** mints. The VPS resolves your
`did:plc` via `plc.directory` and verifies it. **CISS never sees your password** —
only the JWT; your password only ever goes from your machine to your own PDS.
There is no OAuth/browser step in v1 — the app password *is* the login.

### 5.1 Create an app password

In the bsky app: **Settings → App Passwords → Add App Password**. This is a
revocable, scoped credential — not your account password. (Use a throwaway
account if you prefer.)

### 5.2 Log in (stores the credential locally at `0600`)

```bash
cctl login --pds https://bsky.social --identifier you.bsky.social
# app password for you.bsky.social at https://bsky.social:   ← typed, not echoed
# logged in as you.bsky.social (did:plc:xyfhca…) — credential saved to profile 'default'.
# run `did:` commands with:  ciss-ctl --identity did --profile default …
```

`login` verifies the credential against bsky before saving (a bad app password
fails right here, not later), learns your `did:plc`, and writes it to
`$XDG_CONFIG_HOME/ciss-ctl/profiles/default/pds.json` at mode `0600`. The password
is never echoed and never printed. To confirm:

```bash
ls -l "$XDG_CONFIG_HOME/ciss-ctl/profiles/default/pds.json"   # -rw------- (0600)
```

*Non-interactive alternative* (CI): set `CISS_PDS_APP_PASSWORD` and `login` reads
it from the env instead of prompting. Env `CISS_PDS_HOST`/`CISS_PDS_IDENTIFIER`/
`CISS_PDS_APP_PASSWORD` also work without `login` at all — but `login` is the
first-class path.

### 5.3 Upload and read back as your `did:` — against the VPS

```bash
echo "via a did: service-auth token" > blob.txt

cctl --identity did put blob.txt --via pds
# uploaded via pds (did: service-auth)
#   cid: 6f15e9d6…   cidv1: bafkrei…   bytes: 30

CID=$(cctl --identity did --json put blob.txt --via pds \
      | python3 -c 'import sys,json;print(json.load(sys.stdin)["cid"])')
cctl --identity did get "$CID" --via pds -o back.txt
# wrote 30 bytes to back.txt (cid verified)   ← the VPS resolved YOUR did:plc live
```

Under `-v`, you can watch the two-hop flow — the client discovers the service DID,
your PDS mints the JWT, and CISS accepts it:

```bash
cctl --identity did -v put blob.txt --via pds
# [ciss-ctl] discover service DID: HTTP 200
# [ciss-ctl] upload: HTTP 200
```

Under a `did:` identity, `--via s3` is refused (there is no local signing key). A
`did:` owner can also set an object policy (Model C — CISS provider-attests it
from your JWT):

```bash
cctl --identity did acl set "$CID" --class grantees --readers did:plc:somereader
# policy set (Model C): 6f15e9d6… class=grantees seq=1
```

On the **server side** (next section), a `did:` upload shows up under your real
`did:plc` in the meter and receipts — the same ledger as `id:`, keyed by your
atproto identity. This is the whole point: one metered byte-path, whether you
authenticate with a local key or your atproto account.

---

## 6. Output & diagnostics

```bash
cctl --json meter        # any command's output as machine-readable JSON
cctl -v put note.txt     # log each request's outcome to stderr:
#   [ciss-ctl] upload: HTTP 200      (secrets are never logged)
cctl man | head          # the roff man page
```

Errors map the server's status: `401` (no/invalid credential), `403` (bad
signature / wrong signer / bad Model-C credential), `404` (not found **or** not
visible), `409` (policy `seq` not newer), and a clear "server unreachable" on a
connect failure. `id:`-only commands (`meter`, `ls`) refuse a `--identity did`
invocation with a clear message rather than a confusing failure.

---

## 7. The server side — seeing both halves

Everything above is the *client's* view. The matching *server* state lives on the
VPS and is worth inspecting to understand what each client action actually did.
This section is the **operator view**: it needs SSH access to the box.

The deploy (croft-stack) runs CISS as a hardened systemd unit:

```
systemd: ciss.service   → /opt/ciss/current/ciss --data-dir /var/lib/ciss --listen 127.0.0.1:8301
                          (User=ciss, StateDirectory=ciss → /var/lib/ciss, mode 0700)
Caddy:   443 → 127.0.0.1:8301   (the only path in from the internet)
```

So all state is under **`/var/lib/ciss`**:

```
/var/lib/ciss/
  meter.sqlite            the per-DID metering ledger (canonical: receipts, totals, policies)
  blocks/{did}/{cid}      content-addressed blob bytes
  tmp/                    write staging (temp → rename)
```

### The sanctioned report: `ciss usage`

The binary ships a **read-only** usage report — the first thing to reach for:

```bash
ssh you@ciss.croft.ing
sudo -u ciss /opt/ciss/current/ciss usage --data-dir /var/lib/ciss
```

```
CISS storage — data-dir /var/lib/ciss
  partition:     926.4 GiB total, 378.3 GiB free
  store ceiling: 50.0 GiB  (5.4% of partition)
  store used:    46 B  (0.0% of ceiling · 0.0% of partition)
  per-DID cap:   (none — opportunistic)

  DID                        stored (disk)  transferred (cum)  receipts
  id:cfc14edf…                       46 B              138 B         3
```

Scope it to the identity you tested with (the DID `cctl whoami` printed):

```bash
sudo -u ciss /opt/ciss/current/ciss usage --data-dir /var/lib/ciss --did id:b8c1ecda…
```

The `transferred (cum)` and `receipts` columns are exactly what `cctl meter`
showed you on the client — same numbers, opposite ends of the wire.

### Watch requests live: journald

The server logs every request boundary and every **denied** auth decision at
INFO (public data only — DIDs, method, status, reason; **never** key material).
Grants are logged at DEBUG, so add `RUST_LOG=debug` (or the unit's log-level env)
if you want to see them too.

```bash
sudo journalctl -u ciss -f
# … "object boundary" method=PUT did=id:b8c1… bytes=29           (every request, INFO)
# … "gated-read denied" resource=id:owner… reason="not a grantee" (the stranger's 404, INFO)
```

Run a `cctl put` / a denied `cctl get` in another terminal and watch the matching
lines appear. The corresponding **grant** ("owner-authz granted", "gated-read
granted", "service-auth granted") is emitted at DEBUG.

### The ledger itself: `meter.sqlite`

Open it **read-only** so you never contend with the running server (it uses WAL):

```bash
sudo -u ciss sqlite3 -readonly /var/lib/ciss/meter.sqlite
```

The running meter — this is the source `cctl meter` and `ciss usage` read from:

```sql
SELECT did, receipt_count, upload_bytes, download_bytes, stored_bytes FROM did_total;
-- id:35696ea5…  1  3  0  3
```

The **signed transfer receipts** — one per byte-crossing, the cryptographic proof
behind the meter (the client only sees the aggregate; the server holds the
signatures):

```sql
SELECT json FROM receipt ORDER BY id DESC LIMIT 1;
```
```json
{
  "core": { "direction": "upload", "cid": "98ea6e4f…", "bytes": 3,
            "running_total": 3, "sender_id": "id:3569…", "receiver_id": "id:471d…" },
  "content_hash": "c607e182…",
  "mode": "unilateral",
  "sigs": { "id:471d…": "1841e00b…" }        // the provider's signature over the transfer
}
```

The **gated-read policies** your `acl set` wrote — the owner-signed record CISS
stores and enforces on every read:

```sql
SELECT did, cid, seq FROM object_policy;      -- per-object policies (acl set <cid>)
SELECT did, seq       FROM namespace_policy;  -- whole-DID default (not set by the CLI; see §8)
```

### The blobs on disk

Content-addressed, one file per `(did, cid)`:

```bash
sudo ls -R /var/lib/ciss/blocks/ | head
# blocks/id:b8c1ecda…/f2c13d14…      ← the object you PUT, keyed by its cid
```

### Both-sides cheat-sheet

| Client action | Server-side effect you can observe |
|---|---|
| `cctl put note.txt` | new `blocks/{did}/{cid}` file · `receipt` row (upload, provider-signed) · `did_total.upload_bytes` += bytes · journald "object boundary" PUT |
| `cctl get <cid>` | `receipt` row (download) · `did_total.download_bytes` += bytes |
| `cctl meter` | reads `did_total` (no state change) — matches `ciss usage --did` |
| `cctl acl set <cid> …` | new/updated `object_policy` row (higher `seq`) |
| stranger `cctl get` (denied) | journald "gated-read denied … not a grantee" (INFO); **no** receipt (nothing transferred) |
| `cctl --identity did put` | as PUT above, under your `did:plc`; journald "object boundary" for the uploadBlob (the JWT-verify grant is DEBUG) |

---

## 8. Not yet testable from the CLI

CISS has surface the client does not expose — real server features or deliberate
SEAMs you cannot exercise with `ciss-ctl` today.

| Server capability | Why it's not reachable from the CLI |
|---|---|
| **Namespace-level policy** (`PUT/GET /{did}/policy`) | `acl` only targets a single object (`acl set <cid>`). The whole-DID default (`namespace_policy` table) has no command. |
| **Manifest & rent** (`PUT/GET /{did}/manifest`) | The customer-signed manifest that is the *rent* base is not exposed. `meter` shows bytes transferred + postage, not rent or the manifest. |
| **Bilateral (client co-signed) receipts** | The server is unilateral-only (`receipt: unilateral`); there is no `--bilateral`. The `sigs` map in a receipt carries only the provider signature. |
| **S3 DELETE / bucket LIST / HEAD / multipart** | Server answers these `501` (SEAMs); the client doesn't expose verbs the server doesn't implement. (`ls` uses atproto `listBlobs`, not S3 LIST.) |
| **`did:` metering / listing** | `meter` and `ls` are `id:`-plane only (they refuse under `--identity did`); a `did:` account can't read its meter or list via the CLI. |
| **`did:` grantee reading a *gated* blob** | `--identity did get --via pds` is a public/world read. A `did:` reader fetching an object it was *granted* needs a `getBlob` bearer the `did:` `get` command doesn't send — so Model-C **grantee reads** aren't wired in the CLI (only Model-C policy *set*, and Model-A `id:` grantee reads, are). |
| **Operational endpoints** (`/healthz`, `/.well-known/did.json`) | The CLI reads `did.json` internally to discover the service DID but exposes no command; use `curl` (as in §0). |
| **Full atproto OAuth** (PAR / DPoP / PKCE) | The `did:` path uses an app password for `createSession`; full OAuth is a tracked follow-on. |
| **Range-scoped policy** (history convergence) | Planned/deferred on the server; no client surface. |
| **Storage quota / availability / grace** | Server-side enforcement; observable only as errors (e.g. a quota rejection) or in `ciss usage` (ceiling/cap), not exercised directly. |
| **Provider key provisioning, admin pins, resolver config** | Operational (croft-stack / server env), not a client concern. |

---

## Cleanup

```bash
rm -rf "$XDG_CONFIG_HOME"     # remove the throwaway profiles/keys
unset -f cctl
# revoke the bsky app password if you created one
```

Test objects written to the VPS persist (no delete verb); they are a few small
blobs under throwaway DIDs. For the narrative walkthrough rather than a test
checklist, see [`docs/CLIENT.md`](CLIENT.md).
