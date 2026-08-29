# CISS deployment & operations

How CISS is packaged, deployed as a [croft-stack](https://github.com/CroftCommunity/croft-stack)
tenant, governed, and operated — including the incident runbook for the Caddy
front. For the design/internals see [`ARCHITECTURE.md`](ARCHITECTURE.md).

## 1. Where it runs

CISS runs as a governed croft-stack **tenant** on the OVH VPS:

```
   Internet ──HTTPS :443──▶ Caddy (shared, TLS via Let's Encrypt)
                              name-routes by Host header (the live vhosts):
                                ciss.croft.ing    → 127.0.0.1:8301  (CISS)
                                canary.croft.ing  → 127.0.0.1:8100  (contract/smoke canary)
                                account.croft.ing → 127.0.0.1:8001  (OAuth broker)
                                relay.croft.ing   → cert-only (iroh-relay serves its own TLS on :8443)
                              │  reverse_proxy (with request-retry)
                              ▼
   systemd: ciss.service  ──▶  /opt/ciss/current/ciss --data-dir /var/lib/ciss
   (User=ciss, hardened,        --listen 127.0.0.1:8301
    cgroup-governed)           binds LOOPBACK ONLY — nftables opens only 22/80/443,
                               so 8301 is unreachable from the internet.
```

The only path from the internet to CISS is `443 → Caddy → 127.0.0.1:8301`.

The above is the *deployed* set (the `active_tenants` — ciss, canary — plus the
broker and relay, which their own roles install). The croft-stack repo also
*declares* the AppView-family tenants `appview-stellin` and `appview-croft-groups`
(firehose-ingest + XRPC-serving AppViews, a different tier from CISS's storage
role), but they are stub + not activated, so they have no vhost and do not appear
on the box. `caddy-admin list` on the host is the source of truth for what is
actually fronted.

## 2. The croft-stack tenant contract

CISS satisfies `croft-stack/CONTRACT.md` so it drops in with no kit changes:

- `--data-dir <path>` + `--listen <host:port>`, nothing else required to start.
- `GET /healthz` → `200 ok` once serving. It is exempt from the app's request
  timeout + concurrency limits (it does no work and must not be starved), and its
  *public* exposure is controlled at the Caddy edge, not the app — see
  [`adr/0002-healthz-exposure-and-limit-exemption.md`](adr/0002-healthz-exposure-and-limit-exemption.md).
  **Done (croft-stack):** the `ciss.croft.ing` vhost gates `/healthz` at the
  Caddy edge to a loopback allowlist (`croft-stack/services/ciss.toml`
  `healthz_allowlist`); the public internet gets 403 (verified live 2026-08-24).
  The allowlist matches `path /healthz` exactly and never gates `/.well-known/*`.
- `GET /.well-known/did.json` → CISS's `did:web` document. **Must stay public** —
  external atproto clients resolve `did:web:ciss.croft.ing` here to address CISS as
  a service-auth `aud`. Any future `/healthz` edge allowlist must **not** also gate
  `/.well-known/*` (see the atproto-identity note below).

### atproto identity (Model R) — config

CISS verifies bsky-delegated **service-auth JWTs** against the caller's
DID-resolved key (`docs/notes/atproto-integration-model.md`). Deploy config, all
optional with safe defaults:

| env | default | meaning |
|---|---|---|
| `CISS_SERVICE_DID` | `did:web:ciss.croft.ing` | the JWT `aud`; also the served `did.json` id |
| `CISS_PLC_DIRECTORY_URL` | `https://plc.directory` | `did:plc` resolution base |
| `CISS_DID_RESOLVE_TIMEOUT_MS` | `3000` | hard resolve timeout (fails closed) |
| `CISS_DID_CACHE_TTL_S` | `300` | resolution cache TTL |
| `CISS_ADMIN_PINS_FILE` | — | pinned-admin-DID file (break-glass) |
| `CISS_ADMIN_ONLY_DU` | unset (off) | Lock the remote `du` (self usage report) to admins. `du` is **always self-only** — cross-DID is never served over the wire (use the on-box `ciss usage` for other DIDs). Unset ⇒ any authenticated caller may `du` its own namespace. Set (`1`/`true`) ⇒ only an admin-pin DID may run `du`, still only for its own namespace (ADR 0003 / invariant Z9). |

The admin-pin file (lines `<did> <did:key>`) is security-sensitive break-glass
material; provision it like `provider-seed` (a systemd credential / mode-0400
path) and point `CISS_ADMIN_PINS_FILE` at it. A malformed file fails startup
loudly. Resolution reaches `plc.directory` outbound over HTTPS (rustls) — the only
egress CISS makes.

> **TODO (croft-stack): `CISS_ADMIN_PINS_FILE` is not yet populated.** As deployed,
> the pin set is **empty** — every `did:` resolves via the network, so there is no
> break-glass for the admin identities and a `plc.directory` outage means `did:`
> auth fails closed for everyone (the `id:` session path is unaffected). Provision
> the pin file (admin DID → `did:key`, like `provider-seed`) and set
> `CISS_ADMIN_PINS_FILE` before relying on `did:` auth in an outage.
- **All** state under the data dir; no root; port ≥ 1024 (TLS is Caddy's).
- Self-managed layout matching the manifest's `data_profile`:
  `meter.sqlite` (canonical) + `blocks/` (blobs) + `tmp/` (staging, outside the mirror).

The tenant manifest is `croft-stack/services/ciss.toml`:

```toml
name = "ciss"; fqdn = "ciss.croft.ing"; port = 8301
artifact = "github:CroftCommunity/CISS/releases"; serve_api = false
[limits] memory_high="256M" memory_max="384M" cpu_quota="60%" tasks_max=256 io_weight=200
[data_profile] canonical=["meter.sqlite"] blobs=["blocks/"] blobs_immutable=["blocks/"]
```

## 3. Packaging & release

CISS ships as a **pinned, checksummed GitHub release binary** (the same pattern
croft-stack uses for the iroh relay). Since v0.9.0 the packaging is a workflow,
not a ritual: pushing a `vX.Y.Z` tag runs
[`.github/workflows/release.yml`](../.github/workflows/release.yml), which

1. **Gates on the tagged commit**: refuses a tag that does not match the
   workspace `Cargo.toml` version, then runs the full `cargo test --workspace`
   + pedantic clippy gate on that exact commit (a tag is not a gate, so the
   gate runs here too), under the `rust-toolchain.toml`-pinned toolchain.
2. **Builds + packages**: a stripped **glibc** `cargo build --release` binary
   for the estate (Debian 13 trixie, glibc 2.41, x86_64; built on
   ubuntu-latest glibc 2.39, forward-compatible), tarballed **with the man
   page** — `ciss-vX.Y.Z-x86_64-linux-gnu.tar.gz` containing `ciss` +
   `docs/man/ciss.1` — so the operator tooling deploys with the service.
   *(A fully-static `x86_64-unknown-linux-musl` build remains the portability
   hardening follow-up; on a single trixie box the glibc build is correct and
   simplest.)*
3. **Publishes** the tarball and its `.sha256` as the `vX.Y.Z` GitHub release.
   A `workflow_dispatch` input takes an *existing* tag for re-builds (a tag cut
   on a commit predating the workflow file never fires the push trigger).

The one manual step left: **pin it** in `croft-stack/ansible/group_vars/all.yml`
under the `ciss` `active_tenants` entry (`binary_version`, `binary_url`,
`binary_sha256` — verify the checksum against a locally-hashed download, not
just the published `.sha256`).

Release flow, cutting a version: roll the `[Unreleased]`/pending entries in
the one changelog (`CHANGELOG.md`, entries prefixed `**server:**` / `**cli:**`) into the new
version heading, bump root + `ciss-cli` `Cargo.toml` in lockstep, land green,
tag, push the tag.

The `ciss usage` operator report is the same binary (a subcommand, not a separate
tool), so it is deployed with the service. The croft-stack `tenants` role installs
`ciss.1` to the man path and symlinks `/usr/local/bin/ciss → /opt/ciss/current/ciss`
so `ciss usage …`, `ciss -h`, and `man ciss` work on the box.

The croft-stack `tenants` role then `get_url`s the tarball (verifying the
checksum) and unpacks `ciss` to `/opt/ciss/current/ciss` — the exact path the
generated unit's `ExecStart` uses.

## 4. The systemd unit (generated, governed, hardened)

`render.py` emits `ciss.service` from the manifest. Every tenant unit is
hardened + cgroup-governed by default:

- `User=ciss`, `StateDirectory=ciss` (0700 `/var/lib/ciss`), `WorkingDirectory`
  + `ReadWritePaths` = the data dir only.
- `NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`, `MemoryDenyWriteExecute`,
  `SystemCallFilter=@system-service`, empty `CapabilityBoundingSet` — a Rust
  binary (no JIT) takes the full sandbox; `systemd-analyze security ciss.service`
  ≈ **1.5 (OK)**.
- `MemoryAccounting`/`CPUAccounting`/`IOAccounting`/`TasksAccounting=yes` plus the
  manifest's limits (`MemoryHigh=256M`, `MemoryMax=384M`, `CPUQuota=60%`,
  `TasksMax=256`, `IOWeight=200`).
- `Restart=always`, `RestartSec=2`.

## 5. Caddy front + zero-downtime posture

The generated vhost (`ciss.croft.ing.caddy`) reverse-proxies `443 →
127.0.0.1:8301` with **request-retry** so a tenant restart doesn't 502:

```caddy
ciss.croft.ing {
	reverse_proxy 127.0.0.1:8301 {
		lb_try_duration 5s      # hold + re-dial the upstream across a restart
		lb_try_interval 250ms   # (graceful drain covers in-flight; this covers new)
	}
	encode gzip
	header -Server
}
```

Verified live (point-in-time check, 2026-08-03; recorded in the croft-stack
`reviews/2026-08-03-stack-review.md`): **120/120 requests returned 200 across a
full `systemctl restart ciss`.** Retry is safe for PUT/POST — Caddy only retries
when the dial fails, before any bytes reach the upstream. True zero-downtime
(kernel holds the socket) is the E87 socket-activation stretch.

## 6. Data profile & backup

| Path | Class | Backup mechanism | Status |
|---|---|---|---|
| `meter.sqlite` | canonical | Litestream → R2 (`sync-interval 1s`) | unit **generated, not yet activated** |
| `blocks/` | blobs, immutable | rclone `sync --immutable` → R2 | unit **generated, not yet activated** |

The Litestream/rclone units are rendered but **not enabled** — they need the R2
credential environment wired into the estate. **R2 backup is set aside for now
(2026-08-03).** Until then, `meter.sqlite` is not mirrored off-box; treat the
deployment as test/dogfood, not durable-of-record. `blocks/` is content-addressed,
so its mirror uses `--immutable` (no overwrite/delete churn) once activated.

## 7. Telemetry

The croft-stack telemetry poller reads **cgroup v2** files per unit
(`/sys/fs/cgroup/system.slice/ciss.service/{memory.current,cpu.stat,pids.current,io.stat}`)
— it does **not** scrape logs. CISS emits no app-level metrics; its governed unit
is enough. App-level `tracing` goes to **journald** for debugging
(`journalctl -u ciss`) and carries only the *public* provider id — no key material.

## 8. Deploy / upgrade a version

```sh
# 1. build + publish a new release (see §3), pin it in group_vars/all.yml
# 2. converge (from croft-stack/ansible):
ansible-playbook site.yml                 # full, idempotent, no-lockout-safe
#   or scope to the tenant + front + telemetry with a small play running only
#   the caddy, tenants, telemetry roles.
# 3. verify:
curl -sS https://ciss.croft.ing/healthz   # -> 200 ok
```

The `tenants` role's unpack is **version-aware**: the `creates:` marker is
`/opt/ciss/current/.installed-<version>`, so bumping `binary_version` re-extracts
the new binary over `current/` and notifies the restart handler automatically — a
plain `binary_version` bump + converge deploys the new binary. *(Historical note:
before this fix the guard was keyed on `current/ciss`'s existence, so upgrades
silently fetched-but-never-unpacked; found deploying v0.4.0. Fixed in croft-stack
`fix(tenants): version-aware binary unpack`.)*

## 9. Incident runbook — the Caddy front

**Quick-list what Caddy is brokering for** (on the box):

```sh
# each *.caddy in conf.d is one fronted site:
ls /etc/caddy/conf.d/
# fqdn -> backend port, at a glance:
grep -H reverse_proxy /etc/caddy/conf.d/*.caddy
# the tenant backends and their state:
systemctl list-units --type=service | grep -E 'ciss|canary|appview|broker|relay|caddy'
# from the repo (source of truth): croft-stack/generated/ports.json + generated/caddy/
```

Caddy's admin API is on a root/caddy-only unix socket (not `localhost:2019`):
`sudo curl --unix-socket /run/caddy/admin.sock http://localhost/config/` dumps the
live config as JSON if you need to inspect what is actually loaded.

**Disable / enable a fronted backend during an incident.** Two levers:

*(a) Take a site off the internet (cut at Caddy; process keeps running).* Best for
abuse/DNS/"make it stop serving now" — instant, clean, and does not touch data:

```sh
# disable — the Caddyfile imports conf.d/*.caddy, so renaming drops it from the glob
sudo mv /etc/caddy/conf.d/ciss.croft.ing.caddy /etc/caddy/conf.d/ciss.croft.ing.caddy.disabled
sudo systemctl reload caddy      # graceful; a bad config is rejected, old config kept

# re-enable
sudo mv /etc/caddy/conf.d/ciss.croft.ing.caddy.disabled /etc/caddy/conf.d/ciss.croft.ing.caddy
sudo systemctl reload caddy
```

*(b) Stop the backend itself (process down).* Best for a runaway/compromised
service; data at rest is untouched:

```sh
sudo systemctl stop ciss.service            # down now
sudo systemctl start ciss.service           # back up
sudo systemctl disable --now ciss.service   # down + stays down across reboot
```

**Which lever:** to take a site *offline*, prefer (a) — with `lb_try_duration 5s`
in place, merely *stopping* the backend makes Caddy hold each request ~5s **then**
502 (a hang, not a clean cutoff). Use (b) when the goal is to kill the process
(compromise, memory runaway), and pair it with (a) if you also want the public
name to stop answering immediately. `systemctl stop caddy` takes **every** site
down — reserve it for an incident in Caddy itself.

**Reconcile afterward.** These are imperative, box-local overrides. The
declarative source of truth is `active_tenants` in `croft-stack/group_vars` — a
future `ansible-playbook site.yml` will re-enable a tenant you only stopped
imperatively. After the incident, either restore the imperative state or, for a
lasting change, remove the tenant from `active_tenants` and re-converge.

## 10. VPS baseline (for reference)

Debian 13 (trixie), kernel 6.12, systemd 257, cgroup v2 unified, x86_64 +
glibc 2.41, **ext4**. Consequences: E84 reflink is N/A (ext4 has no CoW; the
FsBlobStore temp→rename baseline is the whole story); systemd 257 fully supports
the E87 socket-activation seam when we choose to wire it.
