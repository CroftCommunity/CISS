# ADR 0002 — `/healthz` exposure and rate-limit exemption

- **Status:** Accepted
- **Date:** 2026-08-03
- **Context:** raised during Phase 2 (availability hardening), when the request
  timeout + global concurrency limit were added to the data plane but `/healthz`
  was left exempt.

---

## Problem statement

Phase 2 layered a request timeout and a global in-flight concurrency limit on the
metered data plane, but exempted `/healthz` (it must answer even when the data
plane is saturated — the croft-stack contract §2 liveness probe). Two questions
follow:

1. **What protects the exempt endpoint?** An unlimited endpoint looks like a DoS
   amplifier.
2. **Who is even allowed to call it?** `https://ciss.croft.ing/healthz` currently
   returns `200` to the public internet, yet nothing external legitimately
   health-checks CISS today — the croft-stack telemetry poller reads cgroup v2
   files, not HTTP (DEPLOYMENT.md §7). So the endpoint is exposed with no consumer.

## Decision

### 1. Keep `/healthz` exempt from the app's timeout / concurrency limits

`/healthz` does zero work — no I/O, no lock, no allocation (`server.rs`
`healthz_handler` returns a static `200 ok`). It therefore cannot cause the
resource exhaustion those limits defend against, and it *must not* be queued
behind data-plane load, because a liveness probe that stalls under load defeats
its own purpose. Flood protection for a trivial static endpoint belongs at the
edge (Caddy / nftables / the OS), not in per-request application limits.

### 2. Control `/healthz` *exposure* at the edge (Caddy), not in the app

This is the load-bearing subtlety: **the app cannot see the real client IP.** CISS
binds loopback only (`127.0.0.1:8301`) and is reached from the internet solely
through Caddy's `reverse_proxy`, so every proxied request arrives at the app from
`127.0.0.1`. The app cannot distinguish a genuine localhost caller from an
internet caller relayed by Caddy — both look like loopback. An app-level IP
allowlist would therefore allowlist *all* Caddy-proxied traffic, i.e. do nothing.
The real client IP is known only at Caddy.

So we deliberately **do not** add app-level IP filtering. Instead:

- **Now:** restrict `/healthz` at the Caddy vhost to loopback only. No external
  health-checker exists yet, so nothing legitimate is cut off.
- The **local** liveness path is unaffected: systemd or a local prober hitting
  `127.0.0.1:8301/healthz` directly (bypassing Caddy) still gets `200`, satisfying
  the contract.

**Enforcement lives in croft-stack** (`ciss.croft.ing.caddy`), not in this repo.
The directive to add (an allowlist, extended with monitoring-host IPs later):

```caddy
@healthz path /healthz
handle @healthz {
    @allowed remote_ip 127.0.0.1/8 ::1   # + external monitor IP(s) when one exists
    handle @allowed {
        reverse_proxy 127.0.0.1:8301
    }
    respond 403
}
```

(Equivalently, drop `/healthz` from the public proxy entirely until a consumer
needs it.)

### Revisit trigger

When we add something that health-checks CISS over the public name — an external
uptime monitor, a load balancer, a status page — add its source IP(s) to the
`@allowed` list above. That is the moment this ADR should be reopened; until then
the allowlist is loopback-only by intent, not by omission.

## Reasoning

- The exemption is correct: a trivial, side-effect-free probe must stay fast and
  unstarved, and cannot itself exhaust resources.
- Enforcement belongs at the edge because the app is IP-blind behind the loopback
  reverse-proxy; putting it in the app would be security theater (an allowlist
  that matches everything).
- Documented now, with an explicit revisit trigger, so the "allowlist IPs later"
  intent is not silently forgotten when a real health-checker appears.

## Consequences

- Until the Caddy change lands, `ciss.croft.ing/healthz` remains a public liveness
  oracle (low sensitivity: it confirms the service is up, nothing more). Closing
  it is a croft-stack task, tracked here.
- CISS keeps a single `--listen` port and the contract-required `200 ok` on the
  local path; no app change is needed or wanted for this decision.
