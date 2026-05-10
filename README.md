# PharOS

**OS-layer authentication membrane for substrate-bound identity.**

PharOS is the third deployment in the
[Triad Deployments](#position-in-the-triad-deployments) portfolio.
It exposes the LavaLamp verifier API (LL-023) to platform-native
authentication infrastructure — PAM on Linux, Authorization
Plug-in on macOS, Credential Provider on Windows. Each platform
shim translates the verifier's `accept` / `reject` Bool into
platform-native authentication results **without leaking distance
information to the threshold** (LL-017 no-oracle preservation
through the membrane).

In the threat-landscape metaphor: **PharOS is the membrane
gate** of the castle/membrane/immune-system architecture. It
does not block everything (the castle has to be useful); it
filters selectively (the membrane is permeable to legitimate
identity claims and impermeable to spoofed ones).

## Status

**v0.0.2 — MVP-2 prototype-stage.** A reference Linux PAM
module that gates session authentication on the LavaLamp
daemon's **substrate-bound verify result**, not just
liveness.

The PAM module connects to the daemon's LL-040 AF_UNIX socket
(`/var/run/lavalamp/verify.sock` system-mode preferred,
`~user/.lavalamp/verify.sock` user-mode fallback), reads a
single response byte, and gates accordingly:

- `'A'` (ACCEPT, fresh) → `PAM_SUCCESS`
- `'R'` (REJECT, fresh) → `PAM_AUTH_ERR`
- `'S'` (cache stale) → `PAM_AUTH_ERR`
- socket missing → fall back to **MVP-1 (v0.0.1)** heartbeat
  liveness gate via LL-039

**Honest framing.** MVP-2 actually traverses the substrate-
bound proof through to the auth result. An attacker who runs
a LavaLamp daemon under a *different* envelope on *different*
hardware is now caught: the daemon's `verify_full` fails →
cache holds 'R' → PAM returns `PAM_AUTH_ERR`. **MVP-3** (next
milestone, v0.0.5) adds anti-replay via session-binding
tokens (TPM-bound signing keys per LL-022 strategy 1); MVP-2
does not yet provide replay protection.

## Position in the Triad Deployments

| Deployment | Role | Repo |
|---|---|---|
| **LavaLamp** | Substrate-level immune-system identity (chaotic-SDE residue audit, the "alive" identity) | [IridiumSoftware/lavalamp](https://github.com/IridiumSoftware/lavalamp) |
| **PharOS** | OS-layer authentication membrane (this repo) | here |
| **Lazarus** | Backend / inner sanctum (substantive work behind the membrane) | [IridiumSoftware/lazarus](https://github.com/IridiumSoftware/lazarus) |

The three together form a closure-of-three at the operational
tier. The threat-landscape companion in the LavaLamp repo
(`triad_deployments_threat_landscape.txt`, §1.5 + §2.2) is the
canonical reference for the castle/membrane/immune-system
framing PharOS instantiates.

## What v0.0.2 ships

- **`src/c/pam_lavalamp/`** — Linux PAM module. Single C file
  + Makefile. Builds with `make` (requires `libpam0g-dev` on
  Debian/Ubuntu). Installs to `/lib/x86_64-linux-gnu/security/`.
  Implements MVP-2 IPC client (`try_ipc_query`) with MVP-1
  heartbeat fallback.
- **`test/mock_lavalamp_daemon.py`** — Python AF_UNIX mock
  daemon for protocol fixture testing without requiring a
  running Julia daemon.
- **`test/test_pam_lavalamp.sh`** — integration test harness.
  §1 MVP-1 heartbeat-age fixtures + §2 MVP-2 IPC protocol
  fixtures + §3 module sanity.
- **CI** on `ubuntu-latest`. Builds the module, runs the test
  harness on every push to master.

## What v0.0.2 does NOT ship

- **Anti-replay (session-binding tokens).** Status: queued for
  MVP-3 (v0.0.5). Requires TPM-bound signing keys (LL-022
  strategy 1). An attacker who can read the LL-040 socket
  once and replay the connection currently gets the same
  byte response.
- **macOS Authorization Plugin.** Status: queued for v0.0.3.
  Requires Cocoa + private-API integration; harder build and
  code-signing pipeline.
- **Windows Credential Provider.** Status: queued for v0.0.4.
  WMI + COM surface; deferred to last.
- **Registration ceremony / revocation flow.** Status: queued
  for MVP-3 (v0.0.5). Bundled with TPM-bound envelope store.

## Build + try

```bash
# Linux (Ubuntu / Debian):
sudo apt install libpam0g-dev build-essential
cd src/c/pam_lavalamp
make
sudo make install
```

Then add the module to a PAM service. For testing on a
non-production system, edit `/etc/pam.d/sudo` (BACK IT UP
FIRST) and prepend:

```
auth   required   pam_lavalamp.so
```

With the LavaLamp daemon running, `sudo` will succeed
normally. Stop the daemon (`pkill -f lavalamp_daemon.jl`),
wait 30 seconds for the heartbeat to go stale, and `sudo`
will fail with `PAM_AUTH_ERR`. Restart the daemon to
restore.

**WARNING.** Adding a PAM module to a production
authentication service can lock you out of the system.
Always test in a VM or on a non-critical user account
first, and keep a root shell open in another terminal
while testing.

## How does this protect against an attacker?

**MVP-2 (this release):** the substrate-bound verify result
actually traverses the auth flow. The PAM module reads the
LL-040 IPC byte; the daemon's cached `verify_full` outcome
gates `PAM_SUCCESS` / `PAM_AUTH_ERR`. An attacker who runs
their own LavaLamp daemon under their own envelope on
different hardware is caught: their daemon's verify returns
REJECT against the registered envelope they don't have, the
IPC byte is 'R', PAM denies. The substrate-bound proof
defends here, not just the existence-bit.

**MVP-1 fallback:** if the LL-040 socket is unavailable, the
module falls back to the LL-039 heartbeat-age gate. Raises
the bar on credential-replay attacks (attacker needs the
daemon running on the substrate) but doesn't actually
traverse the verify result — that's the gap MVP-2 closes.

**MVP-3 (next):** anti-replay via session-binding tokens.
Without it, an attacker who can read the IPC byte once and
replay the connection during a different session window gets
the same byte response. Production deployments at higher
threat tiers should wait for MVP-3 / TPM-bound signing keys.

**Out of scope:** kernel-level adversaries on the device
(LavaLamp LL-015 permanent `:open`); user-layer attacks
(phishing, SIM-swap); state-actor TEMPEST (LavaLamp LL-025
tier-bounded). PharOS is one membrane in a defense-in-depth
stack; it is not a panacea.

## License

Released under the Triadic Closure License (TCL v1.3). See
`LICENSE.txt`.

## Author

Aaron Green, 2026. Part of the Triad Deployments portfolio
addressing digital identity resilience.
