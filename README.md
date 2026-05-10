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

**v0.0.1 — MVP-1 prototype-stage.** A reference Linux PAM module
that gates session unlock on LavaLamp daemon liveness. This is
the simplest credible first integration: it uses the same
strict-LL-002 one-bit liveness channel that the LavaLamp menu-
bar app uses (LL-039 heartbeat file at `~/.lavalamp/heartbeat`
or `/var/run/lavalamp/heartbeat`). If the daemon is alive, the
PAM module returns `PAM_SUCCESS`; if dead/stale, `PAM_AUTH_ERR`.

**Honest framing.** MVP-1 gates on *liveness*, not on the
verify *result* itself. An attacker who can run the LavaLamp
daemon under a different envelope on different hardware
defeats this layer alone. **MVP-2** (next milestone) closes
this gap by integrating the daemon's verify ACCEPT/REJECT via
a Unix-socket IPC channel, so PAM can gate on the actual
substrate-bound proof.

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

## What MVP-1 ships

- **`src/c/pam_lavalamp/`** — Linux PAM module. Single C file +
  Makefile. Builds with `make` (requires `libpam0g-dev` on
  Debian/Ubuntu). Installs to `/lib/x86_64-linux-gnu/security/`.
- **`test/test_pam_lavalamp.sh`** — integration test harness.
  Exercises the module against synthetic heartbeat fixtures
  (fresh / stale / missing) without requiring a running
  LavaLamp daemon.
- **CI** on `ubuntu-latest`. Builds the module, runs the test
  harness on every push to master.

## What MVP-1 does NOT ship

- **MVP-2 verify-result IPC.** Status: queued for v0.0.2.
  Requires a Unix-socket between the PAM module (or a helper
  helper-process) and the LavaLamp daemon, and a deliberate
  LL-002 amendment for the verify result traversing a channel
  beyond the daemon's stdout. The amendment will be a new spec
  entry (PH-NNN) with its own threat-model justification.
- **macOS Authorization Plugin.** Status: queued. Requires
  Cocoa + private-API integration; harder build and
  code-signing pipeline.
- **Windows Credential Provider.** Status: queued. WMI + COM
  surface; deferred to last.
- **Registration ceremony / revocation flow.** Status: queued
  for MVP-3. Requires TPM-bound envelope storage (LL-022
  strategy 1) + key-rotation primitives.

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

**MVP-1 (this release):** raises the bar on credential-replay
attacks. An attacker who steals your password / token / ssh
key but doesn't have the LavaLamp daemon running on your
substrate cannot complete a PAM auth flow that requires
`pam_lavalamp.so`. They would need to *also* gain code
execution on your machine to start the daemon — at which
point they have the substrate, but the daemon's LavaLamp
verify will fail because the chaotic process they're running
on a different substrate diverges from your registered
envelope. (MVP-2 makes this defense actually fire; MVP-1
relies on the attacker not being able to spoof the heartbeat
file.)

**MVP-2 (next):** the PAM module talks to the daemon over a
Unix socket, gets the actual ACCEPT/REJECT for the current
session, and passes through the substrate-bound proof.
Attacker who runs their own LavaLamp daemon under their own
envelope on different hardware is now caught: the verify
returns REJECT against the registered envelope they don't
have.

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
