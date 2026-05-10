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

**v0.0.5 — MVP-5 ECDSA P-256 protocol upgrade.** Same
asymmetric-signing posture as v0.0.4, but on a curve
compatible with both Apple Secure Enclave and TPM 2.0 —
unblocks future SE/TPM2 hardware binding without further
protocol changes. Wire format speaks **LL-043 v4**: 17-byte
challenge (`0x04` + nonce), 74-byte response (version +
result + 8-byte timestamp + 64-byte raw r‖s ECDSA P-256
signature). Public key file is 33 bytes (SEC1-compressed).

**v0.0.4 — MVP-4 asymmetric signing.** A reference Linux PAM
module that gates session authentication on the LavaLamp
daemon's substrate-bound verify result, with **Ed25519
asymmetric-signature** challenge-response. The architectural
step over v0.0.3: client no longer holds a secret. Daemon
holds private key; clients read public key only.

The PAM module speaks the **LL-042 v3 protocol**:

1. Reads the 32-byte daemon **public key** from
   `/var/run/lavalamp/verify.pub` (mode 0644 — world-
   readable; verification capability does not require
   secret-holding).
2. Generates a 16-byte random nonce per request.
3. Sends a 17-byte challenge (`0x03 + nonce`).
4. Receives a 74-byte response (version + result + 8-byte
   daemon timestamp + **64-byte Ed25519 signature** over
   `nonce ‖ result ‖ timestamp`).
5. Validates: signature against the public key via
   OpenSSL `EVP_DigestVerify`; timestamp within ±30 s of
   current time; version correct.
6. Gates on result byte if all validations pass.

Result-byte semantics (LL-040/041/042):
- `'A'` (ACCEPT, fresh) + valid Ed25519 signature →
  `PAM_SUCCESS`
- `'R'` (REJECT) + valid signature → `PAM_AUTH_ERR`
- `'S'` (STALE) + valid signature → `PAM_AUTH_ERR`
- signature invalid / stale timestamp / wrong version →
  `PAM_AUTH_ERR` (no fallback; possible tamper signal)
- socket *or* public-key file missing → fall back to
  **MVP-1** heartbeat liveness gate via LL-039

**Honest framing.** v0.0.4 defends four classes of attack:
capture-and-replay (nonce binding), same-process-tier MITM
forgery (signature can't be forged without private key),
stale captured responses (timestamp freshness), and
**public-key compromise → no forgery** (the asymmetric
shape lets anyone verify, but only the daemon can sign).
It does NOT defend against same-UID attackers (root or
daemon UID can read `verify.priv` directly on disk → can
forge any signature). TPM/Secure-Enclave key binding
(deferred to **v0.0.7**, matching LavaLamp LL-043 / LL-044)
closes that gap by moving the private key off-disk into a
hardware-bound enclave.

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
sudo apt install libpam0g-dev libssl-dev build-essential
cd src/c/pam_lavalamp
make
sudo make install
```

`libssl-dev` is required for HMAC-SHA256 (LL-041 v2 protocol).
Fedora/RHEL: `dnf install pam-devel openssl-devel`.

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

**v0.0.4 / LL-042 v3 (this release).** Substrate-bound
verify result traverses the auth flow with **asymmetric**
cryptographic integrity. Four defenses now active:

- **Capture-and-replay defended.** Client supplies a fresh
  16-byte random nonce per request; daemon binds the nonce
  into the signed payload. Captured responses can't be
  replayed in a different session.
- **Same-process-tier MITM forgery defended.** Daemon
  generates a 32-byte Ed25519 keypair on startup; writes
  private to `verify.priv` (mode 0600) and public to
  `verify.pub` (mode 0644). An unprivileged attacker who
  gains socket access cannot read the private key file and
  so cannot forge valid signatures. The signature is over
  `nonce ‖ result ‖ timestamp` (25 bytes); recomputing it
  without the private key requires breaking Ed25519.
- **Stale captures defended.** Daemon includes its current
  Unix epoch second in the signed payload; client validates
  freshness within `IPC_TS_SKEW_S = 30s`.
- **Public-key compromise → no forgery (NEW vs v0.0.3).**
  Anyone can read `verify.pub` and verify; only the daemon
  (with the private key) can sign. The asymmetric shape lets
  verification capability be distributed widely (Lazarus,
  future shims, third-party consumers) without expanding the
  forge-capable surface.

**MVP-3 fallback (v2 HMAC):** superseded by v3 in v0.0.4. v2
daemons (LavaLamp v0.0.85) are NOT backward-compatible with
v3 clients; a v0.0.4 PharOS PAM module talking to a v0.0.85
daemon will fail closed. Upgrade both sides together.

**MVP-1 fallback (LL-039 heartbeat):** if the v3 socket OR
public-key file is missing, the module falls back to the
heartbeat-age gate. Raises the bar on credential-replay
attacks but doesn't traverse the verify result.

**Not yet defended (load-bearing limit):** same-UID
attackers (root or daemon UID) can read `verify.priv`
directly on disk → can forge any signature. **TPM-bound
key storage** (deferred to **v0.0.7**, matching LavaLamp
LL-043 SE on Apple Silicon / LL-044 TPM2 on Linux) replaces
the on-disk private key with a hardware-bound key that
never leaves the secure element. Same wire format; only
the key-storage layer swaps. That's the next milestone.

**Out of scope (LavaLamp boundaries).** Kernel-level
adversaries on the device (LL-015 permanent `:open`);
user-layer attacks (phishing, SIM-swap); state-actor TEMPEST
(LL-025 tier-bounded). PharOS is one membrane in a
defense-in-depth stack; it is not a panacea.

## License

Released under the Triadic Closure License (TCL v1.3). See
`LICENSE.txt`.

## Author

Aaron Green, 2026. Part of the Triad Deployments portfolio
addressing digital identity resilience.
