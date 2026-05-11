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

**v0.0.8 — Windows Credential Provider Filter scaffold.**
Three-platform OS-membrane coverage now present in repo:

- **Linux PAM module** (`src/c/pam_lavalamp/`) — `:tested`.
  ubuntu-latest CI runs build + five MVP-5 v4 protocol
  fixtures on every push (ACCEPT / REJECT / STALE /
  ts-skew / no-socket-fallback).
- **macOS Authorization Plug-in**
  (`src/macos/LavaLampMechanism.bundle`) — `:argued`.
  ObjC bundle, ad-hoc-signed, 54 KB Mach-O arm64. macos-
  latest CI builds + verifies signature on every push;
  authd-mediated runtime testing requires user-supervised
  install on a test machine (lockout risk).
- **Windows Credential Provider Filter**
  (`src/windows/lavalamp_credprov/`) — `:argued`. ~600 LOC
  C++ COM scaffold, structurally complete. NOT compile-
  tested on Windows (PharOS dev on macOS; no Windows host);
  promotion to `:tested` requires VS 2022 build + Win11 VM
  install + admit/deny validation.

All three shims speak the **LL-043 v4 ECDSA P-256
protocol** against the LavaLamp daemon at
`~/.lavalamp/verify.sock` (or `/var/run/lavalamp/`
system-mode):

1. Reads the 33-byte SEC1-compressed **public key** from
   `verify.pub` (mode 0644).
2. Generates a 16-byte random nonce per request.
3. Sends a 17-byte challenge (`0x04 + nonce`).
4. Receives a 74-byte response (version + result + 8-byte
   daemon timestamp + 64-byte raw r‖s ECDSA P-256 signature).
5. Validates: signature via OpenSSL `EVP_DigestVerify` with
   SHA-256; timestamp within ±30 s; version correct.
6. Gates on result byte if all validations pass.

Result-byte semantics:
- `'A'` (ACCEPT, fresh) + valid signature → admit (PAM_SUCCESS,
  kAuthorizationResultAllow, all-tiles-shown).
- `'R'` (REJECT) + valid signature → deny.
- `'S'` (STALE) + valid signature → deny.
- signature invalid / stale timestamp / wrong version → deny
  (no fallback; possible tamper signal).
- socket or public-key file missing → deny (fail closed for
  the cryptographic path; Linux PAM has a separate liveness
  fallback to MVP-1 LL-039 heartbeat).

**Whitepaper v1.0** ships in this repo as
`pharos_whitepaper.txt` + `pharos_whitepaper.pdf`. 8 sections
+ 2 appendices, mirroring the LavaLamp whitepaper structure,
scoped to the OS-membrane shim role.

**Honest framing.** PharOS does NOT add a new security
primitive. The load-bearing claim is LavaLamp's resolution-
bounded security (LL-008), transmitted through the membrane
verbatim. PharOS preserves LL-002 visual-security decoupling,
LL-017 no-oracle, and LL-008 scope. PharOS defends
capture-and-replay (nonce), MITM forgery (asymmetric
signing), stale captures (freshness), and public-key
compromise (asymmetric shape). It does NOT defend same-UID
attackers — that's LL-044 Linux TPM 2.0 binding (active on
Linux hosts with `tpm2-tools`), forthcoming LL-045 macOS SE
binding (gated by Apple Developer ID provisioning), and a
forthcoming PH-NNN Windows TPM 2.0 binding via Windows CNG
+ Microsoft Platform Crypto Provider.

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

## What v0.0.8 ships

- **`src/c/pam_lavalamp/`** — Linux PAM module
  (`pam_lavalamp.so`). C source + Makefile. Builds with
  `make` (requires `libpam0g-dev` + `libssl-dev` on
  Debian/Ubuntu). Implements LL-043 v4 ECDSA P-256 client
  with MVP-1 heartbeat fallback. 10 spec entries' worth of
  evolution from MVP-1 (v0.0.1, heartbeat liveness) to
  MVP-5 (v0.0.5, v4 ECDSA).
- **`src/macos/LavaLampMechanism.bundle/`** — macOS
  Authorization Plug-in. ObjC source + `Info.plist` +
  Makefile + careful-deployment README. ~54 KB Mach-O
  arm64, ad-hoc-signed. Loaded by `authd` when a configured
  authorization right's mechanism array references the
  bundle.
- **`src/windows/lavalamp_credprov/`** — Windows Credential
  Provider Filter scaffold. ~600 LOC C++ COM scaffold:
  `dllmain.cpp` (DllMain + class factory + COM exports),
  `LavaLampCredentialProviderFilter.cpp/.h` (filter impl),
  `LavaLampIPC.cpp/.h` (v4 client with AF_UNIX or named-pipe
  transport selectable at compile time), CMakeLists.txt +
  vcpkg.json + register-instructions README. Compile-tested
  in shape only; Windows-host build deferred.
- **`test/`** — Python AF_UNIX mock daemon
  (`mock_lavalamp_daemon.py`) + integration test harness
  (`test_pam_lavalamp.sh`) with §1 MVP-1 heartbeat fixtures
  + §2 MVP-5 v4 protocol fixtures.
- **CI** on `ubuntu-latest` (PAM build + test) and
  `macos-latest` (bundle build + sign-verify) on every push.
- **`pharos_whitepaper.txt`** + **`pharos_whitepaper.pdf`** —
  whitepaper v1.0. 8 sections + 2 appendices.

## What v0.0.8 does NOT ship

- **Windows-host build artefact.** The Credential Provider
  Filter is scaffold-stage: compiles in shape, COM contracts
  wired, OpenSSL ECDSA path mirroring Linux/macOS shims;
  but not built against a Windows compiler. PharOS dev is
  on macOS; no Windows host available. Promotion to
  `:tested` requires Visual Studio 2022 + Win11 VM
  validation.
- **Daemon-side Windows IPC.** The LavaLamp daemon uses
  AF_UNIX at `~/.lavalamp/verify.sock`. Julia's
  `Sockets.UnixDomainSocket` should work on Windows 10
  build 17063+ but is unproven for this codebase. The
  Windows credprov scaffold compiles with either AF_UNIX
  or named-pipe transport so a future daemon-side commit
  can choose either.
- **Hardware-bound key storage on the PharOS side.**
  Currently the daemon's ECDSA P-256 private key lives in
  process memory (LL-043 software-key tier) or in a TPM 2.0
  persistent handle on Linux (LL-044 active when
  `tpm2-tools` is installed). macOS Secure Enclave binding
  (forthcoming LL-045) is gated by Apple Developer ID
  provisioning. Windows TPM 2.0 binding via Windows CNG +
  Microsoft Platform Crypto Provider is a forthcoming
  PH-NNN.
- **Registration ceremony / revocation flow.** Status:
  queued for v0.0.10. Currently relies on LavaLamp's
  registration (LL-010 / LL-011 / LL-012 in the LavaLamp
  spec).

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
