# PharOS macOS post-authentication reactor (PH-019)

Status: **MVP-1, `:open` per PHAROS_SPEC.md PH-019.**

This is the macOS leg of PharOS as of v0.0.19. It supersedes
the PH-011 Authorization Plug-in path operationally on
macOS 26+, where Apple's new `StagedPlugins` rejection
mechanism blocks 3rd-party pre-auth plug-ins regardless of
notarization status. See `../macos/README.md` and
`PHAROS_SPEC.md` PH-011 Notes (2026-05-22 update) for the
full record of the PH-011 dead end.

## Posture (honest)

| Aspect | PH-011 (intended) | PH-019 (this) |
|--------|-------------------|---------------|
| When we see auth events | Before the OS admits the session | After the OS has admitted the session |
| Can veto the auth | Yes | **No** |
| Reaction surface | Return `errAuthorizationDenied` | Lock screen / kill session / force re-auth |
| Attacker window | None | Tens of ms (MVP-1) → sub-ms (MVP-2) |
| Apple gate | `StagedPlugins` rejection (closed) | None for MVP-1; ES entitlement for MVP-2 |
| Substrate verify | Per-auth, synchronous, blocking | Per-event, async, post-fact |

The structural strength gap (pre-auth veto vs post-auth
react) is **not** an implementation deficiency — Apple has
removed the pre-auth surface for 3rd parties in 2026 and
has not published a replacement entitlement. The reactor is
the best-available 2026 macOS posture, not a stepping stone
toward something stronger from inside the platform.

## What this reactor does

1. Subscribes to macOS authentication events (MVP-1 via
   `log stream`; MVP-2 via Endpoint Security framework).
2. On every observed auth event, runs the LL-043 v4 ECDSA
   P-256 challenge-response protocol against the LavaLamp
   daemon to read the current substrate verify result.
3. If the substrate verify returns `REJECT`, fires one or
   more reaction primitives:
   - `pmset displaysleepnow` (lock screen).
   - `launchctl kickstart -k user/<uid>/com.apple.loginwindow`
     (kill graphical session, return to login window).
   - Force re-auth via cleared session cookies.
   - `security delete-generic-password` for revocable
     keychain items (MVP-2, scoped).

Output channel is intentionally **stdout / system log only**.
The reactor does not write user-visible UI; the visible
consequence is the OS reaction it triggers. This preserves
LL-002 visual-security decoupling at the OS layer.

## Threat model

**Defends.**

- *Stolen-credential session takeover.* An attacker who has
  obtained valid credentials enters a session, but cannot
  sustain it past the first verify-result poll — typically
  <100 ms after `loginwindow` admits the session.
- *Persistent attacker survival across reboots.* The
  LavaLamp substrate verify must pass at every auth-event
  boundary; an attacker who has installed persistence
  cannot remain logged in if the substrate envelope no
  longer matches.

**Does not defend.**

- *The brief window between auth completion and reactor
  wake-up.* MVP-1 latency is tens of ms typical (the `log
  stream` pipeline is non-real-time); MVP-2 reduces this to
  sub-ms (kernel-emitted ES event). An attacker with
  millisecond-precise pre-staged actions can complete a
  single action before the reactor reacts.
- *Same-UID attackers who can disable the reactor before
  logging in.* The reactor runs as a LaunchAgent under the
  user's UID; an attacker who can edit
  `~/Library/LaunchAgents/` to unload the reactor before
  authenticating bypasses it. Out-of-band integrity gates
  (filesystem ACL, code-signing of the reactor binary
  itself, alternative LaunchDaemon mode) are out of scope
  for MVP-1.

**Closed gap: attacker kills `lavalampd` to evade detection.**

A naive post-auth reactor with `react_to_timeout = no-op` is
blind to an attacker who shuts the substrate daemon down:
every verify returns UNREACHABLE, and the reactor never
fires. MVP-1 closes this gap with an **UNREACHABLE-escalation
counter**: after `LL_REACTOR_UNREACHABLE_LIMIT` (default 5)
consecutive UNREACHABLE / TIMEOUT results, the reactor treats
the substrate as effectively REJECT and dispatches the full
lock+kill reaction. Counter resets to 0 on any non-unreachable
result.

At the default (5 events × ~5s throttle ≈ 25s elapsed),
escalation triggers comfortably longer than a legitimate
`lavalampd` restart (LL-039 daemon comes up in <2s) but short
enough to catch malicious shutdown before the attacker can
accomplish much. Tunable via env or CLI:

```sh
# Stricter (3 events ≈ 15s).
launchctl setenv LL_REACTOR_UNREACHABLE_LIMIT 3

# Looser (20 events ≈ 100s — for noisy daemons under
# development).
python3 pharos_reactor.py --foreground --unreachable-limit 20

# Effectively disabled (10000 events ≈ 14h before escalation).
python3 pharos_reactor.py --foreground --unreachable-limit 10000
```

**Cannot defend.**

- *Pre-auth blocking.* Apple closed this surface for 3rd
  parties — that's why we're here. The pre-auth gate
  (PH-011 Authorization Plug-in) remains in the spec as a
  revert-if-fixed anchor; if Apple ever opens the staging
  gate, the existing notarized bundle reinstalls cleanly.

## Files

- `pharos_reactor.py` — main daemon. Subscribes to the
  selected event source, runs the verify pipeline on each
  event, dispatches reactions.
- `lavalamp_client.py` — LL-043 v4 ECDSA P-256 protocol
  consumer. Mirrors the Security.framework verify path
  implemented in C/ObjC at
  `../macos/LavaLampMechanism.m`. Uses the Python `ecdsa`
  package, which is the only non-stdlib dependency.
- `reactions.py` — reaction primitives (lock screen, kill
  session, force re-auth). Pure subprocess wrappers; no
  side-channel inputs.
- `com.iridiumsoftware.pharos.reactor.plist` — sample
  LaunchAgent. Install to
  `~/Library/LaunchAgents/com.iridiumsoftware.pharos.reactor.plist`
  and `launchctl load` to activate.
- `test/` — fixture harness. See `test/README.md`.

## Install (MVP-1, manual)

Single-user, dev-machine workflow. Production install
(packaged, signed, auto-update) is out of scope for v0.0.19.

```sh
# 1. Verify Python 3.10+ and the ecdsa package.
python3 --version
python3 -c "import ecdsa; print(ecdsa.__version__)"
# If missing: pip3 install --user ecdsa

# 2. Decide event source.
#    MVP-1 default: log stream (no Apple entitlement needed).
#    Override via env LL_REACTOR_SOURCE=es_client (requires MVP-2 entitlement).

# 3. Test invocation in foreground (interactive, ctrl-C to stop).
python3 pharos_reactor.py --foreground

# 4. Install as LaunchAgent (auto-start at login).
cp com.iridiumsoftware.pharos.reactor.plist \
   ~/Library/LaunchAgents/
launchctl load ~/Library/LaunchAgents/com.iridiumsoftware.pharos.reactor.plist
```

## Safety practices

Before running the reactor against a live LavaLamp daemon:

1. **Keep a backup terminal open.** The reactor will lock
   the screen if `daemon.verify_full` ever returns REJECT
   while it's running. If your LavaLamp daemon is mis-
   configured, the lock may be persistent. A second
   terminal lets you kill the reactor.
2. **Confirm the LavaLamp daemon is responsive before
   loading the reactor.** Run `lavalamp status` and confirm
   `verify_full: ACCEPT` at least once before
   `launchctl load`.
3. **Test in `--foreground --dry-run` mode first.** Logs
   the reactions it *would* fire without actually running
   them. Validates the event-source subscription, the
   verify pipeline, and the reaction logic without
   touching session state.
4. **Disable mid-task with `launchctl unload`** — the
   reactor responds to SIGTERM cleanly and will not
   re-react after unload.
5. **Recovery path.** If a reactor bug locks you out of
   the GUI, ssh to the machine from a peer device, run
   `launchctl unload ~/Library/LaunchAgents/com.iridium
   software.pharos.reactor.plist`. The plist supports
   `KeepAlive: false` semantics (no auto-relaunch).

## MVP-2 upgrade path (gated on Apple entitlement)

`com.apple.developer.endpoint-security.client` is an
Apple-managed entitlement — it ships only to security ISVs
who apply through `feedbackassistant.apple.com` /
developer.apple.com routing and survive a manual review.
Typical lead time: weeks to months. Lazarus's macOS leg
will require the same entitlement when it surfaces a
process-monitor reactor, so the application doubles as
groundwork there.

When the entitlement is granted:

1. Replace `pharos_reactor.py`'s event-source backend with
   an ES client that subscribes to
   `ES_EVENT_TYPE_NOTIFY_AUTHENTICATION`,
   `ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN`,
   `ES_EVENT_TYPE_NOTIFY_SUDO`,
   `ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN`,
   `ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN`,
   `ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGOUT`.
2. Switch the reactor binary to Swift (the ES API is
   Swift/ObjC-native; the Python `pyobjc` bindings for ES
   do not currently exist).
3. Re-sign the binary with the ES entitlement embedded.
4. Re-submit for notarization.
5. The reaction primitives in `reactions.py` carry over
   unchanged.

This is a strict latency + signal-fidelity upgrade. ES auth
events are still `NOTIFY`-only — the reactor still cannot
veto, only react.

## Cross-Triad integration

The reactor preserves the **LL-017 membrane-no-oracle**
invariant at the OS layer: reactions are a function of
`DaemonResult` only (ACCEPT / REJECT / STALE / TIMEOUT) —
no presentation-tier inputs reach the reaction primitives.
This is the same invariant PH-004 proves formally for the
membrane (`src/lean4/Membrane.lean`). PH-019 sits inside
the same cross-Triad joint-closure backbones (PH-014
no-oracle, PH-018 decoupling).

## See also

- `PHAROS_SPEC.md` PH-019 (this entry) + PH-011 Notes
  (2026-05-22 update with the staging-gate analysis).
- `../macos/README.md` — the original PH-011 path,
  preserved as a revert-if-fixed anchor.
- `../macos/LavaLampMechanism.bundle` — notarized + stapled
  bundle, ready to install if Apple ever opens the staging
  gate.
- LavaLamp repo LL-043 v4 protocol spec — the wire format
  this reactor consumes.
