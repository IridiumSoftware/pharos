# LavaLampMechanism — macOS Authorization Plug-in (PH-011)

The macOS counterpart to PharOS's Linux PAM module
(`pam_lavalamp.so`). Hooks the macOS authorization subsystem
(`authd`) so that selected privileged operations require the
LavaLamp substrate to be alive + the daemon to attest with an
unforgeable Ed25519 / ECDSA P-256 signature before the system
will grant the right.

Same LL-043 v4 wire protocol as the Linux PAM. Same threat
model. Different OS-level integration surface.

## Scope (v0.0.6)

This bundle:

- **Builds clean.** `make` produces an ad-hoc-signed bundle.
- **Implements the LL-043 v4 ECDSA P-256 verify protocol**
  end-to-end (nonce → challenge → 74-byte response → freshness
  + signature verify → allow/deny).
- **Resolves daemon paths** in two modes — system-mode
  (`/var/run/lavalamp/`) preferred, falls back to user-mode
  (`~$user/.lavalamp/`) when the system paths aren't present.
- **Is NOT validated on a live macOS system** in this
  session. Live deployment requires editing the authorization
  database, which is a high-risk operation if done wrong (you
  can lock yourself out of the system). The DEPLOYMENT section
  below documents the careful install path. Run it with a
  backup root shell already open.

## Build

```
cd /Users/aarongreen/Desktop/pharos/src/macos
make
```

Output: `LavaLampMechanism.bundle/` with ad-hoc-signed binary
at `Contents/MacOS/LavaLampMechanism`. Bundle is universal
(arm64 + x86_64).

Requirements:
- Xcode command-line tools (`xcode-select --install`)
- Homebrew OpenSSL 3 (`brew install openssl@3`)

## Deployment (careful — read every step before running anything)

### Pre-flight checks

1. **Open a backup root shell.** Open a second Terminal,
   run `sudo -i`, leave the window open. Do not close it
   until you have confirmed the mechanism works correctly
   on a low-risk rule. This shell is your escape hatch if
   authorization breaks.

2. **Confirm the LavaLamp daemon is running** and producing
   a valid pubkey on this user's account:
   ```
   ls -la ~/.lavalamp/verify.sock ~/.lavalamp/verify.pub
   ```
   Both must exist, with the daemon listening on the socket.

3. **Smoke-test the v4 protocol against your local daemon
   from the shell** before touching authd. The PAM module's
   Python mock daemon in `pharos/test/` can verify the wire
   format independently.

### Install the bundle

```
sudo make install
```

This copies `LavaLampMechanism.bundle` to
`/Library/Security/SecurityAgentPlugins/`. authd will dlopen
the bundle on next authorization invocation that references
it. If the dlopen fails, authd logs to
`/var/log/system.log` and `Console.app` — check there before
proceeding.

### Wire to a TEST rule (NOT system.login or sudo)

Pick a low-stakes rule that:
- You can recover from if it goes wrong (you don't need it to
  log in / become root).
- Exists by default on macOS.

Good choices: `system.preferences.printing`,
`system.preferences.network`, or a custom rule you create
just for testing.

**Bad choices that can lock you out:** `system.login.console`,
`authenticate`, `system.preferences.security`,
`com.apple.Terminal`, anything PAM-related, anything that
`sudo` or `screensaver-unlock` uses.

To wire to `system.preferences.printing`:

```
security authorizationdb read system.preferences.printing > /tmp/p.plist
```

Open `/tmp/p.plist` in an editor. Find or add the
`mechanisms` array under the rule dict. Add an entry:

```xml
<string>LavaLampMechanism:invoke,privileged</string>
```

Order matters — list our mechanism *after* the
authentication step (e.g., after `authinternal`), so authd
only invokes us on an otherwise-authorized session.

Write the modified rule:

```
sudo security authorizationdb write system.preferences.printing < /tmp/p.plist
```

Test the rule by triggering the privileged action it gates
(e.g., open System Settings → Printers and click the lock).
You should see:
- LavaLamp running → admit normally.
- LavaLamp killed → System Settings denies the action with
  no override path (until you remove the mechanism).

Check `Console.app` (filter by `LavaLampMechanism`) for the
syslog lines emitted by the bundle.

### Removal (if you must)

```
sudo security authorizationdb read system.preferences.printing
```

Manually remove the `LavaLampMechanism:invoke,privileged`
entry from the mechanisms array. Write it back:

```
sudo security authorizationdb write system.preferences.printing < /tmp/p-fixed.plist
```

Then:

```
sudo make uninstall
```

### Hard-recovery (if you wired the wrong rule and locked yourself out)

From your backup root shell (you DID keep one open, right?):

```
security authorizationdb remove system.<the-rule-you-broke>
security authorizationdb write system.<the-rule-you-broke> allow
```

Or boot in single-user mode and restore
`/var/db/auth.db` from a Time Machine backup.

## Protocol details

See `pharos/PHAROS_SPEC.md` entry **PH-011**
(macOS-authorization-plugin) and the LavaLamp daemon's
`lavalamp_daemon.jl` for the canonical wire-format
description (LL-040 through LL-043). This bundle is
implementation parity with the Linux PAM module.

## License

Triadic Closure License (TCL v1.3). See PharOS root.
