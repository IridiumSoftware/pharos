# LavaLampCredentialProvider (PharOS PH-013, Windows)

The Windows counterpart to PharOS's Linux PAM module
(`pam_lavalamp.so`) and macOS Authorization Plug-in
(`LavaLampMechanism.bundle`). A Credential Provider Filter
that gates Windows logon / unlock-workstation on the LavaLamp
substrate's LL-043 v4 attestation.

## Scope (v0.0.8)

This bundle ships as **scaffold-stage**:

- **Source code**: ~600 LOC of C++, structurally complete, COM
  contracts wired correctly, OpenSSL-based ECDSA P-256
  verification, AF_UNIX transport (Win10 17063+) with
  named-pipe fallback selectable at compile time.
- **NOT built or tested on a Windows host.** PharOS development
  is happening on macOS. The scaffold compiles in shape (header
  / signature checks pass) but has not been built or run on
  Windows as of PharOS v0.0.8. PH-013 in `PHAROS_SPEC.md` is
  marked `:argued`, not `:tested`.
- **NOT integrated with a LavaLamp daemon that binds on
  Windows.** The daemon's Julia code uses AF_UNIX sockets; on
  Windows that requires Julia's `Sockets.UnixDomainSocket`
  support, which is present from Julia 1.10+ but is less
  battle-tested than on Linux/macOS. The named-pipe transport
  is provided so a future daemon-side commit can choose
  whichever path proves more reliable on Windows.

## What this filter does

A Credential Provider Filter is a COM object loaded by
LogonUI / CredUI during tile-enumeration. When LogonUI builds
the list of credential providers to show on the lock screen,
sign-in screen, or workstation-unlock dialog, it calls our
`Filter(cpus, dwFlags, rgclsidProviders, rgbAllow, cProviders)`
method. We return per-provider show/hide decisions via the
`rgbAllow` array.

Our policy:

- For `cpus == CPUS_LOGON` or `cpus == CPUS_UNLOCK_WORKSTATION`:
  query the LavaLamp daemon via LL-043 v4 ECDSA P-256 challenge-
  response. On admit (`'A'` + valid signature + fresh
  timestamp), leave all tiles visible. On any other outcome
  (`'R'`, `'S'`, signature invalid, daemon unreachable, etc.):
  hide every tile.
- For other scenarios (CredUI in-session, change-password,
  etc.): pass through; no substrate gating.

## Honest scope: filter vs. full credential provider

A filter fires only at tile-enumeration time — typically once
per LogonUI / CredUI invocation. It cannot intervene **between**
the user clicking a tile and the credential being submitted.
Per-attempt gating requires implementing the full
`ICredentialProvider` interface (~1000 LOC of COM glue) and
running the LavaLamp verify inside the credential's
`GetSerialization` method.

The filter scaffold is the right v0.0.8 shape because:

1. It mirrors the macOS Authorization Plug-in's gate-at-invoke
   semantics: a one-shot check that runs when the substrate
   gate is invoked.
2. It requires only ~150 LOC of COM glue, leaving budget for
   correctness review and security analysis.
3. It suffices for the v1 membrane claim: *"is the substrate
   alive when the user tries to log in?"*

A future PH-NNN will extend to a full credential provider with
per-attempt gating. That work is queued for after Windows
build + test infrastructure exists in CI.

## Build

Requires:
- Visual Studio 2022 (C++ Desktop Development workload)
- Windows 10 SDK build 17063+ (for AF_UNIX support) — or
  later versions for named-pipe-only builds
- `vcpkg` with the manifest mode (root checked out at
  `%VCPKG_ROOT%`)

```bat
:: From an x64 Native Tools Command Prompt:
cd src\windows\lavalamp_credprov
cmake -B build -A x64 ^
      -DCMAKE_TOOLCHAIN_FILE=%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake
cmake --build build --config Release
```

Output: `build\Release\LavaLampCredentialProvider.dll`.

Transport selection (default is AF_UNIX):

```bat
cmake -B build -A x64 ^
      -DLL_IPC_TRANSPORT=LL_IPC_NAMED_PIPE ^
      -DCMAKE_TOOLCHAIN_FILE=%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake
```

## Installation (run as Administrator)

> **Warning.** A misbehaving credential-provider-filter DLL
> can lock you out of Windows. Test in a VM first. Keep a
> rescue boot media (USB or recovery partition) ready before
> installing on a production machine. Production-tier
> deployments should sign the DLL with an Authenticode
> certificate; this scaffold uses an unsigned DLL which
> Windows will not load on machines with Driver Signature
> Enforcement on (default for ARM64 + some Pro SKUs).

```bat
:: 1. Copy the DLL to a stable system location.
copy build\Release\LavaLampCredentialProvider.dll ^
     C:\Windows\System32\

:: 2. Self-register the COM server.
regsvr32.exe C:\Windows\System32\LavaLampCredentialProvider.dll

:: 3. Confirm the filter is registered.
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Provider Filters"
```

Reboot or sign out + sign in to load the filter into LogonUI.

## Uninstall

```bat
regsvr32.exe /u C:\Windows\System32\LavaLampCredentialProvider.dll
del C:\Windows\System32\LavaLampCredentialProvider.dll
```

## Rescue (you got locked out)

1. Boot into Safe Mode (hold Shift while clicking Restart).
   Safe Mode disables third-party credential providers.
2. Open an Administrator command prompt.
3. Run the uninstall commands above.
4. Reboot normally.

If Safe Mode is also blocked (don't install this filter without
trying it in a VM first), boot from rescue media and delete the
DLL + registry entries manually.

## What the filter logs

Admit / deny decisions write to the Windows Event Log under
`Application` channel, Source = `LavaLampCredentialProvider`,
with the following fields:

- Event type: `INFORMATION` (admit), `WARNING` (deny),
  `ERROR` (could not resolve daemon paths).
- Message: includes the `LavaLampResult` enum name and the
  number of providers gated.

Read via:

```bat
wevtutil qe Application ^
  /q:"*[System[Provider[@Name='LavaLampCredentialProvider']]]" ^
  /f:text /c:10
```

## Threat-model parity (with PH-009, PH-011)

This filter implements the same threat-model surface as the
Linux PAM module and macOS Authorization Plug-in via the
LL-043 v4 protocol:

- **Defended.** Capture-and-replay (nonce binding),
  same-process-tier MITM forgery (asymmetric signing), stale
  responses (timestamp freshness ±30s), public-key compromise
  (anyone can verify; only daemon can sign).
- **NOT defended.** Same-UID attackers (when LavaLamp LL-044
  Linux TPM2 is inactive — there is no equivalent for the
  daemon's Windows-host private key yet; that's a future
  PH-NNN gated on Windows TPM 2.0 binding via Windows CNG +
  Microsoft Platform Crypto Provider).
- **Out of scope per LavaLamp scope.** A3 kernel-level
  adversaries (LL-015 permanent `:open`), A7 passive emanation
  (LL-025 tier-bounded).

## License

Triadic Closure License (TCL v1.3). See PharOS repo root.
