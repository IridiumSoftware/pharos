// Guid.h — CLSID for the LavaLamp Credential Provider.
//
// One-off GUID generated for PharOS v0.0.8. If you re-generate
// this CLSID (e.g., during forking), regenerate the registration
// entries in register.reg and any matching policy templates.
//
// Generated 2026-05-10. Do not change without a coordinated
// re-registration on every deployed host.

#pragma once

// {7B7A2C7F-9DA3-4F4D-A0AE-3C9E8B7F4D11}
//
// CLSID for the LavaLamp Credential Provider FILTER COM class.
// Registered under:
//   HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\
//     Authentication\Credential Provider Filters\{CLSID}
//   HKCR\CLSID\{CLSID}\InprocServer32 → DLL path
//
// The filter is a thinner shim than a full ICredentialProvider:
// LogonUI / CredUI calls our Filter() method during tile
// enumeration; we return SHOW for all tiles (admit) or HIDE
// for all tiles (deny) based on LL-043 v4 substrate verify.
//
// One-off GUID generated for PharOS v0.0.8. If you re-generate
// this CLSID (e.g., during forking), regenerate the registration
// entries in register.reg and any matching policy templates.
//
// Generated 2026-05-10. Do not change without a coordinated
// re-registration on every deployed host.
static const CLSID CLSID_LavaLampCredentialProviderFilter =
    { 0x7B7A2C7F, 0x9DA3, 0x4F4D,
      { 0xA0, 0xAE, 0x3C, 0x9E, 0x8B, 0x7F, 0x4D, 0x11 } };
