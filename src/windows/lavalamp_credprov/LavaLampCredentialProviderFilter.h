// LavaLampCredentialProviderFilter.h — ICredentialProviderFilter
// implementation for PharOS v0.0.8.
//
// Membrane semantics: when LogonUI / CredUI calls Filter() to
// determine which credential provider tiles to show, we invoke
// the LL-043 v4 ECDSA P-256 protocol against the running
// LavaLamp daemon. If the daemon attests admit ('A') with a
// valid signature, we let all tiles through. Otherwise we hide
// them — the user sees no logon options and cannot proceed.
//
// Honest scope: a filter fires only at tile-enumeration time
// (typically once per LogonUI / CredUI invocation), not on
// every authentication attempt. Per-attempt gating requires a
// full ICredentialProvider implementation (~1000 LOC) that
// runs the verify check inside GetSerialization. The filter
// scaffold is the right v0.0.8 shape because it (a) closely
// mirrors the macOS Authorization Plug-in's gate-at-invoke
// semantics, (b) requires only ~150 LOC of COM glue, (c)
// suffices for the "is the substrate alive when the user
// tries to log in" question that is the load-bearing v1
// membrane claim. Extension to per-attempt gating is queued
// for a future PH-NNN.

#pragma once

#include <windows.h>
#include <credentialprovider.h>

class LavaLampCredentialProviderFilter
    : public ICredentialProviderFilter {
public:
    LavaLampCredentialProviderFilter();
    virtual ~LavaLampCredentialProviderFilter();

    // IUnknown.
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** ppv) override;
    ULONG   STDMETHODCALLTYPE AddRef() override;
    ULONG   STDMETHODCALLTYPE Release() override;

    // ICredentialProviderFilter.
    HRESULT STDMETHODCALLTYPE Filter(
        CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
        DWORD                              dwFlags,
        GUID*                              rgclsidProviders,
        BOOL*                              rgbAllow,
        DWORD                              cProviders) override;

    HRESULT STDMETHODCALLTYPE UpdateRemoteCredential(
        const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcsIn,
        CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*       pcpcsOut) override;

private:
    LONG m_refCount;
};
