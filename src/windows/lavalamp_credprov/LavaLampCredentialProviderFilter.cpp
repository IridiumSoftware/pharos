// LavaLampCredentialProviderFilter.cpp — implementation.
//
// Filter() is called by LogonUI / CredUI during tile-enumeration
// for a given CREDENTIAL_PROVIDER_USAGE_SCENARIO (logon,
// unlock-workstation, credui, change-password, etc.). We return
// per-provider show/hide decisions via the rgbAllow array.
//
// Our policy: query LavaLamp once per filter call. On admit,
// leave every provider visible (we don't suppress anyone else's
// tiles — including the password provider, the smart-card
// provider, etc.). On deny, suppress every provider so the
// user has no tile to click. On a substrate that's unreachable
// (no daemon, no pubkey), we deny — fail closed.
//
// Logging: we emit ETW events for admit/deny decisions through
// the Windows Event Log "Application" channel as Source =
// "LavaLampCredentialProvider". Operators read these to
// reconcile failed logons against substrate state.

#define WIN32_LEAN_AND_MEAN
#include "LavaLampCredentialProviderFilter.h"
#include "LavaLampIPC.h"

#include <shlobj.h>     // SHGetFolderPathW for %USERPROFILE%
#include <strsafe.h>
#include <wchar.h>

#pragma comment(lib, "Shell32.lib")

// ─── Helpers ──────────────────────────────────────────────────

// Resolve the LavaLamp daemon paths. For Win10+ AF_UNIX builds
// we look at %USERPROFILE%\.lavalamp\verify.{sock,pub}. For
// named-pipe builds the endpoint is a logical name; pubkey
// still lives on disk under %USERPROFILE%.
//
// Buffers must each be at least MAX_PATH wide chars.
static bool ResolveDaemonPaths(wchar_t* pubKeyPath,
                                wchar_t* endpointPath,
                                size_t bufLen) {
    wchar_t userProfile[MAX_PATH];
    if (FAILED(SHGetFolderPathW(NULL, CSIDL_PROFILE, NULL,
                                 SHGFP_TYPE_CURRENT, userProfile))) {
        return false;
    }

    if (FAILED(StringCchPrintfW(pubKeyPath, bufLen,
                                 L"%s\\.lavalamp\\verify.pub",
                                 userProfile))) {
        return false;
    }

#if LL_IPC_TRANSPORT == LL_IPC_AF_UNIX
    if (FAILED(StringCchPrintfW(endpointPath, bufLen,
                                 L"%s\\.lavalamp\\verify.sock",
                                 userProfile))) {
        return false;
    }
#else
    // Named pipe: the endpoint is a logical name appended to
    // \\.\pipe\ inside ExchangeNamedPipe. We use a stable
    // hardcoded name; deployment-specific pipe names are a
    // future deployment-policy knob.
    if (FAILED(StringCchCopyW(endpointPath, bufLen,
                               L"lavalamp\\verify"))) {
        return false;
    }
#endif
    return true;
}

static void LogToEventLog(WORD type, const wchar_t* msg) {
    HANDLE h = RegisterEventSourceW(NULL,
                                     L"LavaLampCredentialProvider");
    if (h) {
        const wchar_t* msgs[] = { msg };
        ReportEventW(h, type, 0, 0, NULL, 1, 0, msgs, NULL);
        DeregisterEventSource(h);
    }
}

// ─── Construction ─────────────────────────────────────────────

LavaLampCredentialProviderFilter::LavaLampCredentialProviderFilter()
    : m_refCount(1) {}

LavaLampCredentialProviderFilter::~LavaLampCredentialProviderFilter() {}

// ─── IUnknown ─────────────────────────────────────────────────

HRESULT STDMETHODCALLTYPE
LavaLampCredentialProviderFilter::QueryInterface(REFIID iid, void** ppv) {
    if (!ppv) return E_POINTER;
    if (iid == IID_IUnknown || iid == IID_ICredentialProviderFilter) {
        *ppv = static_cast<ICredentialProviderFilter*>(this);
        AddRef();
        return S_OK;
    }
    *ppv = NULL;
    return E_NOINTERFACE;
}

ULONG STDMETHODCALLTYPE
LavaLampCredentialProviderFilter::AddRef() {
    return InterlockedIncrement(&m_refCount);
}

ULONG STDMETHODCALLTYPE
LavaLampCredentialProviderFilter::Release() {
    LONG c = InterlockedDecrement(&m_refCount);
    if (c == 0) delete this;
    return c;
}

// ─── ICredentialProviderFilter ────────────────────────────────

HRESULT STDMETHODCALLTYPE
LavaLampCredentialProviderFilter::Filter(
    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    DWORD                              /*dwFlags*/,
    GUID*                              /*rgclsidProviders*/,
    BOOL*                              rgbAllow,
    DWORD                              cProviders) {

    // Gate only the logon-related scenarios. Other scenarios
    // (CredUI for application-level prompts, change-password,
    // etc.) bypass the substrate check — they're either
    // already inside an authenticated session or are
    // password-change flows that don't need substrate gating.
    bool gate = (cpus == CPUS_LOGON
              || cpus == CPUS_UNLOCK_WORKSTATION);

    if (!gate) {
        // Leave the rgbAllow array untouched — caller's
        // defaults apply (all SHOW).
        return S_OK;
    }

    wchar_t pubKeyPath[MAX_PATH];
    wchar_t endpointPath[MAX_PATH];
    if (!ResolveDaemonPaths(pubKeyPath, endpointPath, MAX_PATH)) {
        LogToEventLog(EVENTLOG_ERROR_TYPE,
                       L"LavaLampCredentialProvider: "
                       L"could not resolve daemon paths; failing closed.");
        for (DWORD i = 0; i < cProviders; i++) rgbAllow[i] = FALSE;
        return S_OK;
    }

    LavaLampResult r = VerifyLavaLamp(pubKeyPath, endpointPath);

    wchar_t logMsg[512];
    StringCchPrintfW(logMsg, _countof(logMsg),
                      L"LavaLampCredentialProvider Filter() result: %s; "
                      L"cpus=%d; providers gated: %u",
                      LavaLampResultName(r), (int)cpus, cProviders);

    if (r == LavaLampResult::Admit) {
        LogToEventLog(EVENTLOG_INFORMATION_TYPE, logMsg);
        // Leave rgbAllow untouched — caller's defaults apply.
        return S_OK;
    }

    // Any non-admit outcome (Deny, SignatureInvalid,
    // TimestampSkew, ProtocolError, NoDaemon, NoPublicKey) →
    // suppress every tile. The user cannot log in until the
    // substrate attests admit.
    LogToEventLog(EVENTLOG_WARNING_TYPE, logMsg);
    for (DWORD i = 0; i < cProviders; i++) rgbAllow[i] = FALSE;
    return S_OK;
}

HRESULT STDMETHODCALLTYPE
LavaLampCredentialProviderFilter::UpdateRemoteCredential(
    const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* /*pcpcsIn*/,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*       /*pcpcsOut*/) {
    // We don't transform remote credentials in this filter.
    // Return E_NOTIMPL per Microsoft sample-credprov convention.
    return E_NOTIMPL;
}
