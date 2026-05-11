// dllmain.cpp — DLL entry point + COM class factory + the four
// COM-server exports (DllMain, DllGetClassObject, DllCanUnloadNow,
// DllRegisterServer, DllUnregisterServer).
//
// LogonUI / CredUI loads our DLL when iterating the registered
// credential-provider filter list (HKLM\SOFTWARE\Microsoft\
// Windows\CurrentVersion\Authentication\Credential Provider
// Filters\{CLSID}). It calls DllGetClassObject(CLSID, IID_
// IClassFactory) to obtain our class factory, then
// IClassFactory::CreateInstance to get an
// ICredentialProviderFilter pointer.
//
// COM lifecycle: g_DllRefCount tracks outstanding objects. The
// host can unload the DLL only when DllCanUnloadNow returns S_OK
// (ref count zero). Each class-factory + filter instance bumps
// the count; their destructors decrement.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <unknwn.h>
#include <new>
#include <stdio.h>

#include "Guid.h"
#include "LavaLampCredentialProviderFilter.h"

static LONG g_DllRefCount = 0;
static HINSTANCE g_hInstance = NULL;

// ─── DLL entry ────────────────────────────────────────────────

BOOL WINAPI DllMain(HINSTANCE hInstDLL, DWORD reason, LPVOID /*reserved*/) {
    if (reason == DLL_PROCESS_ATTACH) {
        g_hInstance = hInstDLL;
        DisableThreadLibraryCalls(hInstDLL);
    }
    return TRUE;
}

// ─── IClassFactory ────────────────────────────────────────────

class LavaLampClassFactory : public IClassFactory {
public:
    LavaLampClassFactory() : m_refCount(1) {
        InterlockedIncrement(&g_DllRefCount);
    }

    ~LavaLampClassFactory() {
        InterlockedDecrement(&g_DllRefCount);
    }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (iid == IID_IUnknown || iid == IID_IClassFactory) {
            *ppv = static_cast<IClassFactory*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = NULL;
        return E_NOINTERFACE;
    }

    ULONG STDMETHODCALLTYPE AddRef() override {
        return InterlockedIncrement(&m_refCount);
    }

    ULONG STDMETHODCALLTYPE Release() override {
        LONG c = InterlockedDecrement(&m_refCount);
        if (c == 0) delete this;
        return c;
    }

    HRESULT STDMETHODCALLTYPE CreateInstance(IUnknown* outer,
                                              REFIID iid,
                                              void** ppv) override {
        if (outer) return CLASS_E_NOAGGREGATION;
        if (!ppv)  return E_POINTER;
        *ppv = NULL;

        LavaLampCredentialProviderFilter* obj =
            new(std::nothrow) LavaLampCredentialProviderFilter();
        if (!obj) return E_OUTOFMEMORY;
        InterlockedIncrement(&g_DllRefCount);

        HRESULT hr = obj->QueryInterface(iid, ppv);
        obj->Release();  // release the ctor's reference
        if (FAILED(hr)) {
            InterlockedDecrement(&g_DllRefCount);
        }
        return hr;
    }

    HRESULT STDMETHODCALLTYPE LockServer(BOOL lock) override {
        if (lock) InterlockedIncrement(&g_DllRefCount);
        else      InterlockedDecrement(&g_DllRefCount);
        return S_OK;
    }

private:
    LONG m_refCount;
};

// ─── COM exports ──────────────────────────────────────────────

extern "C" HRESULT STDMETHODCALLTYPE
DllGetClassObject(REFCLSID rclsid, REFIID riid, void** ppv) {
    if (!ppv) return E_POINTER;
    *ppv = NULL;
    if (rclsid != CLSID_LavaLampCredentialProviderFilter) {
        return CLASS_E_CLASSNOTAVAILABLE;
    }
    LavaLampClassFactory* cf = new(std::nothrow) LavaLampClassFactory();
    if (!cf) return E_OUTOFMEMORY;
    HRESULT hr = cf->QueryInterface(riid, ppv);
    cf->Release();
    return hr;
}

extern "C" HRESULT STDMETHODCALLTYPE DllCanUnloadNow(void) {
    return (g_DllRefCount == 0) ? S_OK : S_FALSE;
}

// Registry write helpers for self-registration.
static LONG WriteRegString(HKEY root, const wchar_t* subkey,
                            const wchar_t* valueName,
                            const wchar_t* data) {
    HKEY hk = NULL;
    LONG rc = RegCreateKeyExW(root, subkey, 0, NULL, 0,
                               KEY_WRITE, NULL, &hk, NULL);
    if (rc != ERROR_SUCCESS) return rc;
    rc = RegSetValueExW(hk, valueName, 0, REG_SZ,
                        (const BYTE*)data,
                        (DWORD)((wcslen(data) + 1) * sizeof(wchar_t)));
    RegCloseKey(hk);
    return rc;
}

extern "C" HRESULT STDMETHODCALLTYPE DllRegisterServer(void) {
    wchar_t dllPath[MAX_PATH];
    if (GetModuleFileNameW(g_hInstance, dllPath, MAX_PATH) == 0) {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    // Convert CLSID to {…} string form.
    wchar_t clsid[64];
    if (StringFromGUID2(CLSID_LavaLampCredentialProviderFilter,
                         clsid, _countof(clsid)) == 0) {
        return E_FAIL;
    }

    wchar_t key1[256], key2[256];
    swprintf_s(key1, _countof(key1), L"CLSID\\%s", clsid);
    swprintf_s(key2, _countof(key2), L"CLSID\\%s\\InprocServer32", clsid);
    if (WriteRegString(HKEY_CLASSES_ROOT, key1, NULL,
                        L"LavaLamp Credential Provider Filter")
            != ERROR_SUCCESS) return E_ACCESSDENIED;
    if (WriteRegString(HKEY_CLASSES_ROOT, key2, NULL, dllPath)
            != ERROR_SUCCESS) return E_ACCESSDENIED;
    if (WriteRegString(HKEY_CLASSES_ROOT, key2,
                        L"ThreadingModel", L"Apartment")
            != ERROR_SUCCESS) return E_ACCESSDENIED;

    wchar_t key3[256];
    swprintf_s(key3, _countof(key3),
                L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\"
                L"Authentication\\Credential Provider Filters\\%s",
                clsid);
    if (WriteRegString(HKEY_LOCAL_MACHINE, key3, NULL,
                        L"LavaLamp Credential Provider Filter")
            != ERROR_SUCCESS) return E_ACCESSDENIED;

    return S_OK;
}

extern "C" HRESULT STDMETHODCALLTYPE DllUnregisterServer(void) {
    wchar_t clsid[64];
    if (StringFromGUID2(CLSID_LavaLampCredentialProviderFilter,
                         clsid, _countof(clsid)) == 0) {
        return E_FAIL;
    }
    wchar_t key1[256], key3[256];
    swprintf_s(key1, _countof(key1), L"CLSID\\%s", clsid);
    swprintf_s(key3, _countof(key3),
                L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\"
                L"Authentication\\Credential Provider Filters\\%s",
                clsid);
    RegDeleteTreeW(HKEY_LOCAL_MACHINE, key3);
    RegDeleteTreeW(HKEY_CLASSES_ROOT, key1);
    return S_OK;
}
