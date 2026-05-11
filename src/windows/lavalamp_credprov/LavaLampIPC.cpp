// LavaLampIPC.cpp — LL-043 v4 protocol client for Windows.
//
// Mirrors src/c/pam_lavalamp/pam_lavalamp.c and
// src/macos/LavaLampMechanism.m on the Linux/macOS sides.
// Same wire format, same validation logic — only the transport
// layer differs.
//
// OpenSSL is the crypto dependency (vcpkg manifest in
// CMakeLists.txt pins openssl >= 3.0). ECDSA P-256 verification
// uses the deprecated-but-still-supported EC_KEY API; the
// EVP_PKEY-only modern API is fine too but is more verbose for
// a SEC1-compressed-point input.
//
// Honest scope: this code is unverified on Windows. The
// scaffold compiles in shape (header inclusion, function
// signatures, COM compatibility) but has not been built or
// run on a Windows host as of PharOS v0.0.8. PH-013 in
// PHAROS_SPEC.md is :argued, not :tested.

#define WIN32_LEAN_AND_MEAN
#include "LavaLampIPC.h"

#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#if LL_IPC_TRANSPORT == LL_IPC_AF_UNIX
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <afunix.h>   // AF_UNIX support; Win10 build 17063+
#  pragma comment(lib, "Ws2_32.lib")
#endif

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>

#pragma comment(lib, "Bcrypt.lib")

// ─── Helpers ──────────────────────────────────────────────────

const wchar_t* LavaLampResultName(LavaLampResult r) {
    switch (r) {
        case LavaLampResult::Admit:            return L"ADMIT";
        case LavaLampResult::Deny:             return L"DENY";
        case LavaLampResult::SignatureInvalid: return L"BAD_SIG";
        case LavaLampResult::TimestampSkew:    return L"STALE_TS";
        case LavaLampResult::ProtocolError:    return L"PROTO_ERR";
        case LavaLampResult::NoDaemon:         return L"NO_DAEMON";
        case LavaLampResult::NoPublicKey:      return L"NO_PUBKEY";
    }
    return L"?";
}

// Read exactly N bytes from a Win32 HANDLE (named pipe) or
// SOCKET (AF_UNIX). Returns true on success.
template<typename Handle>
static bool ReadFull(Handle h, void* buf, size_t n);

template<>
bool ReadFull<HANDLE>(HANDLE h, void* buf, size_t n) {
    uint8_t* p = (uint8_t*)buf;
    size_t got = 0;
    while (got < n) {
        DWORD r = 0;
        if (!ReadFile(h, p + got, (DWORD)(n - got), &r, NULL) || r == 0)
            return false;
        got += r;
    }
    return true;
}

template<typename Handle>
static bool WriteFull(Handle h, const void* buf, size_t n);

template<>
bool WriteFull<HANDLE>(HANDLE h, const void* buf, size_t n) {
    const uint8_t* p = (const uint8_t*)buf;
    size_t sent = 0;
    while (sent < n) {
        DWORD w = 0;
        if (!WriteFile(h, p + sent, (DWORD)(n - sent), &w, NULL) || w == 0)
            return false;
        sent += w;
    }
    return true;
}

#if LL_IPC_TRANSPORT == LL_IPC_AF_UNIX

template<>
bool ReadFull<SOCKET>(SOCKET s, void* buf, size_t n) {
    uint8_t* p = (uint8_t*)buf;
    size_t got = 0;
    while (got < n) {
        int r = recv(s, (char*)(p + got), (int)(n - got), 0);
        if (r <= 0) return false;
        got += r;
    }
    return true;
}

template<>
bool WriteFull<SOCKET>(SOCKET s, const void* buf, size_t n) {
    const uint8_t* p = (const uint8_t*)buf;
    size_t sent = 0;
    while (sent < n) {
        int w = send(s, (const char*)(p + sent), (int)(n - sent), 0);
        if (w <= 0) return false;
        sent += w;
    }
    return true;
}

#endif

// Convert SEC1-compressed 33-byte public key to an EVP_PKEY
// suitable for EVP_DigestVerify. Caller frees with EVP_PKEY_free.
static EVP_PKEY* PubkeyCompressedToEvp(const uint8_t pub33[LL_IPC_PUB_LEN]) {
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (!group) return NULL;
    EC_POINT* point = EC_POINT_new(group);
    if (!point) { EC_GROUP_free(group); return NULL; }
    EC_KEY* eckey = NULL;
    EVP_PKEY* pkey = NULL;
    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) goto cleanup;
    if (EC_POINT_oct2point(group, point, pub33, LL_IPC_PUB_LEN, ctx) != 1)
        goto cleanup;
    eckey = EC_KEY_new();
    if (!eckey) goto cleanup;
    if (EC_KEY_set_group(eckey, group) != 1) goto cleanup;
    if (EC_KEY_set_public_key(eckey, point) != 1) goto cleanup;
    pkey = EVP_PKEY_new();
    if (!pkey) goto cleanup;
    if (EVP_PKEY_assign_EC_KEY(pkey, eckey) != 1) {
        EVP_PKEY_free(pkey); pkey = NULL; goto cleanup;
    }
    eckey = NULL;
cleanup:
    if (eckey) EC_KEY_free(eckey);
    if (point) EC_POINT_free(point);
    if (group) EC_GROUP_free(group);
    if (ctx)   BN_CTX_free(ctx);
    return pkey;
}

// Convert raw 64-byte r||s to DER for EVP_DigestVerify. Caller
// frees with OPENSSL_free.
static unsigned char* RawToDerEcdsa(const uint8_t raw64[LL_IPC_SIG_LEN],
                                     int* out_len) {
    BIGNUM* r = BN_bin2bn(raw64,                    LL_IPC_RAW_FIELD_LEN, NULL);
    BIGNUM* s = BN_bin2bn(raw64 + LL_IPC_RAW_FIELD_LEN, LL_IPC_RAW_FIELD_LEN, NULL);
    if (!r || !s) {
        if (r) BN_free(r);
        if (s) BN_free(s);
        return NULL;
    }
    ECDSA_SIG* sig = ECDSA_SIG_new();
    if (!sig) { BN_free(r); BN_free(s); return NULL; }
    if (ECDSA_SIG_set0(sig, r, s) != 1) {
        BN_free(r); BN_free(s);
        ECDSA_SIG_free(sig);
        return NULL;
    }
    unsigned char* der = NULL;
    int der_len = i2d_ECDSA_SIG(sig, &der);
    ECDSA_SIG_free(sig);
    if (der_len < 0 || !der) return NULL;
    *out_len = der_len;
    return der;
}

// Generate 16 random bytes from BCryptGenRandom (the Windows
// CNG cryptographic RNG). On failure, returns false; caller
// must not proceed with all-zero nonce.
static bool GenerateNonce(uint8_t nonce[LL_IPC_NONCE_LEN]) {
    NTSTATUS s = BCryptGenRandom(NULL, nonce, LL_IPC_NONCE_LEN,
                                  BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return s == 0;
}

// Load 33-byte SEC1-compressed pubkey from disk. Returns
// true if file exists and is exactly 33 bytes.
static bool LoadPubkeyFile(const wchar_t* path, uint8_t out[LL_IPC_PUB_LEN]) {
    HANDLE fh = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fh == INVALID_HANDLE_VALUE) return false;
    DWORD got = 0;
    BOOL ok = ReadFile(fh, out, LL_IPC_PUB_LEN, &got, NULL);
    CloseHandle(fh);
    return ok && got == LL_IPC_PUB_LEN;
}

// ─── Transport: AF_UNIX or named pipe ─────────────────────────

#if LL_IPC_TRANSPORT == LL_IPC_AF_UNIX

// Send v4 request + read v4 response via Win10+ AF_UNIX socket.
// Endpoint path is interpreted as a filesystem path (e.g.,
// C:\Users\Alice\.lavalamp\verify.sock). Returns true on
// successful 17-byte send + 74-byte recv; caller validates
// crypto separately.
static bool ExchangeAfUnix(const wchar_t* endpointPath,
                           const uint8_t* req, size_t reqLen,
                           uint8_t* resp, size_t respLen) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return false;

    SOCKET s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) { WSACleanup(); return false; }

    // Set send/recv timeouts.
    DWORD timeoutMs = LL_IPC_TIMEOUT_S * 1000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO,
               (const char*)&timeoutMs, sizeof(timeoutMs));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO,
               (const char*)&timeoutMs, sizeof(timeoutMs));

    SOCKADDR_UN addr = {};
    addr.sun_family = AF_UNIX;
    // sun_path is char (UTF-8) on Win10+. Convert from wide.
    int converted = WideCharToMultiByte(CP_UTF8, 0, endpointPath, -1,
                                         addr.sun_path,
                                         sizeof(addr.sun_path) - 1,
                                         NULL, NULL);
    if (converted == 0) {
        closesocket(s); WSACleanup(); return false;
    }

    if (connect(s, (const sockaddr*)&addr, sizeof(addr)) != 0) {
        closesocket(s); WSACleanup(); return false;
    }

    bool ok = WriteFull<SOCKET>(s, req, reqLen)
           && ReadFull<SOCKET>(s, resp, respLen);

    closesocket(s); WSACleanup();
    return ok;
}

#elif LL_IPC_TRANSPORT == LL_IPC_NAMED_PIPE

// Send v4 request + read v4 response via a Windows named pipe.
// Endpoint path is interpreted as a pipe name without the
// `\\.\pipe\` prefix; this function prepends it. So passing
// `lavalamp\verify` here yields `\\.\pipe\lavalamp\verify`.
static bool ExchangeNamedPipe(const wchar_t* endpointPath,
                              const uint8_t* req, size_t reqLen,
                              uint8_t* resp, size_t respLen) {
    wchar_t pipeName[MAX_PATH];
    if (FAILED(StringCchPrintfW(pipeName, MAX_PATH,
                                L"\\\\.\\pipe\\%s", endpointPath))) {
        return false;
    }

    HANDLE h = CreateFileW(pipeName, GENERIC_READ | GENERIC_WRITE,
                            0, NULL, OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return false;

    DWORD mode = PIPE_READMODE_BYTE;
    SetNamedPipeHandleState(h, &mode, NULL, NULL);

    bool ok = WriteFull<HANDLE>(h, req, reqLen)
           && ReadFull<HANDLE>(h, resp, respLen);

    CloseHandle(h);
    return ok;
}

#else
#  error "LL_IPC_TRANSPORT must be LL_IPC_AF_UNIX or LL_IPC_NAMED_PIPE"
#endif

// ─── Entry point ──────────────────────────────────────────────

LavaLampResult VerifyLavaLamp(const wchar_t* pubKeyPath,
                              const wchar_t* endpointPath) {
    // 1. Load pubkey.
    uint8_t pub33[LL_IPC_PUB_LEN];
    if (!LoadPubkeyFile(pubKeyPath, pub33)) {
        return LavaLampResult::NoPublicKey;
    }

    // 2. Generate nonce.
    uint8_t nonce[LL_IPC_NONCE_LEN];
    if (!GenerateNonce(nonce)) {
        return LavaLampResult::ProtocolError;
    }

    // 3. Build 17-byte request.
    uint8_t req[LL_IPC_REQUEST_LEN];
    req[0] = LL_IPC_VERSION;
    memcpy(req + 1, nonce, LL_IPC_NONCE_LEN);

    // 4. Exchange via the configured transport.
    uint8_t resp[LL_IPC_RESPONSE_LEN];
#if LL_IPC_TRANSPORT == LL_IPC_AF_UNIX
    if (!ExchangeAfUnix(endpointPath, req, LL_IPC_REQUEST_LEN,
                         resp, LL_IPC_RESPONSE_LEN)) {
        return LavaLampResult::NoDaemon;
    }
#else
    if (!ExchangeNamedPipe(endpointPath, req, LL_IPC_REQUEST_LEN,
                            resp, LL_IPC_RESPONSE_LEN)) {
        return LavaLampResult::NoDaemon;
    }
#endif

    // 5. Validate version + freshness.
    if (resp[0] != LL_IPC_VERSION) {
        return LavaLampResult::ProtocolError;
    }
    int64_t daemonTs = 0;
    for (int i = 0; i < 8; i++) {
        daemonTs |= (int64_t)resp[2 + i] << (i * 8);
    }
    int64_t nowTs = (int64_t)time(NULL);
    int64_t skew = nowTs - daemonTs;
    if (skew < 0) skew = -skew;
    if (skew > LL_IPC_TS_SKEW_S) {
        return LavaLampResult::TimestampSkew;
    }

    // 6. Verify ECDSA P-256 signature.
    uint8_t signedMsg[LL_IPC_NONCE_LEN + 1 + 8];
    memcpy(signedMsg, nonce, LL_IPC_NONCE_LEN);
    signedMsg[LL_IPC_NONCE_LEN] = resp[1];
    memcpy(signedMsg + LL_IPC_NONCE_LEN + 1, resp + 2, 8);

    EVP_PKEY* pkey = PubkeyCompressedToEvp(pub33);
    if (!pkey) return LavaLampResult::SignatureInvalid;

    int derLen = 0;
    unsigned char* derSig = RawToDerEcdsa(resp + 10, &derLen);
    if (!derSig) { EVP_PKEY_free(pkey); return LavaLampResult::SignatureInvalid; }

    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    int verifyRc = -1;
    if (mctx) {
        if (EVP_DigestVerifyInit(mctx, NULL, EVP_sha256(), NULL, pkey) == 1) {
            verifyRc = EVP_DigestVerify(mctx,
                                         derSig, (size_t)derLen,
                                         signedMsg, sizeof(signedMsg));
        }
        EVP_MD_CTX_free(mctx);
    }
    OPENSSL_free(derSig);
    EVP_PKEY_free(pkey);

    if (verifyRc != 1) {
        return LavaLampResult::SignatureInvalid;
    }

    // 7. Gate on result byte.
    return (resp[1] == LL_RESULT_ACCEPT)
        ? LavaLampResult::Admit
        : LavaLampResult::Deny;
}
