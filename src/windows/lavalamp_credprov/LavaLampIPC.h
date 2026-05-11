// LavaLampIPC.h — LL-043 v4 protocol client for Windows.
//
// Speaks the same wire format as PharOS's Linux PAM module and
// macOS Authorization Plug-in:
//
//   Request:  17 bytes — 0x04 + 16-byte nonce
//   Response: 74 bytes — version + result + 8-byte LE timestamp
//                        + 64-byte raw r||s ECDSA P-256 signature
//                        over SHA-256(nonce || result || timestamp)
//   Pubkey:   33 bytes SEC1-compressed P-256 point
//
// Transport choice is deferred via the LL_IPC_TRANSPORT
// preprocessor symbol:
//
//   LL_IPC_TRANSPORT=LL_IPC_AF_UNIX
//     Windows 10 build 17063+ native AF_UNIX socket at
//     %USERPROFILE%\.lavalamp\verify.sock. Identical wire +
//     filesystem-permission model as Linux/macOS. Requires
//     a daemon that binds AF_UNIX on Windows (forthcoming).
//
//   LL_IPC_TRANSPORT=LL_IPC_NAMED_PIPE
//     Windows native named pipe at
//     \\.\pipe\lavalamp\verify. Conventional Windows IPC;
//     full DACL control. Requires a daemon that creates a
//     named-pipe server (forthcoming separate work).
//
// At compile time exactly one transport is selected. The DLL
// must be rebuilt to switch transports — there is no
// runtime fallback. Honest framing: this scaffold targets
// AF_UNIX as the default because it preserves the Linux/macOS
// wire format byte-for-byte; named-pipe is provided so the
// scaffold compiles on Windows builds without AF_UNIX support
// and so a deployment can choose the more conventional
// Windows IPC if preferred.

#pragma once

#include <windows.h>
#include <stdint.h>

#define LL_IPC_AF_UNIX       1
#define LL_IPC_NAMED_PIPE    2

#ifndef LL_IPC_TRANSPORT
#  define LL_IPC_TRANSPORT  LL_IPC_AF_UNIX
#endif

// LL-043 v4 protocol constants (must match the daemon).
constexpr uint8_t  LL_IPC_VERSION         = 0x04;
constexpr size_t   LL_IPC_REQUEST_LEN     = 17;
constexpr size_t   LL_IPC_RESPONSE_LEN    = 74;
constexpr size_t   LL_IPC_NONCE_LEN       = 16;
constexpr size_t   LL_IPC_SIG_LEN         = 64;
constexpr size_t   LL_IPC_RAW_FIELD_LEN   = 32;
constexpr size_t   LL_IPC_PUB_LEN         = 33;
constexpr int      LL_IPC_TIMEOUT_S       = 2;
constexpr int      LL_IPC_TS_SKEW_S       = 30;

constexpr uint8_t  LL_RESULT_ACCEPT       = 0x41;  // 'A'
constexpr uint8_t  LL_RESULT_REJECT       = 0x52;  // 'R'
constexpr uint8_t  LL_RESULT_STALE        = 0x53;  // 'S'

// Verification outcome distinct from PAM_SUCCESS / PAM_AUTH_ERR;
// callers translate to the credential-provider's allow/deny.
enum class LavaLampResult {
    Admit,                  // signature valid AND result == 'A'
    Deny,                   // signature valid AND result == 'R' or 'S'
    SignatureInvalid,       // crypto verification failed
    TimestampSkew,          // |now - daemon_ts| > 30s
    ProtocolError,          // bad version, short read, etc.
    NoDaemon,               // socket/pipe missing or unreachable
    NoPublicKey,            // verify.pub missing or wrong length
};

const wchar_t* LavaLampResultName(LavaLampResult r);

// Performs one full v4 challenge-response cycle. Caller passes
// the path to the daemon's verify.pub (33-byte SEC1-compressed)
// and the transport-appropriate endpoint string (Unix socket
// path or named-pipe name).
//
// Thread-safety: each call is self-contained — opens, sends,
// reads, closes, verifies. Safe to call from concurrent
// credprov serializations.
LavaLampResult VerifyLavaLamp(const wchar_t* pubKeyPath,
                              const wchar_t* endpointPath);
