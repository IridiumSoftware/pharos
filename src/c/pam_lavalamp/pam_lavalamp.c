/*
 * pam_lavalamp.c — Linux PAM module for substrate-bound
 * identity gating (PharOS MVP-1 + MVP-2 + MVP-3 + MVP-4).
 *
 * Behaviour: pam_sm_authenticate gates the auth result on the
 * LavaLamp daemon's verify state via two paths:
 *
 *   MVP-4 / LL-042 v3 (preferred). Ed25519 asymmetric-signature
 *   challenge-response over the AF_UNIX socket. Client reads
 *   the daemon's PUBLIC key from
 *   ~user/.lavalamp/verify.pub (mode 0644 — world-readable),
 *   generates a 16-byte nonce from /dev/urandom, sends a
 *   17-byte request (version 0x03 + nonce), receives a 74-byte
 *   response (version + result + timestamp + 64-byte Ed25519
 *   signature), validates the signature against the public key
 *   over (nonce || result || timestamp), and gates on the
 *   result byte.
 *
 *     'A' → PAM_SUCCESS  (cached verify ACCEPTed, fresh,
 *                         signature valid, nonce binds,
 *                         timestamp within freshness window)
 *     'R' → PAM_AUTH_ERR (cached verify REJECTed)
 *     'S' → PAM_AUTH_ERR (cache stale or pre-first-verify)
 *     signature invalid / stale ts / malformed → PAM_AUTH_ERR
 *
 *   MVP-1 / LL-039 heartbeat fallback (last-resort). If the
 *   v3 socket OR public-key file is missing (daemon offline /
 *   pre-IPC), check the heartbeat file mtime.
 *     fresh (< STALE_THRESHOLD_S) → PAM_SUCCESS
 *     stale or missing            → PAM_AUTH_ERR
 *
 * The user-mode paths resolve the home directory of the user
 * being authenticated (NOT getuid() — this module runs as root
 * during PAM auth). PAM gives us the username via pam_get_user;
 * we look up the homedir via getpwnam.
 *
 * Threat-model honest framing for v3 (LL-042 software-key tier):
 *   Defended: capture-and-replay (nonce binding); same-process-
 *   tier MITM forgery (signature can't be forged without
 *   private key); public-key compromise → no forgery (anyone
 *   can verify; only daemon can sign).
 *   NOT defended: same-UID attackers (can read verify.priv
 *   directly on disk). TPM/Secure-Enclave key binding
 *   (LL-043/LL-044) is the future defense; deferred.
 *
 * Build:  make  (see Makefile; requires libpam0g-dev + libssl-dev)
 * Install: sudo make install  (copies to /lib/x86_64-linux-gnu/security/)
 *
 * License: Triadic Closure License (TCL v1.3). See ../../../LICENSE.txt.
 *
 * Author: Aaron Green, 2026.
 */

#define PAM_SM_AUTH

#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include <openssl/hmac.h>
#include <openssl/evp.h>

#define STALE_THRESHOLD_S    30      /* heartbeat older than this → REJECT */
#define IPC_TIMEOUT_S        2       /* socket connect/read timeout */
#define IPC_TS_SKEW_S        30      /* daemon timestamp must be within this skew → REJECT */

#define SYSTEM_HEARTBEAT     "/var/run/lavalamp/heartbeat"
#define USER_HEARTBEAT_REL   ".lavalamp/heartbeat"
#define SYSTEM_VERIFY_SOCK   "/var/run/lavalamp/verify.sock"
#define USER_VERIFY_SOCK_REL ".lavalamp/verify.sock"
#define SYSTEM_VERIFY_PUB    "/var/run/lavalamp/verify.pub"
#define USER_VERIFY_PUB_REL  ".lavalamp/verify.pub"

#define IPC_VERSION          0x03
#define IPC_REQUEST_LEN      17     /* 1 version + 16 nonce */
#define IPC_RESPONSE_LEN     74     /* 1 version + 1 result + 8 ts + 64 sig */
#define IPC_NONCE_LEN        16
#define IPC_SIG_LEN          64
#define IPC_KEY_LEN          32     /* Ed25519 raw public key (and signature payload) */

#define MAX_PATH             4096

/*
 * heartbeat_age_s — returns mtime-age in seconds for the file
 * at `path`, or -1 if the file is missing/unreadable.
 */
static long heartbeat_age_s(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0) {
        return -1;
    }
    time_t now = time(NULL);
    if (now < st.st_mtime) {
        /* clock skew — treat future-mtime as just-written */
        return 0;
    }
    return (long)(now - st.st_mtime);
}

/*
 * resolve_user_path — fills `out_path` with the absolute path
 * to ~username/<rel_path>. Returns 0 on success, non-zero if
 * the user can't be looked up or the path doesn't fit.
 * Used for both the heartbeat file and the verify socket.
 */
static int resolve_user_path(const char *username,
                              const char *rel_path,
                              char *out_path,
                              size_t out_size)
{
    struct passwd *pw = getpwnam(username);
    if (pw == NULL || pw->pw_dir == NULL) {
        return -1;
    }
    int n = snprintf(out_path, out_size, "%s/%s",
                     pw->pw_dir, rel_path);
    if (n < 0 || (size_t)n >= out_size) {
        return -1;
    }
    return 0;
}

/*
 * Result codes from try_ipc_query_v3.
 */
#define IPC_RESULT_ACCEPT   1   /* daemon returned 'A' + valid signature */
#define IPC_RESULT_REJECT   0   /* daemon returned 'R' */
#define IPC_RESULT_STALE   -1   /* daemon returned 'S' or stale timestamp */
#define IPC_RESULT_NOSOCK  -2   /* socket or pub-key file missing — fall back */
#define IPC_RESULT_ERROR   -3   /* protocol error / signature invalid / nonce wrong */

/*
 * read_pubkey_file — reads the 32-byte Ed25519 public key from
 * `path` into `out`. Returns 0 on success, non-zero on failure.
 */
static int read_pubkey_file(const char *path, unsigned char out[IPC_KEY_LEN])
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    ssize_t n = read(fd, out, IPC_KEY_LEN);
    close(fd);
    return (n == IPC_KEY_LEN) ? 0 : -1;
}

/*
 * read_full — read exactly `n` bytes into `buf`, looping past
 * short reads. Returns 0 on success, -1 on EOF/error.
 */
static int read_full(int fd, void *buf, size_t n)
{
    unsigned char *p = (unsigned char *)buf;
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, p + got, n - got);
        if (r <= 0) {
            return -1;
        }
        got += (size_t)r;
    }
    return 0;
}

/*
 * write_full — write exactly `n` bytes from `buf`, looping past
 * short writes. Returns 0 on success, -1 on error.
 */
static int write_full(int fd, const void *buf, size_t n)
{
    const unsigned char *p = (const unsigned char *)buf;
    size_t sent = 0;
    while (sent < n) {
        ssize_t w = write(fd, p + sent, n - sent);
        if (w <= 0) {
            return -1;
        }
        sent += (size_t)w;
    }
    return 0;
}

/*
 * try_ipc_query_v3 — LL-042 v3 protocol client (Ed25519
 * asymmetric-signature challenge-response).
 *
 * Reads the 32-byte daemon public key from `pubkey_path`,
 * opens an AF_UNIX connection to `sock_path`, sends a 17-byte
 * request (version 0x03 + 16-byte nonce from /dev/urandom),
 * reads a 74-byte response, validates: response version,
 * timestamp freshness, Ed25519 signature over
 * (nonce ‖ result ‖ timestamp) against the public key.
 * Returns one of the IPC_RESULT_* codes.
 *
 * Validation order is strict — any failure returns either
 * IPC_RESULT_NOSOCK (missing files → fall back to MVP-1
 * heartbeat path) or IPC_RESULT_ERROR (signature invalid /
 * stale timestamp / malformed → fail closed, no fallback).
 *
 * Unlike LL-041 HMAC, the client does not need any secret —
 * only the daemon's public key, which is mode 0644 (world-
 * readable). Verification capability can be distributed
 * widely without expanding the forge-capable surface.
 */
static int try_ipc_query_v3(const char *sock_path, const char *pubkey_path)
{
    /* Quick sanity: socket file must exist + be a socket. */
    struct stat st;
    if (stat(sock_path, &st) != 0 || !S_ISSOCK(st.st_mode)) {
        return IPC_RESULT_NOSOCK;
    }

    /* Read daemon public key. Missing → NOSOCK (fall back). */
    unsigned char pubkey_raw[IPC_KEY_LEN];
    if (read_pubkey_file(pubkey_path, pubkey_raw) != 0) {
        return IPC_RESULT_NOSOCK;
    }

    /* Generate 16-byte client nonce from /dev/urandom. */
    unsigned char nonce[IPC_NONCE_LEN];
    int rfd = open("/dev/urandom", O_RDONLY);
    if (rfd < 0) {
        return IPC_RESULT_ERROR;
    }
    if (read_full(rfd, nonce, IPC_NONCE_LEN) != 0) {
        close(rfd);
        return IPC_RESULT_ERROR;
    }
    close(rfd);

    /* Connect with timeouts. */
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        return IPC_RESULT_ERROR;
    }
    struct timeval tv = { .tv_sec = IPC_TIMEOUT_S, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(sock);
        return IPC_RESULT_NOSOCK;
    }

    /* Send 17-byte request: version + nonce. */
    unsigned char request[IPC_REQUEST_LEN];
    request[0] = IPC_VERSION;
    memcpy(request + 1, nonce, IPC_NONCE_LEN);
    if (write_full(sock, request, IPC_REQUEST_LEN) != 0) {
        close(sock);
        return IPC_RESULT_ERROR;
    }

    /* Read 74-byte response: version + result + ts(8) + sig(64). */
    unsigned char response[IPC_RESPONSE_LEN];
    if (read_full(sock, response, IPC_RESPONSE_LEN) != 0) {
        close(sock);
        return IPC_RESULT_ERROR;
    }
    close(sock);

    if (response[0] != IPC_VERSION) {
        return IPC_RESULT_ERROR;
    }
    unsigned char result_byte = response[1];

    /* Decode 8-byte little-endian Int64 timestamp. */
    int64_t daemon_ts = 0;
    for (int i = 0; i < 8; i++) {
        daemon_ts |= ((int64_t)response[2 + i]) << (i * 8);
    }
    int64_t now_ts = (int64_t)time(NULL);
    int64_t skew = now_ts - daemon_ts;
    if (skew < 0) skew = -skew;
    if (skew > IPC_TS_SKEW_S) {
        return IPC_RESULT_ERROR;   /* timestamp not fresh */
    }

    /* Build the signed message: (nonce ‖ result ‖ timestamp). */
    unsigned char signed_msg[IPC_NONCE_LEN + 1 + 8];
    memcpy(signed_msg, nonce, IPC_NONCE_LEN);
    signed_msg[IPC_NONCE_LEN] = result_byte;
    memcpy(signed_msg + IPC_NONCE_LEN + 1, response + 2, 8);

    /* Build EVP_PKEY from the raw 32-byte public key. */
    EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_ED25519, NULL, pubkey_raw, IPC_KEY_LEN);
    if (pkey == NULL) {
        return IPC_RESULT_ERROR;
    }

    /* Verify the 64-byte Ed25519 signature. */
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    if (mctx == NULL) {
        EVP_PKEY_free(pkey);
        return IPC_RESULT_ERROR;
    }
    int verify_init_rc = EVP_DigestVerifyInit(mctx, NULL, NULL, NULL, pkey);
    int verify_rc = -1;
    if (verify_init_rc == 1) {
        verify_rc = EVP_DigestVerify(mctx,
                                      response + 10, IPC_SIG_LEN,
                                      signed_msg, sizeof(signed_msg));
    }
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);

    if (verify_rc != 1) {
        return IPC_RESULT_ERROR;   /* signature invalid — forge or tamper */
    }

    /* Signature valid + timestamp fresh + nonce binds → trust the result. */
    switch (result_byte) {
    case 'A': return IPC_RESULT_ACCEPT;
    case 'R': return IPC_RESULT_REJECT;
    case 'S': return IPC_RESULT_STALE;
    default:  return IPC_RESULT_ERROR;
    }
}

/*
 * pam_sm_authenticate — the PAM authentication entry point.
 * Returns PAM_SUCCESS if the LavaLamp daemon's heartbeat is
 * fresh (< STALE_THRESHOLD_S old). Returns PAM_AUTH_ERR
 * otherwise.
 */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh,
                                    int flags,
                                    int argc,
                                    const char **argv)
{
    (void)flags;
    (void)argc;
    (void)argv;

    /* Resolve the PAM user once; we need it for both user-mode
     * fallback paths. */
    const char *username = NULL;
    pam_get_user(pamh, &username, NULL);   /* may yield NULL */

    /* ─── MVP-4 / LL-042: try v3 (Ed25519 asymmetric) first ─── */

    /* Try system-mode v3 first. */
    int ipc_result = try_ipc_query_v3(SYSTEM_VERIFY_SOCK,
                                       SYSTEM_VERIFY_PUB);
    const char *ipc_path = SYSTEM_VERIFY_SOCK;

    /* Fall back to user-mode v3 if system files aren't present. */
    if (ipc_result == IPC_RESULT_NOSOCK && username != NULL) {
        char user_sock[MAX_PATH];
        char user_pub[MAX_PATH];
        if (resolve_user_path(username, USER_VERIFY_SOCK_REL,
                               user_sock, sizeof(user_sock)) == 0 &&
            resolve_user_path(username, USER_VERIFY_PUB_REL,
                               user_pub, sizeof(user_pub)) == 0) {
            ipc_result = try_ipc_query_v3(user_sock, user_pub);
            ipc_path = user_sock;
        }
    }

    switch (ipc_result) {
    case IPC_RESULT_ACCEPT:
        pam_syslog(pamh, LOG_INFO,
                   "pam_lavalamp: LL-042 v3 IPC at %s returned 'A' "
                   "(cached ACCEPT, Ed25519 sig valid, nonce binds) → admit",
                   ipc_path);
        return PAM_SUCCESS;
    case IPC_RESULT_REJECT:
        pam_syslog(pamh, LOG_NOTICE,
                   "pam_lavalamp: LL-042 v3 IPC at %s returned 'R' "
                   "(cached REJECT) → reject", ipc_path);
        return PAM_AUTH_ERR;
    case IPC_RESULT_STALE:
        pam_syslog(pamh, LOG_NOTICE,
                   "pam_lavalamp: LL-042 v3 IPC at %s returned 'S' "
                   "(cache stale or pre-first-verify) → reject",
                   ipc_path);
        return PAM_AUTH_ERR;
    case IPC_RESULT_ERROR:
        pam_syslog(pamh, LOG_NOTICE,
                   "pam_lavalamp: LL-042 v3 IPC protocol error at %s "
                   "(Ed25519 signature invalid / stale ts / "
                   "malformed response) → reject (no fallback; "
                   "daemon is reachable but the integrity check "
                   "failed — possible tamper)", ipc_path);
        return PAM_AUTH_ERR;
    case IPC_RESULT_NOSOCK:
    default:
        /* Fall through to MVP-1 heartbeat path. */
        break;
    }

    /* ─── MVP-1 fallback: LL-039 heartbeat-mtime gate ─── */

    long age = heartbeat_age_s(SYSTEM_HEARTBEAT);
    const char *which = SYSTEM_HEARTBEAT;

    if (age < 0 && username != NULL) {
        char user_path[MAX_PATH];
        if (resolve_user_path(username, USER_HEARTBEAT_REL,
                               user_path, sizeof(user_path)) == 0) {
            age = heartbeat_age_s(user_path);
            which = user_path;
        }
    }

    if (age < 0) {
        pam_syslog(pamh, LOG_NOTICE,
                   "pam_lavalamp: no LL-040 socket and no LL-039 "
                   "heartbeat at any known path → reject");
        return PAM_AUTH_ERR;
    }

    if (age <= STALE_THRESHOLD_S) {
        pam_syslog(pamh, LOG_INFO,
                   "pam_lavalamp: MVP-1 fallback — heartbeat at %s "
                   "is %lds old (≤ %d threshold) → admit",
                   which, age, STALE_THRESHOLD_S);
        return PAM_SUCCESS;
    }

    pam_syslog(pamh, LOG_NOTICE,
               "pam_lavalamp: MVP-1 fallback — heartbeat at %s "
               "is %lds old (> %d threshold) → reject",
               which, age, STALE_THRESHOLD_S);
    return PAM_AUTH_ERR;
}

/*
 * pam_sm_setcred — credential management. We don't manage any
 * persistent credentials; trivially succeed.
 */
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh,
                               int flags,
                               int argc,
                               const char **argv)
{
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_SUCCESS;
}
