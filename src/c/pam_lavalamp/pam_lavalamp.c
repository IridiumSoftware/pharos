/*
 * pam_lavalamp.c — Linux PAM module for substrate-bound
 * identity gating (PharOS MVP-1 + MVP-2 + MVP-3).
 *
 * Behaviour: pam_sm_authenticate gates the auth result on the
 * LavaLamp daemon's verify state via three layered paths:
 *
 *   MVP-3 / LL-041 v2 (preferred). HMAC-SHA256 challenge-
 *   response over the AF_UNIX socket. Client reads the daemon's
 *   shared secret from ~user/.lavalamp/verify.secret, generates
 *   a 16-byte nonce from /dev/urandom, sends a 17-byte request
 *   (version 0x02 + nonce), receives a 42-byte response
 *   (version + result + timestamp + HMAC), validates the HMAC
 *   against the shared secret + nonce + result + timestamp,
 *   and gates on the result byte.
 *
 *     'A' → PAM_SUCCESS  (cached verify ACCEPTed, fresh,
 *                         HMAC valid, nonce binds, timestamp
 *                         within freshness window)
 *     'R' → PAM_AUTH_ERR (cached verify REJECTed)
 *     'S' → PAM_AUTH_ERR (cache stale or pre-first-verify)
 *     HMAC mismatch / stale ts / wrong nonce → PAM_AUTH_ERR
 *
 *   MVP-2 / LL-040 v1 fallback (intermediate; daemon predates
 *   v0.0.85). If the v2 secret file is missing but the socket
 *   is reachable, fall back to v1 single-byte protocol — read
 *   1 byte, gate accordingly. Provides no anti-replay; honest
 *   limitation noted in syslog.
 *
 *   MVP-1 / LL-039 heartbeat fallback (last-resort). If neither
 *   v2 nor v1 socket paths work (daemon offline / pre-IPC),
 *   check the heartbeat file mtime.
 *     fresh (< STALE_THRESHOLD_S) → PAM_SUCCESS
 *     stale or missing            → PAM_AUTH_ERR
 *
 * The user-mode paths resolve the home directory of the user
 * being authenticated (NOT getuid() — this module runs as root
 * during PAM auth). PAM gives us the username via pam_get_user;
 * we look up the homedir via getpwnam.
 *
 * Threat-model honest framing for v2 (LL-041):
 *   Defended: capture-and-replay (nonce binding); same-process-
 *   tier MITM forgery (HMAC + 0600 secret).
 *   NOT defended: same-UID attackers (can read both socket and
 *   secret file → can forge any HMAC). TPM-bound asymmetric
 *   signing (LL-022 strategy 1) is the future defense; deferred.
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
#define SYSTEM_VERIFY_SECRET "/var/run/lavalamp/verify.secret"
#define USER_VERIFY_SECRET_REL ".lavalamp/verify.secret"

#define IPC_VERSION          0x02
#define IPC_REQUEST_LEN      17     /* 1 version + 16 nonce */
#define IPC_RESPONSE_LEN     42     /* 1 version + 1 result + 8 ts + 32 hmac */
#define IPC_NONCE_LEN        16
#define IPC_HMAC_LEN         32
#define IPC_SECRET_LEN       32

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
 * Result codes from try_ipc_query_v2.
 */
#define IPC_RESULT_ACCEPT   1   /* daemon returned 'A' + valid HMAC */
#define IPC_RESULT_REJECT   0   /* daemon returned 'R' */
#define IPC_RESULT_STALE   -1   /* daemon returned 'S' or stale timestamp */
#define IPC_RESULT_NOSOCK  -2   /* socket or secret file missing — fall back */
#define IPC_RESULT_ERROR   -3   /* protocol error / HMAC mismatch / nonce wrong */

/*
 * read_secret_file — reads the 32-byte shared secret from
 * `path` into `out`. Returns 0 on success, non-zero on failure.
 */
static int read_secret_file(const char *path, unsigned char out[IPC_SECRET_LEN])
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    ssize_t n = read(fd, out, IPC_SECRET_LEN);
    close(fd);
    return (n == IPC_SECRET_LEN) ? 0 : -1;
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
 * try_ipc_query_v2 — LL-041 v2 protocol client.
 *
 * Reads the 32-byte shared secret from `secret_path`, opens an
 * AF_UNIX connection to `sock_path`, sends a 17-byte request
 * (version + 16-byte nonce from /dev/urandom), reads a 42-byte
 * response, validates: response version, nonce binding via HMAC,
 * timestamp freshness, result byte. Returns one of the
 * IPC_RESULT_* codes.
 *
 * Validation order is strict — any failure returns either
 * IPC_RESULT_NOSOCK (missing files → fall back to v1 / heartbeat)
 * or IPC_RESULT_ERROR (HMAC mismatch / nonce mismatch / stale
 * timestamp → fail closed, no fallback).
 */
static int try_ipc_query_v2(const char *sock_path, const char *secret_path)
{
    /* Quick sanity: socket file must exist + be a socket. */
    struct stat st;
    if (stat(sock_path, &st) != 0 || !S_ISSOCK(st.st_mode)) {
        return IPC_RESULT_NOSOCK;
    }

    /* Read shared secret. Missing → NOSOCK (fall back). */
    unsigned char secret[IPC_SECRET_LEN];
    if (read_secret_file(secret_path, secret) != 0) {
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

    /* Read 42-byte response: version + result + ts(8) + hmac(32). */
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

    /* Recompute HMAC over (nonce ‖ result ‖ timestamp). */
    unsigned char signed_msg[IPC_NONCE_LEN + 1 + 8];
    memcpy(signed_msg, nonce, IPC_NONCE_LEN);
    signed_msg[IPC_NONCE_LEN] = result_byte;
    memcpy(signed_msg + IPC_NONCE_LEN + 1, response + 2, 8);

    unsigned char expected_hmac[EVP_MAX_MD_SIZE];
    unsigned int expected_len = 0;
    if (HMAC(EVP_sha256(), secret, IPC_SECRET_LEN,
             signed_msg, sizeof(signed_msg),
             expected_hmac, &expected_len) == NULL ||
        expected_len != IPC_HMAC_LEN) {
        return IPC_RESULT_ERROR;
    }

    /* Constant-time compare. */
    if (CRYPTO_memcmp(expected_hmac, response + 10, IPC_HMAC_LEN) != 0) {
        return IPC_RESULT_ERROR;   /* HMAC mismatch — forge or tamper */
    }

    /* HMAC valid + timestamp fresh + nonce binds → trust the result. */
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

    /* ─── MVP-3 / LL-041: try v2 (HMAC anti-replay) first ─── */

    /* Try system-mode v2 first. */
    int ipc_result = try_ipc_query_v2(SYSTEM_VERIFY_SOCK,
                                       SYSTEM_VERIFY_SECRET);
    const char *ipc_path = SYSTEM_VERIFY_SOCK;

    /* Fall back to user-mode v2 if system files aren't present. */
    if (ipc_result == IPC_RESULT_NOSOCK && username != NULL) {
        char user_sock[MAX_PATH];
        char user_secret[MAX_PATH];
        if (resolve_user_path(username, USER_VERIFY_SOCK_REL,
                               user_sock, sizeof(user_sock)) == 0 &&
            resolve_user_path(username, USER_VERIFY_SECRET_REL,
                               user_secret, sizeof(user_secret)) == 0) {
            ipc_result = try_ipc_query_v2(user_sock, user_secret);
            ipc_path = user_sock;
        }
    }

    switch (ipc_result) {
    case IPC_RESULT_ACCEPT:
        pam_syslog(pamh, LOG_INFO,
                   "pam_lavalamp: LL-041 v2 IPC at %s returned 'A' "
                   "(cached ACCEPT, HMAC valid, nonce binds) → admit",
                   ipc_path);
        return PAM_SUCCESS;
    case IPC_RESULT_REJECT:
        pam_syslog(pamh, LOG_NOTICE,
                   "pam_lavalamp: LL-041 v2 IPC at %s returned 'R' "
                   "(cached REJECT) → reject", ipc_path);
        return PAM_AUTH_ERR;
    case IPC_RESULT_STALE:
        pam_syslog(pamh, LOG_NOTICE,
                   "pam_lavalamp: LL-041 v2 IPC at %s returned 'S' "
                   "(cache stale or pre-first-verify) → reject",
                   ipc_path);
        return PAM_AUTH_ERR;
    case IPC_RESULT_ERROR:
        pam_syslog(pamh, LOG_NOTICE,
                   "pam_lavalamp: LL-041 v2 IPC protocol error at %s "
                   "(HMAC mismatch / stale ts / wrong nonce / "
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
