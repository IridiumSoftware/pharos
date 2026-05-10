/*
 * pam_lavalamp.c — Linux PAM module for substrate-bound
 * identity gating (PharOS MVP-1 + MVP-2).
 *
 * Behaviour: pam_sm_authenticate gates the auth result on the
 * LavaLamp daemon's verify state. Two paths:
 *
 *   MVP-2 (preferred). Connect to the daemon's AF_UNIX socket
 *   at /var/run/lavalamp/verify.sock or ~user/.lavalamp/
 *   verify.sock (LL-040). Read one byte response:
 *     'A' → PAM_SUCCESS  (cached verify ACCEPTed, fresh)
 *     'R' → PAM_AUTH_ERR (cached verify REJECTed)
 *     'S' → PAM_AUTH_ERR (cache stale or pre-first-verify)
 *
 *   MVP-1 (fallback). If the socket is unreachable (daemon
 *   pre-MVP-2 / socket missing / permission-denied), fall back
 *   to checking the LL-039 heartbeat file's mtime.
 *     fresh (< STALE_THRESHOLD_S) → PAM_SUCCESS
 *     stale or missing            → PAM_AUTH_ERR
 *
 * The user-mode paths resolve the home directory of the user
 * being authenticated (NOT getuid() — this module runs as root
 * during PAM auth). PAM gives us the username via pam_get_user;
 * we look up the homedir via getpwnam.
 *
 * Strict LL-002 + LL-040 compliance: the module reads only the
 * heartbeat file's mtime (LL-039 strict-LL-002, never contents)
 * or the daemon's one-byte IPC response (LL-040 amendment,
 * cached verify Bool only — no residue, no λ values, no timing).
 *
 * Build:  make  (see Makefile in this directory)
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
#include <pwd.h>
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

#define STALE_THRESHOLD_S    30      /* heartbeat older than this → REJECT */
#define IPC_TIMEOUT_S        2       /* socket connect/read timeout */

#define SYSTEM_HEARTBEAT     "/var/run/lavalamp/heartbeat"
#define USER_HEARTBEAT_REL   ".lavalamp/heartbeat"
#define SYSTEM_VERIFY_SOCK   "/var/run/lavalamp/verify.sock"
#define USER_VERIFY_SOCK_REL ".lavalamp/verify.sock"

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
 * Result codes from try_ipc_query.
 */
#define IPC_RESULT_ACCEPT   1   /* daemon returned 'A' */
#define IPC_RESULT_REJECT   0   /* daemon returned 'R' */
#define IPC_RESULT_STALE   -1   /* daemon returned 'S' */
#define IPC_RESULT_NOSOCK  -2   /* socket missing / unreachable — fall back */
#define IPC_RESULT_ERROR   -3   /* protocol error / unexpected response */

/*
 * try_ipc_query — connect to the LL-040 verify socket at `path`,
 * write a one-byte request, read a one-byte response. Returns
 * one of the IPC_RESULT_* codes above.
 *
 * connect/read are bounded by IPC_TIMEOUT_S to avoid hanging
 * the auth flow if the daemon is wedged.
 */
static int try_ipc_query(const char *path)
{
    /* Quick sanity: file must exist. */
    struct stat st;
    if (stat(path, &st) != 0) {
        return IPC_RESULT_NOSOCK;
    }
    if (!S_ISSOCK(st.st_mode)) {
        return IPC_RESULT_NOSOCK;
    }

    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        return IPC_RESULT_ERROR;
    }

    /* Set send/recv timeouts. */
    struct timeval tv = { .tv_sec = IPC_TIMEOUT_S, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(sock);
        return IPC_RESULT_NOSOCK;   /* daemon may be stopping */
    }

    /* Write a request byte (any byte signals; daemon ignores content). */
    char request = 0x01;
    if (write(sock, &request, 1) != 1) {
        close(sock);
        return IPC_RESULT_ERROR;
    }

    /* Read a one-byte response. */
    char response = 0;
    ssize_t n = read(sock, &response, 1);
    close(sock);
    if (n != 1) {
        return IPC_RESULT_ERROR;
    }

    switch (response) {
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

    /* ─── MVP-2: try LL-040 verify-result IPC first ─── */

    int ipc_result = try_ipc_query(SYSTEM_VERIFY_SOCK);
    const char *ipc_path = SYSTEM_VERIFY_SOCK;

    if (ipc_result == IPC_RESULT_NOSOCK && username != NULL) {
        char user_sock[MAX_PATH];
        if (resolve_user_path(username, USER_VERIFY_SOCK_REL,
                               user_sock, sizeof(user_sock)) == 0) {
            ipc_result = try_ipc_query(user_sock);
            ipc_path = user_sock;
        }
    }

    switch (ipc_result) {
    case IPC_RESULT_ACCEPT:
        pam_syslog(pamh, LOG_INFO,
                   "pam_lavalamp: LL-040 IPC at %s returned 'A' "
                   "(cached ACCEPT) → admit", ipc_path);
        return PAM_SUCCESS;
    case IPC_RESULT_REJECT:
        pam_syslog(pamh, LOG_NOTICE,
                   "pam_lavalamp: LL-040 IPC at %s returned 'R' "
                   "(cached REJECT) → reject", ipc_path);
        return PAM_AUTH_ERR;
    case IPC_RESULT_STALE:
        pam_syslog(pamh, LOG_NOTICE,
                   "pam_lavalamp: LL-040 IPC at %s returned 'S' "
                   "(cache stale or pre-first-verify) → reject",
                   ipc_path);
        return PAM_AUTH_ERR;
    case IPC_RESULT_ERROR:
        pam_syslog(pamh, LOG_NOTICE,
                   "pam_lavalamp: LL-040 IPC protocol error at %s "
                   "→ reject (not falling back to MVP-1; daemon "
                   "is reachable but misbehaving)", ipc_path);
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
