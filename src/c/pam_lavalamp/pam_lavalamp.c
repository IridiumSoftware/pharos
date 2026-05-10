/*
 * pam_lavalamp.c — Linux PAM module for substrate-bound
 * identity-liveness gating (PharOS MVP-1).
 *
 * Behaviour: pam_sm_authenticate reads the LavaLamp daemon's
 * heartbeat file mtime. If fresh (< STALE_THRESHOLD_S), returns
 * PAM_SUCCESS. If stale or missing, returns PAM_AUTH_ERR.
 *
 * Heartbeat path resolution (in order):
 *   1. /var/run/lavalamp/heartbeat   (system-mode daemon)
 *   2. ~user/.lavalamp/heartbeat     (user-mode daemon)
 *
 * The user-mode path resolves the home directory of the user
 * being authenticated (NOT getuid(), since this module runs as
 * root during PAM auth). PAM gives us the username via
 * pam_get_user; we look up the homedir via getpwnam.
 *
 * This is MVP-1 — gating on liveness only. It does NOT consume
 * the daemon's verify result; an attacker who can run a LavaLamp
 * daemon under any envelope on any substrate will defeat this
 * layer alone. MVP-2 adds Unix-socket IPC for the actual
 * verify-result gate.
 *
 * Strict LL-002 compliance: the module reads ONLY the heartbeat
 * file's mtime, never the contents. No security state traverses
 * the channel — only the existence-bit "is the daemon alive?".
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
#include <syslog.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define STALE_THRESHOLD_S    30      /* heartbeat older than this → REJECT */
#define SYSTEM_HEARTBEAT     "/var/run/lavalamp/heartbeat"
#define USER_HEARTBEAT_REL   ".lavalamp/heartbeat"
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
 * resolve_user_heartbeat — fills `out_path` with the absolute
 * path to ~username/.lavalamp/heartbeat. Returns 0 on success,
 * non-zero if the user can't be looked up or the path doesn't fit.
 */
static int resolve_user_heartbeat(const char *username,
                                   char *out_path,
                                   size_t out_size)
{
    struct passwd *pw = getpwnam(username);
    if (pw == NULL || pw->pw_dir == NULL) {
        return -1;
    }
    int n = snprintf(out_path, out_size, "%s/%s",
                     pw->pw_dir, USER_HEARTBEAT_REL);
    if (n < 0 || (size_t)n >= out_size) {
        return -1;
    }
    return 0;
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

    /* Try system-mode heartbeat first. */
    long age = heartbeat_age_s(SYSTEM_HEARTBEAT);
    const char *which = SYSTEM_HEARTBEAT;

    if (age < 0) {
        /* Fall back to user-mode heartbeat. */
        const char *username = NULL;
        int rc = pam_get_user(pamh, &username, NULL);
        if (rc != PAM_SUCCESS || username == NULL) {
            pam_syslog(pamh, LOG_NOTICE,
                       "pam_lavalamp: could not get PAM user; "
                       "system heartbeat absent → reject");
            return PAM_AUTH_ERR;
        }
        char user_path[MAX_PATH];
        if (resolve_user_heartbeat(username, user_path,
                                    sizeof(user_path)) != 0) {
            pam_syslog(pamh, LOG_NOTICE,
                       "pam_lavalamp: cannot resolve homedir "
                       "for user '%s' → reject",
                       username);
            return PAM_AUTH_ERR;
        }
        age = heartbeat_age_s(user_path);
        which = user_path;
    }

    if (age < 0) {
        pam_syslog(pamh, LOG_NOTICE,
                   "pam_lavalamp: no heartbeat file at any "
                   "known path → reject");
        return PAM_AUTH_ERR;
    }

    if (age <= STALE_THRESHOLD_S) {
        pam_syslog(pamh, LOG_INFO,
                   "pam_lavalamp: heartbeat at %s is %lds old "
                   "(< %d threshold) → admit",
                   which, age, STALE_THRESHOLD_S);
        return PAM_SUCCESS;
    }

    pam_syslog(pamh, LOG_NOTICE,
               "pam_lavalamp: heartbeat at %s is %lds old "
               "(> %d threshold) → reject",
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
