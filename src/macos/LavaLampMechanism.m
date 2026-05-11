/*
 * LavaLampMechanism.m — macOS Authorization Plug-in mechanism
 * for PharOS (PH-011).
 *
 * Loaded by authd (the macOS authorization daemon) and invoked
 * during specific authorization rights (e.g., system.preferences,
 * system.privilege.admin, etc., depending on which rule the
 * mechanism is wired to). On invoke, this mechanism speaks the
 * LL-043 v4 ECDSA P-256 protocol to the LavaLamp daemon:
 *
 *   1. Read 33-byte SEC1-compressed public key from
 *      ~$AUTH_USER/.lavalamp/verify.pub (or /var/run/lavalamp/
 *      verify.pub for system-mode daemons).
 *   2. Generate 16-byte nonce from /dev/urandom.
 *   3. Send 17-byte v4 request (0x04 + nonce) to
 *      ~$AUTH_USER/.lavalamp/verify.sock.
 *   4. Read 74-byte response (version + result + timestamp + sig).
 *   5. Validate version, freshness (±30s), Ed25519 signature
 *      via OpenSSL EVP_DigestVerify.
 *   6. Set result to kAuthorizationResultAllow if signature
 *      valid AND result byte is 'A'; otherwise
 *      kAuthorizationResultDeny.
 *
 * This is the macOS analog of PharOS's Linux PAM module
 * (pam_lavalamp.so). Same wire format, same threat-model
 * posture; different OS-level integration surface.
 *
 * Honest scope (v0.0.6 / PH-011):
 *   - Code is compile-tested ad-hoc-signed.
 *   - NOT validated on a live system in the session this was
 *     authored in (would require installing to
 *     /Library/Security/SecurityAgentPlugins/ + editing an
 *     authorization rule + careful testing with a backup
 *     root shell). Deployment instructions in the PHAROS_SPEC
 *     PH-011 entry; user runs them with care.
 *
 * Build:
 *   make
 *
 * Install (run as root, with backup root shell open):
 *   sudo cp -R LavaLampMechanism.bundle \
 *     /Library/Security/SecurityAgentPlugins/
 *
 * Configure a test rule (DO NOT touch system.login or sudo
 * until validated):
 *   security authorizationdb read system.preferences.printing > /tmp/p.plist
 *   # edit /tmp/p.plist — add a 'mechanisms' array entry:
 *   #   LavaLampMechanism:invoke,privileged
 *   sudo security authorizationdb write system.preferences.printing < /tmp/p.plist
 *
 * Remove if it misbehaves:
 *   sudo security authorizationdb read system.preferences.printing
 *   # remove the mechanism entry
 *   sudo security authorizationdb write system.preferences.printing
 *   sudo rm -rf /Library/Security/SecurityAgentPlugins/LavaLampMechanism.bundle
 *
 * License: Triadic Closure License (TCL v1.3).
 * Author: Aaron Green, 2026.
 */

#include <Security/AuthorizationPlugin.h>
#include <Security/Authorization.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Foundation/Foundation.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>

#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

/* ─── LL-043 v4 protocol constants (must match LavaLamp daemon) ─ */

#define IPC_VERSION       0x04
#define IPC_REQUEST_LEN   17
#define IPC_RESPONSE_LEN  74
#define IPC_NONCE_LEN     16
#define IPC_SIG_LEN       64
#define IPC_RAW_FIELD_LEN 32
#define IPC_PUB_LEN       33
#define IPC_TIMEOUT_S     2
#define IPC_TS_SKEW_S     30

#define SYSTEM_VERIFY_SOCK "/var/run/lavalamp/verify.sock"
#define SYSTEM_VERIFY_PUB  "/var/run/lavalamp/verify.pub"
#define USER_VERIFY_SOCK_REL ".lavalamp/verify.sock"
#define USER_VERIFY_PUB_REL  ".lavalamp/verify.pub"

#define MAX_PATH 4096

/* ─── Mechanism plumbing (mirrors AuthorizationPlugin.h template) ─ */

typedef struct PluginRecord {
    const AuthorizationCallbacks *callbacks;
} PluginRecord;

typedef struct MechanismRecord {
    AuthorizationEngineRef engine;
    const PluginRecord *plugin;
} MechanismRecord;

/* ─── Crypto / IPC helpers (mirror pam_lavalamp.c) ─ */

static int read_full(int fd, void *buf, size_t n) {
    unsigned char *p = (unsigned char *)buf;
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, p + got, n - got);
        if (r <= 0) return -1;
        got += (size_t)r;
    }
    return 0;
}

static int write_full(int fd, const void *buf, size_t n) {
    const unsigned char *p = (const unsigned char *)buf;
    size_t sent = 0;
    while (sent < n) {
        ssize_t w = write(fd, p + sent, n - sent);
        if (w <= 0) return -1;
        sent += (size_t)w;
    }
    return 0;
}

static int read_pubkey_file(const char *path, unsigned char out[IPC_PUB_LEN]) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read(fd, out, IPC_PUB_LEN);
    close(fd);
    return (n == IPC_PUB_LEN) ? 0 : -1;
}

static EVP_PKEY *pubkey_compressed_to_evp(const unsigned char *pub33) {
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (!group) return NULL;
    EC_POINT *point = EC_POINT_new(group);
    if (!point) { EC_GROUP_free(group); return NULL; }
    EC_KEY *eckey = NULL;
    EVP_PKEY *pkey = NULL;
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) goto cleanup;
    if (EC_POINT_oct2point(group, point, pub33, IPC_PUB_LEN, ctx) != 1) goto cleanup;
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
    if (ctx) BN_CTX_free(ctx);
    return pkey;
}

static unsigned char *raw_to_der_ecdsa(const unsigned char *raw64, int *out_len) {
    BIGNUM *r = BN_bin2bn(raw64, IPC_RAW_FIELD_LEN, NULL);
    BIGNUM *s = BN_bin2bn(raw64 + IPC_RAW_FIELD_LEN, IPC_RAW_FIELD_LEN, NULL);
    if (!r || !s) {
        if (r) BN_free(r);
        if (s) BN_free(s);
        return NULL;
    }
    ECDSA_SIG *sig = ECDSA_SIG_new();
    if (!sig) { BN_free(r); BN_free(s); return NULL; }
    if (ECDSA_SIG_set0(sig, r, s) != 1) {
        BN_free(r); BN_free(s); ECDSA_SIG_free(sig);
        return NULL;
    }
    unsigned char *der = NULL;
    int der_len = i2d_ECDSA_SIG(sig, &der);
    ECDSA_SIG_free(sig);
    if (der_len < 0 || !der) return NULL;
    *out_len = der_len;
    return der;
}

/*
 * verify_lavalamp_substrate — runs the full LL-043 v4 challenge-
 * response against the LavaLamp daemon. Returns 1 if the daemon
 * responds 'A' with a valid Ed25519 signature; 0 otherwise.
 *
 * Resolution: tries SYSTEM_VERIFY_* paths first (root-installed
 * daemon); falls back to ~$auth_user/.lavalamp/* for user-mode.
 */
static int verify_lavalamp_substrate(const char *auth_username) {
    char sock_path[MAX_PATH] = SYSTEM_VERIFY_SOCK;
    char pub_path[MAX_PATH]  = SYSTEM_VERIFY_PUB;
    unsigned char pubkey_raw[IPC_PUB_LEN];

    /* If system-mode files aren't present, try user-mode. */
    if (read_pubkey_file(pub_path, pubkey_raw) != 0 && auth_username) {
        struct passwd *pw = getpwnam(auth_username);
        if (!pw || !pw->pw_dir) {
            syslog(LOG_NOTICE,
                   "LavaLampMechanism: cannot resolve user '%s'",
                   auth_username);
            return 0;
        }
        snprintf(sock_path, sizeof(sock_path), "%s/%s",
                 pw->pw_dir, USER_VERIFY_SOCK_REL);
        snprintf(pub_path, sizeof(pub_path), "%s/%s",
                 pw->pw_dir, USER_VERIFY_PUB_REL);
        if (read_pubkey_file(pub_path, pubkey_raw) != 0) {
            syslog(LOG_NOTICE,
                   "LavaLampMechanism: pubkey not found at %s",
                   pub_path);
            return 0;
        }
    }

    /* Generate 16-byte nonce. */
    unsigned char nonce[IPC_NONCE_LEN];
    int rfd = open("/dev/urandom", O_RDONLY);
    if (rfd < 0) return 0;
    if (read_full(rfd, nonce, IPC_NONCE_LEN) != 0) { close(rfd); return 0; }
    close(rfd);

    /* Connect to socket. */
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) return 0;
    struct timeval tv = { .tv_sec = IPC_TIMEOUT_S, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(sock);
        return 0;
    }

    /* Send 17-byte request. */
    unsigned char request[IPC_REQUEST_LEN];
    request[0] = IPC_VERSION;
    memcpy(request + 1, nonce, IPC_NONCE_LEN);
    if (write_full(sock, request, IPC_REQUEST_LEN) != 0) {
        close(sock); return 0;
    }

    /* Read 74-byte response. */
    unsigned char response[IPC_RESPONSE_LEN];
    if (read_full(sock, response, IPC_RESPONSE_LEN) != 0) {
        close(sock); return 0;
    }
    close(sock);

    if (response[0] != IPC_VERSION) return 0;
    unsigned char result_byte = response[1];

    /* Freshness check. */
    int64_t daemon_ts = 0;
    for (int i = 0; i < 8; i++) {
        daemon_ts |= ((int64_t)response[2 + i]) << (i * 8);
    }
    int64_t now_ts = (int64_t)time(NULL);
    int64_t skew = now_ts - daemon_ts;
    if (skew < 0) skew = -skew;
    if (skew > IPC_TS_SKEW_S) return 0;

    /* Build signed message + verify Ed25519 signature. */
    unsigned char signed_msg[IPC_NONCE_LEN + 1 + 8];
    memcpy(signed_msg, nonce, IPC_NONCE_LEN);
    signed_msg[IPC_NONCE_LEN] = result_byte;
    memcpy(signed_msg + IPC_NONCE_LEN + 1, response + 2, 8);

    EVP_PKEY *pkey = pubkey_compressed_to_evp(pubkey_raw);
    if (!pkey) return 0;

    int der_len = 0;
    unsigned char *der_sig = raw_to_der_ecdsa(response + 10, &der_len);
    if (!der_sig) { EVP_PKEY_free(pkey); return 0; }

    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    int verify_rc = -1;
    if (mctx) {
        if (EVP_DigestVerifyInit(mctx, NULL, EVP_sha256(), NULL, pkey) == 1) {
            verify_rc = EVP_DigestVerify(mctx,
                                          der_sig, (size_t)der_len,
                                          signed_msg, sizeof(signed_msg));
        }
        EVP_MD_CTX_free(mctx);
    }
    OPENSSL_free(der_sig);
    EVP_PKEY_free(pkey);

    if (verify_rc != 1) {
        syslog(LOG_NOTICE,
               "LavaLampMechanism: signature verify failed");
        return 0;
    }

    /* Signature valid + timestamp fresh + nonce binds. Gate on
     * the result byte: 'A' admits; 'R' / 'S' / other denies. */
    syslog(LOG_INFO,
           "LavaLampMechanism: signature valid; result='%c'",
           result_byte);
    return (result_byte == 'A') ? 1 : 0;
}

/* ─── Authorization Plug-in entry points ─ */

static OSStatus MechanismCreate(AuthorizationPluginRef inPlugin,
                                 AuthorizationEngineRef inEngine,
                                 AuthorizationMechanismId mechanismId,
                                 AuthorizationMechanismRef *outMechanism) {
    MechanismRecord *mech = (MechanismRecord *)calloc(1, sizeof(MechanismRecord));
    if (!mech) return errAuthorizationInternal;
    mech->engine = inEngine;
    mech->plugin = (const PluginRecord *)inPlugin;
    *outMechanism = (AuthorizationMechanismRef)mech;
    return errAuthorizationSuccess;
}

static OSStatus MechanismInvoke(AuthorizationMechanismRef inMechanism) {
    MechanismRecord *mech = (MechanismRecord *)inMechanism;

    /* Try to fetch the authenticating user's name from the engine
     * context, in case we need to resolve their homedir for
     * user-mode fallback paths. */
    char *auth_username = NULL;
    AuthorizationContextFlags flags = 0;
    const AuthorizationValue *user_val = NULL;
    OSStatus user_status = mech->plugin->callbacks->GetContextValue(
        mech->engine, "username", &flags, &user_val);
    if (user_status == errAuthorizationSuccess && user_val && user_val->data) {
        auth_username = strndup((const char *)user_val->data, user_val->length);
    }

    int allow = verify_lavalamp_substrate(auth_username);

    if (auth_username) free(auth_username);

    AuthorizationResult result = allow ? kAuthorizationResultAllow
                                       : kAuthorizationResultDeny;
    return mech->plugin->callbacks->SetResult(mech->engine, result);
}

static OSStatus MechanismDeactivate(AuthorizationMechanismRef inMechanism) {
    (void)inMechanism;
    return errAuthorizationSuccess;
}

static OSStatus MechanismDestroy(AuthorizationMechanismRef inMechanism) {
    if (inMechanism) free(inMechanism);
    return errAuthorizationSuccess;
}

static OSStatus PluginDestroy(AuthorizationPluginRef inPlugin) {
    if (inPlugin) free((void *)inPlugin);
    return errAuthorizationSuccess;
}

/*
 * AuthorizationPluginCreate — the entry point authd dlsym's to
 * initialize the plug-in. Returns a callbacks struct authd uses
 * to invoke our MechanismCreate / Invoke / Deactivate / Destroy /
 * PluginDestroy functions.
 */
OSStatus AuthorizationPluginCreate(const AuthorizationCallbacks *callbacks,
                                    AuthorizationPluginRef *outPlugin,
                                    const AuthorizationPluginInterface **outPluginInterface) {
    static AuthorizationPluginInterface plugin_interface;
    plugin_interface.version = kAuthorizationPluginInterfaceVersion;
    plugin_interface.PluginDestroy = PluginDestroy;
    plugin_interface.MechanismCreate = MechanismCreate;
    plugin_interface.MechanismInvoke = MechanismInvoke;
    plugin_interface.MechanismDeactivate = MechanismDeactivate;
    plugin_interface.MechanismDestroy = MechanismDestroy;

    PluginRecord *plugin = (PluginRecord *)calloc(1, sizeof(PluginRecord));
    if (!plugin) return errAuthorizationInternal;
    plugin->callbacks = callbacks;

    *outPlugin = (AuthorizationPluginRef)plugin;
    *outPluginInterface = &plugin_interface;
    return errAuthorizationSuccess;
}
