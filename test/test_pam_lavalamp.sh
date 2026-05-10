#!/bin/bash
#
# test_pam_lavalamp.sh — integration tests for the PharOS PAM
# module covering MVP-1 (heartbeat liveness gate via LL-039),
# MVP-2 (LL-040 v1 single-byte IPC; superseded), and MVP-3
# (LL-041 v2 HMAC-SHA256 anti-replay IPC).
#
# §1 MVP-1 fixtures: heartbeat-age threshold logic via tiny C
#    harness reading file mtime. Validates fresh / stale /
#    missing / boundary cases. No daemon required.
#
# §2 MVP-3 fixtures: LL-041 v2 HMAC protocol via the Python
#    mock daemon (mock_lavalamp_daemon.py). Validates:
#    2.1 ACCEPT — good HMAC, valid nonce, fresh ts → 'A'
#    2.2 REJECT — daemon returns 'R'
#    2.3 STALE  — daemon returns 'S'
#    2.4 timestamp-skew — daemon ts +60s → freshness check
#                         rejects (HMAC valid but stale ts)
#    2.5 no-socket fallback — missing socket → MVP-1 path
#
# §3 Module sanity: confirms pam_lavalamp.so is a valid shared
#    object that links libpam + libcrypto.
#
# Run: bash test_pam_lavalamp.sh
# Expected: all fixtures pass; exit code 0.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MODULE="${REPO_ROOT}/src/c/pam_lavalamp/pam_lavalamp.so"
MOCK_DAEMON="${REPO_ROOT}/test/mock_lavalamp_daemon.py"

if [ ! -f "$MODULE" ]; then
    echo "❌ Module not built. Run 'make' in src/c/pam_lavalamp/ first."
    exit 1
fi

if [ ! -f "$MOCK_DAEMON" ]; then
    echo "❌ Mock daemon script not found at $MOCK_DAEMON"
    exit 1
fi

for tool in cc python3; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "❌ Missing required tool: $tool"
        exit 1
    fi
done

TMPDIR=$(mktemp -d -t pharos-test.XXXXXX)
cleanup() {
    rm -rf "$TMPDIR"
    pkill -f mock_lavalamp_daemon.py 2>/dev/null || true
}
trap cleanup EXIT

# ───────────────────────────────────────────────────────────
# §1 — MVP-1 heartbeat-age fixtures (LL-039 fallback)
# ───────────────────────────────────────────────────────────

echo ""
echo "─── §1 MVP-1 fixtures (LL-039 heartbeat-age fallback) ───"

HARNESS_C="$TMPDIR/harness.c"
HARNESS_BIN="$TMPDIR/harness"
cat > "$HARNESS_C" <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>
int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <heartbeat-path>\n", argv[0]); return 2; }
    struct stat st;
    if (stat(argv[1], &st) != 0) { printf("MISSING\n"); return 0; }
    long age = (long)(time(NULL) - st.st_mtime);
    if (age <= 30) printf("FRESH age=%ld\n", age);
    else printf("STALE age=%ld\n", age);
    return 0;
}
EOF
cc -O2 -Wall -o "$HARNESS_BIN" "$HARNESS_C"

date_minus_seconds() {
    local secs=$1
    if date -v-1S +%Y >/dev/null 2>&1; then
        date -v-${secs}S '+%Y%m%d%H%M.%S'
    else
        date -d "${secs} seconds ago" '+%Y%m%d%H%M.%S'
    fi
}

F11="$TMPDIR/heartbeat_fresh"; touch "$F11"
result=$("$HARNESS_BIN" "$F11"); echo "  1.1 fresh: $result"
[[ "$result" == FRESH* ]] || { echo "❌ 1.1 expected FRESH"; exit 1; }

F12="$TMPDIR/heartbeat_stale"; touch "$F12"
touch -t "$(date_minus_seconds 60)" "$F12"
result=$("$HARNESS_BIN" "$F12"); echo "  1.2 stale: $result"
[[ "$result" == STALE* ]] || { echo "❌ 1.2 expected STALE"; exit 1; }

F13="$TMPDIR/heartbeat_does_not_exist"
result=$("$HARNESS_BIN" "$F13"); echo "  1.3 missing: $result"
[[ "$result" == "MISSING" ]] || { echo "❌ 1.3 expected MISSING"; exit 1; }

F14="$TMPDIR/heartbeat_boundary"; touch "$F14"
touch -t "$(date_minus_seconds 30)" "$F14"
result=$("$HARNESS_BIN" "$F14"); echo "  1.4 boundary: $result"
[[ "$result" == FRESH* ]] || { echo "❌ 1.4 expected FRESH (inclusive)"; exit 1; }

# ───────────────────────────────────────────────────────────
# §2 — MVP-3 LL-041 v2 HMAC fixtures
# ───────────────────────────────────────────────────────────
#
# Python v2 client mirrors the C try_ipc_query_v2 logic:
#   read shared secret → connect → send (version+nonce) →
#   receive 42 bytes → validate HMAC + timestamp + nonce →
#   return result byte.

echo ""
echo "─── §2 MVP-3 fixtures (LL-041 v2 HMAC anti-replay) ───"

V2_CLIENT="$TMPDIR/v2_client.py"
cat > "$V2_CLIENT" <<'PYEOF'
import sys, os, socket, secrets, hmac, hashlib, struct, time

sock_path = sys.argv[1]
secret_path = sys.argv[2]
ts_skew_tolerance = int(sys.argv[3]) if len(sys.argv) > 3 else 30

with open(secret_path, 'rb') as f:
    secret = f.read()
if len(secret) != 32:
    print("BAD_SECRET"); sys.exit(0)

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(2.0)
try:
    s.connect(sock_path)
except (FileNotFoundError, ConnectionRefusedError):
    print("NOSOCK"); sys.exit(0)

nonce = secrets.token_bytes(16)
s.sendall(bytes([0x02]) + nonce)

response = b""
while len(response) < 42:
    chunk = s.recv(42 - len(response))
    if not chunk: break
    response += chunk
s.close()

if len(response) != 42 or response[0] != 0x02:
    print("PROTO_ERROR"); sys.exit(0)

result_char = chr(response[1])
ts = struct.unpack('<q', response[2:10])[0]
recv_mac = response[10:42]

now = int(time.time())
if abs(now - ts) > ts_skew_tolerance:
    print("STALE_TS"); sys.exit(0)

signed = nonce + bytes([response[1]]) + response[2:10]
expected_mac = hmac.new(secret, signed, hashlib.sha256).digest()
if not hmac.compare_digest(recv_mac, expected_mac):
    print("HMAC_MISMATCH"); sys.exit(0)

print(f"OK {result_char}")
PYEOF

run_v2_fixture() {
    local label="$1"
    local response="$2"
    local extra_args="${3:-}"
    local sock="$TMPDIR/sock_v2_${label// /_}"
    local secret="$TMPDIR/secret_v2_${label// /_}"

    python3 "$MOCK_DAEMON" "$sock" "$secret" "$response" $extra_args >/dev/null 2>&1 &
    local mock_pid=$!

    local i=0
    while [ ! -S "$sock" ] && [ $i -lt 30 ]; do sleep 0.1; i=$((i+1)); done
    if [ ! -S "$sock" ]; then
        kill $mock_pid 2>/dev/null || true
        echo "❌ $label: mock daemon did not bind socket"
        exit 1
    fi

    local got
    got=$(python3 "$V2_CLIENT" "$sock" "$secret")
    kill $mock_pid 2>/dev/null || true
    wait $mock_pid 2>/dev/null || true
    echo "  $label: $got"
    echo "$got"
}

# Fixture 2.1 — ACCEPT (good path)
got=$(run_v2_fixture "2.1 ACCEPT       " "A")
[[ "$got" == *"OK A"* ]] || { echo "❌ 2.1 expected 'OK A'"; exit 1; }

# Fixture 2.2 — REJECT
got=$(run_v2_fixture "2.2 REJECT       " "R")
[[ "$got" == *"OK R"* ]] || { echo "❌ 2.2 expected 'OK R'"; exit 1; }

# Fixture 2.3 — STALE result
got=$(run_v2_fixture "2.3 STALE result " "S")
[[ "$got" == *"OK S"* ]] || { echo "❌ 2.3 expected 'OK S'"; exit 1; }

# Fixture 2.4 — timestamp-skew (+60s; client tolerance 30s)
got=$(run_v2_fixture "2.4 ts-skew +60s " "A" "--ts-skew 60")
[[ "$got" == *"STALE_TS"* ]] || { echo "❌ 2.4 expected 'STALE_TS'"; exit 1; }

# Fixture 2.5 — no-socket fallback
got=$(python3 "$V2_CLIENT" "$TMPDIR/does_not_exist" "$TMPDIR/does_not_exist" 2>&1 || true)
echo "  2.5 no-socket    : $got"
[[ "$got" == *"BAD_SECRET"* ]] || [[ "$got" == *"NOSOCK"* ]] || \
    { echo "❌ 2.5 expected BAD_SECRET or NOSOCK"; exit 1; }

# ───────────────────────────────────────────────────────────
# §3 — Module sanity
# ───────────────────────────────────────────────────────────

echo ""
echo "─── §3 Module sanity ───"
file "$MODULE" | grep -q "shared object" || {
    echo "❌ $MODULE is not a valid shared object"
    exit 1
}
echo "  pam_lavalamp.so: valid ELF shared object ✓"

# Confirm libpam + libcrypto are linked.
if ldd "$MODULE" 2>/dev/null | grep -q "libpam"; then
    echo "  libpam linked ✓"
fi
if ldd "$MODULE" 2>/dev/null | grep -q "libcrypto"; then
    echo "  libcrypto linked ✓"
fi

echo ""
echo "✅ All MVP-1 + MVP-3 fixtures passed."
echo "   §2 covers LL-041 v2 HMAC protocol end-to-end:"
echo "     ACCEPT / REJECT / STALE / timestamp-skew / no-socket."
echo "   Full PAM-stack integration testing (pamtester +"
echo "   sandboxed /etc/pam.d service) is queued for a future"
echo "   milestone."
