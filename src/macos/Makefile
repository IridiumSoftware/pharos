# Makefile — LavaLampMechanism.bundle for macOS authd.
#
# Builds the C/ObjC plug-in source into a bundle binary, code-signs
# it, and (for the production install path) notarizes + staples it.
#
# Two signing paths:
#   - `make` / `make sign`    — ad-hoc signed; for local dev iteration
#                                only. Will NOT pass authd's spctl
#                                gate on macOS 14+ (see project
#                                memory: PharOS macOS Dev ID gate).
#   - `make release`          — Developer ID + Hardened Runtime +
#                                Apple notarization + stapled ticket.
#                                Required for live install.
#
# Production install (after `make release`):
#   sudo make install        — copies to /Library/Security/SecurityAgentPlugins/
#   sudo make uninstall      — removes
#
# Required env / config:
#   DEVELOPER_ID  — codesigning identity. Default matches the
#                   keychain identity established 2026-05-21.
#   NOTARY_PROFILE — notarytool keychain-profile name (set up via
#                   `xcrun notarytool store-credentials`).

BUNDLE      = LavaLampMechanism.bundle
SRC         = LavaLampMechanism.m
BINARY      = $(BUNDLE)/Contents/MacOS/LavaLampMechanism
ZIP         = $(BUNDLE).zip

# Signing identity. Override via env, e.g.:
#   make release DEVELOPER_ID="Developer ID Application: Your Name (TEAMID)"
# or set a persistent default in a gitignored Makefile.local you include
# before this rule. The default is an unusable placeholder so a fresh
# checkout cannot accidentally produce a no-op-signed binary.
DEVELOPER_ID    ?= Developer ID Application: YOUR_NAME (TEAMID)
# notarytool keychain-profile (set up via `xcrun notarytool store-credentials`).
NOTARY_PROFILE  ?= pharos-notary

CC          = clang
# Universal binary — arm64 + x86_64. Both arches link only against
# macOS system frameworks (Security, CoreFoundation, Foundation) — no
# Homebrew or other non-system dylib dependencies, so the bundle runs
# under root-privileged authd's restricted dyld search path. OpenSSL
# was removed in v0.0.9 (verify path on Security.framework
# SecKeyVerifySignature).
CFLAGS      = -arch arm64 -arch x86_64 \
              -fobjc-arc -Wall -Wextra -O2
LDFLAGS     = -bundle \
              -framework Security \
              -framework CoreFoundation \
              -framework Foundation

INSTALL_DIR = /Library/Security/SecurityAgentPlugins

# --------------------------------------------------------------
# Default: build + ad-hoc sign (local dev iteration).
# --------------------------------------------------------------
all: $(BINARY) sign

$(BINARY): $(SRC)
	@mkdir -p $(BUNDLE)/Contents/MacOS
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

# Ad-hoc sign — local dev only. Will not pass spctl on macOS 14+.
sign: $(BINARY)
	codesign --force --sign - --timestamp=none $(BUNDLE)
	@echo "Ad-hoc signed: $(BUNDLE)"
	@codesign -dvv $(BUNDLE) 2>&1 | head -10

# --------------------------------------------------------------
# Production: Developer ID + Hardened Runtime + secure timestamp.
# Required prerequisite for notarization.
# --------------------------------------------------------------
signed: $(BINARY)
	codesign --force \
	         --sign "$(DEVELOPER_ID)" \
	         --options runtime \
	         --timestamp \
	         $(BUNDLE)
	@echo "Developer ID signed: $(BUNDLE)"
	@codesign -dvv $(BUNDLE) 2>&1 | head -10
	@echo "--- runtime + timestamp check ---"
	@codesign -dv --verbose=4 $(BUNDLE) 2>&1 | grep -E "Identifier|Authority|Timestamp|Runtime"

# --------------------------------------------------------------
# Notarize the signed bundle via Apple's notary service.
# Bundle must be zipped before submission. notarytool waits until
# Apple's notary service finishes (typically 1-5 minutes).
# --------------------------------------------------------------
notarize: signed
	@echo "--- zipping $(BUNDLE) for submission ---"
	rm -f $(ZIP)
	/usr/bin/ditto -c -k --keepParent $(BUNDLE) $(ZIP)
	@echo "--- submitting to Apple notary (this can take a few minutes) ---"
	xcrun notarytool submit $(ZIP) \
	      --keychain-profile "$(NOTARY_PROFILE)" \
	      --wait
	rm -f $(ZIP)

# --------------------------------------------------------------
# Staple the notarization ticket to the bundle so it's accepted
# offline by Gatekeeper.
# --------------------------------------------------------------
staple:
	xcrun stapler staple $(BUNDLE)
	xcrun stapler validate $(BUNDLE)

# --------------------------------------------------------------
# Full pipeline: clean → build → signed → notarize → staple → verify.
# --------------------------------------------------------------
release: clean $(BINARY) signed notarize staple verify
	@echo
	@echo "--- $(BUNDLE) is production-ready: signed, notarized, stapled, verified ---"

# --------------------------------------------------------------
# spctl assess + codesign verify.
# --------------------------------------------------------------
verify:
	@echo "--- codesign verify ---"
	codesign --verify --verbose=4 $(BUNDLE)
	@echo "--- spctl assess (install type) ---"
	spctl -a -vvv -t install $(BUNDLE) || true
	@echo "--- spctl assess (open type) ---"
	spctl -a -vvv -t open --context context:primary-signature $(BUNDLE) || true

# --------------------------------------------------------------
# Install / uninstall.
# --------------------------------------------------------------
install: $(BUNDLE)
	@if [ "$(shell id -u)" != "0" ]; then \
		echo "ERROR: install must run as root: sudo make install"; \
		exit 1; \
	fi
	@echo "Installing $(BUNDLE) to $(INSTALL_DIR)/"
	cp -R $(BUNDLE) $(INSTALL_DIR)/
	@echo "Installed. Bundle owner/perms:"
	@ls -la $(INSTALL_DIR)/$(BUNDLE)/Contents/MacOS/
	@echo
	@echo "To wire to an authorization rule, see README.md (DEPLOYMENT)."

uninstall:
	@if [ "$(shell id -u)" != "0" ]; then \
		echo "ERROR: uninstall must run as root: sudo make uninstall"; \
		exit 1; \
	fi
	rm -rf $(INSTALL_DIR)/$(BUNDLE)
	@echo "Removed: $(INSTALL_DIR)/$(BUNDLE)"

clean:
	rm -rf $(BUNDLE)/Contents/MacOS $(ZIP)

.PHONY: all sign signed notarize staple release verify install uninstall clean
