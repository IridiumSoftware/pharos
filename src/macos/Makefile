# Makefile — LavaLampMechanism.bundle for macOS authd.
#
# Builds the C/ObjC plug-in source into a bundle binary,
# ad-hoc code-signs it (no Developer ID required for local
# install — Apple Developer ID gates only kSecAttrToken-
# SecureEnclave, not Authorization Plug-ins).
#
# Build:    make
# Install:  sudo make install   (copies to
#                                /Library/Security/SecurityAgentPlugins/)
# Uninstall: sudo make uninstall

BUNDLE      = LavaLampMechanism.bundle
SRC         = LavaLampMechanism.m
BINARY      = $(BUNDLE)/Contents/MacOS/LavaLampMechanism

CC          = clang
# Universal binary — arm64 + x86_64. Both arches link only
# against macOS system frameworks (Security, CoreFoundation,
# Foundation) — no Homebrew or other non-system dylib
# dependencies, so the bundle runs under root-privileged
# authd's restricted dyld search path. The OpenSSL dependency
# from the v0.0.6 build was removed in v0.0.9 (verify path
# rewritten on Security.framework SecKeyVerifySignature).
CFLAGS      = -arch arm64 -arch x86_64 \
              -fobjc-arc -Wall -Wextra -O2
LDFLAGS     = -bundle \
              -framework Security \
              -framework CoreFoundation \
              -framework Foundation

INSTALL_DIR = /Library/Security/SecurityAgentPlugins

all: $(BINARY) sign

$(BINARY): $(SRC)
	@mkdir -p $(BUNDLE)/Contents/MacOS
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

sign: $(BINARY)
	codesign --force --sign - --timestamp=none $(BUNDLE)
	@echo "Ad-hoc signed: $(BUNDLE)"
	@codesign -dvv $(BUNDLE) 2>&1 | head -10

install: all
	@if [ "$(shell id -u)" != "0" ]; then \
		echo "ERROR: install must run as root: sudo make install"; \
		exit 1; \
	fi
	@echo "Installing $(BUNDLE) to $(INSTALL_DIR)/"
	cp -R $(BUNDLE) $(INSTALL_DIR)/
	@echo "Installed. To wire to an authorization rule, see"
	@echo "  src/macos/README.md (DEPLOYMENT section)."

uninstall:
	@if [ "$(shell id -u)" != "0" ]; then \
		echo "ERROR: uninstall must run as root: sudo make uninstall"; \
		exit 1; \
	fi
	rm -rf $(INSTALL_DIR)/$(BUNDLE)
	@echo "Removed: $(INSTALL_DIR)/$(BUNDLE)"

clean:
	rm -rf $(BUNDLE)/Contents/MacOS

.PHONY: all sign install uninstall clean
