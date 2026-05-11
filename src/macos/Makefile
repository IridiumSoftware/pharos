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
# arm64-only on Apple Silicon hosts (Homebrew OpenSSL is arm64
# on this machine). Rebuild on x86_64 hosts produces an
# x86_64 binary; cross-archs require x86_64 OpenSSL too.
CFLAGS      = -arch arm64 \
              -fobjc-arc -Wall -Wextra -O2 \
              -I/opt/homebrew/include \
              -I/opt/homebrew/opt/openssl@3/include
LDFLAGS     = -bundle \
              -framework Security \
              -framework CoreFoundation \
              -framework Foundation \
              -L/opt/homebrew/lib \
              -L/opt/homebrew/opt/openssl@3/lib \
              -lcrypto

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
