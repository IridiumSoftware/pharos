# pam_lavalamp Makefile — Linux PAM module build for PharOS
# MVP-1 + MVP-2 + MVP-3 (HMAC anti-replay).
#
# Build: make
# Install: sudo make install
# Test (without installing): make test  (uses test/test_pam_lavalamp.sh)
#
# Requires:
#   - libpam0g-dev (Debian/Ubuntu) or pam-devel (Fedora/RHEL)
#   - libssl-dev (Debian/Ubuntu) or openssl-devel (Fedora/RHEL)
#     for HMAC-SHA256 via libcrypto
#
# The PAM module is a position-independent shared object loaded
# by libpam at runtime. Links against libpam (-lpam) and
# libcrypto (-lcrypto, OpenSSL or LibreSSL).

CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -Werror -fPIC -fstack-protector-strong
LDFLAGS ?= -shared
LIBS    := -lpam -lcrypto

TARGET  := pam_lavalamp.so
SOURCES := pam_lavalamp.c
OBJECTS := $(SOURCES:.c=.o)

# PAM modules live in a multiarch-aware directory on modern
# Debian/Ubuntu; fall back to /lib/security on older systems.
PAM_LIB_DIR ?= $(shell \
    if [ -d /lib/x86_64-linux-gnu/security ]; then \
        echo /lib/x86_64-linux-gnu/security; \
    elif [ -d /lib/aarch64-linux-gnu/security ]; then \
        echo /lib/aarch64-linux-gnu/security; \
    elif [ -d /lib64/security ]; then \
        echo /lib64/security; \
    else \
        echo /lib/security; \
    fi)

.PHONY: all clean install uninstall test

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

install: $(TARGET)
	@echo "Installing $(TARGET) → $(PAM_LIB_DIR)/"
	install -d $(PAM_LIB_DIR)
	install -m 0644 $(TARGET) $(PAM_LIB_DIR)/

uninstall:
	rm -f $(PAM_LIB_DIR)/$(TARGET)

clean:
	rm -f $(TARGET) $(OBJECTS)

test: $(TARGET)
	cd ../../../test && bash test_pam_lavalamp.sh
