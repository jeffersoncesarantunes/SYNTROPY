CC=gcc
CFLAGS=-Wall -Wextra -Wpedantic -O2 -std=c99 -D_FORTIFY_SOURCE=2 \
       -fstack-protector-strong -fPIE -Wformat -Wformat-security
LDFLAGS=-pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack

TARGETS=K-Scanner/kscanner LinSpec/linspec
MANDIR ?= $(DESTDIR)/usr/local/share/man/man1

.PHONY: all build test docker install install-man clean

all: build

build: $(TARGETS)

K-Scanner/kscanner: K-Scanner/Makefile
	@echo "Building K-Scanner..."
	@$(MAKE) -C K-Scanner all

LinSpec/linspec: LinSpec/Makefile
	@echo "Building LinSpec..."
	@$(MAKE) -C LinSpec all

test:
	@echo "Running ShellCheck on scripts..."
	@shellcheck scripts/*.sh
	@echo "OK all tests passed."

docker:
	@docker build -t syntropy:latest .
	@echo "OK Docker image built: syntropy:latest"

install: build
	@install -m 0755 -d $(DESTDIR)/usr/local/bin
	@install -m 0755 scripts/syntropy-run.sh $(DESTDIR)/usr/local/bin/
	@install -m 0755 scripts/syntropy-bind.sh $(DESTDIR)/usr/local/bin/
	@install -m 0755 scripts/syntropy-scan-offline.sh $(DESTDIR)/usr/local/bin/
	@$(MAKE) -C K-Scanner install
	@$(MAKE) -C LinSpec install
	@echo "OK Installed."

install-man:
	@install -m 0755 -d $(MANDIR)
	@install -m 644 man/syntropy.1 $(MANDIR)/syntropy.1
	@echo "  Installed man page to $(MANDIR)"

clean:
	@$(MAKE) -C K-Scanner clean 2>/dev/null || true
	@$(MAKE) -C LinSpec clean 2>/dev/null || true
	@echo "Clean."
