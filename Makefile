# mod_digest_fields Makefile
# Apache module for RFC 9530 Digest Fields
# Cross-platform build for macOS (MacPorts) and FreeBSD

UNAME := $(shell uname)

# Platform-specific apxs path
ifeq ($(UNAME),Darwin)
    APXS ?= /opt/local/bin/apxs
else
    APXS ?= /usr/local/sbin/apxs
endif

MODULE = mod_digest_fields.so
SOURCE = mod_digest_fields.c

.PHONY: all install clean test

all: $(MODULE)

$(MODULE): $(SOURCE)
	$(APXS) -c $(SOURCE)
	@if [ -f .libs/$(MODULE) ]; then \
		cp .libs/$(MODULE) .; \
	fi

install: $(MODULE)
	$(APXS) -i -a $(MODULE)

clean:
	rm -rf *.o *.lo *.la *.so *.slo .libs/

# Run basic tests (requires Apache to be configured with test/httpd-test.conf)
test:
	@echo "Test files in test/ directory:"
	@ls -la test/
	@echo ""
	@echo "To test manually:"
	@echo "  1. Build: make"
	@echo "  2. Install: sudo make install"
	@echo "  3. Add to Apache config and restart"
	@echo "  4. Run: curl -I http://localhost/path/to/file"
