CC ?= cc
CPPFLAGS ?=
CFLAGS ?= -O3 -std=gnu99 -Wall -Wextra -D_FILE_OFFSET_BITS=64
BINDIR ?= $(HOME)/bin
UNAME_S := $(shell uname -s 2>/dev/null)
LDLIBS ?=
ifeq ($(UNAME_S),Linux)
LDLIBS += -ldl
endif
.PHONY: all install native clean
all: native
install: native
	mkdir -p "$(BINDIR)"
	install -m 755 hashcheck "$(BINDIR)/hashcheck"
	@printf 'installed: %s\n' "$(BINDIR)/hashcheck"
native: hashcheck
hashcheck: hashcheck.c
	$(CC) $(CPPFLAGS) $(CFLAGS) hashcheck.c $(LDLIBS) -o hashcheck
clean:
	rm -f hashcheck
