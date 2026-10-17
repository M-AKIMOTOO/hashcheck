PYTHON ?= python3
CC ?= cc
CPPFLAGS ?=
CFLAGS ?= -O3 -std=gnu99 -Wall -Wextra -D_FILE_OFFSET_BITS=64
BINDIR ?= $(HOME)/bin
UNAME_S := $(shell uname -s 2>/dev/null)
LDLIBS ?=
ifeq ($(UNAME_S),Linux)
LDLIBS += -ldl
endif
.PHONY: all check-python install native win11-zig clean
all: check-python native
check-python: hashcheck.py
	$(PYTHON) hashcheck.py --help >/dev/null
install: check-python
	mkdir -p "$(BINDIR)"
	install -m 755 hashcheck.py "$(BINDIR)/hashcheck"
	@printf 'installed: %s\n' "$(BINDIR)/hashcheck"
native: hashcheck
hashcheck: hashcheck.c
	$(CC) $(CPPFLAGS) $(CFLAGS) hashcheck.c $(LDLIBS) -o hashcheck
win11-zig: hashcheck.c
	zig cc -O3 -std=c11 -target x86_64-windows-gnu -municode hashcheck.c -s -o hashcheck.exe
clean:
	rm -f hashcheck hashcheck.exe
