PREFIX ?= /usr
BINDIR ?= $(PREFIX)/bin
CC ?= cc
CFLAGS ?= -O2 -g
CPPFLAGS += $(shell krb5-config --cflags 2>/dev/null)
KRB5_LIBS := $(shell krb5-config --libs 2>/dev/null)

.PHONY: all clean install
all: mitlist

mitlist: src/mitlist.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -Wall -Wextra -Wformat=2 -Wshadow -Wconversion -o $@ $< $(KRB5_LIBS)

install: mitlist
	install -D -m 0755 mitlist $(DESTDIR)$(BINDIR)/mitlist

clean:
	rm -f mitlist
