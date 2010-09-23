MK_CFLAGS=-std=gnu99 -Wall
prefix ?= /usr/local

all: unsuspendd autosuspend

unsuspendd: unsuspendd.c unsuspend.h
	$(CC) -o $@ $(CFLAGS) $(MK_CFLAGS) $(LDFLAGS) $^

autosuspend: autosuspend.c unsuspend.h
	$(CC) -o $@ $(CFLAGS) $(MK_CFLAGS) $(LDFLAGS) $^

clean:
	rm -f unsuspendd autosuspend

install: all
	install -m755 -D unsuspendd $(DESTDIR)$(prefix)/sbin/unsuspendd
	install -m755 -D autosuspend $(DESTDIR)$(prefix)/bin/autosuspend
