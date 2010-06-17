MK_CFLAGS=-std=gnu99

all: unsuspendd autosuspend

unsuspendd: unsuspendd.c unsuspend.h
	$(CC) -o $@ $(CFLAGS) $(MK_CFLAGS) $(LDFLAGS) $^

autosuspend: autosuspend.c unsuspend.h
	$(CC) -o $@ $(CFLAGS) $(MK_CFLAGS) $(LDFLAGS) $^

clean:
	rm -f unsuspendd autosuspend
