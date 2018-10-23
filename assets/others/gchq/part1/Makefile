CC=gcc
CFLAGS=-m32 -g
LDFLAGS=

all: gchq launcher

launcher: launcher.c
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

gchq:
	nasm gchq.asm

.PHONY: clean mrproper

clean:

mrproper: clean
	rm gchq
	rm launcher
