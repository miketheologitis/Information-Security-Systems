CC=gcc
CFLAGS=-I.
DEPS = simple_crypto.h

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

demoprogram: simple_crypto.o
	$(CC) -o demoprogram simple_crypto.o 	