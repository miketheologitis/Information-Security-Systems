CC=gcc
DBUG = -g
CCFLAGS = -O2 -Wall -pedantic
LIBPCAP = -lpcap

TARGETS = monitor

all: $(TARGETS)

monitor: monitor.c
	$(CC) $(CCFLAGS) $(DBUG) -o $@ $< $(LIBPCAP)

clean:
	rm -f $(TARGETS)
	rm -rf monitor.o