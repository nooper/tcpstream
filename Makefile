CFLAGS=-Werror
LDLIBS=-lpcap

all: tcpstream

debug: CFLAGS += -g -DDEBUG
debug: tcpstream

tcpstream: session.h session.c tcpstream.c tcp.c diskwriter.c diskwriter.h

clean:
	${RM} tcpstream

.PHONY: all debug clean
