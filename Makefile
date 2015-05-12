CFLAGS=-g
LDLIBS=-lpcap

all: reads

reads: *.c *.h

clean:
	${RM} reads
