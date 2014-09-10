reads: session.o
	gcc -g -lpcap reads.c session.o -o reads

session.o: session.c session.h
	gcc -g -c session.c

