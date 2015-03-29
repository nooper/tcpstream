reads: session.o reads.c diskwriter.o tcp.o
	gcc -g -Werror -lpcap reads.c session.o diskwriter.o tcp.o ll.o -o reads

tcp.o: tcp.c diskwriter.o session.o
	gcc -g -c tcp.c

session.o: session.c session.h
	gcc -g -c session.c

diskwriter.o: diskwriter.c
	gcc -g -c diskwriter.c
