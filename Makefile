reads: session.o reads.c diskwriter.o tcp.o session.h
	gcc -g -Werror -lpcap reads.c session.o diskwriter.o tcp.o -o reads

tcp.o: tcp.c
	gcc -g -c tcp.c

session.o: session.c session.h
	gcc -g -c session.c

diskwriter.o: diskwriter.c
	gcc -g -c diskwriter.c
