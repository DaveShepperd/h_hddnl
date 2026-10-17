INCS = -I.
DEFS = -DLINUX=2
OPT = -O2
MACH = -m32
CFLAGS = -g ${INCS} ${DEFS} ${OPT} $(MACH) -Wall -pedantic -ansi -Wno-trigraphs
LFLAGS = -g $(MACH)
CC = gcc
LIBDIRS = 
LIBS = -lz 
ECHO = /usr/bin/echo -e

.SILENT:

hddnl : h_hddnl.o ascleapio.o h_hdparse.o
	$(ECHO) "\tLinking $@ ..."
	$(CC) $(LFLAGS) -o $@ $^ ${LIBDIRS} ${LIBS}

%.o : %.c
	$(ECHO) "\tCompiling $< ..."
	$(CC) $(CFLAGS) -c $<

ascleapio.o : ascleapio.c ascleapio.h stdnet.h icelesspkt.h

h_hddnl.o : h_hddnl.c hddnl.h ascleapio.h icelesspkt.h h_hdparse.h #zlib.h zconf.h

h_hdparse.o : h_hdparse.c h_hdparse.h

clean:
	rm -f *.o *.lis hddnl
