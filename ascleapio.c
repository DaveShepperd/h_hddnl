#include "stdnet.h"
#include "ascleapio.h"

static char emsg[132];

static struct hostent hostentstruct, *hostentptr;

#if defined(LINUX)
# define CONNECT_TYPE (struct sockaddr *)
#else
# define CONNECT_TYPE 
#endif

static AscleapIO *open_common(char *host, int port, int type) {
   struct sockaddr_in sadr;
   int sock;
   AscleapIO *io;
   
   io = (AscleapIO *)calloc(1,sizeof(AscleapIO));
   if (io == 0) return io;
   hostentptr = gethostbyname(host);	/* get the ip address of the server */
   if (hostentptr == 0) {
      int olderr;
      olderr = errno;
      sprintf(emsg,"Error getting inet address of \"%s\"",host);
      perror(emsg);
      free(io);
      errno = olderr;
      return (AscleapIO *)0;
   }
   sock = socket(AF_INET, type ? SOCK_DGRAM : SOCK_STREAM, 0);
   if (sock < 0) {
      int olderr=errno;
      perror("Error creating socket");
      free(io);
      errno = olderr;
      return (AscleapIO *)0;
   }
   hostentstruct = *hostentptr;
   sadr.sin_family = hostentstruct.h_addrtype;
   sadr.sin_port = htons(port);
   sadr.sin_addr = *((struct in_addr *)hostentstruct.h_addr_list[0]);
   if (connect(sock, CONNECT_TYPE &sadr, sizeof(sadr)) < 0) {
      sprintf(emsg,"Error connecting to socket %d",sock);
      perror(emsg);
      return ascleapio_close(io);
   }
   io->state = 0;
   io->socket = sock;
   return io;
}

AscleapIO *ascleapio_open(char *host, int port, int type) {
   AscleapIO *io;
   int retry;

   for (retry=1;retry < 2; ++retry) {
      struct timeval tv;
      io = open_common(host, port, type);
      if (io != 0) return io;
      tv.tv_usec = 0;
      tv.tv_sec = retry;		/* wait n seconds */
      select(1, 0, 0, 0, &tv);
   }
   if (io) ascleapio_rdchkw(io, 1l, 0l);
   return io;
}

int ascleapio_rdchkw(AscleapIO *io, long sec, long usec) {
#if !defined(LINUX) || (LINUX < 2)
   struct fd_set
#else
   fd_set
#endif
	rfdset;
   struct timeval tv;

   tv.tv_sec = sec;
   tv.tv_usec = usec;
   FD_ZERO(&rfdset);
   FD_SET(io->socket, &rfdset);
   return select(io->socket+1, &rfdset, 0, 0, &tv);
}

int ascleapio_rdchk(AscleapIO *io) {
   return ascleapio_rdchkw(io, 0L, 0L);
}

int ascleapio_read(AscleapIO *io, char *hisbuff, int len) {
   int rdta;

   rdta = recv(io->socket, hisbuff, len, 0);
   return rdta;
}
   
int ascleapio_write(AscleapIO *io, char *buff, int size) {
   return send(io->socket, buff, size, 0);
}

AscleapIO *ascleapio_close(AscleapIO *io) {
   close(io->socket);
   free(io);
   return (AscleapIO *)0;
}

