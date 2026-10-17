#if !defined(_STDNET_H_)
#define _STDNET_H_

/****************************************
 * (Almost) Generic...
 ****************************************/
#if !defined(VMS)
#  define EXIT_ERROR	1
#  define EXIT_SUCCESS	0
#  include <sys/types.h>
#  include <sys/stat.h>
#endif

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>

/***************************************
 * DOS specific...
 ***************************************/
#if defined(_DOS)
#  include <fcntl.h>
#  define TIME_T_DEFINED
#  include <pctcp/types.h>
   extern int bsd_close(int);
#endif

/***************************************
 * WIN32 specific...
 ***************************************/
#if defined(WIN32)
#  include <io.h>	  /* for WIN32 compatiblity */
#  include <winsock.h>
#  include <stdlib.h>
#  include <time.h>
#  define sprintf wsprintf
#  define GET_TIME(x) GetSystemTime(&x)
#  define Close closesocket
   static void *WPDialog;
   extern void Wprintf(void *, char *, ...);
   extern void Wperror(void *, char *);
   extern void Wputs(char *, void *);
#  define Fflush(ptr)
#else
#  define Wprintf fprintf
#  define Fflush fflush
#  if !defined(WPDialog)
#    define WPDialog stderr
#  endif
#  define Wperror(a,b) perror(b)
#  define Wputs fputs
#  define Close close
#endif

/***************************************
 * SUN specific...
 ***************************************/
#if defined(SUN)
#  define strtoul strtol
#endif

/***************************************
 * IRIX or Linux specific...
 ***************************************/
#if defined(IRIX) || defined(LINUX)
#include <unistd.h>
#endif

/***************************************
 * IRIX specific...
 ***************************************/
#if defined(IRIX)
#include <bstring.h>
#endif

/***************************************
 * VMS specific...
 ***************************************/
#if defined(VMS)
#  include <stat.h>
#  include <types.h>
#  include <socket.h>
#  include <netdb.h>
#  include <inet.h>
#  include <time.h>
#  define FD_SET(sock, ptr) *(int *)(ptr) |= (1<<(sock))
#  define FD_ZERO(ptr) *(int *)(ptr) = 0
#  define FD_ISSET(sock, ptr) ((*(int *)ptr)&(1<<(sock)))
#  define GET_TIME(x) sys$gettim(&x)
#  define EXIT_ERROR	0x10000002
#  define EXIT_SUCCESS	0x10000001
#  define GET_TIME(x) sys$gettim(&x)
#endif

/****************************************
 * More generic stuff...
 ****************************************/
#if !defined(VMS) && !defined(WIN32) 
#  include <sys/socket.h>
#  include <netdb.h>
#  include <netinet/in.h>
#  include <sys/time.h>
#  if !defined(IRIX) && !defined(LINUX)
     extern int select(int fd, struct fd_set *in, struct fd_set *out, struct fd_set *ex, struct timeval *to);
     extern int send(int fd, char *buf, int len, int flag);
     extern int recv(int fd, char *buf, int len, int flag);
     extern int gettimeofday(struct timeval *t, int flag);
#  endif
#  define GET_TIME(x) gettimeofday(&x, 0)
#endif

#if !defined(_DOS)
#  include <errno.h>
#if !defined(VMS) && !defined(WIN32)
#  include <sys/fcntl.h>
#endif
#if !defined(WIN32) && !defined(IRIX) && !defined(LINUX)
   extern int socket(int, int, int);
   extern int connect(int, struct sockaddr_in *, int);
#endif
   extern int close(int);
#endif

#include "icelesspkt.h"

#endif
