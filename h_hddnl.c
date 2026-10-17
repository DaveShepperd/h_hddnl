/*		h_hddnl.c: Communication pipe with ICELESS via an ASCLEAP
 *	This program runs under Unix(tm) and connects to an ASCLEAP
 *	running Xinu (tm) and from there to the communication s/w running
 *	on the game hadrware (target flavor of hddnl) using the ICELESS
 *	board communication protocol. 
 *
 *		Copyright 1996, 1997, 1998, 1999 Atari Games, Corp.
 *	Unauthorized reproduction, adaptation, distribution, performance or 
 *	display of this computer program or the associated audiovisual work
 *	is strictly prohibited.
 *
 */

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <ctype.h>
#include <errno.h>
#if !defined(LINUX)
#include <bstring.h>
#else
#include <sys/time.h>
#if LINUX > 1
#include <sys/select.h>
#endif
extern int fileno(FILE *);
#endif
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <utime.h>
#include "ascleapio.h"
#include "icelesspkt.h"
#include "zlib.h"
#include <unistd.h>
#include <sys/stat.h>

#ifndef FSYS_MAX_ALTS
# define FSYS_MAX_ALTS	3
#endif

#ifndef n_elts
#define n_elts(x) (sizeof(x)/sizeof((x)[0]))
#endif

typedef unsigned long U32;
typedef unsigned short U16;
typedef unsigned char U8;
#include "hddnl.h"
#include "h_hdparse.h"

#define Wprintf fprintf
#define WPDialog stdout
#define Wputs fputs
#define Wperror perror

#define EXIT_ERROR 1
#define EXIT_SUCCESS 0
#define EXIT(n) call_exit(n)

#if 0
struct timeval {
	long	tv_sec;		/* seconds */
	long	tv_usec;	/* and microseconds */
};
#endif

char *image_name;

#define X_SEND_PKTS	1
#define X_RECV_PKTS	2
#define X_MKFILE	4
int x_commands;

#define DBG_SHO_CMD		0x001 	/* show command file processing */
#define DBG_SHO_NTRAFFIC 	0x002	/* show network packet traffic */
#define DBG_SHO_INETPKT		0x004	/* show incoming network packets */
#define DBG_SHO_ONETPKT		0x008	/* show outgoing network packets */
#define DBG_SHO_ONETCMD		0x010	/* show outgoing network command */
int debug_level;
int quiet;
int date_diff;

#define ASC_PORT	(230)

typedef struct net_buf {
    int thread;				/* process thread (1-254) */
    int patnet;				/* patnet port (0-1) */
    int board;				/* board (0-3) */
    int port;				/* tcp/ip port (ASC_PORT) */
    char *host;				/* Ascleap host name */
    int from;				/* from channel */
    int to;				/* to channel */
    unsigned char *buf;			/* ptr to I/O buffer */
    int buf_size;			/* size of buffer in bytes */
    int buf_len;			/* amt of data in buffer */
    int cmd;				/* Mole/Iceless command received */
    int reason;				/* error reason code */
    int expected_seq;			/* expected sequence number */
    unsigned char *u_data;		/* ptr to start of user data */
    int u_len;				/* length of user's data */
    int errors;				/* input errors */
    unsigned char seq;			/* next packet sequence number */
} NetState;

typedef struct csum {
    unsigned char fid[4];
    unsigned char cs[4];
} ChkSum;

#ifndef MAX_NUMB_PACKETS
#define MAX_NUMB_PACKETS	20
#endif

static NetState cmd_ice = {2, 1, 1, ASC_PORT};
static NetState poll_ice = {2, 1, 1, ASC_PORT};
static int g_timeout = 10000;		/* assume a 10 second timeout */
static int mount_timeout = 15000;	/* assume a 15 second mount timeout */
#if LINUX
static int max_packet_size = MAX_PKT_SIZE;
static int max_numb_packets = MAX_NUMB_PACKETS/2;
#else
static int max_packet_size = 500;
static int max_numb_packets = 10;
#endif
static int files_sent;
static int verify;
static int squeeze_em;
static int compression_factor=1; /* Z_DEFAULT_COMPRESSION is too slow */
       int default_copies;
static const char erase[] = "\r                                                                               \r";
static char *eol_char = "\n", *bol_char = "";
static int need_erase;
static char *while_processing;

static void call_exit(int arg) {
    exit(arg);
}

void PrintPacket(unsigned char * buf, int len) {
  int i, j, k;
  
  k = (len <= 16*32) ? len : 16*32;
  len -= k;
  while (k > 0) {
     for (i=0; i<16 && k > 0; ++i) {
       for (j=0; j<32 && k > 0; --k, ++j) {
	 printf("%2.2X ", buf[i*32+j]);
       }
       printf("\n");
     }
     printf("\n\n");
  }
  if (len > 0) printf("... + and additional %d bytes ...", len);
}

#define DUMP_COLS (16)
static char *tmp_buf;
static int size_tmpbuf;
static char hex2asc[] = "0123456789ABCDEF";

void dump_buf(char *id, unsigned char *buf, int count, int flag) {
   int kk, cnt;
   char *tb;

   if (!(flag&2)) Wprintf(WPDialog, "%s: %d bytes ", id, count);
   kk = 4*count+2;
   if (size_tmpbuf < kk) {
      if (tmp_buf) free(tmp_buf);
      size_tmpbuf = kk;
      tmp_buf = malloc(size_tmpbuf);
      if (tmp_buf == 0) {
	 Wprintf(WPDialog, "Out of memory allocating %d bytes\n", size_tmpbuf);
	 exit (EXIT_ERROR);
      }
   }
   tb = tmp_buf;
   if (buf) {
       for (kk=cnt = 0; cnt < count; ++cnt) {
	  if (flag && isprint(buf[cnt])) {
	     if (kk == 0) {
		if (cnt != 0) *tb++ = ' ';
		*tb++ = '"';
	     }
	     ++kk;
	     *tb++ = buf[cnt];
	  } else {
	     if (kk) *tb++ = '"';
	     if (cnt) *tb++ = ' ';
	     *tb++ = hex2asc[(buf[cnt]>>4)&15];
	     *tb++ = hex2asc[buf[cnt]&15];
	     kk = 0;
	  }
       }
   }
   if (kk) *tb++ = '"';
   *tb++ = '\n';
   *tb = 0;
   Wputs(tmp_buf, WPDialog);
#if 0
   while ( count > 0 ) {
      memset(obuf,' ',DUMP_COLS*3);
      memset(obuf+DUMP_COLS*3,'.',DUMP_COLS);
      obuf[DUMP_COLS*4] = '\n';
      obuf[DUMP_COLS*4+1] = '\0';
      for ( col = 0 ; col < count ;  ) {
	 obuf[col*3] = hexdig[(buf[col]>>4)&0xF];
	 obuf[col*3+1] = hexdig[buf[col]&0xF];
	 if ( isprint(buf[col]) ) obuf[DUMP_COLS*3+col] = buf[col];
	 if ( ++col >= DUMP_COLS ) break;
      }
      putn_ams(id,strlen(id));
      putn_ams(obuf,sizeof(obuf));
      buf += col;
      count -= col;
   }
   putn_ams("\033[A\n",4);
#endif
}

static int put_iceless(AscleapIO *iop, NetState *net, unsigned char *buff, int ilen, int cmd) {
    int tot=0, ii, cs, len;
    unsigned char *dst;

    do {
	len = net->buf_size - PKTuser - 4; /* assume the max */
	if (len > ilen) len = ilen;	/* minimize to the asking amount */
	ilen -= len;			/* take from total */
	len += len ? 4 : 2;		/* if there is data, make room for checksum */
	dst = net->buf;
	dst[PKTmsl] = len>>8;		/* prepare to copy message */
	dst[PKTlsl] = len;			/* msb of length */
	dst[PKTto]  = net->to;		/* to wherever */
	dst[PKTtothrd] = net->thread;
	dst[PKTfrom] = 0;			/* placeholder */
	dst[PKTfromthrd] = net->thread;	/* us */
	dst[PKTuser+0] = net->seq;	/* packet number */
	dst[PKTuser+1] = cmd;		/* command */
	if (len > 4) {
	    cs = 0;
	    dst = net->buf + PKTuser+4;	/* skip over seq, cmd and cs */
	    for (ii=4; ii < len; ++ii) cs += (*dst++ = *buff++);
	    dst = net->buf + PKTuser+2;	/* point to where cs goes */
	    *dst++ = cs >> 8;		/* stuff it in (big endian style) */
	    *dst++ = cs;
	}
	if (debug_level&DBG_SHO_NTRAFFIC) Wprintf(WPDialog,"Writing %d user, %d total bytes...\n",
    			len, len+PKTuser);
	ii = ascleapio_write(iop, (char *)net->buf, len+PKTuser);
	if (debug_level&DBG_SHO_ONETPKT) PrintPacket((unsigned char *)net->buf, len+PKTuser);
	if (ii < 0) return ii;
	if (ii > 0) tot += ii;
    } while (ilen > 0);
    return tot;
}

static int get_from_net(AscleapIO *iop, unsigned char *buff, int min, int len, int timeout) {
    int sel_status;
    fd_set rfds;
    struct timeval tv, otv;
    int got;
    unsigned char *begin;

    if (timeout >= 1000) {
        otv.tv_usec = 0;
        otv.tv_sec = timeout/1000;		/* timeout in seconds */
    } else {
        otv.tv_usec = timeout*1000;		/* timeout in microseconds */
        otv.tv_sec = 0;
    }

    if ((len == 0 || min == 0) && (debug_level&DBG_SHO_NTRAFFIC)) {
	Wprintf(WPDialog,"%sWARNING: Into get_from_net with min=%d, and len=%d\n", bol_char, min, len);
    }
    begin = buff;
    while (buff - begin < min) {
	FD_ZERO(&rfds);
	FD_SET(iop->socket, &rfds);
	tv = otv;
	sel_status = select(iop->socket+1, &rfds, 0, 0, &tv);
	if ( sel_status < 0 ) {
	    perror("Error doing select");
	    EXIT(2);
	}
	if (sel_status == 0) return -1;		/* timed out */
	if (debug_level&DBG_SHO_NTRAFFIC) Wprintf(WPDialog,"Waiting to read from net %d bytes...\n",
    			len);
	got = ascleapio_read(iop, (char *)buff, len);
	if ( got < 0 ) {
	    perror("AscleapIO");
	    EXIT(EXIT_ERROR);		/* done */
	} else if ( got == 0 ) {
	    Wprintf(WPDialog,"\nEOF from far end. Probably need to reset the ASCLEAP\n");
	    EXIT(EXIT_ERROR);		/* done */
	} 
	buff += got;
	len -= got;
    }
    got = buff - begin;
    if ((debug_level&(DBG_SHO_NTRAFFIC|DBG_SHO_INETPKT))) {
	char msg[30];
	sprintf(msg, "buf[0-%d]", got-1);
	Wprintf(WPDialog, "Received %d bytes from network\n", got);
	if ((debug_level&DBG_SHO_INETPKT) && begin) dump_buf(msg, begin, got, 1);
    }
    return got;
}

#define NET_ERRORS_TIMEOUT	1	/* timeout */
#define NET_ERRORS_OUR_OOS	2	/* we received an out of sequence packet */
#define NET_ERRORS_HIS_OOS	4	/* he received an out of sequence packet */
#define NET_ERRORS_CS		8	/* checksum error */
#define NET_ERRORS_NAK		16	/* received a nak */

static int get_iceless(AscleapIO *iop, NetState *net, int timeout) {
    unsigned char *bp;
    int blen, cs;

    net->errors = 0;				/* assume no errors */
    bp = net->buf;
    blen = net->buf_len = get_from_net(iop, bp, PKTuser+2, PKTuser+2, timeout);	/* get packet hdr */
    if (blen < 0) {
	net->errors = NET_ERRORS_TIMEOUT;
	if ((debug_level&(DBG_SHO_NTRAFFIC|DBG_SHO_INETPKT))) Wprintf(WPDialog, "Timeout receiving packet.\n");
	return -1;
    }
    net->u_len = (bp[PKTmsl]<<8) | bp[PKTlsl];	/* get the length of user's data in packet */
    net->cmd = bp[PKTuser+PKTcmd];		/* get the command */
    if (net->u_len > 2) {		/* get rest of packet */
	blen = get_from_net(iop, bp+net->buf_len, net->u_len-2, net->u_len-2, timeout);
	if (blen != net->u_len-2) {
	    if ((debug_level&(DBG_SHO_NTRAFFIC|DBG_SHO_INETPKT))) Wprintf(WPDialog, "Timeout receiving packet.\n");
	    net->errors = NET_ERRORS_TIMEOUT;
	    return -1;
	}
	net->buf_len += blen;
    }
    if (net->cmd == ICEnak) {
	net->reason = bp[PKTuser+4];		/* reason is byte after seq+cmd+cs0+cs1 */
    	if (net->reason == MOLE_ERR_OOS) {
	    net->expected_seq = bp[PKTuser+PKTpktn];	/* remember what he expected */
	    net->errors = NET_ERRORS_NAK|NET_ERRORS_HIS_OOS;
	    return -1;					/* and the rest of the packet is ignored */
	}
    }
    if (bp[PKTuser+PKTpktn] != net->seq) {
	net->errors = NET_ERRORS_NAK|NET_ERRORS_OUR_OOS;
	if ((debug_level&(DBG_SHO_NTRAFFIC|DBG_SHO_INETPKT))) {
	     Wprintf(WPDialog, "Received out of sequence packet. Expected 0x%02X, got 0x%02X\n",
	       net->seq, bp[PKTuser+PKTpktn]);
	}
	return -1;					/* ignore incoming packet */
    }
    ++net->seq;				/* next packet should be this one */
    if (net->u_len >= 4) {		/* we have a checksum to handle */
	int ii;
	bp = net->buf + PKTuser+4;
	net->u_data = bp;
	net->u_len -= 4;
	cs = 0;
	for (ii=0; ii < net->u_len; ++ii) cs += *bp++;
	bp = net->buf + PKTuser+2;
	if (((cs>>8)&0xff) != bp[0] || (cs&0xff) != bp[1]) {
	    net->errors = NET_ERRORS_CS;
	    Wprintf(WPDialog, "%sChecksum error on incoming packet\n", bol_char);
	    return -1;
	}
    } else {
	net->u_len -= 2;		/* remove the packet number and command byte */
	net->u_data = net->buf + PKTuser+2;
    }
    if (net->cmd == ICEnak) {			/* received a NAK packet */
	if ((debug_level&(DBG_SHO_NTRAFFIC|DBG_SHO_INETPKT))) {
	    Wprintf(WPDialog, "Received ICEnak. Reason code=%d", net->u_data[0]);
	    if (net->u_len > 1) {
		Wprintf(WPDialog, ", Message from target (%d bytes):\n", net->u_len-1);
		if (net->u_data) dump_buf(0, net->u_data+1, net->u_len-1, 3);
	    } else {
		Wprintf(WPDialog, "\n");
	    }
	}
	net->errors = NET_ERRORS_NAK;
	return -1;
    }
    return net->u_len;			/* return number of user data bytes */
}

#if 0
static int get_data(AscleapIO *iop, NetState *net, unsigned char *buff, int amt, int timeout) {
    int len;
    unsigned char *bp;

    bp = buff;
    while (amt > 0) {
	len = get_iceless(iop, net, timeout);
	if (len <= 0) break;
	memcpy((char *)bp, net->u_data, len);
	bp += len;
	amt -= len;
    }
    return bp - buff;
}

static int write_data(AscleapIO *iop, NetState *net, unsigned char *buff, int amt, int timeout) {
    int len;
    unsigned char *bp;

    bp = buff;
    while (amt > 0) {
	len = get_iceless(iop, net, timeout);
	if (len <= 0) break;
	memcpy((char *)bp, net->u_data, len);
	bp += len;
	amt -= len;
    }
    return bp - buff;
}
#endif

void sleep100(int ticks) {		/* sleep n 10 millisecond ticks */
   struct timeval tv;
   unsigned long usec = ticks*10000;
   if (usec >= 1000000) {
      tv.tv_sec = usec/1000000;		/* SGI's won't let one have both secs and usecs non-zero */
      tv.tv_usec = 0;
   } else {
      tv.tv_usec = usec;
      tv.tv_sec = 0;
   }
   select(0, 0, 0, 0, &tv);		/* pause for the specified period of time */
}

#if !defined(WIN32)
static char *help_msgs[] = {
/*  00000000001111111111222222222233333333334444444444555555555566666666667777777777
    01234567890123456789012345678901234567890123456789012345678901234567890123456789 */
   "Usage: hddnl [-b n] [-C n] -c file [-d n] [-D n] [-h host] [-m n] [-M n] \\\n"
   "             [-p n] [-r n] [-R n] [-t n] [-T n] [-Tm n] [-z n] [-Z n] \\\n"
   "             [-fFiIlnNux?] [-la] [-ld] [-lr] [-lf] [pattern...]\n",
   "  where:\n",
   "       []'s represent optional parameters. Whitespace between any option\n",
   "       character and its argument is optional (except for -la, -lr, -ld and\n",
   "       -Tm). Whitespace is shown in this list for clarity. (i.e. '-cfile' is\n",
   "       equivalent to '-c file'). Options may appear on the command line in\n",
   "       any order but all options must appear before any patterns.\n\n",
   "       -c cmd_file = name of command file. Expects a string argument.\n",
   "       -C n = sets the default number of file copies to place on game\n",
   "              disk. The default number of copies is 1 if not specified\n",
   "              otherwise. A value for COPIES set in the DEFAULT or FILE\n",
   "              command in the command file overrides the value set with\n",
   "              this option.\n",
   "       -d define_file = name of file where #define FID's are placed.\n",
   "              (Not implemented; accepted and ignored.)\n",
   "       -f = force update of all files matching pattern.\n",
   "       -F = Initialize the volume. This also sets -f.\n",
   "       -h host = name of ASCLEAP host to which to connect. Expects a string\n",
   "             argument. (Defaults to value of environment variable ASCHOST).\n",
   "       -i = delete files on the game disk that have no entry in the command\n",
   "              file. At this time, does not delete empty directories.\n",
   "       -I = copy files if date on source disk is different than one on\n",
   "              destination. The default is to only copy source files whose\n",
   "              date is younger (newer) than that on the destination disk.\n",
   "       -l = lists the name of each file on the game disk.\n",
   "              (No command file is required when using this option.)\n",
   "       -la = lists everything about each file on the game disk.\n",
   "              **** NOTE: The the option is '-la' with no spaces ***\n",
   "              The fields are listed in the following order:\n",
   "              File ID, # of retrevial pointers, # of copies, file allocation\n",
   "              in sectors, file size in bytes, default allocation in sectors,\n",
   "              creation date, modification date and pathname. Directories are\n",
   "              listed with a trailing '/' character.\n",
   "              (No command file is required when using this option.)\n",
   "       -ld = lists, in order, the # of copies, size, modification date and\n",
   "              name of each file on the game disk.\n",
   "              *** NOTE: The the option is '-ld' with no spaces *** \n",
   "              (No command file is required when using this option.)\n",
   "       -lr = lists, in order, the File ID, # of retrieval pointers, # of\n",
   "              copies, the first retrevial pointer (listed as start-end) of\n",
   "              each copy and the filename of each file on the game disk.\n",
   "              *** NOTE: The the option is '-lr' with no spaces *** \n",
   "              (No command file is required when using this option.)\n",
   "       -lf = lists the files in a syntax suitable for use as an input\n",
   "              command file to hddnl (with some minor editing).\n",
   "              *** NOTE: The the option is '-lf' with no spaces *** \n",
   "              (No command file is required when using this option.)\n",
   "       -lp = lists the partition table on the game disk.\n",
   "              (No command file is required when using this option.)\n",
   "       -Tm n = sets the timeout in seconds for the mount to complete.\n",
   "              The default is 15 seconds, but with thousands of files\n",
   "              on some of the newer drives (spelled _s_l_o_w_), it may\n",
   "              take more than 15 seconds to complete the mount.\n",
   "              *** NOTE: The the option is '-Tm' with no spaces between\n",
   "                  then 'T' and the 'm'. A space may be appear between the\n",
   "                  'm' and the number (n), however. *** \n",
   "       -u = upload files (as specified in the command file) from the\n",
   "              target's disk.\n",
   "       -v = verify all the checksums, update files as appropriate and\n",
   "            update the checksums file.\n",
   "       -V = verify all the checksums but don't update any files.\n",
   "       -? = this message.\n",
   "       -z num = compress files larger than 'num' bytes before sending.\n",
   "            0=don't compress any files. This is the default.\n",
   "            Append k or K for *1024 bytes or m or M for *1024*1024.\n",
   "            I.E. -z1m to compress files over 1megabyte.\n",
   "       -Z num = compression factor in a range between 1 through 7. Smaller\n",
   "            numbers have lower compression rates but are faster.\n",
   "            The default of 1 is probably best when using ethernet.\n\n",
   "       'Pattern' is a simple string. A match occurs if the pattern appears\n",
   "       _anywhere_ in the game's path/filename. At this time, the pattern is\n",
   "       _not_ interpreted as a regular expression. Only files matching the\n",
   "       pattern are processed. If no pattern is provided, all files listed\n",
   "       in the command file are processed.\n\n",
   "  The following options are for debugging and special uses. Care should be\n",
   "  taken when using them:\n",
   "       -b board = ICELESS board number to use (0-3, default=1).\n",
   "       -D level = sets debug level. Logical 'or' of: (Default=0).\n",
   "                0x01 - report details on command file processing.\n",
   "                0x02 - show network packet traffic.\n",
   "                0x04 - show incoming network packets.\n",
   "                0x08 - show outgoing network packets.\n",
   "                0x10 - show outgoing network commands.\n",
   "       -m num = sets maximum number of bytes in a single ICELESS packet.\n",
   "                 (Default is 500. The maximum is 1440).\n",
   "       -M num = sets maximum number of packets sent before expecting an\n",
   "                ACK/NAK. (Default is 10; The maximum is 20).\n",
   "       -n = Do not reset target before issuing a volume initialize.\n",
   "       -N = Do not mount the volume.\n",
   "       -p port = TCP port number to use (default=230).\n",
   "       -r port = PATNET port to use (0-1, Default=1).\n",
   "       -R rate = Probe rate in milliseconds (Default=200).\n",
   "       -t thread = sets thread number to use (Default=2).\n",
   "       -T timeout = sets packet timeout in milliseconds (Default=10000).\n",
   "       -x = Just say what would happen without actually doing it.\n\n",
   "  Look in http://iweb.agames.com/software/doc/hddnl for details on the\n",
   "  format of the command file.\n",
   0
};

static int help_him(int msg) {
   char **p;
   p = help_msgs;
   Wputs(*p++, WPDialog);
   if (msg) {
      while (*p) Wputs(*p++, WPDialog);
   }
   return 0;
}
#endif

static int send_to_asap(AscleapIO *iop, int cmd, NetState *net) {
   int ii;
   char buf[PKTuser+5];
   buf[PKTmsl] = 0;		/* msb of length */
   buf[PKTto]  = 0;		/* to the ASAP itself */
   buf[PKTtothrd] = 0;		/* not significant here */
   buf[PKTfrom] = 0;		/* placeholder */
   buf[PKTfromthrd] = net->thread; /* us */
   buf[PKTuser+0] = net->seq;	/* packet number */
   buf[PKTuser+1] = cmd;	/* command */
   buf[PKTuser+2] = net->patnet; /* patnet port (0/1) */
   buf[PKTuser+3] = net->board;	/* ICELESS board (0-3) */
   buf[PKTuser+4] = net->thread; /* to thread */
   buf[PKTlsl] = 5;		/* five bytes of data */
   if (debug_level&DBG_SHO_NTRAFFIC) Wprintf(WPDialog,"Writing %d bytes...\n", PKTuser+5);
   ii = ascleapio_write(iop, buf, PKTuser+5);
   if (debug_level&DBG_SHO_ONETPKT) PrintPacket((unsigned char *)buf, PKTuser+5);
   return ii;
}

static int sync_up(AscleapIO *iop, NetState *net) {
    int ii, jj, got;

    jj = debug_level;
    debug_level &= ~(DBG_SHO_NTRAFFIC|DBG_SHO_INETPKT);
    while (get_iceless(iop, net, 50) > 0) { ; }		/* flush any "typeahead" */
    debug_level = jj;
    for (jj=0; jj < 4; ++jj) {
	got = 0;
	if ((jj&3) == 0) {
	    if (jj > 0) printf("\n");
	    if (!quiet) Wprintf(WPDialog, "Probing %s .", net->host);
	    fflush(stdout);
	} else {
	    if (!quiet) Wprintf(WPDialog, ".");
	    fflush(stdout);
	}
	ii = put_iceless(iop, net, 0, 0, MOLE_RESYNC);
	if (ii <= 0) {
	    Wprintf(WPDialog, "\nCouldn't complete probe(). Giving up...\n");
	    exit (EXIT_ERROR);
	}
	while (1) {
	    ii = get_iceless(iop, net, got ? 100 : 2000);
	    if (ii == 0 && net->cmd == ICEack) {
		++got;
		continue;
	    }
	    break;
	}
	if (got) break;
    }
    if (!got) {
	Wprintf(WPDialog, "\nCouldn't connect to HDDNL program. Giving up...\n");
	exit (EXIT_ERROR);
    }
    if (!quiet) printf("%s", eol_char);
    return 0;
}

static AscleapIO *open_connection(NetState *net, int probe) {
   int ii;
   AscleapIO *iop;

   if (debug_level&DBG_SHO_NTRAFFIC) Wprintf(WPDialog, "Attempting to open %s:%d\n", net->host, net->port);
   iop = ascleapio_open(net->host, net->port, 0);		/* open a TCP connection */
   if (iop == 0) {
      if (errno != 0) {
	 Wperror("Error opening connection");
      }
      exit (EXIT_ERROR);
   }

   if (net->port == ASC_PORT) {
       net->to = 0;
       net->from = 0;
       if (debug_level&DBG_SHO_NTRAFFIC) Wprintf(WPDialog, "Sending command ICEopenp(%d)\n", ICEopenp);
       send_to_asap(iop, ICEopenp, net);
       if (debug_level&DBG_SHO_NTRAFFIC) Wprintf(WPDialog, "Waiting for reply...\n");
       ii = get_iceless(iop, net, 100);
       if (ii != 1) {
	    Wprintf(WPDialog, "%sUnexpected %d byte response from %s\n", bol_char, net->u_len, net->host);
	    if (net->u_data) dump_buf(0, net->u_data+1, net->u_len-1, 3);
	    exit (EXIT_ERROR);
       }
       if ((debug_level&(DBG_SHO_NTRAFFIC|DBG_SHO_INETPKT))) {
	  Wprintf(WPDialog, "Received %d bytes.\n", ii);
	  if ((debug_level&DBG_SHO_INETPKT)) PrintPacket(net->buf, ii);
       }

       net->from = net->buf[PKTto];
       net->to = *net->u_data;
       if (probe) sync_up(iop, net);
   }
   return iop;
}

static int process_reply(AscleapIO *iop, NetState *net, const char *txt, int ok) {
    int ii;
    if (net->port != ASC_PORT) return 0;		/* assume success */
    ii = get_iceless(iop, net, g_timeout);
    if (ii < 0 || (net->cmd != ICEack && net->cmd != ICEreply)) {
	if (net->cmd == ICEnak && ok && net->u_data[0] == ok) return 1; /* quietly accept this error */
	if (while_processing) {
	    Wprintf(WPDialog, "%sError %s \"%s\".\n", bol_char, txt, while_processing);
	    while_processing = 0;
	} else {
	    Wprintf(WPDialog, "%sError %s.\n", bol_char, txt);
	}
	if (net->cmd == ICEnak) {
	    Wprintf(WPDialog, " Reason code=%d", net->u_data[0]);
	} else if (ii < 0) {
	    Wprintf(WPDialog, " Timeout waiting for reply.");
	}
	if (net->cmd == ICEnak && net->u_len > 1) {
	    Wprintf(WPDialog, ", Message from target (%d bytes):\n", net->u_len-1);
	    if (net->u_data) dump_buf(0, net->u_data+1, net->u_len-1, 3);
	} else {
	    Wprintf(WPDialog, "\n");
	}
	return 1;
    }
    return 0;
}

static int do_cmd(AscleapIO *iop, NetState *net, const char *txt, int cmd, unsigned char *cmd_buf, int buf_len, int ok) {
    int ii;
    if ((debug_level&DBG_SHO_ONETCMD)) Wprintf(WPDialog, "Doing %s...\n", txt);
    ii = put_iceless(iop, net, cmd_buf, buf_len, cmd);	/* issue the command */
    if (ii <= 0) {
	Wprintf(WPDialog, "%sCouldn't complete %s. Giving up...\n", bol_char, txt);
	exit (EXIT_ERROR);
    }
    return process_reply(iop, net, txt, ok);
}

typedef struct pkt_lst {
    unsigned char buf[MAX_PKT_SIZE-4];
    int cmd;
    int amt;
    int seq;
} PacketList;

static int retry_packet(int cnt, PacketList *packet_list, AscleapIO *iop, NetState *ns) {
    int ii, retry;
    PacketList *pl;
    int got_oos=0;

    if (ns->port != ASC_PORT) return 0;			/* perfect */
    for (retry=0; retry < 4; ++retry) {
	ii = get_iceless(iop, ns, got_oos ? 500 : g_timeout); /* get something */
	if (ii >= 0) {
	    if (ns->cmd == ICEack) return 0;			/* perfect */
	    Wprintf(WPDialog, "%sUnexpected reply: %d bytes, cmd=%d\n", bol_char, ns->u_len, ns->cmd);
	    if (ns->u_data) dump_buf(0, ns->u_data+1, ns->u_len-1, 3);
	    return 1;
	}
	if ((ns->errors&NET_ERRORS_TIMEOUT) && !got_oos) { /* timeout. probe to see what last good packet was */
#if 0
printf("Retry probe %d\n", retry);
#endif
	    if (put_iceless(iop, ns, 0, 0, MOLE_NOP) < 0) {
		Wprintf(WPDialog, "%sError probing\n", bol_char);
		return 1;
	    }
	    continue;
	}
	if (!(ns->errors&(NET_ERRORS_HIS_OOS|NET_ERRORS_TIMEOUT))) { /* other than sequence error, we give up and die */
	    Wprintf(WPDialog, "%sMessage from remote host: %d bytes, cmd=%d, reason=%d\n", bol_char,
		ns->u_len, ns->cmd, ns->reason);
	    if (ns->u_data) dump_buf(0, ns->u_data+1, ns->u_len-1, 3);
	    return 1;
	}
	if ((ns->errors&NET_ERRORS_HIS_OOS)) {
	    got_oos = ns->expected_seq+1;	/* just eat all oos packets */
	    --retry;				/* oos packet doesn't count against retry */
	    continue;
	}
	--got_oos;
	for (ii=0; ii < cnt; ++ii) {
	    pl = packet_list + ii;
	    if (pl->seq == got_oos) {		/* find the packet that got dismissed */
		int jj;
printf("%sRetry after dropping %d packets.\n", bol_char, cnt-ii);
		for (jj=ii; jj < cnt; ++jj, ++pl) {
		    ns->seq = pl->seq;		/* reset the sender's sequence number */
		    if (put_iceless(iop, ns, pl->buf, pl->amt, pl->cmd) < 0) {	/* resend the packet */
			Wprintf(WPDialog, "%sError re-sending data packet\n", bol_char);
			return 1;
		    }
		}
		break;
	    }
	}
	if (ii >= cnt) {
	    Wprintf(WPDialog, "%sInternal error in retry_packet. Couldn't find packet to send.\n", bol_char);
	    break;
	}
    }
    return 1;
}

static void print_mkb(const char *prefix, int amt, const char *suffix, int scale) {
    char c;
    float famt;

    if (amt < 1024/scale) {
	printf("%s%5d B%s", prefix, amt*scale, suffix);
	return;
    }
    if (amt < 995*1024/scale) {
	famt = (float)amt/(1024.0/scale);
	c = 'K';
    } else if (amt < 995*1024*1024/scale) {
	famt = (float)amt/(1024.0*1024.0/scale);
	c = 'M';
    } else {
	famt = (float)amt/(1024.0*1024.0*1024.0/scale);
	c = 'G';
    }
    printf("%s%5.1f%cB%s", prefix, famt, c, suffix);
    return;
}

typedef struct file_stats {
    time_t mtime;
    long blks;
    long size;
    int use_it;
    ParseUnion *parse;
} FileStats;

static ParseUnion *volume_details, *chksum_details;
static ParseFile *delete_details;
static FileStats *stats_head;
static int stats_size=0, stats_next=0;
typedef struct lcl_partition {
    unsigned long start_lba;
    unsigned long num_lbas;
    int status;
    int type;
    int line;
} MolePartitions;

static MolePartitions partitions[4];

static int get_command_file(const char *command_file, int argc, char *argv[], int force) {
    int ii, jj, tot_alloc=0;
    FILE *cmd_ifp;
    char emsg[132];
    ParseUnion *ans;
    FileStats *st;

    cmd_ifp = fopen(command_file, "r");
    if (!cmd_ifp) {
	sprintf(emsg, "Error opening %s for input", command_file);
	perror(emsg);
	return 1;
    }

    while ((ii = parse_it(cmd_ifp, &ans)) >= 0) {
	if (ii >= 0) {
	    struct stat stat_str;
	    if (stats_next >= stats_size) {
		stats_size += 500;
		stats_head = (FileStats *)realloc(stats_head, stats_size*sizeof(FileStats));
		if (!stats_head) {
		    Wprintf(WPDialog, "%s:%d Ran out of memory malloc'ing for stats_head\n", image_name, input_line_no);
		    EXIT(1);
		}
	    }
	    st = stats_head + stats_next;
	    memset((char *)st, 0, sizeof(FileStats));
	    if (ans->type == PARSE_TYPE_PART) {
		MolePartitions *mpi;
		int jj;
		jj = ans->p.index;
		if (jj > 3) {
		    Wprintf(WPDialog, "%s:%d Only primary partitions 0-3 are allowed\n", image_name, input_line_no);
		    ++parse_errors;
		    continue;
		}
		mpi = partitions + jj;
		if (mpi->line) {	/* we've already set this partition */
		    Wprintf(WPDialog, "%s:%d Already set partition %d at line %d\n",
			image_name, input_line_no, jj, mpi->line);
		    ++parse_errors;
		} else {
		    if (ans->p.ptype) {
			mpi->type = ans->p.ptype;
			mpi->status = ans->p.status;
			mpi->start_lba = ans->p.start_lba;
			mpi->num_lbas = ans->p.num_lbas;
		    }
		    mpi->line = input_line_no;
		}
		continue;
	    }
	    if (ans->type == PARSE_TYPE_VOL) {
		if (!volume_details) {
		    volume_details = ans;
		} else {
		    Wprintf(WPDialog, "%s:%d More than one VOLUME command present\n", image_name, input_line_no);
		    ++parse_errors;
		}
		continue;
	    }
	    if (ans->type == PARSE_TYPE_CS) {
		if (!chksum_details) {
		    chksum_details = ans;
		} else {
		    Wprintf(WPDialog, "%s:%d More than one CHECKSUM command present\n", image_name, input_line_no);
		    ++parse_errors;
		}
		continue;
	    }
	    if (ans->type == PARSE_TYPE_DEL) {
		ParseFile *next, **prev;
		prev = &delete_details;
		while ((next = *prev)) {
		    prev = &next->next;
		}
		ans->f.next = 0;
		*prev = &ans->f;
		continue;
	    }
	    if (ans->type == PARSE_TYPE_DEL || ans->type == PARSE_TYPE_EOF ) {
		free(ans);
		continue;
	    }
	    if (argc) {
		for (jj=0; jj < argc; ++jj) {
		    char *s, *av;
#if 0
		    int sl;
#endif
		    av = argv[jj];
		    s = strstr(ans->f.unix_name, av);
		    if (!s) continue;
#if 0
		    sl = strlen(av);
		    if (*av != '/' && s > av && s[-1] != '/') continue;
		    if (av[sl-1] != '/' && s[sl] && s[sl] != '/') continue;
#endif
		    if ((debug_level&DBG_SHO_CMD)) {
			printf("%s on %s\n",
				force == 1 ? "Will check for update" : "Forcing update",
				ans->f.game_name);
		    }
		    st->use_it = force >= 0 ? force : 1;
		}
	    } else {
		st->use_it = force >= 0 ? force : 1;
	    }
	    if (st->use_it) {
		ii = stat(ans->f.unix_name, &stat_str);
		if (ii >= 0) {
		    st->mtime = stat_str.st_mtime;
		    st->blks = stat_str.st_blocks;
		    st->size = stat_str.st_size;
		    if (ans->f.alloc < st->size) ans->f.alloc = st->size;
		    tot_alloc += st->blks;
		    if (!ans->f.copies) ans->f.copies = 1;
		    if ((debug_level&DBG_SHO_CMD)) {
			printf("Stat %4d: %s\n      blocks=%5ld, size=%9ld, copies=%d, time=%s", input_line_no, ans->f.unix_name,
				st->blks, st->size, ans->f.copies, ctime(&st->mtime));
		    }
		} else {
		    if (force >= 0) {
			char emsg[132];
			sprintf(emsg, "%s:%d Unable to stat %s", image_name, input_line_no, ans->f.unix_name);
			perror(emsg);
#if 0						/* no such file is not an error */
			++parse_errors;
#endif
			continue;
		    } 
		    st->mtime = 0;
		    st->blks = 0;
		    st->size = 0;
		} 
	    }
	    ++stats_next;
	    st->parse = ans;
	}
    }
    fclose(cmd_ifp);
    if (parse_errors) {
	fprintf(stderr, "%s:%d Due to %d parse errors, no action taken\n", image_name, input_line_no, parse_errors);
	return 1;
    }
    if (!quiet && force >= 0) {
	printf("A total of %3d files and %d sectors ", stats_next, tot_alloc);
	print_mkb("(", tot_alloc, ")\n", 512);
    }
    return 0;
}

static int do_x_commands(AscleapIO *iop, int x_commands) {
    if ((x_commands&X_SEND_PKTS)) {
	int ackcnt;
	ackcnt = 0;
	while (1) {
	    unsigned char a;
	    unsigned char tbuf[MAX_PKT_SIZE-4];
	    int ii;
	    for (a=cmd_ice.seq, ii=0; ii < sizeof(tbuf); ++ii) {
		tbuf[ii] = a++;
	    }
	    if (ackcnt < 9) {
		if (put_iceless(iop, &cmd_ice, tbuf, sizeof(tbuf), MOLE_RTEST) <= 0) {
		    Wprintf(WPDialog, "%sCouldn't complete rtest(). Giving up...\n", bol_char);
		    EXIT(EXIT_ERROR);
		}
		++ackcnt;
		++cmd_ice.seq;
	    } else {		
		ackcnt = 0;
		if (do_cmd(iop, &cmd_ice, "issuing rtest()", MOLE_RTESTack, tbuf, sizeof(tbuf), 0)) {
		    EXIT(EXIT_ERROR);
		}
	    }
	}
    }
    if ((x_commands&X_MKFILE)) {
	MoleMkFileExt *mk;
	char *ptr, *name;
	time_t t;
	int tmp, cookie, ii;

	name = "/d0/Fred/Foo/GoodNight/Mrs/Kalabash/Wherever/You/Are/testing_1_2_3";
	while_processing = name;
	tmp = strlen(name);
	mk = (MoleMkFileExt *)calloc(1, sizeof(MoleMkFileExt)+tmp+1);
	mk->fname = sizeof(MoleMkFileExt);
	ptr = (char *)(mk+1);
	strcpy(ptr, name);
	ptr += tmp+1;
	tmp = 10000*512;
	mk->alloc[0] = tmp >> (3*8);
	mk->alloc[1] = tmp >> (2*8);
	mk->alloc[2] = tmp >> (1*8);
	mk->alloc[3] = tmp >> (0*8);
	tmp /= 512;
	mk->def_extend[0] = tmp >> (1*8);
	mk->def_extend[1] = tmp >> (0*8);
	tmp = MOLE_O_WRONLY | MOLE_O_CREAT | MOLE_O_TRUNC;
	mk->mode[0] = tmp >> (3*8);
	mk->mode[1] = tmp >> (2*8);
	mk->mode[2] = tmp >> (1*8);
	mk->mode[3] = tmp >> (0*8);
	mk->copies = 1;
	t = time(0);
	mk->ctime[0] = t >> (3*8);
	mk->ctime[1] = t >> (2*8);
	mk->ctime[2] = t >> (1*8);
	mk->ctime[3] = t >> (0*8);
	if (do_cmd(iop, &cmd_ice, "open()'ing file", MOLE_OPENFILE, (unsigned char *)mk, ptr-(char *)mk, 0)) {
	    EXIT(EXIT_ERROR);
	}
	mk = (MoleMkFileExt *)cmd_ice.u_data;
	cookie = (mk->cookie[0] << (3*8)) | 
	    	 (mk->cookie[1] << (2*8)) | 
	    	 (mk->cookie[2] << (1*8)) | 
	    	 (mk->cookie[3] << (0*8));
	printf("Open returned %d bytes: fid = %08X, parent = %08X, cookie = %08X\n",
	    cmd_ice.u_len,
	    mk->fid[0] << (3*8) | 
	    mk->fid[1] << (2*8) | 
	    mk->fid[2] << (1*8) | 
	    mk->fid[3] << (0*8),
	    mk->parent[0] << (3*8) | 
	    mk->parent[1] << (2*8) | 
	    mk->parent[2] << (1*8) | 
	    mk->parent[3] << (0*8),
	    cookie);
	
	for (ii=0; ii < 8000 ; ++ii) {
	    unsigned char tbuf[500];
	    int sts;
	    tbuf[0] = cookie >> (3*8);
	    tbuf[1] = cookie >> (2*8);
	    tbuf[2] = cookie >> (1*8);
	    tbuf[3] = cookie >> (0*8);
	    sts = ascleapio_rdchk(iop);
	    if (sts) {
		sts = ascleapio_rdchk(iop);
		if (sts < 0) {
		    fprintf(stderr, "rdchk returned %d\n", sts);
		    break;
		}
		if (sts > 0) {
		    process_reply(iop, &cmd_ice, "write()'ing file", 0);
		    break;
		}
	    }
	    if (put_iceless(iop, &cmd_ice, tbuf, sizeof(tbuf), MOLE_WRFILE) <= 0) {
		EXIT(EXIT_ERROR);
	    }
	    ++cmd_ice.seq;
	}
	    
	ptr = (char *)cmd_ice.u_data;
	ptr[0] = cookie >> (3*8);
	ptr[1] = cookie >> (2*8);
	ptr[2] = cookie >> (1*8);
	ptr[3] = cookie >> (0*8);
	if (do_cmd(iop, &cmd_ice, "close()'ing file", MOLE_CLOSE, (unsigned char *)ptr, 4, 0)) {
	    EXIT(EXIT_ERROR);
	}
	free(mk);
    }
    return 0;
}

typedef struct fdir {
    unsigned long fid;		/* file ID */
    char *name;			/* filename */
} FDir;

typedef struct retp {
    unsigned int start;
    unsigned int nblocks;
} RetPtr;

typedef struct fheader {
    unsigned long fid;		/* file ID */
    int type;			/* file type (0=invalid, 1=plain, 2=directory) */
    int used;			/* .ne. if file has been referenced in command file */
    int alloc;			/* allocation in sectors */
    int size;			/* size in bytes */
    time_t ctime;		/* creation time */
    time_t mtime;		/* modification time */
    time_t atime;		/* access time */
    time_t btime;		/* backup time */
    int perms;			/* permissions */
    int owner;			/* owner */
    int copies;			/* number of copies */
    int nrps;			/* number of retrieval pointers */
    int defext;			/* default allocation in sectors */
    RetPtr rptr[FSYS_MAX_ALTS];	/* list of retrieval pointers */
    FDir *directory;		/* pointer to directory listing */
    int num_dirs;		/* number of entries in directory */
} FHeader;

static FHeader *remote_fhs;
static int remote_fhs_size;
static FDir empty_fd;

#define HDDNL_DIR_CMDFILE 0x40000000

static int do_get_dir(AscleapIO *iop, int *flags) {
    MoleMkFileExt *mk;
    int tmp, cookie, ii, len;
    PacketList packet_list, *pl;
    unsigned char cbuf[4];
    FHeader *fh;

    if (!quiet) {
	if (need_erase) printf(erase);
	Wprintf(WPDialog, "Getting directory from game disk ...%s", eol_char);
    }
    mk = (MoleMkFileExt *)calloc(1, sizeof(MoleMkFileExt)+128);
    tmp = MOLE_O_FHBITS;
    mk->mode[0] = tmp >> (3*8);
    mk->mode[1] = tmp >> (2*8);
    mk->mode[2] = tmp >> (1*8);
    mk->mode[3] = tmp >> (0*8);
    tmp = HDDNL_GETFH_DIR;
    if (*flags == 2) {
	tmp |=  HDDNL_GETFH_SIZE |
		HDDNL_GETFH_COPIES|
		HDDNL_GETFH_MTIME;
    } else if (*flags == 3 ) {
	tmp |=  HDDNL_GETFH_ALLOC |
		HDDNL_GETFH_SIZE  |
		HDDNL_GETFH_CTIME | 
		HDDNL_GETFH_MTIME | 
		HDDNL_GETFH_ATIME | 
		HDDNL_GETFH_BTIME | 
		HDDNL_GETFH_PERMS | 
		HDDNL_GETFH_OWNER | 
		HDDNL_GETFH_NRPS  |
		HDDNL_GETFH_COPIES| 
		HDDNL_GETFH_DEFEXT;
    } else if (*flags == 4) {
	tmp |=	HDDNL_GETFH_COPIES |
    		HDDNL_GETFH_NRPS   |
    		HDDNL_GETFH_FIRSTRP;
    } else if (*flags == 5) {
	tmp |=	HDDNL_GETFH_COPIES;
    }
    mk->hddnlfhbits[0] = tmp >> (3*8);
    mk->hddnlfhbits[1] = tmp >> (2*8);
    mk->hddnlfhbits[2] = tmp >> (1*8);
    mk->hddnlfhbits[3] = tmp >> (0*8);
    mk->fname = sizeof(MoleMkFileExt);
    strcpy((char *)(mk+1), "/d0/.");
    while_processing = "/d0/.";
    if (do_cmd(iop, &cmd_ice, "open()'ing root directory", MOLE_OPENFILE, (unsigned char *)mk, sizeof(MoleMkFileExt)+6, 0)) {
	EXIT(EXIT_ERROR);
    }
    free(mk);
    mk = (MoleMkFileExt *)cmd_ice.u_data;
    cookie = (mk->cookie[0] << (3*8)) | 
	     (mk->cookie[1] << (2*8)) | 
	     (mk->cookie[2] << (1*8)) | 
	     (mk->cookie[3] << (0*8));
    ii = (mk->mode[0] << (3*8)) |
	 (mk->mode[1] << (2*8)) |
	 (mk->mode[2] << (1*8)) |
	 (mk->mode[3] << (0*8));
    tmp = (mk->hddnlfhbits[0] << (3*8)) | 
	  (mk->hddnlfhbits[1] << (2*8)) | 
	  (mk->hddnlfhbits[2] << (1*8)) | 
	  (mk->hddnlfhbits[3] << (0*8));
    if ((debug_level&DBG_SHO_CMD)) {
	printf("Directory open returned %d bytes: mode = %08X, fhbits = %08X, cookie = %08X\n",
	    cmd_ice.u_len, ii, tmp, cookie);
    }
    if (!(ii&MOLE_O_FHBITS_OK)) {
	*flags = 0;
    } else {
	unsigned char *dst, *src, *beg, *lim;
	int done=0;
	int old_npkt, old_mpkt;
	
	old_npkt = max_numb_packets;
	old_mpkt = max_packet_size;
	max_numb_packets = 10;
	max_packet_size = 500;

	if (*flags == 5) {
	    *flags = tmp | HDDNL_DIR_CMDFILE;
	} else {
	    *flags = tmp;
	}
	pl = &packet_list;
	beg = dst = calloc(10240,1);
	lim = beg + 10240;
	if (!dst) {
	    printf("%sCould not calloc %d bytes\n", bol_char, 10240);
	    EXIT(EXIT_ERROR);
	} 
	while_processing = "Directory tree";
	while (!done) {
	    int max;

	    max = (max_numb_packets*(max_packet_size-4))&-512;
	    pl->seq = cmd_ice.seq;
	    pl->buf[ 0] = cookie >> (3*8);
	    pl->buf[ 1] = cookie >> (2*8);
	    pl->buf[ 2] = cookie >> (1*8);
	    pl->buf[ 3] = cookie >> (0*8);
	    pl->buf[ 4] = max >> (3*8);
	    pl->buf[ 5] = max >> (2*8);
	    pl->buf[ 6] = max >> (1*8);
	    pl->buf[ 7] = max >> (0*8);
	    pl->buf[ 8] = max_packet_size >> (3*8);
	    pl->buf[ 9] = max_packet_size >> (2*8);
	    pl->buf[10] = max_packet_size >> (1*8);
	    pl->buf[11] = max_packet_size >> (0*8);

	    if (put_iceless(iop, &cmd_ice, pl->buf, 12, MOLE_RDFILE) <= 0) {
		Wprintf(WPDialog, "%sCouldn't complete read() request. Giving up...\n", bol_char);
		EXIT(EXIT_ERROR);
	    }
	    for (ii=0; ii < max_numb_packets; ++ii) {
		if (process_reply(iop, &cmd_ice, "read()'ing file", MOLE_EOF)) {
		    if (cmd_ice.cmd == ICEnak && cmd_ice.u_data[0] == MOLE_EOF) {
			done = 1;
			break;
		    }
		    EXIT(EXIT_ERROR);
		}
		if (cmd_ice.u_len == 0) {
		    break;
		}
		if (lim-dst < cmd_ice.u_len) {
		    int l, n;
		    unsigned char *t;		    
		    l = dst-beg;
		    n = lim-beg + 10240;
		    t = realloc(beg, n);
		    if (!t) {
			Wprintf(WPDialog, "%sCouldn't realloc %d bytes.\n", bol_char, n);
			EXIT(EXIT_ERROR);
		    }
		    beg = t;
		    dst = beg+l;
		    lim = beg+n;
		}
		memcpy(dst, cmd_ice.u_data, cmd_ice.u_len);
		dst += cmd_ice.u_len;
	    }
	}
	len = dst-beg;
	src = beg;
	lim = beg+len;
	fh = 0;
	while (src < lim) {
	    int fid;
	    fid = (src[0]<<24) | (src[1]<<16) | (src[2]<<8) | src[3];
	    if (!fid) break;			/* EOF */
	    src += 4;
	    if ((ii=fh-remote_fhs) >= remote_fhs_size-1) {
		remote_fhs_size += remote_fhs_size ? 256 : 1000;
		remote_fhs = realloc(remote_fhs, remote_fhs_size*sizeof(FHeader));
		if (!remote_fhs) {
		    Wprintf(WPDialog, "%sUnable to realloc %d bytes\n", bol_char, remote_fhs_size*sizeof(FHeader));
		    EXIT(EXIT_ERROR);
		}
		fh = remote_fhs + ii;
	    }
	    fh->fid = fid;
	    fh->type = *src++;
#define GET_4(bit, dst, src) do { if ((tmp&(HDDNL_GETFH_ ##bit))) { dst = (src[0]<<24)|(src[1]<<16)|(src[2]<<8)|src[3]; src += 4; } } while (0)
#define GET_2(bit, dst, src) do { if ((tmp&(HDDNL_GETFH_ ##bit))) { dst = (src[0]<<8)|src[1]; src += 2; } } while (0)
#define GET_1(bit, dst, src) do { if ((tmp&(HDDNL_GETFH_ ##bit))) { dst = src[0]; ++src; } } while (0)
	    GET_1(NRPS, fh->nrps, src);
	    GET_1(COPIES, fh->copies, src);
	    if ((tmp&HDDNL_GETFH_FIRSTRP)) {
		int rc;
		for (rc=0; rc < fh->copies; ++rc) {
		    GET_4(FIRSTRP, fh->rptr[rc].start, src);
		    GET_4(FIRSTRP, fh->rptr[rc].nblocks, src);
		}
	    }
	    GET_4(ALLOC, fh->alloc, src);
	    GET_4(SIZE, fh->size, src);
	    GET_2(DEFEXT, fh->defext, src);
	    GET_4(CTIME, fh->ctime, src);
	    GET_4(MTIME, fh->mtime, src);
	    GET_4(ATIME, fh->atime, src);
	    GET_4(BTIME, fh->btime, src);
	    GET_4(PERMS, fh->perms, src);
	    GET_4(OWNER, fh->owner, src);
	    if ((fh->type&HDDNL_GETFH_TYPE_MASK) == HDDNL_GETFH_TYPE_DIR) { /* if directory contents follow */
		if ((tmp&HDDNL_GETFH_DIR)) {
		    FDir *fd;
		    unsigned char *tsrc;
		    int cnt;
		    tsrc = src;
		    cnt = 0;
		    while (tsrc < lim) {
			int l;
			unsigned long f;
			f = (tsrc[0]<<24) | (tsrc[1]<<16) | (tsrc[2]<<8) | tsrc[3];
			tsrc += 4;
			if (!f) break;
			l = *tsrc++;
			tsrc += l;
			++cnt;
		    }
		    fh->num_dirs = cnt+1;
		    cnt = fh->num_dirs*sizeof(FDir)+(tsrc-src)+2;
		    fh->directory = malloc(cnt);
		    if (!fh->directory) {
			Wprintf(WPDialog, "%sUnable to calloc %d bytes\n", bol_char, cnt);
			EXIT(EXIT_ERROR);
		    }
		    dst = (unsigned char *)(fh->directory+fh->num_dirs);
		    fd = fh->directory;
		    while (src < lim) {
			int l;
			unsigned long f;
			f = (src[0]<<24) | (src[1]<<16) | (src[2]<<8) | src[3];
			src += 4;
			if (!f) break;
			fd->fid = f;
			fd->name = (char *)dst;
			l = *src++;
			memcpy(dst, src, l);
			src += l;
			dst += l;
			++fd;
		    }
		    fd->fid = 0;
		    fd->name = 0;
		} else {
		    fh->directory = &empty_fd;
		}
	    }
	    ++fh;
	}
	if (fh) memset((char *)fh, 0, sizeof(FHeader));
	free(beg);
	max_numb_packets = old_npkt;
	max_packet_size = old_mpkt;
    }
    cbuf[0] = cookie >> (3*8);
    cbuf[1] = cookie >> (2*8);
    cbuf[2] = cookie >> (1*8);
    cbuf[3] = cookie >> (0*8);
    if (do_cmd(iop, &cmd_ice, "close()'ing file", MOLE_CLOSE, cbuf, 4, 0)) {
	EXIT(EXIT_ERROR);
    }
    return 0;
}

static FHeader *fg_part(FDir *dir, const char *name) {
    const char *end;
    int l;

    end = strchr(name, '/');
    if (!end) {
	l = strlen(name);
    } else {
	l = end - name;
    }
    for (; dir && dir->name; ++dir) {
	if (strncmp(dir->name, name, l) == 0 &&
            (!dir->name[l] || dir->name[l] == '/')) {
	    int fid;
	    FHeader *fh;
	    fid = dir->fid&0x00FFFFFF;
	    if (fid >= remote_fhs_size) return 0;
	    fh = remote_fhs + fid;
	    if (!fh->type) return 0;
	    name += l;
	    if (*name == 0) return fh;
	    if (*name == '/' && ((fh->type&HDDNL_GETFH_TYPE_MASK) == HDDNL_GETFH_TYPE_DIR)) {
		return fg_part(fh->directory, name+1);
	    }
	    return 0;
	}
    }
    return 0;
}

static FHeader *find_game_file(const char *name) {
    if (*name == '/') ++name;
    if (strncmp(name, "d0/", 3) == 0) name += 3;
    return fg_part(remote_fhs[2].directory, name);
}

static void print_date(time_t tim) {
    struct tm *tp;
    if (tim) {
	tp = localtime(&tim);		/* convert to localtime */
	printf("%4d/%02d/%02d:%02d:%02d:%02d ",
	    tp->tm_year+1900,
	    tp->tm_mon+1,
	    tp->tm_mday,
	    tp->tm_hour,
	    tp->tm_min,
	    tp->tm_sec);
    } else {
	printf("<none>              ");
    }
}

static int print_dirs(int fields, FDir *fd, char *prefix) {
    FHeader *fh;
    int fid, diagdir;

    diagdir = (strcmp(prefix, "diags/") == 0);
    for (;fd && fd->fid; ++fd) {
	fid = fd->fid&0x00FFFFFF;
	if (fid >= remote_fhs_size) {
	    printf("%08lX <No such file> %s%s\n", fd->fid, prefix, fd->name);
	    continue;
	} 
	fh = remote_fhs + fid;
	if (!fh->type) {
	    printf("%08lX <No such file> %s%s\n", fd->fid, prefix, fd->name);
	    continue;
	} 
	if (strcmp(fd->name, "..") == 0) continue;
	if (strcmp(fd->name, ".") == 0 && strcmp(prefix, "/d0/") != 0) continue;
	if ((fields&HDDNL_DIR_CMDFILE)) {
	    if ((fh->type&HDDNL_GETFH_TYPE_MASK) == HDDNL_GETFH_TYPE_PLAIN) {
		if ((fh->type&HDDNL_GETFH_TYPE_BOOT)) {
		    printf("BOOT%d UNIX=%s%s\n",
			(fh->type>>HDDNL_GETFH_TYPE_BOOT_V)&((1<<HDDNL_GETFH_TYPE_BOOT_B)-1),
			prefix, fd->name);
		} else {
		    if (!diagdir || strcmp(fd->name,"checksums")) {
			printf("FILE UNIX=%s%s COPIES=%d\n", prefix, fd->name, fh->copies);
		    } else {
			printf("CHECKSUM GAME=diags/checksums\n");
		    }
		}
	    }
	} else {
	    if ((fields&~(HDDNL_GETFH_DIR|HDDNL_GETFH_MTIME|HDDNL_GETFH_SIZE|HDDNL_GETFH_COPIES))) printf("%08lX ", fd->fid);
	    if ((fields&HDDNL_GETFH_PERMS)) printf("%08X", fh->perms);
	    if ((fields&HDDNL_GETFH_OWNER)) printf("%08X ", fh->owner);
	    if ((fields&HDDNL_GETFH_NRPS)) printf("%2d ", fh->nrps);
	    if ((fields&HDDNL_GETFH_COPIES)) printf("%d ", fh->copies);
	    if ((fields&HDDNL_GETFH_FIRSTRP)) {
		int rc;
		for (rc=0; rc < fh->copies; ++rc) {
		    if (rc) printf("/");
		    printf("0x%08X-0x%08X", fh->rptr[rc].start,
			    fh->rptr[rc].start+fh->rptr[rc].nblocks-1);
		}
		printf("%c ", fh->nrps > 1 ? '+' : ' ');
		for (; rc < FSYS_MAX_ALTS; ++rc) {
		    printf("                      ");
		}
	    }
	    if ((fields&HDDNL_GETFH_ALLOC)) printf("%9d ", fh->alloc);
	    if ((fields&HDDNL_GETFH_SIZE)) printf("%9d ", fh->size);
	    if ((fields&HDDNL_GETFH_DEFEXT)) printf("%6d ", fh->defext);
	    if ((fields&HDDNL_GETFH_CTIME)) print_date(fh->ctime);
	    if ((fields&HDDNL_GETFH_MTIME)) print_date(fh->mtime);
	    if ((fields&HDDNL_GETFH_ATIME)) print_date(fh->atime);
	    if ((fields&HDDNL_GETFH_BTIME)) print_date(fh->btime);
	    printf("%s%s%c\n", prefix, fd->name,
	    	((fh->type&HDDNL_GETFH_TYPE_MASK) == HDDNL_GETFH_TYPE_DIR) ? '/' : ' ');
	}
	if (((fh->type&HDDNL_GETFH_TYPE_MASK) == HDDNL_GETFH_TYPE_DIR) &&
	    	strcmp(fd->name, ".") != 0 && strcmp(fd->name, "..") != 0) {
	    int l1 = strlen(fd->name)+2;
	    int l2 = strlen(prefix)+1;
	    char *new_prefix;
	    for (new_prefix=fd->name; *new_prefix; ++new_prefix) {
		if (!isprint(*new_prefix)) {
		    Wprintf(WPDialog, "\nFilename is not printable\n");
		    EXIT(EXIT_ERROR);
		}
	    }
	    new_prefix = malloc(l1+l2);
	    if (!new_prefix) {
		Wprintf(WPDialog, "Unable to malloc %d bytes\n", l1+l2);
		EXIT(EXIT_ERROR);
	    }
	    strcpy(new_prefix, prefix);
	    strcat(new_prefix, fd->name);
	    strcat(new_prefix, "/");
	    print_dirs(fields, fh->directory, new_prefix);
	    free(new_prefix);
	}
    }
    return 0;
}

static int delete_files(AscleapIO *iop, FDir *fd, char *prefix) {
    FHeader *fh;
    int fid;

    for (;fd && fd->fid; ++fd) {
	fid = fd->fid&0x00FFFFFF;
	if (fid >= remote_fhs_size) continue;
	fh = remote_fhs + fid;
	if (!fh->type) continue;
	if ((fh->type&HDDNL_GETFH_TYPE_MASK) == HDDNL_GETFH_TYPE_DIR) {
	    if (strcmp(fd->name, ".") == 0 || strcmp(fd->name, "..") == 0) continue;
	}
	if (((fh->type&HDDNL_GETFH_TYPE_MASK) == HDDNL_GETFH_TYPE_DIR) || !fh->used) {
	    int l1 = strlen(fd->name)+2;
	    int l2 = strlen(prefix)+1;
	    char *new_prefix;
	    new_prefix = malloc(l1+l2);
	    if (!new_prefix) {
		Wprintf(WPDialog, "Unable to malloc %d bytes\n", l1+l2);
		EXIT(EXIT_ERROR);
	    }
	    strcpy(new_prefix, prefix);
	    strcat(new_prefix, "/");
	    strcat(new_prefix, fd->name);
	    if (((fh->type&HDDNL_GETFH_TYPE_MASK) == HDDNL_GETFH_TYPE_DIR)) {
		delete_files(iop, fh->directory, new_prefix);
		free(new_prefix);
		continue;
	    }
	    if (!chksum_details || !chksum_details->f.game_name || strcmp(new_prefix, chksum_details->f.game_name) != 0) {
		MoleMkFileExt *mk;
		int tmp, len;

		len = sizeof(MoleMkFileExt)+strlen(new_prefix)+1;
		mk = (MoleMkFileExt *)calloc(1, len);
		tmp = MOLE_O_DELETE;
		mk->mode[0] = tmp >> (3*8);
		mk->mode[1] = tmp >> (2*8);
		mk->mode[2] = tmp >> (1*8);
		mk->mode[3] = tmp >> (0*8);
		mk->fname = sizeof(MoleMkFileExt);
		strcpy((char *)(mk+1), new_prefix);
		while_processing = new_prefix;
		if (do_cmd(iop, &cmd_ice, "delete()'ing file", MOLE_OPENFILE, (unsigned char *)mk, len, 0)) {
		    EXIT(EXIT_ERROR);
		}
		Wprintf(WPDialog, "Deleted %s\n", new_prefix);
		free(mk);
	    }
	    free(new_prefix);
	    continue;
    	}
    }
    return 0;
}

#if 0	
#define PRINT_4a(ctl, x) do { printf(ctl, (x[3]<<24)|(x[2]<<16)|(x[1]<<8)|x[0]); x += 4; } while (0)
#define PRINT_4(bit, ctl, x) do { if ((tmp&(HDDNL_GETFH_ ##bit))) { printf(ctl, (x[0]<<24)|(x[1]<<16)|(x[2]<<8)|x[3]); x += 4; } } while (0)
#define PRINT_2(bit, ctl, x) do { if ((tmp&(HDDNL_GETFH_ ##bit))) { printf(ctl, (x[0]<<8)|x[1]); x += 2; } } while (0)
#define PRINT_1(bit, ctl, x) do { if ((tmp&(HDDNL_GETFH_ ##bit))) { printf(ctl, x[0]); x += 1; } } while (0)
	while (dst < lim) {
	    int type, fid;
	    fid = (dst[0]<<24) | (dst[1]<<16) | (dst[2]<<8) | dst[3];
	    if (!fid) break;			/* EOF */
	    dst += 4;
	    printf("%08X", fid);
	    type = *dst++;			/* remember file type */
	    printf(" %c", type ? 'd' : ' ');
	    printf("\n");
	    if (type && (tmp&HDDNL_GETFH_DIR)) { /* if directory contents follow */
		while (dst < lim) {
		    int l;
		    unsigned long f;
		    f = (dst[0]<<24) | (dst[1]<<16) | (dst[2]<<8) | dst[3];
		    dst += 4;
		    if (!f) break;
		    l = *dst++;
		    printf("\t%08lX %s\n", f, dst);
		    dst += l;
		}
	    }
	}
	free(beg);
    }
}
#endif

static int read_a_file(AscleapIO *iop, unsigned char **data, ParseFile *pf, int ok, FILE *ofp);

static int process_checksums(AscleapIO *iop, int verify) {
    ChkSum *css, *csp;
    ParseFile *pf, oldcs;
    int cksum_size, ii, tmp, ackcnt, cookie, numcs;
    char *name, *ptr, *bufp;
    unsigned char *oldcs_data;
    MoleMkFileExt *mk;
    FileStats *st;
    time_t t;
    PacketList packet_list[MAX_NUMB_PACKETS], *pl;

    oldcs = chksum_details->f;			/* clone the details */
    ii = read_a_file(iop, &oldcs_data, &oldcs, MOLE_ERR_OPEN, 0);
    if (ii <= 0) {
	oldcs_data = 0;				/* no old checksums */
	oldcs.eof = 0;
    }

    cksum_size = (stats_next * sizeof(ChkSum) + oldcs.eof + 511)&-512;
    css = (ChkSum *)calloc(1, cksum_size);
    if (!css) {
	Wprintf(WPDialog, "Ran out of memory malloc'ing %d bytes for checksum\n", cksum_size);
	if (oldcs_data) free(oldcs_data);
	return 2;
    }
    if (oldcs.eof) {
	memcpy((char *)css, (char *)oldcs_data, oldcs.eof);
	numcs = oldcs.eof/sizeof(ChkSum);
    } else {
	numcs = 0;
    }
    if (oldcs_data) free(oldcs_data);
    oldcs_data = 0;
    for (st=stats_head, ii=0; ii < stats_next; ++ii, ++st) {
	int jj;
	if (!st->parse) break;
	if (st->parse->type < PARSE_TYPE_FILE || st->parse->type > PARSE_TYPE_BOOT3) continue;
	if (!st->use_it) continue;
	pf = &st->parse->f;
	if (!pf->fid) continue;		/* skip entries with FID of 0 */
	for (csp=css, jj=0; jj < numcs; ++jj, ++csp) {
	    if (csp->fid[0] == ((pf->fid >> (0*8))&0xFF) &&
	    	csp->fid[1] == ((pf->fid >> (1*8))&0xFF) &&
	    	csp->fid[2] == ((pf->fid >> (2*8))&0xFF) &&
	    	csp->fid[3] == ((pf->fid >> (3*8))&0xFF) ) {
		unsigned long hcs;
		hcs = (csp->cs[3] << (3*8)) |
		      (csp->cs[2] << (2*8)) |
		      (csp->cs[1] << (1*8)) |
		      (csp->cs[0] << (0*8));
		if (verify) {
		    if (pf->nocksum) {
			Wprintf(WPDialog, "FID %08lX: Checksum needs to be removed from file\n", pf->fid);
			break;
		    }
		    if ( hcs != pf->cksum ) {
			Wprintf(WPDialog, "FID %08lX: Checksum in game's checksum file = %08lX, s/b %08lX\n",
				pf->fid, hcs, pf->cksum);
		    }
		} else {
		    if (pf->nocksum) {
			if ((debug_level&DBG_SHO_CMD)) {
			    Wprintf(WPDialog, "Removing FID %08lX's checksum.\n", pf->fid);
			}
			memcpy(csp, csp+1, (numcs-jj-1)*sizeof(ChkSum));
			--numcs;
			break;
		    }
		    if ((debug_level&DBG_SHO_CMD)) {
			Wprintf(WPDialog, "Replacing FID %08lX's checksum. old = %08lX, new = %08lX\n",
			    pf->fid, hcs, pf->cksum);
		    }
		    csp->cs[0] = pf->cksum >> (0*8);
		    csp->cs[1] = pf->cksum >> (1*8);
		    csp->cs[2] = pf->cksum >> (2*8);
		    csp->cs[3] = pf->cksum >> (3*8);
		}
		break;
	    }
	}
	if (pf->nocksum) continue;
	if (jj >= numcs) {
	    if (verify) {
		Wprintf(WPDialog, "FID %08lX: No entry in game's checksum file. s/b %08lX\n",
			pf->fid, pf->cksum);
	    } else {
		if ((debug_level&DBG_SHO_CMD)) {
		    Wprintf(WPDialog, "Adding FID %08lX to checksum file; value: %08lX\n",
		    		pf->fid, pf->cksum);
		}
		csp->fid[0] = pf->fid >> (0*8);
		csp->fid[1] = pf->fid >> (1*8);
		csp->fid[2] = pf->fid >> (2*8);
		csp->fid[3] = pf->fid >> (3*8);
		csp->cs[0] = pf->cksum >> (0*8);
		csp->cs[1] = pf->cksum >> (1*8);
		csp->cs[2] = pf->cksum >> (2*8);
		csp->cs[3] = pf->cksum >> (3*8);
		++numcs;
	    }
	}
    }
    if (verify) {
	free(css);
	return 0;
    }
    pf = &chksum_details->f;
    cksum_size = numcs*sizeof(ChkSum);
    pf->alloc = (cksum_size+511)&-512;
    name = pf->game_name;
    tmp = strlen(name);
    bufp = calloc(1, sizeof(MoleMkFileExt)+tmp+2);
    if (!bufp) {
	Wprintf(WPDialog, "Ran out of memory calloc'ing %d bytes\n", sizeof(MoleMkFileExt)+tmp+2);
	return 2;
    }
    mk = (MoleMkFileExt *)bufp;
    mk->fname = sizeof(MoleMkFileExt);
    ptr = (char *)(mk+1);
    strcpy(ptr, name);
    ptr += tmp+1;
    mk->alloc[0] = pf->alloc >> (3*8);
    mk->alloc[1] = pf->alloc >> (2*8);
    mk->alloc[2] = pf->alloc >> (1*8);
    mk->alloc[3] = pf->alloc >> (0*8);
    pf->def_extend /= 512;
    if (pf->def_extend > 0x10000) pf->def_extend = 0xFFFF;
    mk->def_extend[0] = pf->def_extend >> (1*8);
    mk->def_extend[1] = pf->def_extend >> (0*8);
    tmp = MOLE_O_WRONLY | MOLE_O_CREAT | MOLE_O_TRUNC;
    mk->mode[0] = tmp >> (3*8);
    mk->mode[1] = tmp >> (2*8);
    mk->mode[2] = tmp >> (1*8);
    mk->mode[3] = tmp >> (0*8);
    mk->copies = pf->copies;
    if (!(t=pf->ctime)) t = time(0);
    mk->ctime[0] = t >> (3*8);
    mk->ctime[1] = t >> (2*8);
    mk->ctime[2] = t >> (1*8);
    mk->ctime[3] = t >> (0*8);
    while_processing = name;
    if (do_cmd(iop, &cmd_ice, "open()'ing file", MOLE_OPENFILE, (unsigned char *)mk, ptr-(char *)mk, 0)) {
	return 6;
    }
    mk = (MoleMkFileExt *)cmd_ice.u_data;
    cookie = (mk->cookie[0] << (3*8)) | 
	     (mk->cookie[1] << (2*8)) | 
	     (mk->cookie[2] << (1*8)) | 
	     (mk->cookie[3] << (0*8));
    pf->fid = (mk->fid[0] << (3*8)) | 
	      (mk->fid[1] << (2*8)) | 
	      (mk->fid[2] << (1*8)) | 
	      (mk->fid[3] << (0*8));
    if (need_erase) printf(erase);
    print_mkb("Writing ", pf->alloc, ", ", 1);
    printf("FID=%08lX, %s%s", pf->fid, pf->game_name, eol_char);
    fflush(stdout);
    ackcnt = 0;
    csp = css;
    while (1) {
	pl = packet_list + ackcnt;
	pl->amt = (max_packet_size-8)&-8;
	if (pl->amt > cksum_size) pl->amt = cksum_size;
	if (pl->amt <= 0) break;
	memcpy(pl->buf+4, (char *)csp, pl->amt);
	csp += pl->amt/sizeof(ChkSum);
	cksum_size -= pl->amt;
	pl->seq = cmd_ice.seq;
	pl->buf[0] = cookie >> (3*8);
	pl->buf[1] = cookie >> (2*8);
	pl->buf[2] = cookie >> (1*8);
	pl->buf[3] = cookie >> (0*8);
	pl->cmd = (ackcnt < max_numb_packets-1) ? MOLE_WRFILE : MOLE_WRFILEack;
	pl->amt += 4;
	if (put_iceless(iop, &cmd_ice, pl->buf, pl->amt, pl->cmd) <= 0) {
	    Wprintf(WPDialog, "%sCouldn't complete write(). Giving up...\n", bol_char);
	    return 5;
	}
	if (ackcnt < max_numb_packets-1) {
	    ++ackcnt;
	    ++cmd_ice.seq;
	} else {
	    if (retry_packet(ackcnt+1, packet_list, iop, &cmd_ice)) EXIT(EXIT_ERROR);
	    ackcnt = 0;
	}
    }
    pl->amt = 4;
    pl->seq = cmd_ice.seq;
    pl->buf[0] = cookie >> (3*8);
    pl->buf[1] = cookie >> (2*8);
    pl->buf[2] = cookie >> (1*8);
    pl->buf[3] = cookie >> (0*8);
    pl->cmd = MOLE_CLOSE;
    if (put_iceless(iop, &cmd_ice, pl->buf, pl->amt, pl->cmd) <= 0) {
	Wprintf(WPDialog, "%sCouldn't complete close(). Giving up...\n", bol_char);
	return 1;
    }
    if (retry_packet(ackcnt+1, packet_list, iop, &cmd_ice)) {
	return 2;
    }
    free(bufp);
    free(css);
    return 0;
}

static int open_remote_file(AscleapIO *iop, FileStats *st, MoleMkFileExt *mk, ParseFile *pf, int *imode, unsigned long *cookie) {
    time_t t;
    char *ptr;
    int mode = *imode;

    memset((char *)mk, 0, sizeof(MoleMkFileExt));
    mk->fname = sizeof(MoleMkFileExt);
    ptr = (char *)(mk+1);
    strcpy(ptr, pf->game_name);
    ptr += strlen(pf->game_name)+1;
    mk->alloc[0] = pf->alloc >> (3*8);
    mk->alloc[1] = pf->alloc >> (2*8);
    mk->alloc[2] = pf->alloc >> (1*8);
    mk->alloc[3] = pf->alloc >> (0*8);
    pf->def_extend /= 512;
    if (pf->def_extend > 0x10000) pf->def_extend = 0xFFFF;
    mk->def_extend[0] = pf->def_extend >> (1*8);
    mk->def_extend[1] = pf->def_extend >> (0*8);
    mk->mode[0] = mode >> (3*8);
    mk->mode[1] = mode >> (2*8);
    mk->mode[2] = mode >> (1*8);
    mk->mode[3] = mode >> (0*8);
    mk->copies = pf->copies;
    if (!(t=pf->ctime)) {
	if (!(t=st->mtime)) t = time(0);
    }
    mk->ctime[0] = t >> (3*8);
    mk->ctime[1] = t >> (2*8);
    mk->ctime[2] = t >> (1*8);
    mk->ctime[3] = t >> (0*8);
    mk->mtime[0] = t >> (3*8);
    mk->mtime[1] = t >> (2*8);
    mk->mtime[2] = t >> (1*8);
    mk->mtime[3] = t >> (0*8);
    while_processing = pf->game_name;
    if (do_cmd(iop, &cmd_ice, "open()'ing file", MOLE_OPENFILE, (unsigned char *)mk, ptr-(char *)mk, 0)) {
	return 3;
    }
    if (cmd_ice.port == ASC_PORT) {
	mk = (MoleMkFileExt *)cmd_ice.u_data;
	*cookie = (mk->cookie[0] << (3*8)) | 
		 (mk->cookie[1] << (2*8)) | 
		 (mk->cookie[2] << (1*8)) | 
		 (mk->cookie[3] << (0*8));
	pf->fid = (mk->fid[0] << (3*8)) | 
		  (mk->fid[1] << (2*8)) | 
		  (mk->fid[2] << (1*8)) | 
		  (mk->fid[3] << (0*8));
	*imode = (mk->mode[0] << (3*8)) |
		 (mk->mode[1] << (2*8)) |
		 (mk->mode[2] << (1*8)) |
		 (mk->mode[3] << (0*8));
    }
    return 0;
}

static int read_a_file(AscleapIO *iop, unsigned char **data, ParseFile *pf, int ok, FILE *ofp) {
    unsigned char *bufp, *dst;
    char *ptr;
    int ii, tmp, cookie, cnt, exit_sts=0;
    PacketList packet_list[1], *pl;
    MoleMkFileExt *mk;
    int old_npkt, old_mpkt, max;

    while_processing = pf->game_name;
    ii = strlen(pf->game_name)+1;
    mk = (MoleMkFileExt *)calloc(1, sizeof(MoleMkFileExt)+ii);
    mk->fname = sizeof(MoleMkFileExt);
    ptr = (char *)(mk+1);
    strcpy(ptr, pf->game_name);
    ptr += ii;
    tmp = MOLE_O_RDONLY;
    mk->mode[0] = tmp >> (3*8);
    mk->mode[1] = tmp >> (2*8);
    mk->mode[2] = tmp >> (1*8);
    mk->mode[3] = tmp >> (0*8);
    if (do_cmd(iop, &cmd_ice, "read()'ing a file", MOLE_OPENFILE, (unsigned char *)mk, ptr-(char *)mk, ok)) {
	free(mk);
	if (cmd_ice.cmd == ICEnak && ok && cmd_ice.u_data[0] == ok) return 0;
	return -1;
    }
    free(mk);
    mk = (MoleMkFileExt *)cmd_ice.u_data;
    pf->copies = mk->copies;
    pf->mkdir = mk->mkdir;
    cookie = (mk->cookie[0] << (3*8)) | 
	     (mk->cookie[1] << (2*8)) | 
	     (mk->cookie[2] << (1*8)) | 
	     (mk->cookie[3] << (0*8));
    pf->fid = (mk->fid[0] << (3*8)) | 
	      (mk->fid[1] << (2*8)) | 
	      (mk->fid[2] << (1*8)) | 
	      (mk->fid[3] << (0*8));
    pf->alloc = (mk->alloc[0] << (3*8)) | 
	      (mk->alloc[1] << (2*8)) | 
	      (mk->alloc[2] << (1*8)) | 
	      (mk->alloc[3] << (0*8));
    pf->eof = cnt = (mk->eof[0] << (3*8)) | 
	      (mk->eof[1] << (2*8)) | 
	      (mk->eof[2] << (1*8)) | 
	      (mk->eof[3] << (0*8));
    pf->ctime = (mk->mtime[0] << (3*8)) | 
	      (mk->mtime[1] << (2*8)) | 
	      (mk->mtime[2] << (1*8)) | 
	      (mk->mtime[3] << (0*8));
    if (!pf->ctime) {
       pf->ctime = (mk->ctime[0] << (3*8)) | 
	      (mk->ctime[1] << (2*8)) | 
	      (mk->ctime[2] << (1*8)) | 
	      (mk->ctime[3] << (0*8));
    }
    if (need_erase) printf(erase);
    print_mkb("Reading ", pf->eof, ", ", 1);
    printf("FID=%08lX, %s%s", pf->fid, pf->game_name, eol_char);
    fflush(stdout);
    pl = packet_list;
    if (!ofp) {
	dst = bufp = malloc(cnt);
	if (!bufp) {
	    Wprintf(WPDialog, "%sRan out of mem malloc'ing %d bytes. Giving up...\n", bol_char, cnt);
	    return -1;
	}	
    } else {
	dst = bufp = 0;
    }
    old_npkt = max_numb_packets;
    old_mpkt = max_packet_size;
    max = (max_numb_packets*(max_packet_size-4))&-512;
#define XINU_TCP_MAX (0x3E00)
#if MAX_PKT_SIZE < XINU_TCP_MAX
    if (max > XINU_TCP_MAX) max = XINU_TCP_MAX;  /* Don't let upload ask for more than Xinu's TCP buffer at one shot */
#endif
    max_numb_packets = max/max_packet_size;	/* They have to fit in this many packets */

    while (cnt > 0) {
	max = (max_numb_packets*(max_packet_size-4))&-512;
	if (max > cnt) max = cnt;
	pl->seq = cmd_ice.seq;
	pl->buf[ 0] = cookie >> (3*8);
	pl->buf[ 1] = cookie >> (2*8);
	pl->buf[ 2] = cookie >> (1*8);
	pl->buf[ 3] = cookie >> (0*8);
	pl->buf[ 4] = max >> (3*8);
	pl->buf[ 5] = max >> (2*8);
	pl->buf[ 6] = max >> (1*8);
	pl->buf[ 7] = max >> (0*8);
	pl->buf[ 8] = max_packet_size >> (3*8);
	pl->buf[ 9] = max_packet_size >> (2*8);
	pl->buf[10] = max_packet_size >> (1*8);
	pl->buf[11] = max_packet_size >> (0*8);
	
	if (put_iceless(iop, &cmd_ice, pl->buf, 12, MOLE_RDFILE) <= 0) {
	    Wprintf(WPDialog, "%sCouldn't complete read() request. Giving up...\n", bol_char);
	    exit_sts = -4;
	    break;
	}
	for (ii=0; ii < max_numb_packets && cnt > 0; ++ii) {
	    if (process_reply(iop, &cmd_ice, "read()'ing file", MOLE_EOF)) {
		exit_sts = -5;
		break;
	    }
	    if (ofp) {
		int sts;
		sts = fwrite(cmd_ice.u_data, 1, cmd_ice.u_len, ofp);
		if (sts != cmd_ice.u_len) {
		    Wprintf(WPDialog, "%sCouldn't write file: %s\n", bol_char, strerror(errno));
		    break;
		}
	    } else {
		memcpy(dst, cmd_ice.u_data, cmd_ice.u_len);
	    }
	    dst += cmd_ice.u_len;
	    cnt -= cmd_ice.u_len;
	}
    }
    max_numb_packets = old_npkt;
    max_packet_size = old_mpkt;
    pl->buf[0] = cookie >> (3*8);
    pl->buf[1] = cookie >> (2*8);
    pl->buf[2] = cookie >> (1*8);
    pl->buf[3] = cookie >> (0*8);
    if (do_cmd(iop, &cmd_ice, "close()'ing file", MOLE_CLOSE, pl->buf, 4, 0)) {
	Wprintf(WPDialog, "%sCouldn't complete close(). Giving up...\n", bol_char);
	exit_sts = -6;
    }
    if (exit_sts < 0) {
	if (bufp) free(bufp);
	bufp = 0;
    } else {
	if (bufp) {
	    exit_sts = dst - bufp;
	} else {
	    exit_sts = dst - (unsigned char *)0;
	}
    }
    if (data) *data = bufp;
    return exit_sts;
}

static int read_files(AscleapIO *iop) {
    ParseFile *pf;
    int ii, stcnt;
    FILE *ifp=0;
    FileStats *st;
    FHeader *fh;
    char emsg[1024];
    unsigned char *bufp=0;

    if (cmd_ice.port != ASC_PORT) return 0;
    for (st=stats_head, stcnt=0; stcnt < stats_next; ++stcnt, ++st) {
	time_t t=0, *timt;
	int tmp=0, skip_it, always;
	struct utimbuf times;

	if (!st->parse) break;
	if (st->parse->type < PARSE_TYPE_FILE || st->parse->type > PARSE_TYPE_BOOT3) continue;
	if (!st->use_it) {
	    if ((debug_level&DBG_SHO_CMD)) {
		printf("%sSkipped because not on commad line: %s\n", bol_char, st->parse->f.unix_name);
	    }
	    continue;
	}
	pf = &st->parse->f;
	fh = 0;
	always = skip_it = 0;
	if (strncmp(pf->game_name, "/prt", 4) == 0) {	/* special partition file? */
	    always = 1;
	} else {
	    if (remote_fhs_size) {
		fh = find_game_file(pf->game_name);
		if (!fh) {
		    printf("%s%s not found on game file system\n", bol_char, pf->game_name);
		    continue;
		} else {
		    tmp = fh->size;
		    t = fh->mtime;
		    fh->used = 1;		/* signal the file has an entry in the command file */
		    if ((debug_level&DBG_SHO_CMD)) printf("Found %s in fhs. size=%d, mtime=%08lX; cmp sz=%ld, mtime=%08lX\n",
			    pf->game_name, fh->size, fh->mtime, st->size, st->mtime);
		}
	    }	    
	}
	if (!always) {
	    if (pf->ctime) {			/* if there's a Unix creation time */
		if (date_diff) {		/* if we're to check if dates are mearly different */
		    if (t == pf->ctime && tmp == st->size) {
			skip_it = 1;		/* dates and sizes match */
		    }
		} else {
		    if (pf->ctime > t) {	/* if Unix file is younger than game file */
			skip_it = 1;
		    } else if (pf->ctime == t && tmp == st->size) { /* dates and sizes match */
			skip_it = 1;
		    }
		}
	    } else {
		if (date_diff) {		/* if we're to check if dates are mearly different */
		    if (t == st->mtime && tmp == st->size) { /* if dates and sizes are the same */
			skip_it = 1;
		    }
		} else {
		    if (st->mtime > t) {	/* if Unix file is younger than game file */
			skip_it = 1;
		    } else if (st->mtime == t && tmp == st->size) { /* if dates and sizes are the same */
			skip_it = 1;
		    }
		}
	    }
	    if (skip_it) {
		st->use_it = 0;			/* skip this file */
		if ((debug_level&DBG_SHO_CMD)) printf("...time and size match, skipped\n");
		continue;
	    }
	}
	ifp = fopen(pf->unix_name, "wb");
	if (!ifp) {
	    if (errno == ENOENT) {		/* maybe we can create the directory for 'em */
		char *s1;
		s1 = strrchr(pf->unix_name, '/');	/* scan back to dir delimiter */
		if (s1) {
		    int olderr = errno;		/* save old error */
		    *s1 = 0;			/* zap off the name */
		    sprintf(emsg, "mkdir -p %s", pf->unix_name); /* make the Unix command */
		    if (system(emsg)) { ; }	/* create all intervening directories (fopen below reports failure) */
		    *s1 = '/';			/* put name back */
		    ifp = fopen(pf->unix_name, "wb"); /* try the open again */
		    errno = olderr;		/* restore previous error code */
		}
	    }
	    if (!ifp) {				/* if it still didn't open */
		sprintf(emsg, "%s%s:0 Error opening %s for output", bol_char, image_name, pf->unix_name);
		perror(emsg);
		free(bufp);
		continue;
	    }
	}
	ii = read_a_file(iop, 0, pf, 0, ifp);
	fclose(ifp);
	if (ii >= 0) {
	    timt = 0;
	    if (fh) {
		timt = (time_t *)&fh->mtime;
	    } else {
		if (pf->ctime) timt = (time_t *)&pf->ctime;
	    }
	    if (timt) {
		times.actime = (pf->ctime) ? pf->ctime : *timt;
		times.modtime = (fh && fh->mtime) ? fh->mtime : *timt;
		utime(pf->unix_name, &times);
#if 0
		ltp = localtime(timt);
		sprintf(emsg, "touch %02d%02d%02d%02d %s",
		    ltp->tm_mon+1, ltp->tm_mday, ltp->tm_hour, ltp->tm_min, pf->unix_name);
		system(emsg);
#endif
	    }
	}
	if (bufp) free(bufp);
	bufp = 0;
    }
    return 0;
}

static int cksum_region(unsigned char *ucp, int amt) {
    int jj, chksum = 0;

    for (jj=0; jj < amt/4; ++jj, ucp += 4) {
	chksum += (ucp[3] << (3*8)) |
		  (ucp[2] << (2*8)) |
		  (ucp[1] << (1*8)) |
		  (ucp[0] << (0*8));
    }
    jj = 0;
    switch(amt&3) {
	case 1: jj = *ucp; break;
	case 2: jj = (ucp[1] << (1*8)) | ucp[0]; break;
	case 3: jj = (ucp[2] << (2*8)) | (ucp[1] << (1*8)) | ucp[0]; break;
    }
    chksum += jj;
    return chksum;
}

#define Z_FLAGS_EOF	0x01
#define Z_FLAGS_DONE	0x02

typedef struct c_zlib_s {
    struct z_stream_s zlib;
    FILE *ifp;
    Bytef *memory;
    Bytef *inp_buff;
    int inp_buff_size;
    int flags;
} CZlib;

static int rd_squeezed(CZlib *zlib, Bytef *buf, int size, unsigned long *chksum) {
    struct z_stream_s *zs;
    int sts, flush;

    zs = &zlib->zlib;
    zs->next_out = buf;
    zs->avail_out = size;
    if ((zlib->flags&Z_FLAGS_DONE)) return 0;
    flush = (zlib->flags&Z_FLAGS_EOF) ? Z_FINISH : Z_NO_FLUSH;
    while (zs->avail_out) {
	if (!zs->avail_in && !(zlib->flags&(Z_FLAGS_EOF|Z_FLAGS_DONE))) {
	    zs->next_in = zlib->inp_buff;
	    sts = fread(zlib->inp_buff, 1, zlib->inp_buff_size, zlib->ifp);
	    if (sts <= 0) {
		if (!feof(zlib->ifp)) {
		    perror("Error reading input");
		    zlib->flags |= Z_FLAGS_DONE;
		    return 0;
		}
		zlib->flags |= Z_FLAGS_EOF;
		flush = Z_FINISH;
	    } else {
		*chksum += cksum_region(zlib->inp_buff, sts);
		zs->avail_in = sts;
	    }
	}
	sts = deflate(zs, flush);
	if (sts == Z_STREAM_END) {
	    zlib->flags |= Z_FLAGS_DONE;
	    return size - zs->avail_out;
	}
	if (sts != Z_OK) {
	    zlib->flags |= Z_FLAGS_DONE;
	    printf("%sError during deflate: %s\n", bol_char, zs->msg);
	    return 0;
	}
    }
    return size;
}

static int erase_files(AscleapIO *iop) {
    ParseFile *pf;
    pf = delete_details;
    while (pf) {
	MoleMkFileExt *mk;
	int tmp, len;

	len = sizeof(MoleMkFileExt)+strlen(pf->game_name)+1;
	mk = (MoleMkFileExt *)calloc(1, len);
	tmp = MOLE_O_DELETE;
	mk->mode[0] = tmp >> (3*8);
	mk->mode[1] = tmp >> (2*8);
	mk->mode[2] = tmp >> (1*8);
	mk->mode[3] = tmp >> (0*8);
	mk->fname = sizeof(MoleMkFileExt);
	strcpy((char *)(mk+1), pf->game_name);
	while_processing = pf->game_name;
	if (do_cmd(iop, &cmd_ice, "delete()'ing file", MOLE_OPENFILE, (unsigned char *)mk, len, 0)) {
	    EXIT(EXIT_ERROR);
	}
	Wprintf(WPDialog, "Deleted %s\n", pf->game_name);
	free(mk);
	pf = pf->next;
    }
    return 0;
}

static int write_files(AscleapIO *iop) {
    ParseFile *pf;
    char *name;
    time_t t=0;
    int ii, tmp=0, ackcnt, exit_sts=0, omode, mode, copies=1;
    FILE *ifp=0;
    PacketList packet_list[MAX_NUMB_PACKETS], *pl;
    FileStats *st;
    unsigned long chksum, cookie;
    char emsg[132];
    void *bufp=0;
    int bufp_size=0;
#if 0
    long xfer=0;
#endif
    CZlib zlib;

    zlib.memory = 0;
    for (st=stats_head, ii=0; ii < stats_next; ++ii, ++st) {
	FHeader *fh;
	if (!st->parse) break;
	if (st->parse->type < PARSE_TYPE_FILE || st->parse->type > PARSE_TYPE_BOOT3) continue;
	pf = &st->parse->f;
	if (remote_fhs_size) {
	    fh = find_game_file(pf->game_name);
	    if (!fh) {
		tmp = 0;		/* there is no file on game end */
		t = 0;
		copies = 0;
		if ((debug_level&DBG_SHO_CMD)) printf("File %s not on remote system.\n", pf->game_name);
	    } else {
		tmp = fh->size;
		t = fh->mtime;
		copies = fh->copies;
		fh->used = 1;		/* signal the file has an entry in the command file */
		if ((debug_level&DBG_SHO_CMD)) printf("Found %s in fhs. size=%d, mtime=%08lX; cmp sz=%ld, mtime=%08lX\n",
			pf->game_name, fh->size, fh->mtime, st->size, st->mtime);
	    }
	}
	if (!st->use_it) {
	    if ((debug_level&DBG_SHO_CMD)) printf("Skipped because not on commad line: %s\n", st->parse->f.unix_name);
	    continue;
	}
	if (st->use_it == 1) {	/* check to see if we need to update it */
	    if (!remote_fhs_size) {
		MoleMkFileExt *mk;
		if ((debug_level&DBG_SHO_CMD)) printf("Doing mole_fstat on %s\n", pf->game_name);
		while_processing = pf->game_name;
		if (do_cmd(iop, &cmd_ice, "fstat()'ing file", MOLE_FSTAT,
				(unsigned char *)pf->game_name, strlen(pf->game_name)+1, 0)) {
		    exit_sts = 1;
		    break;
		}
		mk = (MoleMkFileExt *)cmd_ice.u_data;
		tmp = (mk->eof[0] << (3*8)) | 
		      (mk->eof[1] << (2*8)) | 
		      (mk->eof[2] << (1*8)) | 
		      (mk->eof[3] << (0*8));
		t =   (mk->mtime[0] << (3*8)) | 
		      (mk->mtime[1] << (2*8)) | 
		      (mk->mtime[2] << (1*8)) | 
		      (mk->mtime[3] << (0*8));
		copies = mk->copies;
		if ((debug_level&DBG_SHO_CMD)) printf("...answer is: size=%d, mtime=%08lX; comparing sz=%ld, mtime=%08lX\n",
							tmp, t, st->size, st->mtime);
	    }
	    if (verify || (pf->copies == copies)) {
		int skip_it=0;
		if (pf->ctime) {		/* Unix has a ctime */
		    if (date_diff) {		/* if we're mearly for check for dates different */
			if (t == pf->ctime && tmp == st->size) { /* if date and size match */
			    skip_it = 1;
			}
		    } else {
			if (t > pf->ctime) {	/* if game is younger than Unix file */
			    skip_it = 1;
			} else if (t == pf->ctime && tmp == st->size) { /* if dates and sizes match */
			    skip_it = 1;
			}
		    }
		} else {
		    if (date_diff) {		/* if we're mearly to check for dates different */
			if (t == st->mtime && tmp == st->size) { /* if date and size match */
			    skip_it = 1;
			}
		    } else {
			if (t > st->mtime) {	/* if game is younger than Unix */
			    skip_it = 1;
			} else if (t == st->mtime && tmp == st->size) { /* if date and size match */
			    skip_it = 1;
			}
		    }
		}
		if (skip_it) {
		    if (verify) {		/* if we're to update checksums */
			st->use_it = -1;	/* signal just to checksum both files */
		    } else {
			st->use_it = 0;		/* skip this file for checksums */
			if ((debug_level&DBG_SHO_CMD)) printf("...time and size match, skipped\n");
			continue;
		    }
		} else {
		    if (verify == 2) {
			Wprintf(WPDialog, "%sNeeds updating due to date mismatch: %s\n", bol_char,
			    pf->game_name);
			continue;
		    }
		}
	    }
	    if (verify == 2 && pf->copies != copies) {
		Wprintf(WPDialog, "%sNeeds updating due to diff in # of copies: %s\n",
		    bol_char, pf->game_name);
	    }
	}
	ifp = fopen(pf->unix_name, "rb");
	if (!ifp) {
	    sprintf(emsg, "%s%s:0 Error opening %s for input", bol_char, image_name, pf->unix_name);
	    perror(emsg);
	    continue;
	}
	name = pf->game_name;
	tmp = strlen(name);
	if (sizeof(MoleMkFileExt)+tmp+1 > bufp_size) {
	    bufp_size = sizeof(MoleMkFileExt)+tmp+100;
	    bufp = realloc(bufp, bufp_size);
	    if (!bufp) {
		Wprintf(WPDialog, "%sRan out of memory realloc'ing %d bytes\n",
	    		bol_char, sizeof(MoleMkFileExt)+tmp+100);
		exit_sts = 2;
		break;
	    }
	}
	mode = MOLE_O_RDONLY;
	if (st->use_it > 0) {
	    mode = (MOLE_O_WRONLY | MOLE_O_CREAT | MOLE_O_TRUNC);
	    if (st->parse->type >= PARSE_TYPE_BOOT0 &&
    		st->parse->type <= PARSE_TYPE_BOOT3) {
		int which_boot = (st->parse->type - PARSE_TYPE_BOOT0)<<1;
		mode |= MOLE_O_BOOT | (which_boot<<MOLE_V_BOOT);
	    }
	    if (squeeze_em && st->size >= squeeze_em) {
		mode |= compression_factor << MOLE_V_COMPRESS;
	    }
	}
	omode = mode;			/* remember this */
	while_processing = name;
	exit_sts = open_remote_file(iop, st, (MoleMkFileExt *)bufp, pf, &mode, &cookie);
	if (exit_sts) break;
	if ((omode&MOLE_O_COMPRESS)) {
	    if ( cmd_ice.port == ASC_PORT && ( (omode&MOLE_O_COMPRESS) != (mode&MOLE_O_COMPRESS) || !(mode&MOLE_O_COMPRESS_OK) ) ) {
		Wprintf(WPDialog, "\n********* Remote hddnl doesn't support compress mode. Compression disabled. *****\n\n");
		squeeze_em = 0;
		mode = omode & ~(MOLE_O_COMPRESS|MOLE_O_COMPRESS_OK);
		omode = mode;
	    } else {
		if (!zlib.memory) {
		    memset((char *)&zlib, 0, sizeof(zlib));
		    zlib.inp_buff_size = 1024*1024;
		    zlib.memory = malloc(zlib.inp_buff_size+32);
		    zlib.inp_buff = (Bytef *)(((int)zlib.memory + 31) & -32);
		}
		zlib.ifp = ifp;		/* remember this for later */
		zlib.flags = 0;		/* start with empty flags */
		zlib.zlib.avail_in = 0;	/* nothing in the input to force a read */
		if ((ii=deflateInit(&zlib.zlib, compression_factor)) != Z_OK) {
		    fprintf(stderr, "%sError during deflateInit(): %s\n", bol_char, zlib.zlib.msg);
		    return ii;
		}
	    }
	}
	if ((omode&MOLE_O_BOOT) && !(mode&MOLE_O_BOOT)) {
	    Wprintf(WPDialog, "\n********* Remote hddnl doesn't support boot feature. *****\n\n");
	}
	while_processing = pf->game_name;
	if (need_erase) printf(erase);
	print_mkb( st->use_it >= 0 ? "Writing " : "Csuming ", pf->alloc, ", ", 1);
	printf("FID=%08lX, %s%s", pf->fid, pf->game_name, eol_char);
	fflush(stdout);
	ackcnt = 0;
	if (st->use_it < 0) {
	    unsigned long his_cs;
	    U8 *bp = (U8*)bufp;
	    bp[0] = cookie >> (3*8);
	    bp[1] = cookie >> (2*8);
	    bp[2] = cookie >> (1*8);
	    bp[3] = cookie >> (0*8);
	    if (put_iceless(iop, &cmd_ice, bufp, 4, MOLE_CCHKSUM) <= 0) {
		Wprintf(WPDialog, "%sCouldn't start chksum(). Giving up...\n", bol_char);
		exit_sts = 4;
		break;
	    }
	    chksum = 0;
	    while (1) {
		int len;
		U8 tbuf[64*1024];
		len = fread(tbuf, 1, sizeof(tbuf), ifp);
		if (len <= 0) break;
		chksum += cksum_region(tbuf, len);
	    }
	    if (process_reply(iop, &cmd_ice, "chsum()'ing file", 0) > 0) {
		Wprintf(WPDialog, "%sError computing checksum. Giving up...\n", bol_char);
		exit_sts = 5;
		break;
	    }
	    bp = cmd_ice.u_data;
	    his_cs = (bp[0] << (3*8)) | 
	    	     (bp[1] << (2*8)) |
	    	     (bp[2] << (1*8)) |
	    	     (bp[3] << (0*8));
	    bp[0] = cookie >> (3*8);
	    bp[1] = cookie >> (2*8);
	    bp[2] = cookie >> (1*8);
	    bp[3] = cookie >> (0*8);
	    if (do_cmd(iop, &cmd_ice, "close()'ing file", MOLE_CLOSE, bp, 4, 0)) {
		exit_sts = 1;
		break;
	    }
	    if ((debug_level&DBG_SHO_CMD)) {
		Wprintf(WPDialog, "   Checksum: Unix end: %08lX, game end: %08lX\n",
				chksum, his_cs);
	    }
	    if (his_cs != chksum) {
		Wprintf(WPDialog, "%s   Checksum didn't match. Expected %08lX, computed %08lX\n",
    				bol_char, chksum, his_cs);
	    }
	    if (his_cs != chksum && verify == 1) {
		int mode;
		st->use_it = 1;
		rewind(ifp);
		mode = (MOLE_O_WRONLY | MOLE_O_CREAT | MOLE_O_TRUNC);
		if (st->parse->type >= PARSE_TYPE_BOOT0 &&
	    	    st->parse->type <= PARSE_TYPE_BOOT3) {
		    int which_boot = (st->parse->type - PARSE_TYPE_BOOT0)<<1;
		    mode |= MOLE_O_BOOT | (which_boot<<MOLE_V_BOOT);
		}
		exit_sts = open_remote_file(iop, st, (MoleMkFileExt *)bufp, pf, &mode, &cookie);
		if (exit_sts) break;
		if (need_erase) printf(erase);
		print_mkb("Writing ", pf->alloc, ", ", 1);
		printf("FID=%08lX, %s%s", pf->fid, pf->game_name, eol_char);
		fflush(stdout);
	    } else {
		pf->cksum = chksum;
		fclose(ifp);
		continue;
	    }
	}
	chksum = 0;
	while (1) {
	    pl = packet_list + ackcnt;
	    if ((mode&MOLE_O_COMPRESS)) {
		pl->amt = rd_squeezed(&zlib, pl->buf+4, (max_packet_size-8)&-4, &chksum);
	    } else {
		pl->amt = fread(pl->buf+4, 1, (max_packet_size-8)&-4, ifp);
		if (pl->amt > 0) chksum += cksum_region(pl->buf+4, pl->amt);
	    }
	    if (pl->amt <= 0) break;
	    pl->seq = cmd_ice.seq;
	    pl->buf[0] = cookie >> (3*8);
	    pl->buf[1] = cookie >> (2*8);
	    pl->buf[2] = cookie >> (1*8);
	    pl->buf[3] = cookie >> (0*8);
	    pl->cmd = (ackcnt < max_numb_packets-1) ? MOLE_WRFILE : MOLE_WRFILEack;
	    pl->amt += 4;
	    if (put_iceless(iop, &cmd_ice, pl->buf, pl->amt, pl->cmd) <= 0) {
		Wprintf(WPDialog, "%sCouldn't complete write(). Giving up...\n", bol_char);
		exit_sts = 4;
		break;
	    }
	    if (ackcnt < max_numb_packets-1) {
		++ackcnt;
		++cmd_ice.seq;
	    } else {
		if (retry_packet(ackcnt+1, packet_list, iop, &cmd_ice)) EXIT(EXIT_ERROR);
		ackcnt = 0;
	    }
	}
	if (ifp) fclose(ifp);
	if ((mode&MOLE_O_COMPRESS)) {
	    deflateEnd(&zlib.zlib);	/* done with compression code */
	}
	pf->cksum = chksum;
	if ((debug_level&DBG_SHO_CMD)) {
	    Wprintf(WPDialog, "   Computed checksum of: %08lX\n", chksum);
	}
	pl->amt = 4;
	pl->seq = cmd_ice.seq;
	pl->buf[0] = cookie >> (3*8);
	pl->buf[1] = cookie >> (2*8);
	pl->buf[2] = cookie >> (1*8);
	pl->buf[3] = cookie >> (0*8);
	pl->cmd = MOLE_CLOSE;
	if (put_iceless(iop, &cmd_ice, pl->buf, pl->amt, pl->cmd) <= 0) {
	    Wprintf(WPDialog, "%sCouldn't complete close(). Giving up...\n", bol_char);
	    exit_sts = 1;
	    break;
	}
	if (retry_packet(ackcnt+1, packet_list, iop, &cmd_ice)) {
	    exit_sts = 2;
	    break;
	}
	++files_sent;
#if 0
	xfer += pf->alloc;
	if (xfer > 20000000) {
Wprintf(WPDialog, "%sReopening connection ...\n", bol_char);
	    ascleapio_close(iop);
	    iop = open_connection(&cmd_ice, 1);
	    xfer = 0;
	}
#endif
    }
    if (ifp) fclose(ifp);
    if (bufp) free(bufp);
    if (zlib.memory) free(zlib.memory);
    if (!exit_sts && chksum_details && (files_sent || verify )) exit_sts = process_checksums(iop, verify == 2);
    return exit_sts;
}

int main(int argc, char *argv[]) {
    int ii, force=1, init=0, exit_sts=0, no_reset=0, upload=0;
    char *t, *s, *command_file=0;
    int nomount=0, port=ASC_PORT;
    int image_mode=0, get_dir=0;
    AscleapIO *iop;

    t = strrchr(argv[0], '/');
    image_name = t ? t+1 : argv[0];
    
    for (--argc, ++argv; argc > 0; --argc, ++argv) {
	s = *argv;
	if (*s++ != '-') break; /* done with options */
	switch (ii = *s++) {
	    default:
		if (isprint(ii)) {
		    Wprintf(WPDialog, "Unknown switch: -%c\r\n", ii);
		} else {
		    Wprintf(WPDialog, "Unknown switch char: 0x%02X\r\n", ii&0xFF);
		}
	    case '?':
		help_him(1);
		return EXIT_ERROR;
	    case 'b':     /* board number */
		if (*s == 0) { ++argv; --argc; s = *argv; }
		if (argc <= 0 || *s == 0) goto no_arg;
		cmd_ice.board = poll_ice.board = strtol(s, &t, 10);
		if (s == t || *t != 0) goto no_numb;
		continue;
	    case 'c':     /* command file name */
		if (*s == 0) { ++argv; --argc; s = *argv; }
		if (argc <= 0 || *s == 0) {
no_arg:
		    Wprintf(WPDialog, "Expected argument after -%c\r\n", ii);
		    return EXIT_ERROR;
	        }
		command_file = s;
		continue;
	    case 'C':     /* default number of copies */
		if (*s == 0) { ++argv; --argc; s = *argv; }
		if (argc <= 0 || *s == 0) goto no_arg;
		default_copies = strtol(s, &t, 0);
		if (s == t || *t != 0) goto no_numb;
		continue;
	    case 'd':     /* FID defines filename */
		if (*s == 0) { ++argv; --argc; s = *argv; }
		if (argc <= 0 || *s == 0) goto no_arg;
		continue;		/* accepted but not implemented */
	    case 'D':     /* debug level */
		if (*s == 0) { ++argv; --argc; s = *argv; }
		if (argc <= 0 || *s == 0) goto no_arg;
		debug_level = strtol(s, &t, 0);
		if (s == t || *t != 0) goto no_numb;
		continue;
	    case 'F':	/* init mode */
		init = 1;
		++force; /* don't bother to fstat anything */
		continue;
	    case 'f':	/* force mode */
		++force;
		continue;
	    case 'h':     /* host name */
		if (*s == 0) { ++argv; --argc; s = *argv; }
		if (argc <= 0 || *s == 0) goto no_arg;
		cmd_ice.host = poll_ice.host = s;
		continue;
	    case 'i':	/* image mode (delete files afterwards) */
		++image_mode;
		continue;
	    case 'I':	/* copy files if dates are different instead of less */
		++date_diff;
		continue;
	    case 'l':	/* get directory */
		if (*s == 0) {
		    get_dir = 1;
		} else if (*s == 'd') {
		    get_dir = 2;
		} else if (*s == 'a') {
		    get_dir = 3;
		} else if (*s == 'r') {
		    get_dir = 4;
		} else if (*s == 'f') {
		    get_dir = 5;
		} else if (*s == 'p') {
		    get_dir = 6;		/* Dump partition table */
		    nomount = 1;		/* No need to mount fsys for this */
		} else {
		    Wprintf(WPDialog, "Argument after -l can be only 'a', 'd' or 'r'\r\n");
		    return EXIT_ERROR;
		}		    
		continue;
	    case 'm':
		if (*s == 0) { ++argv; --argc; s = *argv; }
		if (argc <= 0 || *s == 0) goto no_arg;
		max_packet_size = strtol(s, &t, 0);
		if (s == t || *t != 0) goto no_numb;
		if (max_packet_size > MAX_PKT_SIZE) max_packet_size = MAX_PKT_SIZE;
		continue;
	    case 'M':
		if (*s == 0) { ++argv; --argc; s = *argv; }
		if (argc <= 0 || *s == 0) goto no_arg;
		max_numb_packets = strtol(s, &t, 0);
		if (s == t || *t != 0) goto no_numb;
		if (max_numb_packets > MAX_NUMB_PACKETS) max_numb_packets = MAX_NUMB_PACKETS;
		continue;
	    case 'n':	  /* no reset on init */
		no_reset = 1;
		continue;
	    case 'N':	  /* no ping mode */
		nomount = 1;
		continue;
	    case 'p':     /* port number */
		if (*s == 0) { ++argv; --argc; s = *argv; }
		if (argc <= 0 || *s == 0) goto no_arg;
		port = strtol(s, &t, 0);
		if (s == t || *t != 0) {
no_numb:
		    Wprintf(WPDialog, "Expected decimal number after -%c: %s\r\n", ii, s);
		    return EXIT_ERROR;
	        }
		continue;
	    case 'r':     /* patnet port number */
		if (*s == 0) { ++argv; --argc; s = *argv; }
		if (argc <= 0 || *s == 0) goto no_arg;
		cmd_ice.patnet = poll_ice.patnet = strtol(s, &t, 0);
		if (s == t || *t != 0) goto no_numb;
		continue;
	    case 't':     /* thread */
		if (*s == 0) { ++argv; --argc; s = *argv; }
		if (argc <= 0 || *s == 0) goto no_arg;
		cmd_ice.thread = poll_ice.thread = strtol(s, &t, 0);
		if (s == t || *t != 0) goto no_numb;
		continue;
	    case 'T':     /* timeout */
		if (*s == 'm') {	/* mount timeout */
		    ++s;
		    if (*s == 0) { ++argv; --argc; s = *argv; }
		    if (argc <= 0 || *s == 0) goto no_arg;
		    mount_timeout = strtol(s, &t, 0);
		    if (s == t || *t != 0) goto no_numb;
		} else {		    
		    if (*s == 0) { ++argv; --argc; s = *argv; }
		    if (argc <= 0 || *s == 0) goto no_arg;
		    g_timeout = strtol(s, &t, 0);
		    if (s == t || *t != 0) goto no_numb;
		}
		continue;
	    case 'u':	  /* upload */
		upload = 1;
		continue;
	    case 'v':	  /* verify and update checksums */
		verify = 1;
		continue;
	    case 'V':	  /* verify but don't update checksums */
		verify = 2;
		continue;
	    case 'x':     /* x commands */
		if (*s == 0) { ++argv; --argc; s = *argv; }
		if (argc <= 0 || *s == 0) goto no_arg;
		x_commands = strtol(s, &t, 0);
		if (s == t || *t != 0) goto no_numb;
		continue;
	    case 'z': {	  /* z command */
		int c;
		if (*s == 0) { ++argv; --argc; s = *argv; }
		if (argc <= 0 || *s == 0) goto no_arg;
		squeeze_em = strtol(s, &t, 0);
		if (s == t) goto no_numb;
		c = *t++;			/* pickup char after number */
		if (!c) continue;		/* nothing left. its ok as is */
		if (*t != 0) goto no_numb;	/* if not null, bad */
		if (islower(c)) c = toupper(c);	/* up case it */
		if (c == 'K') {			/* if wants K */
		    squeeze_em *= 1024;		/* adjust amount */
		} else if (c == 'M') {		/* if wants M */
		    squeeze_em *= 1024*1024;	/* adjust amount */
		} else {
		    goto no_numb;		/* any other char is crap */
		}
		continue;
	    }
	    case 'Z':     /* Compression factor */
		if (*s == 0) { ++argv; --argc; s = *argv; }
		if (argc <= 0 || *s == 0) goto no_arg;
		compression_factor = strtol(s, &t, 0);
		if (s == t || *t != 0) goto no_numb;
		if (compression_factor < 1 || compression_factor > 7) {
		    Wprintf(WPDialog, "Expected decimal number between 1 and 7 after -%c: %s\r\n",
		    		ii, s);
		    return EXIT_ERROR;
		}
		continue;
	}
    }

    if (get_dir) quiet = 1;		/* suppress announcements */

    if (!(debug_level&DBG_SHO_CMD) && isatty(fileno(stdout)) && !quiet) {
	need_erase = 1;
	eol_char = "\r";
	bol_char = "\r\n";
    }
    if (!quiet) {
#if 0
	Wprintf(WPDialog, "%s Copyright 1996-1999 Atari Games Corp. Version " __DATE__ " " __TIME__ "\n",
		image_name);
#else
	Wprintf(WPDialog, "%s Copyright 2000 Midway Games West, Inc. Version " __DATE__ " " __TIME__ "\n",
		image_name);
#endif
    }
    if (!cmd_ice.host) {
	cmd_ice.host = poll_ice.host = getenv("ASCHOST");
	if (!cmd_ice.host) {
	    Wputs("No ASCLEAP hostname provided. Use '-h host' or set environment variable ASCHOST.\n", WPDialog);
	    help_him(0);
	    return EXIT_ERROR;
	}
    }

    if (port <= 0) {
	Wprintf(WPDialog, "Port number invalid.\n");
	return EXIT_ERROR;
    }

    poll_ice.buf_size = cmd_ice.buf_size = max_packet_size + PKTuser;
    cmd_ice.buf = malloc(cmd_ice.buf_size);
    poll_ice.buf = malloc(poll_ice.buf_size);

    cmd_ice.port = poll_ice.port = port;

    if (!x_commands) {
	if (get_dir && !command_file) command_file = "/dev/null";
	if (!command_file) {
	    Wputs("No command file provided. Use '-c file' to set one\n", WPDialog);
	    help_him(0);
	    return EXIT_ERROR;
	}
	if (get_command_file(command_file, argc, argv, upload ? -1 : force) || parse_errors) {
	    return EXIT_ERROR;
	}
	if (!stats_next && !get_dir && !init) return EXIT_SUCCESS;
    }

    iop = open_connection(&cmd_ice, !init || no_reset);

    if (!upload && !get_dir && init) {
	MoleInitFSExt *efs;
	ParseUnion *pu;
	char *ptr;

	if (!no_reset) {
	    Wprintf(WPDialog, "Initialize requires a reset. Reseting target ...\n");
	    send_to_asap(iop, ICEreset, &cmd_ice);	/* reset the game */
	    Wprintf(WPDialog, "Waiting for it to reboot ...\n");
	    sleep(6);			/* wait a little */
	    sync_up(iop, &cmd_ice);	/* reconnect to hddnl */
	}

	if (partitions[0].line || partitions[1].line || partitions[2].line || partitions[3].line) {
	    char *name = "/rd0/.";
	    ParseUnion *pu;
	    MolePartitionExt *mp;
	    MolePartitions *mpi;
	    int loop, inner, cyl, trk, sec, part_errors=0;
	    int max_cyl, trk_p_cyl, sec_p_trk, sec_p_cyl;
	    U32 max_lba, lba, nlba;
	    U8 *up;

	    if ((pu=volume_details) && pu->v.phys) { /* phys name supplied on VOLUME command */
		name = pu->v.phys;
	    }
	    if (do_cmd(iop, &cmd_ice, "issuing get_partition()", MOLE_GETPART, (U8*)name, strlen(name)+1, 0)) {
		EXIT(EXIT_ERROR);
	    }
	    mp = (MolePartitionExt *)cmd_ice.u_data;
	    up = (U8*)(mp+4);					/* point to max lba */
	    max_lba = (up[0]<<24) | (up[1]<<16) | (up[2]<<8) | up[3];
	    max_cyl = (up[4]<<8) | up[5];
	    trk_p_cyl = up[6];
	    if (!trk_p_cyl) trk_p_cyl = 64;		/* give 'em some defaults */
	    sec_p_trk = up[7];
	    if (!sec_p_trk) sec_p_trk = 63;		/* give 'em some defaults */
	    sec_p_cyl = sec_p_trk*trk_p_cyl;
	    mpi = partitions;
	    for (loop=0; loop < 4; ++loop, ++mpi) {
		if (!mpi->line) {			/* if user didn't spec this partition */
		    mpi->type = mp->type;		/* clone what is currently on the drive */
		    mpi->status = mp->status;
		    mpi->start_lba = (mp->abs_sect[3]<<24) | (mp->abs_sect[2]<<16) |
					(mp->abs_sect[1]<<8) | mp->abs_sect[0];
		    mpi->num_lbas = (mp->num_sects[3]<<24) | (mp->num_sects[2]<<16) |
					(mp->num_sects[1]<<8) | mp->num_sects[0];
		}
		if (!mpi->type) {
		    mpi->start_lba = 0;
		    mpi->num_lbas = 0;
		    continue;
		}
		lba = mpi->start_lba;
		nlba = mpi->num_lbas;
		if (!lba) {				/* can't use sector 0 */
		    ++lba;
		    --nlba;
		}
		cyl = lba + nlba;			/* compute address of last sector */
		if (lba >= max_lba) {
		    Wprintf(WPDialog, "%s Partition %d starts 0x%08lX sectors beyond end of medium.\n",
			image_name, loop, lba-max_lba);
		    ++part_errors;
		    continue;
		}
		if (cyl > max_lba) {
		    Wprintf(WPDialog, "%s Warning: partition %d extends 0x%08lX sectors beyond end of medium.\n",
			image_name, loop, cyl - max_lba);
		    nlba = max_lba - lba;		/* limit size to end of medium */
		}
		mpi->start_lba = lba;			/* record starting sector */
		mpi->num_lbas = nlba;			/* record number of sectors */
	    }
	    mpi = partitions;
	    for (loop=0; loop < 3; ++loop, ++mpi) {
		if (mpi->type) {
		    MolePartitions *mpiin;
		    lba = mpi->start_lba;
		    nlba = mpi->num_lbas;
		    cyl = lba + nlba;
		    mpiin = mpi+1;
		    inner = loop+1;
		    for (; inner < 4; ++inner, ++mpiin) {
			if (!mpiin->type) continue;
			if (mpiin->start_lba >= cyl) continue;
			if (mpiin->start_lba+mpiin->num_lbas <= lba) continue;
			Wprintf(WPDialog, "%s:%d Partition %d overlaps partition %d defined on line %d\n",
    				image_name, mpi->line, loop, inner, mpiin->line);
			++part_errors;
		    }
		}
	    }
	    if (part_errors) {
		Wprintf(WPDialog, "%s Due to partition table errors, no action performed\n", image_name);
		EXIT(1);
	    }
	    mpi = partitions;
	    for (loop=0; loop < 4; ++loop, ++mp, ++mpi) {
		if (!mpi->line) continue;		/* skip types not specified by the user */
		lba = mpi->start_lba;
		nlba = mpi->num_lbas;
		cyl = lba / sec_p_cyl;			/* total sectors/sectors_cyl = cylinders */
		if (cyl >= max_cyl || cyl >= 1024) {
		    cyl = cyl >= 1024 ? 1023 : max_cyl;	/* max the starting cylinder */
		    trk = 0;
		    sec = 1;
		} else {
		    trk = (lba - (cyl * sec_p_cyl))/sec_p_trk; /* remaining sectors/sectors_trk = trks */
		    sec = (lba % sec_p_trk)+1;		/* starting sector */
		}
		mp->abs_sect[3] = lba>>24;
		mp->abs_sect[2] = lba>>16;
		mp->abs_sect[1] = lba>>8;
		mp->abs_sect[0] = lba;
		mp->num_sects[3] = nlba>>24;
		mp->num_sects[2] = nlba>>16;
		mp->num_sects[1] = nlba>>8;
		mp->num_sects[0] = nlba;
		mp->status = mpi->status;
		mp->type = mpi->type;
		mp->st_sectcyl[0] = (sec&0x3f) | ((cyl&0x300)>>2);
		mp->st_sectcyl[1] = cyl;
		mp->st_head = trk;
		lba += nlba-1;				/* ending sector */
		cyl = lba / sec_p_cyl;
		if (cyl >= max_cyl || cyl >= 1024) {
		    cyl = cyl >= 1024 ? 1023 : max_cyl;	/* max the starting cylinder */
		    trk = trk_p_cyl-1;
		    sec = sec_p_trk;
		} else {
		    trk = (lba - (cyl * sec_p_cyl))/sec_p_trk; /* remaining sectors/sectors_trk = trks */
		    sec = (lba % sec_p_trk)+1;		/* ending sector */
		}
		mp->en_sectcyl[0] = (sec&0x3f) | ((cyl&0x300)>>2);
		mp->en_sectcyl[1] = cyl;
		mp->en_head = trk;
		if ((debug_level&DBG_SHO_CMD)) {
		    printf("Partition %d, status:%02X, type:%02X, lba:%08lX, num:%08lX, s_c/h/s: %03X/%02X/%02X, e_c/h/s: %03X/%02X/%02X\n",
			loop, mp->status, mp->type, mpi->start_lba, mpi->num_lbas,
			((mp->st_sectcyl[0]&0xC0)<<2) | mp->st_sectcyl[1],
			  mp->st_head, mp->st_sectcyl[0]&0x3F,
			((mp->en_sectcyl[0]&0xC0)<<2) | mp->en_sectcyl[1],
			  mp->en_head, mp->en_sectcyl[0]&0x3F);
		}
	    }
	    mp = (MolePartitionExt *)cmd_ice.u_data;
	    up = (U8*)(mp+4);
	    strcpy((char *)up, name);
	    up += strlen(name)+1;
	    if (do_cmd(iop, &cmd_ice, "issuing set_partition()", MOLE_SETPART, (U8*)mp, up-cmd_ice.u_data, 0)) {
		EXIT(EXIT_ERROR);
	    }
	}
	if (!(pu=volume_details)) {
	    efs = malloc(sizeof(MoleInitFSExt)+6);
	    if (!efs) {
		Wprintf(WPDialog, "Ran out of memory alloc'ing %d bytes\n", sizeof(MoleInitFSExt)+6);
		exit (EXIT_ERROR);
	    }
	    memset((char *)efs, 0, sizeof(MoleInitFSExt));
	    efs->cluster = 1;
	    ptr = (char *)(efs+1);
	    efs->phys = ptr - (char *)efs;
	    strcpy(ptr, "/rd0");
	    ptr += strlen(ptr)+1;
	    efs->virt = ptr - (char *)efs;
	    *ptr++ = 0;				/* null virtual name */
	} else {
	    int l;
	    l = sizeof(MoleInitFSExt)+2;
	    if (pu->v.phys) l += strlen(pu->v.phys);
	    if (pu->v.virt) l += strlen(pu->v.virt);
	    efs = malloc(l);
	    efs->cluster = pu->v.cluster ? pu->v.cluster : 1;
	    efs->index_sectors[0] = pu->v.index_sectors>>(3*8);
	    efs->index_sectors[1] = pu->v.index_sectors>>(2*8);
	    efs->index_sectors[2] = pu->v.index_sectors>>(1*8);
	    efs->index_sectors[3] = pu->v.index_sectors>>(0*8);
	    efs->free_sectors[0] = pu->v.free_sectors>>(3*8);
	    efs->free_sectors[1] = pu->v.free_sectors>>(2*8);
	    efs->free_sectors[2] = pu->v.free_sectors>>(1*8);
	    efs->free_sectors[3] = pu->v.free_sectors>>(0*8);
	    efs->root_sectors[0] = pu->v.root_sectors>>(3*8);
	    efs->root_sectors[1] = pu->v.root_sectors>>(2*8);
	    efs->root_sectors[2] = pu->v.root_sectors>>(1*8);
	    efs->root_sectors[3] = pu->v.root_sectors>>(0*8);
	    efs->default_extend[0] = pu->v.def_extend>>(3*8);
	    efs->default_extend[1] = pu->v.def_extend>>(2*8);
	    efs->default_extend[2] = pu->v.def_extend>>(1*8);
	    efs->default_extend[3] = pu->v.def_extend>>(0*8);
	    efs->max_lba[0] = pu->v.max_lba>>(3*8);
	    efs->max_lba[1] = pu->v.max_lba>>(2*8);
	    efs->max_lba[2] = pu->v.max_lba>>(1*8);
	    efs->max_lba[3] = pu->v.max_lba>>(0*8);
	    efs->hb_range[0] = pu->v.hb_range>>(3*8);
	    efs->hb_range[1] = pu->v.hb_range>>(2*8);
	    efs->hb_range[2] = pu->v.hb_range>>(1*8);
	    efs->hb_range[3] = pu->v.hb_range>>(0*8);
	    efs->jou_sectors[0] = pu->v.jou_sectors>>(3*8);
	    efs->jou_sectors[1] = pu->v.jou_sectors>>(2*8);
	    efs->jou_sectors[2] = pu->v.jou_sectors>>(1*8);
	    efs->jou_sectors[3] = pu->v.jou_sectors>>(0*8);
	    efs->phys = sizeof(MoleInitFSExt);
	    ptr = (char *)efs + efs->phys;
	    if (!pu->v.phys) {
		*ptr++ = 0;
	    } else {
		strcpy(ptr, pu->v.phys);
		ptr += strlen(pu->v.phys)+1;
	    }
	    efs->virt = ptr - (char *)efs;
	    if (!pu->v.virt) {
		*ptr++ = 0;
	    } else {
		strcpy(ptr, pu->v.virt);
		ptr += strlen(pu->v.virt)+1;
	    }
	}
	Wprintf(WPDialog, "Initializing volume ...\n");
	if (do_cmd(iop, &cmd_ice, "init'ing filesystem", MOLE_INITFS, (unsigned char *)efs, ptr-(char *)efs, 0)) {
	    exit (EXIT_ERROR);
	}
    }
    if (!nomount) {
	MoleMountExt *mnt;
	ParseUnion *pu;
	char *ptr;
	int old_gtime;
	if (!(pu=volume_details)) {
	    mnt = malloc(sizeof(MoleMountExt)+4+1+3+1);
	    if (!mnt) {
		Wprintf(WPDialog, "Ran out of memory alloc'ing %d bytes\n", sizeof(MoleMountExt)+6);
		exit (EXIT_ERROR);
	    }
	    mnt->type = 0;
	    ptr = (char *)(mnt+1);
	    mnt->phys = ptr - (char *)mnt;
	    strcpy(ptr, "/rd0");
	    ptr += strlen(ptr)+1;
	    mnt->virt = ptr - (char *)mnt;
	    strcpy(ptr, "/d0");
	    ptr += strlen(ptr)+1;
	} else {
	    int l;
	    l = sizeof(MoleMountExt)+2;
	    if (pu->v.phys) l += strlen(pu->v.phys);
	    if (pu->v.virt) l += strlen(pu->v.virt);
	    mnt = malloc(l);
	    mnt->type = 0;
	    ptr = (char *)(mnt+1);
	    mnt->phys = ptr - (char *)mnt;
	    if (!pu->v.phys) {
		*ptr++ = 0;
	    } else {
		strcpy(ptr, pu->v.phys);
		ptr += strlen(pu->v.phys)+1;
	    }
	    mnt->virt = ptr - (char *)mnt;
	    if (!pu->v.virt) {
		*ptr++ = 0;
	    } else {
		strcpy(ptr, pu->v.virt);
		ptr += strlen(pu->v.virt)+1;
	    }
	}
	old_gtime = g_timeout;
	g_timeout = mount_timeout * 1000;
	if (do_cmd(iop, &cmd_ice, "mount()'ing filesystem", MOLE_MOUNT, (unsigned char *)mnt, ptr-(char *)mnt, 0)) {
	    EXIT(EXIT_ERROR);
	}
	g_timeout = old_gtime;
	free(mnt);
    }
    if (x_commands) {
	exit_sts = do_x_commands(iop, x_commands);
    } else if (get_dir) {
	FHeader *fh;
	if (port == ASC_PORT) {
	    if (get_dir == 6) {			/* dump partition table */
		char *name = "/rd0/.";
		ParseUnion *pu;
		MolePartitionExt *mp;
		int loop;
		U32 blocks;
		U8 *up;

		if ((pu=volume_details) && pu->v.phys) { /* phys name supplied on VOLUME command */
		    name = pu->v.phys;
		}
		if (do_cmd(iop, &cmd_ice, "issuing get_partition()", MOLE_GETPART, (U8*)name, strlen(name)+1, 0)) {
		    EXIT(EXIT_ERROR);
		}
		mp = (MolePartitionExt *)cmd_ice.u_data;
		for (loop=0; loop < 4; ++loop, ++mp) {
		    int scyl, ssect, ecyl, esect;
		    U32 asect, nsect;
		    asect = (mp->abs_sect[3]<<24) | (mp->abs_sect[2]<<16) |
    				   (mp->abs_sect[1]<<8) | mp->abs_sect[0];
		    nsect = (mp->num_sects[3]<<24) | (mp->num_sects[2]<<16) |
    				    (mp->num_sects[1]<<8) | mp->num_sects[0];
		    ssect = mp->st_sectcyl[0]&0x3F;
		    scyl = mp->st_sectcyl[1] | ((mp->st_sectcyl[0]&0xC0)<<2);
		    esect = mp->en_sectcyl[0]&0x3F;
		    ecyl = mp->en_sectcyl[1] | ((mp->en_sectcyl[0]&0xC0)<<2);
		    Wprintf(WPDialog, "%d: sts=%02X, typ=%02X, st_c/h/s=%03X/%02X/%02X, en_c/h/s=%03X/%02X/%02X, sec=%08lX, num=%08lX\n",
			loop, mp->status, mp->type, scyl, mp->st_head, ssect, ecyl, mp->en_head, esect,
			asect, nsect);
		}
		up = (U8*)mp;
		blocks = (up[0]<<24) | (up[1]<<16) | (up[2]<<8) | up[3];
		Wprintf(WPDialog, "Disk size: %08lX sectors. Phys c/h/s: %04X/%02X/%02X\n",
		    blocks, (up[4]<<8) | up[5], up[6], up[7]);
	    } else {				/* any other directory */
		exit_sts = do_get_dir(iop, &get_dir);
		fh = remote_fhs;
		if (!get_dir || !fh) {
		    Wprintf(WPDialog, "Directory listings not supported by remote hddnl. You need to get an update.\n");
		} else if (!exit_sts) {
		    char *prefix = "/d0/";
		    fh += 2;			/* point to root directory */
		    if ((get_dir&HDDNL_DIR_CMDFILE)) {
			printf("DEFAULT UNIX=. GAME=/d0\n");
			prefix = "";
		    }
		    print_dirs(get_dir, fh->directory, prefix);
		}
	    }
	}
    } else {
	int flags = 2;
	if (port == ASC_PORT) {
	    exit_sts = do_get_dir(iop, &flags);	/* get names, dates and sizes */
	} else {
	    exit_sts = 0;
	}
	if (!exit_sts) {
	    if (upload) {
		if (squeeze_em) {
		    Wprintf(WPDialog, "Sorry, compression during uploads is not supported at this time.\n");
		    Wprintf(WPDialog, "Compression mode disabled.\n");
		    squeeze_em = 0;
		}
		exit_sts = read_files(iop);
	    } else {
		exit_sts = erase_files(iop);
		exit_sts = write_files(iop);
		if (!exit_sts && port == ASC_PORT) {
		    if (image_mode) {
			FHeader *fh;
			if (!(fh=remote_fhs)) {
			    Wprintf(WPDialog, "%sRemote hddnl doesn't support deletes. You need to get an update.\n",
	    				bol_char);
			} else {
			    fh += 2;
			    delete_files(iop, fh->directory, "/d0");
			}
		    }
		}
	    }
	}
    }
    if (need_erase) {
	printf(erase);
	printf("\n");
    }
    put_iceless(iop, &cmd_ice, 0, 0, MOLE_GOODBYE);
    ascleapio_close(iop);
    sleep100(90);	/* sleep 900 milliseconds */
    sleep100(60);	/* sleep 600 milliseconds */
    return exit_sts;    
}
