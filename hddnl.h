#ifndef _MOLE_H_
#define _MOLE_H_

#if !defined(WATCOM_LIBC) || !WATCOM_LIBC
#ifndef _ICELESSPKT_H_
#include <icelesspkt.h>
#endif
#endif

typedef enum mole_codes {
#if !defined(WATCOM_LIBC) || !WATCOM_LIBC
    PKTcs = PKTcmd+1,		/* checksum goes at first byte after command */
    MOLE_NOP=ICEnak+1,		/* do nothing */
    MOLE_RESYNC,		/* resync to packet sequence number (also HELLO msg) */
    MOLE_MOUNT,			/* mount the filesystem */
    MOLE_INITFS,		/* init the filesystem */
    MOLE_OPENFILE,		/* open a file/directory for I/O */
    MOLE_RDFILE,		/* read file last opened */
    MOLE_WRFILE,		/* write file last opened */
    MOLE_WRFILEack,		/* write file last opened send ack when done */
    MOLE_CLOSE,			/* close file last opened */
    MOLE_OPENDIR,		/* open a directory */
    MOLE_RDDIR,			/* read a directory */
    MOLE_FSTAT,			/* get file stats */
    MOLE_FSSTAT,		/* get filesystem stats */
    MOLE_EOF,			/* reports end of input */
    MOLE_RTEST,			/* receive test pattern */
    MOLE_RTESTack,		/* receive test pattern */
    MOLE_STEST,			/* send test pattern */
    MOLE_CCHKSUM,		/* compute checksum on file */
    MOLE_GOODBYE,		/* sign off */
    MOLE_GETPART,		/* Get partition table info */
    MOLE_SETPART,		/* Write partition table info */
    MOLE_MAX,			/* maximum number of mole commands */
#endif
    MOLE_ERR_NOTSUPP=1,		/* command not supported */
    MOLE_ERR_INVCMD,		/* invalid command */
    MOLE_ERR_OOS,		/* packet out of sequence */
    MOLE_ERR_CS,		/* checksum error */
    MOLE_ERR_INIT,		/* initfs error */
    MOLE_ERR_INVARG,		/* invalid argument */
    MOLE_ERR_MOUNT,		/* mount error */
    MOLE_ERR_CANTINIT,		/* cannot init (volume already mounted) */
    MOLE_ERR_NOIOQ,		/* no IOQ's left */
    MOLE_ERR_OPEN,		/* error issuing qio_openspc */
    MOLE_ERR_OPENDIR,		/* error issuing qio_open to check directory */
    MOLE_ERR_MKDIR,		/* error issuing qio_open to create directory */
    MOLE_ERR_CLOSE,		/* error doing close */
    MOLE_ERR_NOMEM,		/* ran out of memory */
    MOLE_ERR_WRITING,		/* error writing file */
    MOLE_ERR_READING,		/* error reading file */
    MOLE_ERR_DATA,		/* r/w test error */
    MOLE_ERR_ARMOUNT,		/* volume is already mounted */
    MOLE_ERR_OFFLINE,		/* drive is offline */
    MOLE_ERR_DELETE,		/* error deleting */
    MOLE_ERR_EOF,		/* end of file */
    MOLE_ERR_HOMEB,		/* error updating home blocks */
    MOLE_ERR_MAX
} MoleCodes;

/* Flag values for open(2) and fcntl(2)
 * The kernel adds 1 to the open modes to turn it into some
 * combination of FREAD and FWRITE.
 */
#define MOLE_O_RDONLY        0x00000000	/* +1 == FREAD */
#define MOLE_O_WRONLY        0x00000001	/* +1 == FWRITE */
#define MOLE_O_RDWR          0x00000002	/* +1 == FREAD|FWRITE */
#define MOLE_O_APPEND        0x00000004
#define MOLE_O_CREAT         0x00000008
#define MOLE_O_TRUNC         0x00000010
#define MOLE_O_EXCL          0x00000020
#define MOLE_V_COMPRESS	          6
#define MOLE_O_COMPRESS	     (7<<MOLE_V_COMPRESS)
#define MOLE_O_COMPRESS_OK   0x00000200
#define MOLE_O_FHBITS	     0x00000400	/* read file headers (valid only with MOLE_O_RDONLY | MOLE_O_COMPRESS) */
#define MOLE_O_FHBITS_OK     0x00000800	/* ok to read file headers */
#define MOLE_O_DELETE	     0x00001000	/* Don't actually open the file, delete it */
#define MOLE_V_BOOT          13
#define MOLE_M_BOOT          (7<<MOLE_V_BOOT) /* which boot mask */
#define MOLE_O_BOOT	     (1<<MOLE_V_BOOT) /* Make file into boot file */

#if !defined(WATCOM_LIBC) || !WATCOM_LIBC
#ifndef MAX_PKT_SIZE
#define MAX_PKT_SIZE	(1440) /* maximum number of bytes per packet (1k user + seq + cmd + 2*cs) */
#endif

typedef struct mole_stat_ext {
    U8 size[4];			/* file size in bytes */
    U8 alloc[4];		/* allocation amount */
    U8 rptrs[4];		/* number of retrieval pointers */
    U8 mode[4];			/* file mode */
    U8 ctime[4];		/* file creation time */
    U8 mtime[4];		/* file modification time */
    U8 atime[4];		/* file access time */
    U8 btime[4];		/* file backup time */
} MoleStatExt;

typedef struct mole_part_ext {
    U8 status;
    U8 st_head;
    U8 st_sectcyl[2];
    U8 type;
    U8 en_head;
    U8 en_sectcyl[2];
    U8 abs_sect[4];
    U8 num_sects[4];
} MolePartitionExt;

typedef struct mole_part_int {
    U8 status;
    U8 st_head;
    U16 st_sectcyl;
    U8 type;
    U8 en_head;
    U16 en_sectcyl;
    U32 abs_sect;
    U32 num_sects;
} MolePartitionInt;

typedef struct mole_mount_int {
    const char *phys;		/* physical device name */
    const char *virt;		/* virtual device name */
    int type;			/* filesystem type */
} MoleMountInt;

typedef struct mole_mount_ext {
    U8 phys;			/* index to null terminated phys name */
    U8 virt;			/* index to null terminated virtual name */
    U8 type;			/* filesystem type */
} MoleMountExt;

typedef struct mole_initfs_ext { /* network representation of initfs command */
    U8 cluster;			/* number of sectors per cluster */
    U8 index_sectors[4];	/* number of sectors to preallocate for index file */
    U8 free_sectors[4];		/* number of sectors to preallocate for freelist file */
    U8 root_sectors[4];		/* number of sectors to preallocate for root directory */
    U8 default_extend[4];	/* number of sectors to extend a file by default */
    U8 phys;			/* offset to null terminated physical device name */
    U8 virt;			/* offset to null terminated virtual device name */
    U8 max_lba[4];		/* maximum LBA for filesystem */
    U8 hb_range[4];		/* Home block range */
    U8 jou_sectors[4];		/* Journal size in sectors */
} MoleInitFSExt;

typedef struct mole_mkfile_ext {
    U8 fname;			/* index into buffer to null terminated filename string */
    U8 placement;		/* where on disk file is to be placed */
    U8 copies;			/* number of copies of file */
    U8 mkdir;			/* .ne. if to create directory */
    U8 cookie[4];		/* channel to use for subsequent read/write */
    U8 mode[4];			/* I/O mode bits */
    U8 fid[4];			/* FID to use to open (or FID of newly created file) */
    U8 parent[4];		/* FID of parent */
    U8 alloc[4];		/* file pre-allocation size in bytes */
    U8 eof[4];			/* where EOF is */
    U8 ctime[4];		/* file creation time */
    U8 mtime[4];		/* file modification time */
    U8 atime[4];		/* file access time */
    U8 btime[4];		/* file backup time */
    U8 def_extend[2];		/* default file extension (in sectors) */
} MoleMkFileExt;
#endif

#define hddnlfhbits parent	/* use the 'parent' field to hold the fhbits */
#define HDDNL_GETFH_ALLOC	0x0001	/* get allocation */
#define HDDNL_GETFH_SIZE	0x0002	/* get size */
#define HDDNL_GETFH_CTIME	0x0004	/* get c time */
#define HDDNL_GETFH_MTIME	0x0008	/* get m time */
#define HDDNL_GETFH_ATIME	0x0010	/* get a time */
#define HDDNL_GETFH_BTIME	0x0020	/* get b time */
#define HDDNL_GETFH_PERMS	0x0040	/* get perms */
#define HDDNL_GETFH_OWNER	0x0080	/* get owner */
#define HDDNL_GETFH_DIR		0x0100	/* get type (directory/non-directory) */
#define HDDNL_GETFH_NRPS	0x0200	/* get (max) number of retrieval pointers */
#define HDDNL_GETFH_COPIES	0x0400	/* get number of copies */
#define HDDNL_GETFH_DEFEXT	0x0800	/* get default extension */
#define HDDNL_GETFH_FIRSTRP	0x1000	/* get the first retrieval pointer */

#define HDDNL_GETFH_TYPE_MASK	0x03	/* file type mask */
#define HDDNL_GETFH_TYPE_INV	0x00	/* file is invalid */
#define HDDNL_GETFH_TYPE_PLAIN	0x01	/* file is plain */
#define HDDNL_GETFH_TYPE_DIR	0x02	/* file is directory */
#define HDDNL_GETFH_TYPE_BOOT	0x04	/* file is also boot file */
#define HDDNL_GETFH_TYPE_BOOT_V	   3	/* bit number of starting boot file index bits */
#define HDDNL_GETFH_TYPE_BOOT_B	   2	/* Number of bits of boot file index */
#endif
