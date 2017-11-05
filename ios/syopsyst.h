/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : OS-dependent definitions
 *                 This file is expected to be modified during porting
 *--------------------------------------------------------------------
 * MODULE        : SY - System-dependent
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 22-May-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _SYOPSYST_H_
#define _SYOPSYST_H_

#include "sycommon.h"

/* OS Name */

#define SY_OSNAME       "RedHat Linux"                   /* Operating system name */


#define syAssert(_stat_)        assert(_stat_)          /* assert macro */

/*
    Time and random functions
    -------------------------

  see also syGetTimeAccuracy() in the platform-dependet file

 */

#define syGetTimeInSec()     time(0)         /* system (Posix) time in seconds from 1-Jan-1970 */


NQ_TIME syGetTimeInMsec(void);
NQ_TIME syConvertTimeSpecToTimeInMsec(void * val);
/* Get time zone difference in munites */
NQ_INT
syGetTimeZone(
    void
    );

#define sySetRand()     srand((unsigned int)time(0))  /* take seed from the system time */
#define syRand()        rand()          /* next (pseudo)random value */

/* Decompose system time into fragments */
void
syDecomposeTime(
    NQ_UINT32 time,                     /* system time */
    SYTimeFragments* decomposed         /* structure of file fragments */
    );

/* Compose system time from fragments */
NQ_UINT32                                 /* composed system time */
syComposeTime(
    const SYTimeFragments* decomposed   /* structure of file fragments */
    );

/* Wait a number of seconds. */
#define sySleep(_secs_) sleep(_secs_)

/*
    Threads
    -------

  Thread management calls.
 */

#define SYThread					pthread_t				/* TID - thread handle */
#define syIsValidThread(_taskId_)	TRUE

#define syThreadGetCurrent		    pthread_self
void syThreadStart(SYThread *taskIdPtr, void (*startpoint)(void), NQ_BOOL background);
#define syThreadDestroy(_taskId_)   pthread_cancel(_taskId_);

/*
    Semaphores
    ----------

 1) We use mutex semaphores or simulate their behavior if the OS does not
 support pure mutex semaphores.
 2) We use binary semaphores

 */
//#define SY_SEMAPHORE_AVAILABLE

/* mutex */
#define SYMutex                       pthread_mutex_t

void syMutexCreate(SYMutex* _m);

#ifdef MUTEX_DEBUG
/* Mutex functions - add prints per mutex create, take, give, destroy */
void syMutexDelete(SYMutex* _m);
void syMutexTake(SYMutex* _m);
void syMutexGive(SYMutex* _m);

#else
/* regular mutex operations */
#define syMutexDelete(_m)             pthread_mutex_destroy(_m)
#define syMutexTake(_m)               pthread_mutex_lock(_m)
#define syMutexGive(_m)               pthread_mutex_unlock(_m)
#endif

/* counting semaphore */
#define SYSemaphore                   sem_t

#define sySemaphoreCreate(_s, _count) sem_init(_s, 0, _count)
#define sySemaphoreDelete(_s)         sem_destroy(&_s)
#define sySemaphoreTake(_s)           sem_wait(&_s)
#define sySemaphoreGive(_s)           sem_post(&_s)
#define sySemaphoreGetCount(_s , _val) sem_getvalue(&_s , _val)
NQ_INT	sySemaphoreTimedTake( SYSemaphore *sem , NQ_INT timeout);

/*
    Sockets
    -------

 Most socket operations are BSD 4.x standard calls. However, a few very specific
 operations are OS-dependent. For a BSD-complient system use definitions below

 */

/* Definition of "loopback address". This may be different for different OS. The
   standard value is 127.0.0.1 for IPv4 and ::1 for IPv6 (in NBO), however, some
   OS require a value of O. */

#ifdef UD_NQ_USETRANSPORTIPV6

#ifdef SY_LITTLEENDIANHOST
#define SY_LOCALHOSTIP4 /*{0, 0} */  {0x007f, 0x0100} 
#define SY_LOCALHOSTIP6 {0, 0, 0, 0, 0, 0, 0, 0} /* {0, 0, 0, 0, 0, 0, 0, 0x0100} */
#define SY_LINKLOCALIP  0x80fe
#else /* SY_LITTLEENDIANHOST */
#define SY_LOCALHOSTIP4 /*{0, 0} */ {0x7f00 , 0x0001} 
#define SY_LOCALHOSTIP6 {0, 0, 0, 0, 0, 0, 0, 0} /* {0, 0, 0, 0, 0, 0, 0, 1} */
#define SY_LINKLOCALIP  0xfe80
#endif /* SY_LITTLEENDIANHOST */
#define SY_ANYIP4       {0, 0}
#define SY_ANYIP6       {0, 0, 0, 0, 0, 0, 0, 0}
#define SY_ZEROIP       {0, 0, 0, 0, 0, 0, 0, 0}

#else /* UD_NQ_USETRANSPORTIPV6 */

#ifdef SY_LITTLEENDIANHOST
#define SY_LOCALHOSTIP     0x0100007f
#else /* SY_LITTLEENDIANHOST */
#define SY_LOCALHOSTIP     0x7f000001
#endif /* SY_LITTLEENDIANHOST */
#define SY_ANYIP        0L
#define SY_ZEROIP       0L

#endif /* UD_NQ_USETRANSPORTIPV6 */

#define SY_ZEROIP4      0L

/*#define SY_INTERNALSOCKETPOOL*/       /* define this parameter to use internal socket pool, comment
                                       for per-task pool */
#define SYSocketHandle              NQ_INT
#define SYSocketSet                 fd_set
#define syIsValidSocket(_sock)      (_sock != ERROR)

#ifdef UD_NQ_USETRANSPORTIPV6
/* get IPv6 scope ID */
NQ_UINT32
syGetIPv6ScopeId(
    const NQ_IPADDRESS6 ip
    );
#endif /* UD_NQ_USETRANSPORTIPV6 */

/* Detecting whether a socket is still alive */
NQ_BOOL
syIsSocketAlive(
    SYSocketHandle sock     /* socket handle */
    );

#define syInvalidSocket()                   (ERROR)
#define syAddSocketToSet(_sock, _set)       FD_SET((_sock), (_set))
#define syIsSocketSet(_sock, _set)          FD_ISSET((_sock), (_set))
#define syClearSocketSet(_set)              FD_ZERO((_set))
/*@@syClearSocketFromSet
   Description
   Remove a socket from a socket set.
   Parameters
   _sock :  The socket to remove.
   _set :   Socket set.
   Returns
   None                               */
#define syClearSocketFromSet(_sock, _set)   FD_CLR((_sock), (_set))


/* Stop socket operations and disconnect the socket if it was connected */
NQ_STATUS
syShutdownSocket(
    SYSocketHandle sock
    );

/* Close socket */
NQ_STATUS
syCloseSocket(
    SYSocketHandle sock
    );

/* listen on server socket */
NQ_STATUS
syListenSocket(
    SYSocketHandle sock,
    NQ_INT backlog
    );

/* Create new socket */
SYSocketHandle              /* new socket or invalid socket handle */
syCreateSocket(
    NQ_BOOL stream,          /* TRUE for TCP socket, FALSE for UDP socket */
    NQ_UINT family          /* CM_IPADDR_IPV4 for IPv4, CM_IPADDR_IPV6 for IPv6 */
    );

/* Bind socket to IP and port */

NQ_STATUS                   /* NQ_SUCCESS or NQ_FAIL */
syBindSocket(
    SYSocketHandle sock,    /* socket handle */
    const NQ_IPADDRESS *ip, /* IP to bind to in NBO */
    NQ_PORT port            /* port to bind to in NBO */
    );

/* Allow broadcasts on an UDP socket */

NQ_STATUS                   /* NQ_SUCCESS or NQ_FAIL */
syAllowBroadcastsSocket(
    SYSocketHandle sock     /* socket handle */
    );

/* Tune new client socket */
void
sySetClientSocketOptions(
    SYSocketHandle sock     /* socket handle */
    );

/* Get IP and port the socket is bound to */
void
syGetSocketPortAndIP(
    SYSocketHandle sock,    /* socket handle */
    NQ_IPADDRESS *ip,       /* buffer for IP address in NBO */
    NQ_PORT *port           /* buffer for port number in NBO */
    );

/* Send a UDP message to a specific addressee */
NQ_INT                          /* number of bytes sent or NQ_FAIL */
sySendToSocket(
    SYSocketHandle sock,        /* socket handle */
    const NQ_BYTE* buf,         /* data to send */
    NQ_COUNT len,               /* number of bytes to send */
    const NQ_IPADDRESS *ip,     /* IP address to send to in NBO */
    NQ_PORT port                /* port number to send to in NBO */
    );

/* Connect to a remote server port */
NQ_STATUS                   /* NQ_SUCCESS or NQ_FAIL */
syConnectSocket(
    SYSocketHandle sock,    /* socket handle */
    const NQ_IPADDRESS *ip, /* IP address of the server in NBO */
    NQ_PORT port            /* port number of the server in NBO */
    );

/* Send bytes over a connected socket */
NQ_INT                      /* NQ_SUCCESS or NQ_FAIL */
sySendSocket(
    SYSocketHandle sock,        /* socket handle */
    const NQ_BYTE* buf,     /* data to send */
    NQ_COUNT len            /* number of bytes to send */
    );

/* Send bytes asynchronously over a connected socket */
NQ_STATUS                   /* NQ_SUCCESS or NQ_FAIL */
sySendSocketAsync(
    SYSocketHandle sock,        /* socket handle */
    const NQ_BYTE* buf,     /* data to send */
    NQ_COUNT len,           /* number of bytes to send */
    void (*releaseFunc)(const NQ_BYTE*)   /* callback function for releasing the buffer */
    );

/* Select on sockets */
NQ_INT                      /* number of sockets with data pending, zero on timeout or */
                            /* NQ_FAIL on error */
sySelectSocket(
    SYSocketSet* pset,      /* pointer to the file set */
    NQ_UINT32 timeout       /* timeout in seconds */
    );

/* Receive a UDP message */
NQ_INT                      /* number of bytes received or NQ_FAIL */
syRecvFromSocket(
    SYSocketHandle sock,    /* socket handle */
    NQ_BYTE* buf,           /* receive buffer */
    NQ_COUNT len,           /* buffer length */
    NQ_IPADDRESS* ip,       /* buffer for sender IP address in NBO */
    NQ_PORT* port           /* buffer for sender port in NBO */
    );

/* Receive a UDP message from any sender */
NQ_INT                      /* number of bytes received or NQ_FAIL */
syRecvSocket(
    SYSocketHandle sock,    /* socket handle */
    NQ_BYTE* buf,           /* receive buffer */
    NQ_COUNT len            /* buffer length */
    );

/*@@
 Description
 Receive from a datagram or a TCP stream or time out if no data on sockets.
 Parameters
 sock : Socket handle.
 buf : Receive buffer.
 len : Buffer size.
 secs : Number of seconds to wait for data on sockets.
Returns
Number of bytes received or <i>NQ_FAIL</i> on error. */
NQ_INT syRecvSocketWithTimeout(SYSocketHandle sock, NQ_BYTE * buf, unsigned int len,  unsigned int secs);

/* Accept client socket */
SYSocketHandle              /* new socket ID or invalid handle */
syAcceptSocket(
    SYSocketHandle sock,    /* server socket handle */
    NQ_IPADDRESS* ip,       /* buffer for client IP address in NBO */
    NQ_PORT* port           /* buffer for client port in NBO */
    );

/* Send multicast datagram */
NQ_STATUS sySendMulticast(
    SYSocketHandle socket,  /* socket handle */ 
    const NQ_BYTE * buffer, /* data to send */
    NQ_COUNT length,        /* number of bytes to send */
    const NQ_IPADDRESS *ip, /* destination IP */
    NQ_PORT port);          /* destination port */

void sySubscribeToMulticast(SYSocketHandle socket,
		const NQ_IPADDRESS *ip
		);
#define sySetDatagramSocketOptions(_sock)
#define sySetStreamSocketOptions(_sock)

/*
    Tasks
    -----

  Task management calls. We assume that the target system answers the following
  generic model:
  - a task has a unique id (PID) that may be mapped onto a unique 32 bit number

 */

#define syGetPid()  getpid()

/*
    Directories
    -----------

 */

#define SYDirectory                     DIR*
#define syInvalidateDirectory(_pd)      *(_pd) = NULL
#define syIsValidDirectory(_d)          (_d != NULL)

/* Create directory */
NQ_STATUS                               /* NQ_SUCCESS or NQ_FAIL */
syCreateDirectory(
    const NQ_WCHAR* name                /* full directory path */
    );

/* Delete directory */
NQ_STATUS                               /* NQ_SUCCESS or NQ_FAIL */
syDeleteDirectory(
    const NQ_WCHAR* name                /* full directory path */
    );

/* Open directory by name */
SYDirectory                             /* directory handle or invalid handle */
syOpenDirectory(
    const NQ_WCHAR* name                /* full directory path */
    );

/* Open directory and read the first entry */
NQ_STATUS                               /* NQ_SUCCESS or NQ_FAIL */
syFirstDirectoryFile(
    const NQ_WCHAR* name,               /* full directory path */
    SYDirectory* pDir,                  /* buffer for directory handle */
    const NQ_WCHAR** fileName           /* buffer for a pointer to the file name */
    );

/* Read next directory entry */
NQ_STATUS                               /* NQ_SUCCESS or NQ_FAIL */
syNextDirectoryFile(
    SYDirectory dir,                    /* directory handle */
    const NQ_WCHAR** fileName           /* buffer for a pointer to the file name */
    );

NQ_STATUS
syCloseDirectory(
    SYDirectory dir
    );

/*
    Files
    -----

 */

/*#define SY_UNICODEFILESYSTEM*/        /* Whether the filesystem supports Unicode.
                                        Otherwise all filenames will be converted to
                                        ANSI even if CIFS is supporting UNICODE */

#define SY_PATHSEPARATOR    '/'         /* path separator character */

#define SYFile                          int             /* file handle */
#define syInvalidateFile(_f)            *_f = ERROR     /* set invalid file handle */
#define syIsValidFile(_file)            (_file!=ERROR)  /* check file handle */
#define syInvalidFile()                 (ERROR)

/* characters which are not acceptable by the file system as a file name */
#define SY_CP_FIRSTILLEGALCHAR          {0xe5}
#define SY_CP_ANYILLEGALCHAR            {0x7c, 0x5c}


/* Create and open new file */
SYFile                                  /* file handle or invalid handle */
syCreateFile(
    const NQ_WCHAR* name,               /* file name */
    NQ_BOOL denyread,                   /* true - to deny sharing for read */
    NQ_BOOL denyexecute,                /* true - to deny sharing for execute */
    NQ_BOOL denywrite                   /* true - to deny sharing for write */
    );

/* Delete file */
NQ_STATUS                               /* NQ_SUCCESS or NQ_FAIL */
syDeleteFile(
    const NQ_WCHAR* name                /* file name */
    );

/* Rename file */
NQ_STATUS                               /* NQ_SUCCESS or NQ_FAIL */
syRenameFile(
    const NQ_WCHAR* old,                /* file name */
    const NQ_WCHAR* newName             /* new file name */
    );

/* Open file for reading */
SYFile                                  /* file handle or invalid handle */
syOpenFileForRead(
    const NQ_WCHAR* name,               /* file name */
    NQ_BOOL denyread,                   /* true - to deny sharing for read */
    NQ_BOOL denyexecute,                /* true - to deny sharing for execute */
    NQ_BOOL denywrite                   /* true - to deny sharing for write */
    );

/* Open file for writing */
SYFile                                  /* file handle or invalid handle */
syOpenFileForWrite(
    const NQ_WCHAR* name,               /* file name */
    NQ_BOOL denyread,                   /* true - to deny sharing for read */
    NQ_BOOL denyexecute,                /* true - to deny sharing for execute */
    NQ_BOOL denywrite                   /* true - to deny sharing for write */
    );

/* Open file for reading and writing */
SYFile                                  /* file handle or invalid handle */
syOpenFileForReadWrite(
    const NQ_WCHAR* name,               /* file name */
    NQ_BOOL denyread,                   /* true - to deny sharing for read */
    NQ_BOOL denyexecute,                /* true - to deny sharing for execute */
    NQ_BOOL denywrite                   /* true - to deny sharing for write */
    );


/* Truncate file */ 
NQ_STATUS                               /* NQ_SUCCESS or NQ_FAIL */
syTruncateFile(
    SYFile file,                        /* file handle */
    NQ_UINT32 offLow,                   /* offset low */
    NQ_UINT32 offHigh                   /* offset high */
    );
    
#define syFlushFile(_file)                         ((fsync(_file)==OK)? NQ_SUCCESS:NQ_FAIL)

/* Read bytes from file */
NQ_INT                                  /* number of bytes read, zero on end of file, or NQ_FAIL */
syReadFile(
    SYFile file,                        /* file handle */
    NQ_BYTE* buf,                       /* buffer for data */
    NQ_COUNT len                        /* number of bytes to read */
    );

/* Write bytes into file */
NQ_INT                                  /* number of bytes written or NQ_FAIL */
syWriteFile(
    SYFile file,                        /* file handle */
    const NQ_BYTE* buf,                 /* bytes to write */
    NQ_COUNT len                        /* number of bytes to write */
    );

NQ_STATUS
syCloseFile(
    SYFile fd
    );

/* Position file relatively from the current position */
NQ_UINT32                               /* new file position or NQ_FAIL */
sySeekFileCurrent(
    SYFile file,                        /* file handle */
    NQ_INT32 off,                       /* low 32 bits of the offset */
    NQ_INT32 offHigh                    /* hight 32 bits of the offset */
    );

/* Position file from the beginning */
NQ_UINT32                               /* new file position or NQ_FAIL */
sySeekFileStart(
    SYFile file,                        /* file handle */
    NQ_UINT32 off,                      /* low 32 bits of the offset */
    NQ_UINT32 offHigh                   /* hight 32 bits of the offset */
    );

/* Position file from the end */
NQ_UINT32                               /* new file position or NQ_FAIL */
sySeekFileEnd(
    SYFile file,                        /* file handle */
    NQ_INT32 off,                       /* low 32 bits of the offset */
    NQ_INT32 offHigh                    /* hight 32 bits of the offset */
    );

#define syPrintf    printf
#define sySprintf   sprintf
#define sySnprintf   snprintf
#define syVsnprintf   vsnprintf
#define sySscanf    sscanf

/* Read file information structure by file handle */
NQ_STATUS                               /* NQ_SUCCESS or NQ_FAIL */
syGetFileInformation(
    SYFile file,                        /* file id */
    const NQ_WCHAR* fileName,           /* file name */
    SYFileInformation* fileInfo         /* file information structure */
    );

/* Read file information structure by file name */
NQ_STATUS                               /* NQ_SUCCESS or NQ_FAIL */
syGetFileInformationByName(
    const NQ_WCHAR* fileName,           /* file name */
    SYFileInformation* fileInfo         /* file information structure */
    );

/* Update file information by either file name or file handle */
NQ_STATUS                               /* NQ_SUCCESS or NQ_FAIL */
sySetFileInformation(
    const NQ_WCHAR* fileName,           /* file name */
    SYFile handle,                      /* file handle */
    const SYFileInformation* fileInfo   /* file information structure */
    );

/* Query volume information */
NQ_STATUS                               /* NQ_SUCCESS or NQ_FAIL */
syGetVolumeInformation(
    const NQ_WCHAR* name,               /* volume name */
    SYVolumeInformation *info           /* buffer for information */
    );

/* The following two functions are actually user-defined. These macros are used for properly
   redefining file descriptors */

#define syGetSecurityDescriptor(_f, _i, _b)     udGetSecurityDescriptor(_f, _i, _b)
#define sySetSecurityDescriptor(_f, _i, _b, _l) udSetSecurityDescriptor(_f, _i, _b, _l)

/*
    File locking
    ------------

  The default implementation is mere a placeholder

 */
                                                            
#define syUnlockFile(       \
            _file,          \
            _offsetHigh,    \
            _offsetLow,     \
            _lengthHigh,    \
            _lengthLow,     \
            _timeout        \
            )           ((_file==ERROR)? NQ_FAIL:NQ_SUCCESS)
#define syLockFile(         \
            _file,          \
            _offsetHigh,    \
            _offsetLow,     \
            _lengthHigh,    \
            _lengthLow,     \
            _lockType,      \
            _oplockLevel    \
            )           ((_file==ERROR)? NQ_FAIL:NQ_SUCCESS)
/*              
    Networking
    ----------

 */

#define   syGetHostName(_name, _nameLen)       gethostname((_name), (_nameLen))

#ifdef CM_NQ_STORAGE
/*@@syGmtToString@NQ_BYTE *@NQ_COUNT@NQ_TIME@NQ_CHAR *
   Description
   This function converts system time into GMT time and prints
   it according to the format (<i>fmt</i>).

   <b><i><c> @GMT-%Y.%m.%d-%H.%M.%S</c></i></b>
   Parameters
   strTime :  The buffer to return the string.
   size :     The buffer size.
   t :        Time in seconds from Jan 1, 1970 (Unix time).
   fmt :      The string format.
   Returns
   <i>TRUE</i> on success, <i>FALSE</i> on error.
   Note
   The format string in the example is currently the only one
   that need be supported.                                     */
NQ_BOOL syGmtToString(NQ_BYTE * strTime, NQ_COUNT size, NQ_UINT32 t, const NQ_CHAR * fmt);
#endif

/* find host IP by its name */
NQ_IPADDRESS4                   /* host IP */
syGetHostByName(
    const char* name            /* host name */
    );

#if defined(UD_NQ_USETRANSPORTIPV4) || defined(UD_NQ_USETRANSPORTIPV6)
/* returns the DNS initializations parameters */
void
syGetDnsParams(
    NQ_CHAR *domain,           /* The default domain target belongs to */
    NQ_IPADDRESS *server       /* The DNS server IP address */
    );
#endif /* defined(UD_NQ_USETRANSPORTIPV4) || defined(UD_NQ_USETRANSPORTIPV6) */

/* Convert last system error to SMB error */
NQ_UINT32               /* SMB error */
syGetLastSmbError(
    void
    );

/* Convert NQ error into system error */
void
sySetLastNqError(
    NQ_UINT32 nqErr        /* NQ error */
    );

/* Get MAC address by IP4 */

void
syGetMacAddress(
    NQ_IPADDRESS4 ip,       /* next IP address */
    NQ_BYTE* macBuffer      /* buffer for mac address */
    );

/* Get adapter information */
NQ_STATUS                   /* NQ_FAIL when there is no adapter with the given index,
                               NQ_SUCCESS when adapter information available */
syGetAdapter(
    NQ_INDEX adapterIdx,    /* adapter number (zero based) */
	NQ_INDEX * osIndex,		/* buffer for adapter index as defined by the OS */
    NQ_IPADDRESS4 *ip,      /* buffer for adapter IP in NBO */
    NQ_IPADDRESS6 *ip6,     /* buffer for adapter IPv6 in NBO */
    NQ_IPADDRESS4 *subnet,  /* buffer for subnet address in NBO */
	NQ_IPADDRESS4* pBcast, 	/* buffer for bcast address in NBO */
    NQ_IPADDRESS4 *wins     /* buffer for wins address in NBO (may be 0 for a B-node) */
    );

#ifdef UD_CS_INCLUDEDIRECTTRANSFER

/*
    Socket-to-file-to-socket data transfer
    --------------------------------------

 */


/* Start fragmented packet */
NQ_STATUS                   /* NQ_FAIL when this operation is not avaiiable 
                               NQ_SUCCESS when operation succeeded */
syDtStartPacket(
		SYSocketHandle sock	/* socket handle */
		);

/* End fragmented packet */
void
syDtEndPacket(
		SYSocketHandle sock	/* socket handle */
		);

/* Transfer bytes from socket to file */
NQ_STATUS                   	/* NQ_FAIL on error or NQ_SUCCESS when operation succeeded */
syDtFromSocket(
		SYSocketHandle sock,	/* socket handle */
		SYFile file,			/* file handle */
		NQ_COUNT * len			/* IN number of bytes to transfer, OUT bytes transferred */
		);

/* Transfer bytes from file to socket */
NQ_STATUS                   	/* NQ_FAIL on error or NQ_SUCCESS when operation succeeded */
syDtToSocket(
		SYSocketHandle sock,	/* socket handle */
		SYFile file,			/* file handle */
		NQ_COUNT * len			/* IN number of bytes to transfer, OUT bytes transferred */
		);

#endif /* UD_CS_INCLUDEDIRECTTRANSFER */

#ifdef UD_CC_INCLUDELDAP

/* Convert Unicode string to UTF8 */
void
syUnicodeToUTF8N(
    NQ_CHAR *u, 
    const NQ_WCHAR *w,
    NQ_COUNT size 
    );


/* Convert UTF8 string to Unicode */
void
syUTF8ToUnicodeN(
    NQ_WCHAR *w, 
    const NQ_CHAR *u,
    NQ_COUNT size 
    );
#endif

/* Convert UNIX file permissions to DOS file attributes */
int
syUnixMode2DosAttr(
    int mode
    );

#endif  /* _SYOPSYST_H_ */
