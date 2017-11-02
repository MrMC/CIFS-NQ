/*************************************************************************
 * Copyright 2011-2012 by Visuality Systems, Ltd.
 *
 *                     All Rights Reserved
 *
 * This item is the property of Visuality Systems, Ltd., and contains
 * confidential, proprietary, and trade-secret information. It may not
 * be transferred from the custody or control of Visuality Systems, Ltd.,
 * except as expressly authorized in writing by an officer of Visuality
 * Systems, Ltd. Neither this item nor the information it contains may
 * be used, transferred, reproduced, published, or disclosed, in whole
 * or in part, and directly or indirectly, except as expressly authorized
 * by an officer of Visuality Systems, Ltd., pursuant to written agreement.
 **************************************************************************/

#ifndef _CCAPI_H_ 
#define _CCAPI_H_

#include "syapi.h"
#include "cmapi.h"
#include "amcredentials.h"
#include "ccconfig.h"


/*********************************************************************
 * Constants
 ********************************************************************/

/**** Credential fields length ****/
#define CM_USERNAMELENGTH   256     /* maximum user name length */
#define PASSWORD_LENGTH     UD_NQ_MAXPWDLEN /* maximum password length */
#define DOMAIN_LENGTH       (CM_NQ_HOSTNAMESIZE)    /* maximum domain name length */

/**** Notification events ****/
#define NOTIFY_SRCH_HANDLE_ERROR    1   /* An error occurred in Find File handle. Application should clean the related resources. */
#define NOTIFY_FILE_HANDLE_ERROR    2   /* An error occurred in File handle. Application should clean the related resources. */

/**** File attributes ****/
#define CIFS_ATTR_READONLY      0x01 /* file is read-only */
#define CIFS_ATTR_HIDDEN        0x02 /* file is hidden */
#define CIFS_ATTR_SYSTEM        0x04 /* file is a system file */
#define CIFS_ATTR_VOLUME        0x08 /* this is a volume, not a file */
#define CIFS_ATTR_DIR           0x10 /* the file is directory */
#define CIFS_ATTR_ARCHIVE       0x20 /* file is scheduled for archiving */
#define CIFS_ATTR_ALL           (CIFS_ATTR_HIDDEN | CIFS_ATTR_SYSTEM | CIFS_ATTR_DIR)

/**** File access mode ****/
#define FILE_AM_READ            0   /* read-only */
#define FILE_AM_WRITE           1   /* write-only */
#define FILE_AM_READ_WRITE      2   /* read and write */

/**** File share mode ****/
#define FILE_SM_COMPAT          0   /* compatibility mode */
#define FILE_SM_EXCLUSIVE       1   /* deny read/write/execute (exclusive) */
#define FILE_SM_DENY_WRITE      2   /* deny write */
#define FILE_SM_DENY_READ       3   /* deny read/execute */
#define FILE_SM_DENY_NONE       4   /* deny none */

/**** File locality ****/
#define FILE_LCL_UNKNOWN        0   /* locality of reference is unknown */
#define FILE_LCL_SEQUENTIAL     1   /* mainly sequential access */
#define FILE_LCL_RANDOM         2   /* mainly random access */
#define FILE_LCL_MIXED          3   /* random access with some locality */

/**** File create action ****/
#define FILE_CA_FAIL            0   /* if file exists - fail */
#define FILE_CA_CREATE          1   /* if file does not exist - create it */

/**** File open action ****/
#define FILE_OA_FAIL            0   /* if file does not exist - fail */
#define FILE_OA_OPEN            1   /* if file exists - open it */
#define FILE_OA_TRUNCATE        2   /* if file exists - open it and truncate */

/* File seek method */
#define SEEK_FILE_BEGIN         0   /* seek from start of file */
#define SEEK_FILE_CURRENT       1   /* seek from the current position in file */
#define SEEK_FILE_END           2   /* seek from the file end */

/**** LAN Manager Authentication Level ****/
#define NQ_CC_AUTH_LM_AND_NTLM      1   /* forces CIFS Client to send both LM and NTLM encrypted password */
#define NQ_CC_AUTH_NTLM             2   /* forces CIFS Client to send NTLM encrypted password only */
#define NQ_CC_AUTH_NTLM_V2          3   /* forces CIFS Client to use NTLMv2 authentication */
#ifdef UD_CC_INCLUDEEXTENDEDSECURITY_KERBEROS
#define NQ_CC_AUTH_SPNEGO_KERBEROS  4   /* forces CIFS Client to use SPNEGO authentication with an extended security mechanism */
#endif /* UD_CC_INCLUDEEXTENDEDSECURITY_KERBEROS */

/**** Errors ****/

#define NQ_ERR_MODULE   (255 << 16)     /* This module defines the NQ error subset */

#define NQ_ERR_OK               0  /* Success */
#define NQ_ERR_BADPARAM         (NQ_ERR_MODULE | 3)  /* Parameter error */
#define NQ_ERR_GETDATA          (NQ_ERR_MODULE | 18) /* error retrieving data */
#define NQ_ERR_INVALIDMODE      (NQ_ERR_MODULE | 19) /* Invalid open mode */
#define NQ_ERR_NOSERVERMAC      (NQ_ERR_MODULE | 20) /* Server doesn't support MAC signing */
#define NQ_ERR_SIGNATUREFAIL    (NQ_ERR_MODULE | 21) /* MAC signature in incoming packet was broken */
#define NQ_ERR_OBJEXISTS        (NQ_ERR_MODULE | 22) /* database object already exists and cannot be created */
#define NQ_ERR_MOUNTERROR       (NQ_ERR_MODULE | 23) /* mount failed for a reason other then authentication */
#define NQ_ERR_UNABLETODISPOSE  (NQ_ERR_MODULE | 24) /* unable to dispose resources */
#define NQ_ERR_INVALIDHANDLE    (NQ_ERR_MODULE | 25) /* invalid handle passed */
#define NQ_ERR_NEGOTIATEFAILED  (NQ_ERR_MODULE | 26) /* SPNEGO negotiation did not find a match */
#define NQ_ERR_PATHNOTCOVERED   (NQ_ERR_MODULE | 27) /* path should be resolved over DFS */
#define NQ_ERR_DFSCACHEOVERFLOW (NQ_ERR_MODULE | 28) /* DFS cache overflow */
#define NQ_ERR_ACCOUNTLOCKEDOUT (NQ_ERR_MODULE | 29) /* account locked out */
#define NQ_ERR_USEREXISTS       (NQ_ERR_MODULE | 30) /* acount already exists */
#define NQ_ERR_USERNOTFOUND     (NQ_ERR_MODULE | 31) /* account name not mapped */
#define NQ_ERR_OUTOFMEMORY      (NQ_ERR_MODULE | 901) /* failed to allocate memory block */

#define NQ_ERR_BADFUNC          (NQ_ERR_MODULE | 1001)   /* Invalid function. The server did not recognize or could not perform a system call generated by the server, e.g. set the DIRECTORY attribute on a data file, invalid seek mode. */
#define NQ_ERR_BADFILE          (NQ_ERR_MODULE | 1002)   /* File not found. The last component of a file's pathname could not be found. */
#define NQ_ERR_BADPATH          (NQ_ERR_MODULE | 1003)   /* Directory invalid. A directory component in a pathname could not be found. */
#define NQ_ERR_NOFIDS           (NQ_ERR_MODULE | 1004)   /* Too many open files. The server has no file handles available. */
#define NQ_ERR_NOACCESS         (NQ_ERR_MODULE | 1005)   /* Access denied, the client's context does not permit the requested function. This includes the following conditions: invalid rename command, write to a file open for read only, read on a file open for write only, attempt to delete a non-empty directory. */
#define NQ_ERR_BADFID           (NQ_ERR_MODULE | 1006)   /* Invalid file handle. The file handle specified was not recognized by the server. */
#define NQ_ERR_BADMCB           (NQ_ERR_MODULE | 1007)   /* Memory control blocks destroyed */
#define NQ_ERR_NOMEM            (NQ_ERR_MODULE | 1008)   /* Insufficient server memory to perform the requested function */
#define NQ_ERR_BADMEM           (NQ_ERR_MODULE | 1009)   /* Invalid memory block address */
#define NQ_ERR_BADENV           (NQ_ERR_MODULE | 1010)   /* Invalid environment */
#define NQ_ERR_BADFORMAT        (NQ_ERR_MODULE | 1011)   /* Invalid format */
#define NQ_ERR_BADACCESS        (NQ_ERR_MODULE | 1012)   /* Invalid open mode */
#define NQ_ERR_BADDATA          (NQ_ERR_MODULE | 1013)   /* Invalid data (generated only by IOCTL calls within the server) */
#define NQ_ERR_BADDRIVE         (NQ_ERR_MODULE | 1015)   /* Invalid drive specified */
#define NQ_ERR_REMCD            (NQ_ERR_MODULE | 1016)   /* A Delete Directory request attempted to remove the server's current directory */
#define NQ_ERR_DIFFDEVICE       (NQ_ERR_MODULE | 1017)   /* Not the same device (e.g. a cross volume rename was attempted) */
#define NQ_ERR_NOFILES          (NQ_ERR_MODULE | 1018)   /* A File Search command can find no more files matching the specified criteria. */
#define NQ_ERR_BADSHARE         (NQ_ERR_MODULE | 1032)   /* The sharing mode specified for Open conflicts with existing opens on the file. */
#define NQ_ERR_LOCK             (NQ_ERR_MODULE | 1033)   /* A Lock request conflicted with an existing lock or specified an invalid mode, or an Unlock requested attempted to remove a lock held by another process. */
#define NQ_ERR_DONTSUPPORTIPC   (NQ_ERR_MODULE | 1066)   /* Server does not support IPC pseudo-filesystem, so that RPC operations are not available. */
#define NQ_ERR_NOSHARE          (NQ_ERR_MODULE | 1067)   /* Non-existing share required. */
#define NQ_ERR_FILEXISTS        (NQ_ERR_MODULE | 1080)   /* The file named in the request already exists. */
#define NQ_ERR_BADDIRECTORY     (NQ_ERR_MODULE | 1087)   /* The file specified is not a directory while directory expected. */
#define NQ_ERR_INSUFFICIENTBUFFER (NQ_ERR_MODULE | 1122) /* Server compose a response due to constraints applied on the request. */
#define NQ_ERR_INVALIDNAME      (NQ_ERR_MODULE | 1123)   /* File name or path contains invalid characters. */
#define NQ_ERR_ALREADYEXISTS    (NQ_ERR_MODULE | 1183)   /* Object already exists. Returned on an attempt to create file or directory which already exists on the server. */
#define NQ_ERR_BADPIPE          (NQ_ERR_MODULE | 1230)   /* RPC request specifies invalid handle or a handle that does correspond to an RPC pipe. */
#define NQ_ERR_PIPEBUSY         (NQ_ERR_MODULE | 1231)   /* Server cannot currently perform the required RPC operation. Cleint can try again later. */
#define NQ_ERR_PIPECLOSING      (NQ_ERR_MODULE | 1232)   /* RPC pipe is being closed. */
#define NQ_ERR_NOTCONNECTED     (NQ_ERR_MODULE | 1233)   /* Connection to server lost. */
#define NQ_ERR_MOREDATA         (NQ_ERR_MODULE | 1234)   /* The entire payload does not fit in the response. */

#define NQ_ERR_ERROR            (NQ_ERR_MODULE | 2001)   /* Non-specific error code, returned when none of specific error codes is applicable. */
#define NQ_ERR_BADPW            (NQ_ERR_MODULE | 2002)   /* Invalid password - name/password pair. */
#define NQ_ERR_ACCESS           (NQ_ERR_MODULE | 2004)   /* The client does not have the necessary access rights within the specified context for the requested function. */
#define NQ_ERR_INVTID           (NQ_ERR_MODULE | 2005)   /* The TID specified in a command was invalid. */
#define NQ_ERR_INVNETNAME       (NQ_ERR_MODULE | 2006)   /* Invalid network name (host name) specified. */
#define NQ_ERR_INVDEVICE        (NQ_ERR_MODULE | 2007)   /* Invalid device - printer request made to non-printer connection or non-printer request made to printer connection. */
#define NQ_ERR_QFULL            (NQ_ERR_MODULE | 2049)   /* Print queue full (files) -- returned by open print file. */
#define NQ_ERR_QTOOBIG          (NQ_ERR_MODULE | 2050)   /* Print queue full -- no space . */
#define NQ_ERR_QEOF             (NQ_ERR_MODULE | 2051)   /* EOF on print queue dump. */
#define NQ_ERR_INVFID           (NQ_ERR_MODULE | 2052)   /* Invalid file handle. */
#define NQ_ERR_SMBCMD           (NQ_ERR_MODULE | 2064)   /* The server did not recognize the command received. */
#define NQ_ERR_SRVERROR         (NQ_ERR_MODULE | 2065)   /* The server encountered an internal error, e.g. system file unavailable. */
#define NQ_ERR_FILESPECS        (NQ_ERR_MODULE | 2067)   /* The file handle and pathname parameters contained an invalid combination of values. */
#define NQ_ERR_BADPERMITS       (NQ_ERR_MODULE | 2069)   /* The access permissions specified for a file or directory are not a valid combination. The server cannot set the requested attribute. */
#define NQ_ERR_SETATTRMODE      (NQ_ERR_MODULE | 2071)   /* The attribute mode in the Set File Attribute request is invalid. */
#define NQ_ERR_PAUSED           (NQ_ERR_MODULE | 2081)   /* Server paused (reserved for messaging). */
#define NQ_ERR_MSGOFF           (NQ_ERR_MODULE | 2082)   /* Not receiving messages (reserved for messaging). */
#define NQ_ERR_NOROOM           (NQ_ERR_MODULE | 2083)   /* No room to buffer message (reserved for messaging). */
#define NQ_ERR_RMUNS            (NQ_ERR_MODULE | 2087)   /* Too many remote user names (reserved for messaging). */
#define NQ_ERR_TIMEOUT          (NQ_ERR_MODULE | 2088)   /* Operation timed out. */
#define NQ_ERR_NORESOURCE       (NQ_ERR_MODULE | 2089)   /* No resources currently available for request. */
#define NQ_ERR_TOOMANYUIDS      (NQ_ERR_MODULE | 2090)   /* Too many users active on this session. */
#define NQ_ERR_INVUID           (NQ_ERR_MODULE | 2091)   /* The UID is not known as a valid user identifier on this session. */
#define NQ_ERR_USEMPX           (NQ_ERR_MODULE | 2250)   /* Temporarily unable to support Raw, use MPX mode. */
#define NQ_ERR_USESTD           (NQ_ERR_MODULE | 2251)   /* Temporarily unable to support Raw, use standard read/write. */
#define NQ_ERR_CONTMPX          (NQ_ERR_MODULE | 2252)   /* Continue in MPX mode. */
#define NQ_ERR_NOSUPPORT        (NQ_ERR_MODULE | 2999)   /* Function not supported. */

#define NQ_ERR_NOWRITE          (NQ_ERR_MODULE | 3019)   /* Attempt to write on write-protected media. */
#define NQ_ERR_BADUNIT          (NQ_ERR_MODULE | 3020)   /* Unknown unit. */
#define NQ_ERR_NOTREADY         (NQ_ERR_MODULE | 3021)   /* Drive not ready. */
#define NQ_ERR_BADCMD           (NQ_ERR_MODULE | 3022)   /* Unknown command. */
#define NQ_ERR_DATA             (NQ_ERR_MODULE | 3023)   /* Data error (CRC). */
#define NQ_ERR_BADREQ           (NQ_ERR_MODULE | 3024)   /* Bad request structure length. */
#define NQ_ERR_SEEK             (NQ_ERR_MODULE | 3025)   /* Seek error. */
#define NQ_ERR_BADMEDIA         (NQ_ERR_MODULE | 3026)   /* Unknown media type. */
#define NQ_ERR_BADSECTOR        (NQ_ERR_MODULE | 3027)   /* Sector not found. */
#define NQ_ERR_NOPAPER          (NQ_ERR_MODULE | 3028)   /* Printer out of paper. */
#define NQ_ERR_WRITE            (NQ_ERR_MODULE | 3029)   /* Write fault. */
#define NQ_ERR_READ             (NQ_ERR_MODULE | 3030)   /* Read fault. */
#define NQ_ERR_GENERAL          (NQ_ERR_MODULE | 3031)   /* General hardware failure. */
#define NQ_ERR_WRONGDISK        (NQ_ERR_MODULE | 3034)   /* The wrong disk was found in a drive. */
#define NQ_ERR_FCBUNAVAIL       (NQ_ERR_MODULE | 3035)   /* No FCBs are available to process request. */
#define NQ_ERR_SHAREBUFEXC      (NQ_ERR_MODULE | 3036)   /* A sharing buffer has been exceeded. */
#define NQ_ERR_DISKFULL         (NQ_ERR_MODULE | 3039)   /* The disk is full. */

#define NQ_ERR_SIZEERROR       (0xffffffff) /* Error requesting file size. */
#define NQ_ERR_SEEKERROR       (0xffffffff) /* Invalid seek result. */
#define NQ_ERR_ATTRERROR       (0xffffffff) /* Error requesting file attributes. */

/* This structure is a 64-bit value representing the number of
   100-nanosecond intervals since January 1, 1601 (UTC). The
   application can use the NQ system abstraction layer calls for
   converting time from OS native format to FileTime_t.          */
typedef struct {
    NQ_UINT32 timeLow;      /* high 32 bits of file time */
    NQ_UINT32 timeHigh;     /* low 32 bits of file time */
} FileTime_t;

/* file search data - UNICODE version */
typedef struct {
    NQ_UINT32 fileAttributes;       /* \file attributes as defined in <link File Attributes> */
    NQ_UINT32 creationTimeLow;      /* low 32 bits of file creation time */
    NQ_UINT32 creationTimeHigh;     /* high 32 bits of file creation time */
    NQ_UINT32 lastAccessTimeLow;    /* low 32 bits of file last access time */
    NQ_UINT32 lastAccessTimeHigh;   /* high 32 bits of file last access time */
    NQ_UINT32 lastWriteTimeLow;     /* low 32 bits of file last write time */
    NQ_UINT32 lastWriteTimeHigh;    /* high 32 bits of file last write time */
    NQ_UINT32 fileSizeLow;          /* low 32 bits of file data size */
    NQ_UINT32 fileSizeHigh;         /* high 32 bits of file data size */
    NQ_UINT32 allocationSizeLow;    /* low 32 bits of file allocation sizee */
    NQ_UINT32 allocationSizeHigh;   /* high 32 bits of file allocation sizee */
    NQ_UINT32 fileNameLength;       /* file name length in characters */
    NQ_WCHAR fileName[CM_BUFFERLENGTH(NQ_WCHAR, UD_FS_FILENAMELEN)];    /* file name buffer */
} FindFileDataW_t;  /* UNICODE version */

/* file search data - ASCII version */
typedef struct {
    NQ_UINT32 fileAttributes;       /* file attributes as defined in <link File Attributes> */
    NQ_UINT32 creationTimeLow;      /* low 32 bits of file creation time */
    NQ_UINT32 creationTimeHigh;     /* high 32 bits of file creation time */
    NQ_UINT32 lastAccessTimeLow;    /* low 32 bits of file last access time */
    NQ_UINT32 lastAccessTimeHigh;   /* high 32 bits of file last access time */
    NQ_UINT32 lastWriteTimeLow;     /* low 32 bits of file last write time */
    NQ_UINT32 lastWriteTimeHigh;    /* high 32 bits of file last write time */
    NQ_UINT32 fileSizeLow;          /* low 32 bits of file data size */
    NQ_UINT32 fileSizeHigh;         /* high 32 bits of file data size */
    NQ_UINT32 allocationSizeLow;    /* low 32 bits of file allocation sizee */
    NQ_UINT32 allocationSizeHigh;   /* high 32 bits of file allocation sizee */
    NQ_UINT32 fileNameLength;       /* file name length in characters */
    NQ_CHAR fileName[CM_BUFFERLENGTH(NQ_WCHAR, UD_FS_FILENAMELEN)];    /* file name buffer */
} FindFileDataA_t;  /* ASCII version */

/* This structure is used when calling <link ccFindFirstFile, ccFindFirstFile()>
   and <link ccFindNextFile, ccFindNextFile()> calls.                            */
#ifdef UD_CM_UNICODEAPPLICATION
    #define FindFileData_t FindFileDataW_t
#else
    #define FindFileData_t FindFileDataA_t
#endif

/* This structure is used when calling File Information related CIFS Client API calls */ 
typedef struct {
    NQ_UINT32 creationTimeLow;      /* low 32 bits of file creation time */
    NQ_UINT32 creationTimeHigh;     /* high 32 bits of file creation time */
    NQ_UINT32 lastAccessTimeLow;    /* low 32 bits of file last access time */
    NQ_UINT32 lastAccessTimeHigh;   /* high 32 bits of file last access time */
    NQ_UINT32 lastWriteTimeLow;     /* low 32 bits of file last write time */
    NQ_UINT32 lastWriteTimeHigh;    /* high 32 bits of file last write time */
    NQ_UINT32 attributes;           /* file attributes as defined in <link File Attributes> */
    NQ_UINT32 volumeSerialNumber;   /* volume serial number */
    NQ_UINT32 allocationSizeLow;    /* low 32 bits of file allocation sizee */
    NQ_UINT32 allocationSizeHigh;   /* high 32 bits of file allocation sizee */
    NQ_UINT32 fileSizeLow;          /* low 32 bits of file data size */
    NQ_UINT32 fileSizeHigh;         /* high 32 bits of file data size */
    NQ_UINT32 numberOfLinks;        /* number of hard links to this file */
    NQ_UINT32 fileIndexLow;         /* low 32 bits of file ID (always zero) */
    NQ_UINT32 fileIndexHigh;        /* high 32 bits of file ID (always zero) */
} FileInfo_t;

/*********************************************************************
 * API functions
 ********************************************************************/

/* Description
   Initialization functions. Application should call this
   function at its startup to initialize NQ Client.
   
   The <i>fsNotify</i> parameter is used for callback
   notification. Application can provide this function to become
   informed of important events inside NQ Notification is
   useful, for instance, NQ Client is being wrapped as a local
   filesystem.
   Parameters
   fsNotify :  Pointer to the notification function. This value can
               be NULL.
   
   Returns
   None                                                             */
NQ_BOOL ccInit(void (*fsdNotify)(NQ_INT eventId, NQ_ULONG param));

/* Description
   This function stops NQ Client and releases all its resources.
   Returns
   None                                                          */
void ccShutdown(void);

/* Description
   This function checks whether NQ Client has started. 
   Returns
   TRUE when NQ Client was initialized and FALSE otherwise.          */
NQ_BOOL ccIsInitialized(void);

NQ_INT nqAddMountA(const NQ_CHAR *mountPoint, const NQ_CHAR *remotePath, NQ_BOOL connect);     /* ASCII version */
NQ_INT nqAddMountW(const NQ_WCHAR *mountPoint, const NQ_WCHAR *remotePath, NQ_BOOL connect);   /* UNICODE version */

/* Description
   This function mounts the remote share as a local subdirectory
   under the local virtual network file system. This call is a
   triplet call (see <link Summary>).
   Parameters
   mountPoint :  Local mount point for the share. The leading
                 backslash is required. Example\: <i>\\remoteShare1.</i>
   remotePath :  Path to the remote share, starting from host
                 name. Path syntax is <i>\\\\\<host\>\\\<share\>.</i>
   connect :     A value of TRUE means that NQ will immediately
                 connect to the remote share. Use FALSE to
                 postpone connection to the first operation over
                 this mount point.
   Returns
   This function returns 0 – if the mount point was connected
   successfully or -1 otherwise. Application can examine the
   error code for the failure reason.
   See Also
   <link nqRemoveMount>()                                                */
#ifdef UD_CM_UNICODEAPPLICATION
    #define nqAddMount nqAddMountW
#else
    #define nqAddMount nqAddMountA
#endif

/* Description
   This function makes mount point unavailable. It does not close the 
   files opened over this mount point. This call is a triplet
   call (see <link Summary>).
   Parameters
   mountPoint :  The name of the mount point to be removed.
   Returns
   This function returns 0 if the mount point has been
   successfully removed or -1 otherwise. Application can examine
   the error code for the failure reason.
   See Also
   <link nqAddMount, nqAddMount()>                               */
#ifdef UD_CM_UNICODEAPPLICATION
    #define nqRemoveMount nqRemoveMountW
#else
    #define nqRemoveMount nqRemoveMountA
#endif
int nqRemoveMountA(const NQ_CHAR *mountPoint);  /* ASCII version */
int nqRemoveMountW(const NQ_WCHAR *mountPoint); /* UNICODE version */

/* Description
   This function clears user credentials associated with the
   given mount point.
   
   After this call, NQ will query application in any of the
   following cases:
     * Reconnecting one of the shares, associated with this
       mount point as a result of a temporary server disconnect.
     * Establishing a connection with additional servers as a
       \result of DFS redirection.
   This call does not affect those shares that were connected
   before this call. This call is a triplet call (see <link Summary>).
   Parameters
   mountPoint :  The name of the mount point to clear credentials.
   Returns
   TRUE on success, FALSE on failure.                                                               */
#ifdef UD_CM_UNICODEAPPLICATION
    #define ccResetCredentails ccResetCredentailsW
#else
    #define ccResetCredentails ccResetCredentailsA
#endif
NQ_BOOL ccResetCredentailsA(const NQ_CHAR * mountpoint);   /* ASCII version */
NQ_BOOL ccResetCredentailsW(const NQ_WCHAR * mountpoint);   /* UNICODE version */

/* Description
   This function is called by application to print all the CIFS
   Client tables. It is used for debugging purposes only.
   Returns
   None                                                         */
void ccDump(void);

/* Description
   This function is called by application to find a first file
   matching the specified search criteria. On success, this
   function returns a search handle which can be used by
   application for getting more search results (see <link ccFindNextFile, ccFindNextFile()>).
   At the end of the search the application should close this
   handle by calling <link ccFindClose@NQ_HANDLE, ccFindClose()>.
   
   The <i>srchPath</i> argument (see below) designates either a
   local or a remote path. A remote path starts with a mount
   point name. Any other path, which does not start from a mount
   point is considered local. A local path, regardless of its
   form, designates a list of mount points.
   
   This call is a triplet call (see <link Summary>).
   Parameters
   srchPath :      Path and the filename to search on the remote
                   share. Wildcard characters are applicable for
                   the filename.
   findFileData :  Pointer to a structure, where NQ places the
                   search result data in. See <link FindFileData_t, FindFileData_t structure.>
   extractFirst :  This flag specifies whether NQ should place
                   the search results data for this call (if
                   TRUE), or it should only open the search
                   handle for the specified path for future
                   search data retrieval (if FALSE) by calling <link ccFindNextFile, ccFindNextFile()>.
   Returns
   This function returns NULL if it cannot create a handle or a
   valid handle otherwise. The application can inspect the error
   code for the failure reason. Error code NQ_ERR_OK means that
   there are no files on a remote share matching the search
   criteria.
   See Also
   <link FindFileData_t, FindFileData_t structure>
   
   <link ccFindNextFile, ccFindNextFile()>
   
   <link ccFindClose@NQ_HANDLE, ccFindClose()>
   Note
   When application calls this function with a local path, NQ
   Client will lock the list of mount points until the <link ccFindClose@NQ_HANDLE, ccFindClose()>
   will be called. During that period any other application
   thread trying to call a function from NQ Client API may remain
   locked.                                                                                              */
#ifdef UD_CM_UNICODEAPPLICATION
    #define ccFindFirstFile ccFindFirstFileW
#else
    #define ccFindFirstFile ccFindFirstFileA
#endif
NQ_HANDLE ccFindFirstFileA(const NQ_CHAR *srchPath, FindFileDataA_t *findFileData, NQ_BOOL extractFirst);   /* ASCII version */
NQ_HANDLE ccFindFirstFileW(const NQ_WCHAR *srchPath, FindFileDataW_t *findFileData, NQ_BOOL extractFirst);  /* UNICODE version */

/* Description
   This function is called by application to find a next file
   matching the specified wildcard. This call is a triplet call
   (see <link Summary>).
   Parameters
   handle :        Handle value returned by calling <link ccFindFirstFile, ccFindFirstFile()>.
   findFileData :  Pointer to a structure, where NQ places the
                   search result data in. See <link FindFileData_t, FindFileData_t structure>.
   Returns
   This function returns TRUE if the next file was found
   successfully or FALSE otherwise. The application can inspect
   the error code for the failure reason. Error code NQ_ERR_OK
   means that there are no more files on a remote share matching
   the search criteria.
   See Also
   <link FindFileData_t, FindFileData_t structure>
   
   <link ccFindFirstFile, ccFindFirstFile()>
   
   <link ccFindClose@NQ_HANDLE, ccFindClose()>                                                 */
#ifdef UD_CM_UNICODEAPPLICATION
    #define ccFindNextFile ccFindNextFileW
#else
    #define ccFindNextFile ccFindNextFileA
#endif
NQ_BOOL ccFindNextFileA(NQ_HANDLE handle, FindFileDataA_t *findFileData);   /* ASCII version */
NQ_BOOL ccFindNextFileW(NQ_HANDLE handle, FindFileDataW_t *findFileData);   /* UNICODE version */

/* Description
   This function is called by application to close the search
   handle
   Parameters
   handle :  Handle value returned by calling the <link ccFindFirstFile, ccFindFirstFile()>
   Returns
   This function returns TRUE if the search handle is closed
   successfully or FALSE otherwise. The application can inspect
   the error code for the failure reason.                                                   */
NQ_BOOL
ccFindClose(NQ_HANDLE handle);

/* Description
   This function is called by application to create a directory.
   This call is a triplet call (see <link Summary>).
   Parameters
   pathName :  path of the directory to be created
   Returns
   This function returns TRUE if directory is created
   successfully or FALSE otherwise. The application can inspect
   the error code for the failure reason.                        */
#ifdef UD_CM_UNICODEAPPLICATION
    #define ccCreateDirectory ccCreateDirectoryW
#else
    #define ccCreateDirectory ccCreateDirectoryA
#endif
NQ_BOOL ccCreateDirectoryA(const NQ_CHAR *pathName);    /* ASCII version */
NQ_BOOL ccCreateDirectoryW(const NQ_WCHAR *pathName);   /* UNICODE version */

/* Description
   This function is called by application to remove a directory.
   This call is a triplet call (see <link Summary>).
   Parameters
   pathName :  path of the directory to be removed.
   Returns
   This function returns TRUE if the specified directory is
   removed successfully or FALSE otherwise. The application can
   inspect the error code for the failure reason. The directory
   should be empty, otherwise error condition will occur.        */
#ifdef UD_CM_UNICODEAPPLICATION
    #define ccRemoveDirectory ccRemoveDirectoryW
#else
    #define ccRemoveDirectory ccRemoveDirectoryA
#endif
NQ_BOOL ccRemoveDirectoryA(const NQ_CHAR *pathName);    /* ASCII version */
NQ_BOOL ccRemoveDirectoryW(const NQ_WCHAR *pathName);   /* UNICODE version */

/* Description
   This function is called by application to create or open a
   file. This call is a triplet call (see <link Summary>).
   Parameters
   fileName :      Path of the file to be created/opened.
   access :        Desired file access mode (see <link File Access Modes>).
   shareMode :     Desired file share mode (see <link File Share Modes>).
   locality :      Desired file locality (see <link File Localities>).
   writeThrough :  If TRUE then no read ahead or write behind
                   allowed on this file or device. When the
                   response is returned, data is expected to be
                   on the disk or device.
   attributes :    \File attributes for a newly created file (see
                   <link File Attributes>).
   createAction :  Desired file create action (see <link File Create Actions>).
   openAction :    Desired file open action (see <link File Open Actions>).
   Returns
   This function returns NULL if it cannot create/open a file or
   a valid handle otherwise. The application can inspect the
   error code for the failure reason.                                           */
#ifdef UD_CM_UNICODEAPPLICATION
    #define ccCreateFile ccCreateFileW
#else
    #define ccCreateFile ccCreateFileA
#endif
NQ_HANDLE ccCreateFileA(const NQ_CHAR *fileName, NQ_INT access, NQ_INT shareMode,
                        NQ_INT locality, NQ_BOOL writeThrough, NQ_UINT16 attributes, 
                        NQ_INT createAction, NQ_INT openAction);        /* ASCII Version */
NQ_HANDLE ccCreateFileW(const NQ_WCHAR *fileName, NQ_INT access, NQ_INT shareMode,
                        NQ_INT locality, NQ_BOOL writeThrough, NQ_UINT16 attributes, 
                        NQ_INT createAction, NQ_INT openAction);        /* UNICODE version */

/* Description
   This function is called by application to delete a file. This
   call is a triplet call (see <link Summary>).
   Parameters
   pathName :  path of the directory to be created
   Returns
   This function returns TRUE if the specified file is deleted
   successfully or FALSE otherwise. The application can inspect
   the error code for the failure reason.                        */
#ifdef UD_CM_UNICODEAPPLICATION
    #define ccDeleteFile ccDeleteFileW
#else
    #define ccDeleteFile ccDeleteFileA
#endif
NQ_BOOL ccDeleteFileA(const NQ_CHAR *fileName);         /* ASCII version */
NQ_BOOL ccDeleteFileW(const NQ_WCHAR *fileName);        /* UNICODE version */

/* Description
   This function is called by application to move (rename) a
   file/directory to a different location. Note, that a file
   cannot be moved between different remote shares This call is
   a triplet call (see <link Summary>).
   Parameters
   oldFilename :  Path of the file/directory to be moved.
   newFilename :  Path of the file/directory to be moved to.
   Returns
   This function returns TRUE if the specified file is moved
   successfully or FALSE otherwise. The application can inspect
   the error code for the failure reason.                       */
#ifdef UD_CM_UNICODEAPPLICATION
    #define ccMoveFile ccMoveFileW
#else
    #define ccMoveFile ccMoveFileA
#endif
NQ_BOOL ccMoveFileA(const NQ_CHAR *oldFilename, const NQ_CHAR *newFilename); /* ASCII version */
NQ_BOOL ccMoveFileW(const NQ_WCHAR *oldFilename, const NQ_WCHAR *newFilename); /* UNICODE version */

/* Description
   This function is called by application to withdraw the current position in the file.
   
   The result is returned as a 64-bit number composed of 32-but least significant bits 
   and 32-bit most significant bits. The two values should compose a two's
   complement 64bit number. Examples:
   <table>
   value     low         high
   --------  ----------  -----------
   1         1           0
   4Gb + 1   1           1
   \-2       \-2         \-1
   </table>
   Parameters
   handle :      Handle value returned by calling <link ccCreateFile, ccCreateFile()>.
   Returns
   This function returns current offset in the file as a 64-bit value. On error, NQ returns 64 ones (-1, -1).                                                       */
NQ_UINT64 ccGetFilePointer(NQ_HANDLE handle);

/* Description
   This function is called by application to set a file pointer
   of the file read/write location in the opened file. The <i>lowOffset</i>
   and <i>highOffset</i> parameters should compose a two's
   complement 64bit number. Examples:
   <table>
   value     lowOffset   highOffset
   --------  ----------  -----------
   1         1           0
   4Gb + 1   1           1
   \-2       \-2         \-1
   </table>
   Parameters
   handle :      Handle value returned by calling <link ccCreateFile, ccCreateFile()>.
   lowOffset :   Low\-order 32 bits of the file offset.
   highOffset :  Pointer to a variable holding the high\-order 32
                 bits of the file offset. Upon successful return
                 this variable contains new offset high bits.
   method :      \File seek method (see <link SEEK_FILE_BEGIN>, <link SEEK_FILE_CURRENT>
                 and <link SEEK_FILE_END, SEEK_FILE_END Macro>)
   Returns
   This function returns the new file access low offset if
   successful or NQ_ERR_SEEKERROR otherwise. The application can
   inspect the error code for the failure reason. The new high
   offset is placed in highOffset.                                                       */
NQ_UINT32 ccSetFilePointer(NQ_HANDLE handle, NQ_INT32 lowOffset, NQ_INT32 *highOffset, NQ_INT method);

/* Description
   This function is called by application to read data from the
   opened file.
   
   NQ attempts to use the biggest available payload. However, if
   the <i>count</i> parameter is big enough, calling this
   function results in transmitting multiple SMB requests. NQ
   Client attempts to send these requests concurrently. Since
   this call is synchronous, NQ will wait for all responses to
   come back from the server.
   
   NQ Client reads file bytes from its current position. For
   random access, use function <link ccSetFilePointer@NQ_HANDLE@NQ_INT32@NQ_INT32 *@NQ_INT, ccSetFilePointer()>.
   Parameters
   hndl :      Handle value returned by calling <link ccCreateFile, ccCreateFile()>
   buffer :    Pointer to a buffer to read the file data to
   count :     Number of bytes to read from the file
   readSize :  The pointer to a variable which on exit receives
               the number of bytes actually read. This value can
               be NULL.
   
   Returns
   This function returns TRUE if the data is read successfully
   or FALSE otherwise. The application can inspect the error
   code for the failure reason.                                                                                  */
NQ_BOOL ccReadFile(NQ_HANDLE hndl, NQ_BYTE *buffer, NQ_UINT count, NQ_UINT *readSize);

/* Description
   This function is called by application to read data from the
   opened file.
   
   NQ attempts to use the biggest available payload. However, if
   the <i>count</i> parameter is big enough, calling this
   function results in transmitting multiple SMB requests. NQ
   Client attempts to send these requests concurrently. Since
   this call is asynchronous, NQ will not wait for all responses
   to come back from the server but will rather call the <i>callback</i>
   function after receiving the last response.
   
   NQ places the actual number of data read into the first
   argument of the call to the <i>callback </i>function.
   
   NQ Client reads bytes starting from the current position in
   the file. For random read use function <link ccSetFilePointer@NQ_HANDLE@NQ_INT32@NQ_INT32 *@NQ_INT, ccSetFilePointer()>.

   This function is not thread-protected over the same file. It assumes that there is just one thread reading file through the 
   given handle. Otherwise, the result is undefined. It is possible, however, to read the same file over two different
   handles simultaneously. 
   Parameters
   hndl :      Handle value returned by calling <link ccCreateFile, ccCreateFile()>.
   buffer :    Pointer to a buffer to use for reading.
   count :     Number of bytes to write to the file.
   context :   A context pointer supplied by the application. By
               using context, an application can distinguish
               between different write operations.
   callback :  Pointer to a callback function supplied by
               application. This function accepts operation status, the actual
               number of bytes read and an abstract context
               pointer supplied by the application.
   Returns
   This function returns TRUE if the read operations where
   successfully queued or FALSE otherwise. The application can
   inspect the error code for the failure reason.
   
   Because of the asynchronous character of this operation the
   \return value does not reflect read results. Application
   should use <i>callback</i> to analyse read results.                                                                      */
NQ_BOOL ccReadFileAsync(NQ_HANDLE hndl, NQ_BYTE *buffer, NQ_UINT count, void * context, void (* callback)(NQ_STATUS, NQ_UINT, void *));

/* Description
   This function is called by application to write data to an
   open file.
   
   Upon successful completion NQ places the actual number of
   data written into the memory location pointed by parameter
   writtenSize. On an error, this value is left unmodified.
   
   NQ Client writes bytes starting from the current position in
   the file. For random write use function  <link ccSetFilePointer@NQ_HANDLE@NQ_INT32@NQ_INT32 *@NQ_INT, ccSetFilePointer()>.
   
   The ccWriteFile() function can be also called for file
   truncation. Use <link ccSetFilePointer@NQ_HANDLE@NQ_INT32@NQ_INT32 *@NQ_INT, ccSetFilePointer()>
   function first to set file pointer into the desired
   end-of-file position. Then call the current function with
   zero data size. This will truncate the file.
   Parameters
   hndl :         Handle value returned by calling <link ccCreateFile, ccCreateFile()>.
   buffer :       Pointer to a buffer with bytes to be written.
   count :        Number of bytes to write to the file.
   writtenSize :  Pointer to a variable which will receive the
                  number of bytes actually written. This value
                  can be NULL.
   Returns
   This function returns TRUE if the data is written
   successfully or FALSE otherwise. The application can inspect
   the error code for the failure reason.                                                                                     */
NQ_BOOL ccWriteFile(NQ_HANDLE hndl, NQ_BYTE *buffer, NQ_UINT count, NQ_UINT *writtenSize);

/* Description
   This function is called by application to write data to an
   open file using asyncrhonous operations.
   
   Upon successful completion NQ schedules necessary write
   operations. When all writes will be complete, NQ will call
   the <i>callback</i> function.
   
   When calling the <i>callback</i> function, NQ places the
   actual number of data written into the first argument of this
   call.
   
   NQ Client writes bytes starting from the current position in
   the file. For random write use function <link ccSetFilePointer@NQ_HANDLE@NQ_INT32@NQ_INT32 *@NQ_INT, ccSetFilePointer()>.
   
   The ccWriteFile() function can be also called for file
   truncation. Use <link ccSetFilePointer@NQ_HANDLE@NQ_INT32@NQ_INT32 *@NQ_INT, ccSetFilePointer()>
   function first to set file pointer into the desired
   end-of-file position. Then call the current function with
   zero data size. This will truncate the file.
   
   This function is not thread-protected over the same file. It
   assumes that there is just one thread writing to the file
   through the given handle. Otherwise, the result is undefined.
   It is possible, however, to write the same file over two
   different handles simultaneously. The permission to open the
   same file twice for read depends on the server's policies.
   Parameters
   hndl :      Handle value returned by calling <link ccCreateFile, ccCreateFile()>.
   buffer :    Pointer to a buffer with bytes to be written.
   count :     Number of bytes to write to the file.
   context :   A context pointer supplied by the application. By
               using context, an application can distinguish
               between different write operations.
   callback :  Pointer to a callback function supplied by
               application. This function accepts the actual
               number of bytes written and an abstract context
               pointer supplied by the application.
   Returns
   This function returns TRUE if the write operations where
   successfully queued or FALSE otherwise. The application can
   inspect the error code for the failure reason.
   
   Because of the asynchronous character of this operation the
   \return value does not reflect write results. Application
   should use <i>callback</i> to analyse write results.                                                                      */
NQ_BOOL ccWriteFileAsync(NQ_HANDLE hndl, NQ_BYTE *buffer, NQ_UINT count, void * context, void (* callback)(NQ_STATUS , NQ_UINT, void *));

/* Description
   This function is called by application to force server to
   synchronize its local buffers with the file contents.
   Parameters
   handle :  Handle value returned by calling <link ccCreateFile, ccCreateFile()>
   Returns
   This function returns TRUE if the next file was found
   successfully or FALSE otherwise. The application can inspect
   the error code for the failure reason.                                         */
NQ_BOOL ccFlushFile(NQ_HANDLE handle);

/* Description
   This function is called by application to close the file
   handle
   Returns
   This function returns TRUE if the file handle is closed
   successfully or FALSE otherwise. The application can inspect
   the error code for the failure reason.
   Parameters
   handle :  Handle value returned by calling <link ccCreateFile, ccCreateFile()> */
NQ_BOOL ccCloseHandle(NQ_HANDLE handle);
    
/* Description
   This function is called by application to get the free disk
   space information for the specified remote share. This call
   is a triplet call (see <link Summary>).
   Parameters
   pathName :           Path of any object on the remote share
                        the free disk space information is
                        requested for.
   sectorsPerCluster :  Pointer to a variable which will receive
                        the number of sectors per cluster on the
                        remote share.
   bytesPerSector :     Pointer to a variable which will receive
                        the number of bytes per sector on the
                        remote share.
   freeClusters :       Pointer to a variable which will receive
                        the number of free clusters on the remote
                        share.
   totalClusters :      Pointer to a variable which will receive
                        the number of total clusters on the
                        remote share.
   fsType :             Pointer to a variable which will receive
                        the type of the file system.
   serialNumber :       Pointer to a variable which will receive
                        the serial number of the file system
   Returns
   This function returns TRUE if the remote disk information is
   received successfully or FALSE otherwise. The application can
   inspect the error code for the failure reason.                 */
#ifdef UD_CM_UNICODEAPPLICATION
    #define ccGetDiskFreeSpace ccGetDiskFreeSpaceW
#else
    #define ccGetDiskFreeSpace ccGetDiskFreeSpaceA
#endif
NQ_BOOL ccGetDiskFreeSpaceA(const NQ_CHAR *pathName, NQ_UINT *sectorsPerCluster, 
                            NQ_UINT *bytesPerSector, NQ_UINT *freeClusters, NQ_UINT *totalClusters,
                            NQ_UINT *fsType, NQ_UINT *serialNumber);    /* ASCII version */
NQ_BOOL ccGetDiskFreeSpaceW(const NQ_WCHAR *pathName, NQ_UINT *sectorsPerCluster, 
                            NQ_UINT *bytesPerSector, NQ_UINT *freeClusters, NQ_UINT *totalClusters, 
                            NQ_UINT *fsType, NQ_UINT *serialNumber);    /* UNICODE version */

/* Description
   This function is called by application to get attributes of
   the specified file. This call is a triplet call (see <link Summary>).
   Parameters
   fileName :  Path to the file.
   Returns
   This function returns the file attributes (see <link File Attributes>)
   if successful or NQ_ERR_ATTRERROR otherwise. The application
   can inspect the error code for the failure reason.                     */
#ifdef UD_CM_UNICODEAPPLICATION
    #define ccGetFileAttributes ccGetFileAttributesW
#else
    #define ccGetFileAttributes ccGetFileAttributesA
#endif
NQ_UINT32 ccGetFileAttributesA(const NQ_CHAR *fileName);    /* ASCII version */
NQ_UINT32 ccGetFileAttributesW(const NQ_WCHAR *fileName);   /* UNICODE version */

/* Description
   This function is called by application to set attributes of
   the specified file. This call is a triplet call (see <link Summary>).
   Parameters
   fileName :    Path to the file.
   attributes :  Attributes to set. See <link File Attributes>
                 for values.
   Returns
   This function returns TRUE if the specified attributes are
   set successfully or FALSE otherwise. The application can
   inspect the error code for the failure reason.
   See Also
   <link File Attributes>                                                */
#ifdef UD_CM_UNICODEAPPLICATION
    #define ccSetFileAttributes ccSetFileAttributesW
#else
    #define ccSetFileAttributes ccSetFileAttributesA
#endif
NQ_BOOL ccSetFileAttributesA(const NQ_CHAR *fileName, NQ_UINT32 attributes);    /* ASCII version */
NQ_BOOL ccSetFileAttributesW(const NQ_WCHAR *fileName, NQ_UINT32 attributes);   /* UNICODE version */

/* Description
   This function is called by application to get the information
   of the specified file. This call is a triplet call (see <link Summary>).
   Parameters
   fileName :  Path to the file.
   fileInfo :  Pointer to a structure which will receive the file
               information (see <link FileInfo_t, FileInfo_t Structure>).
   Returns
   This function returns TRUE if the specified file information
   is obtained successfully or FALSE otherwise. The application
   can inspect the error code for the failure reason.                       */
#ifdef UD_CM_UNICODEAPPLICATION
    #define ccGetFileInformationByName ccGetFileInformationByNameW
#else
    #define ccGetFileInformationByName ccGetFileInformationByNameA
#endif
NQ_BOOL ccGetFileInformationByNameA(const NQ_CHAR *fileName, FileInfo_t *fileInfo);     /* ASCII version */
NQ_BOOL ccGetFileInformationByNameW(const NQ_WCHAR *fileName, FileInfo_t *fileInfo);    /* UNICODE version */

/* Description
   This function is called by application to set file size when
   file is specified by its name. This call is a triplet call
   (see <link Summary>).
   Parameters
   fileName :  Path to file.
   sizeLow :   Low 32 bit if the desired file size.
   sizeHigh :  High 32 bit if the desired file size.
   Returns
   This function returns TRUE if the file size was modified
   successfully or FALSE otherwise.
   
   When the specified file size is less than the current file
   size, this operation truncates the file to the specified
   size.                                                        */
#ifdef UD_CM_UNICODEAPPLICATION
    #define ccSetFileSizeByName ccSetFileSizeByNameW
#else
    #define ccSetFileSizeByName ccSetFileSizeByNameA
#endif
NQ_BOOL ccSetFileSizeByNameA(const NQ_CHAR *fileName, NQ_UINT32 sizeLow, NQ_UINT32 sizeHigh);   /* ASCII version */
NQ_BOOL ccSetFileSizeByNameW(const NQ_WCHAR *fileName, NQ_UINT32 sizeLow, NQ_UINT32 sizeHigh);  /* UNICODE version */

/* Description
   This function is called by application to apply size to an
   open file. When the specified file size is less than the
   current file size, this operation truncates the file to the
   specified size.
   Parameters
   handle :    Handle value returned by calling <link ccCreateFile, ccCreateFile()>.
   sizeLow :   Low 32 bit if the desired file size.
   sizeHigh :  High 32 bit if the desired file size.
   Returns
   This function returns TRUE if the file size was modified
   successfully or FALSE otherwise.                                                  */
NQ_BOOL ccSetFileSizeByHandle(NQ_HANDLE handle, NQ_UINT32 sizeLow, NQ_UINT32 sizeHigh);

/* Description
   This function is called by application to get the time
   information of the specified file.
   Parameters
   handle :       Handle value returned by calling <link ccCreateFile, ccCreateFile()>
   pCreation :    Pointer to a buffer for file creation time.
                  This buffer should hold the time structure (see
                  <link FileTime_t, FileTime_t Structure>)
   pLastAccess :  Pointer to a buffer for file last access time.
                  This buffer should hold the time structure (see
                  <link FileTime_t, FileTime_t Structure>)
   pLastWrite :   Pointer to a buffer for file last write time.
                  This buffer should hold the time structure (see
                  <link FileTime_t, FileTime_t Structure>)
   Returns
   This function returns TRUE if the specified file time
   information is obtained successfully or FALSE otherwise. The
   application can inspect the error code for the failure
   reason.                                                                             */
NQ_BOOL ccGetFileTime(NQ_HANDLE handle, FileTime_t *pCreation, FileTime_t *pLastAccess, FileTime_t *pLastWrite);

/* Description
   This function is called by application to set the time
   information of the specified file.
   
   NQ Client sends time modification request using the provided
   time values but the server interpretation of this request may
   apply additional calculations, so that the resulted file
   times may differ.
   Parameters
   handle :       Handle value returned by calling <link ccCreateFile, ccCreateFile()>.
   pCreation :    Pointer to a structure holding the file
                  creation time (see <link FileTime_t, FileTime_t Structure>)
   pLastAccess :  Pointer to a structure holding the file last
                  access time (see <link FileTime_t, FileTime_t Structure>)
   pLastWrite :   Pointer to a structure holding the file last
                  write time (see <link FileTime_t, FileTime_t Structure>)
   
   Returns
   This function returns TRUE if the specified file time
   information is set successfully or FALSE otherwise. The
   application can inspect the error code for the failure
   reason.                                                                              */
NQ_BOOL ccSetFileTime(NQ_HANDLE handle, FileTime_t *pCreation, FileTime_t *pLastAccess, FileTime_t *pLastWrite);

/* Description
   This function is called by application to get the size of the
   specified file.
   Parameters
   handle :        Handle value returned by calling <link ccCreateFile, ccCreateFile()>
   fileSizeHigh :  Pointer to a buffer for the high\-order 32
                   bits of the file size
   Returns
   This function returns the low-order 32 bits of the file size
   if the specified file size information is obtained
   successfully or NQ_ERR_SIZEERROR otherwise. The application
   can inspect the error code for the failure reason.                                   */
NQ_UINT32 ccGetFileSize(NQ_HANDLE handle, NQ_UINT32 *fileSizeHigh);

/* Description
   This function is called by application to get the information
   of an open file
   Parameters
   handle :    Handle value returned by calling <link ccCreateFile, ccCreateFile()>
   fileInfo :  Pointer to a structure holding the file
               information (see <link FileInfo_t, FileInfo_t Structure>)
   Returns
   This function returns TRUE if the specified file information
   is obtained successfully or FALSE otherwise. The application
   can inspect the error code for the failure reason.                               */
NQ_BOOL ccGetFileInformationByHandle(NQ_HANDLE handle, FileInfo_t *fileInfo);

#ifdef UD_CC_INCLUDEOLDBROWSERAPI

#ifdef UD_NQ_USETRANSPORTNETBIOS

/* Description
   This function is called by application to get the
   domains/workgroups collected from the network. Browser daemon
   listens on the network for the domain announcements packets
   which are sent by Local Master Browsers of each
   domain/workgroup once per 12 minutes. If no announcements
   have been captured so far then this function returns an empty
   list. This does not indicate an error.
   
   This call is a triplet call (see <link Summary>).
   Parameters
   listBuffer :  Buffer to place the ‘\\0’ separated list of
                 domains/workgroups.
   bufferSize :  Size of listBuffer.
   count :       Pointer to a variable that will receive the
                 number of items returned in the list.
   Returns
   This function returns TRUE if the list of domains/workgroups
   is obtained successfully or FALSE otherwise. Application can
   examine the error code for the failure.
   Note
   This function is only avaiable when NQ supports the NetBIOS transport. 
   Note
   This function is deprecated. Use new Browser API instead. The
   functions of the new Browser API are designated with a <i>ccNetwork...
   </i>prefix.                                                            */
#ifdef UD_CM_UNICODEAPPLICATION
    #define nqGetCachedWorkgroups nqGetCachedWorkgroupsW
#else
    #define nqGetCachedWorkgroups nqGetCachedWorkgroupsA
#endif
NQ_BOOL nqGetCachedWorkgroupsA(NQ_CHAR *listBuffer, NQ_UINT  bufferSize, NQ_UINT *count);   /* ASCII version */
NQ_BOOL nqGetCachedWorkgroupsW(NQ_WCHAR *listBuffer, NQ_UINT  bufferSize, NQ_UINT *count);  /* UNICODE version */

/* Description
   This function defines the name of domain/workgroup that will
   be used as the default in subsequent calls. This call is a
   triplet call (see <link Summary>).
   Parameters
   workgroup :  The name of the domain/workgroup to be used in
                subsequent browser related calls as the default
                domain/workgroup.
   Returns
   None                                                         
   Note
   This function is only avaiable when NQ supports the NetBIOS transport. 
   Note
   This function is deprecated. Use new Browser API instead. The
   functions of the new Browser API are designated with a <i>ccNetwork...
   */
#ifdef UD_CM_UNICODEAPPLICATION
    #define nqSetClientDefaultWorkgroup nqSetClientDefaultWorkgroupW
#else
    #define nqSetClientDefaultWorkgroup nqSetClientDefaultWorkgroupA
#endif
void nqSetClientDefaultWorkgroupA(NQ_CHAR *workgroup);      /* ASCII version */
void nqSetClientDefaultWorkgroupW(NQ_WCHAR *workgroup);     /* UNICODE version */

/* Description
   This function is called by application to get the name of the
   workgroup/domain that CIFS Client will use by default. This
   workgroup/domain will be used in those CIFS Client functions
   where workgroup/domain is not explicitly specified.
   
   This call is a triplet call (see <link Summary>).
   Parameters
   workgroup :  Buffer to place the name of the default
                domain/workgroup. This buffer should be able to
                accommodate at least <link DOMAIN_LENGTH>
                charactesr.
   Returns
   None
   Note
   This function is only avaiable when NQ supports the NetBIOS transport. 
   Note
   This function is deprecated. Use new Browser API instead. The
   functions of the new Browser API are designated with a <i>ccNetwork...
   </i>prefix.                                                            */
#ifdef UD_CM_UNICODEAPPLICATION
    #define nqGetClientDefaultWorkgroup nqGetClientDefaultWorkgroupW
#else
    #define nqGetClientDefaultWorkgroup nqGetClientDefaultWorkgroupA
#endif
void nqGetClientDefaultWorkgroupA(NQ_CHAR *workgroup);      /* ASCII version */
void nqGetClientDefaultWorkgroupW(NQ_WCHAR *workgroup);     /* UNICODE version */

/* Description
   This function is called by application to get the list of all
   domains/workgroups registered with the default workgroup’s
   Local Master Browser. Normally Local Master Browser of each
   domain/workgroup has a list of all known domains/workgroups.
   If no domains/workgroups are known then it is possible to
   call <link nqGetCachedWorkgroups, nqGetCachedWorkgroups()> to
   get at least one, which can be used in a call to <link nqGetWorkgroupsByWg, nqGetWorkgroupsByWg()>
   function to obtain the entire list.
   
   This call is a triplet call (see <link Summary>).
   Parameters
   listBuffer :  Buffer to place the ‘\\0’ separated list of
                 domains/workgroups.
   bufferSize :  Size of listBuffer.
   count :       Pointer to a variable that will receive the
                 number of items returned in the list.
   Returns
   This function returns TRUE if the list of domains/workgroups
   is obtained successfully or FALSE otherwise. Application can
   examine the error code for the failure reason.
   See Also
   <link nqGetCachedWorkgroups, nqGetCachedWorkgroups()>
   
   <link nqGetWorkgroupsByWg, nqGetWorkgroupsByWg()>
   Note
   This function is only avaiable when NQ supports the NetBIOS transport. 
   Note
   This function is deprecated. Use new Browser API instead. The
   functions of the new Browser API are designated with a <i>ccNetwork...
   </i>prefix.                                                                                        */
#ifdef UD_CM_UNICODEAPPLICATION
    #define nqGetWorkgroups nqGetWorkgroupsW
#else
    #define nqGetWorkgroups nqGetWorkgroupsA
#endif
NQ_BOOL nqGetWorkgroupsA(NQ_CHAR *listBuffer, NQ_COUNT bufferSize, NQ_INT *count);  /* ASCII version */
NQ_BOOL nqGetWorkgroupsW(NQ_WCHAR *listBuffer, NQ_COUNT bufferSize, NQ_INT *count); /* UNICODE version */

/* Description
   This function is called by application to get the list of all
   domains/workgroups registered with the specified workgroup’s
   Local Master Browser. This function can be used if at least
   one domain/workgroup is known on the network. Normally Local
   Master Browser of each domain/workgroup has a list of all
   known domains/workgroups. If no domains/workgroups are known
   then it is possible to call <link nqGetCachedWorkgroups, nqGetCachedWorkgroups()>
   to get at least one, which can be used in a call to this
   function to obtain the entire list.
   
   This call is a triplet call (see <link Summary>).
   Parameters
   workgroup :   Workgroup/Domain name.
   listBuffer :  Buffer to place the ‘\\0’ separated list of
                 domains/workgroups.
   bufferSize :  Size of listBuffer.
   count :       Pointer to a variable that will receive the number
                 of items returned in the list.
   Returns
   This function returns TRUE if the list of all workgroups is
   obtained successfully or FALSE otherwise. Application can
   examine the error code for the failure reason.
   See Also
   <link nqGetCachedWorkgroups, nqGetCachedWorkgroups()>
   Note
   This function is only avaiable when NQ supports the NetBIOS transport. 
   Note
   This function is deprecated. Use new Browser API instead. The
   functions of the new Browser API are designated with a <i>ccNetwork...
   </i>prefix.
                                                                                     */
#ifdef UD_CM_UNICODEAPPLICATION
    #define nqGetWorkgroupsByWg nqGetWorkgroupsByWgW
#else
    #define nqGetWorkgroupsByWg nqGetWorkgroupsByWgA
#endif
NQ_BOOL nqGetWorkgroupsByWgA(NQ_CHAR *workgroup, NQ_CHAR *listBuffer, NQ_COUNT bufferSize, NQ_INT *count);      /* ASCII version */
NQ_BOOL nqGetWorkgroupsByWgW(NQ_WCHAR *workgroup, NQ_WCHAR *listBuffer, NQ_COUNT bufferSize, NQ_INT *count);    /* UNICODE version */

#endif /* UD_NQ_USETRANSPORTNETBIOS */

/* Description
   This function is called by application to get the list of all
   hosts in the default Domain/Workgroup. This call is a triplet
   call (see <link Summary>).
   Parameters
   listBuffer :  Buffer to place the ‘\\0’ separated list of
                 hosts.
   bufferSize :  Size of listBuffer in characters.
   count :       Pointer to a variable that will receive the
                 number of items in the list returned.
   Returns
   This function returns TRUE if the list of all hosts in
   specified Domain/Workgroup is obtained successfully or FALSE
   otherwise. Application can examine the error code for the
   failure reason.
   Note
   This function is deprecated. Use new Browser API instead. The
   functions of the new Browser API are designated with a <i>ccNetwork...
   </i>prefix.      
   */
#ifdef UD_CM_UNICODEAPPLICATION
    #define nqGetHostsInWorkgroup nqGetHostsInWorkgroupW
#else
    #define nqGetHostsInWorkgroup nqGetHostsInWorkgroupA
#endif
NQ_BOOL nqGetHostsInWorkgroupA(NQ_CHAR *listBuffer, NQ_COUNT bufferSize, NQ_INT *count);    /* ASCII version */
NQ_BOOL nqGetHostsInWorkgroupW(NQ_WCHAR *listBuffer, NQ_COUNT bufferSize, NQ_INT *count);   /* UNICODE version */

/* Description
   This function is called by application to get the list of all
   hosts in the specified Domain/Workgroup. This call is a
   triplet call (see <link Summary>).
   Parameters
   workgroup :   Domain/workgroup name.
   listBuffer :  Buffer to place the ‘\\0’ separated list of hosts.
   bufferSize :  Size of listBuffer in characters.
   count :       Pointer to a variable that will receive the number
                 of items in the list returned.
   Returns
   This function returns TRUE if the list of all hosts in
   specified Domain/Workgroup is obtained successfully or FALSE
   otherwise. Application can examine the error code for the
   failure reason.
   Note
   This function is deprecated. Use new Browser API instead. The
   functions of the new Browser API are designated with a <i>ccNetwork...
   </i>prefix.                                                            */
#ifdef UD_CM_UNICODEAPPLICATION
    #define nqGetHostsInWorkgroupByWg nqGetHostsInWorkgroupByWgW
#else
    #define nqGetHostsInWorkgroupByWg nqGetHostsInWorkgroupByWgA
#endif
NQ_BOOL nqGetHostsInWorkgroupByWgA(NQ_CHAR *workgroup, NQ_CHAR *listBuffer, NQ_COUNT bufferSize, NQ_INT *count);    /* ASCII version */
NQ_BOOL nqGetHostsInWorkgroupByWgW(NQ_WCHAR *workgroup, NQ_WCHAR *listBuffer, NQ_COUNT bufferSize, NQ_INT *count);  /* UNICODE version */

/* Description
   This function is called by application to get the list of all
   shares on the specified host. This call is a triplet call
   (see <link Summary>).
   Parameters
   hostName :    Host name.
   listBuffer :  Buffer to place the ‘\\0’ separated list of
                 shares.
   bufferSize :  Size of listBuffer in characters.
   count :       Pointer to a variable that will receive the
                 number of items in the list returned.
   Returns
   This function returns TRUE if the list of all shares on the
   host is obtained successfully or FALSE otherwise. Application
   can examine the error code for the failure reason.
   Note
   This function is deprecated. Use new Browser API instead. The
   functions of the new Browser API are designated with a <i>ccNetwork...
   </i>prefix.                                                            */
#ifdef UD_CM_UNICODEAPPLICATION
    #define nqGetSharesOnHost nqGetSharesOnHostW
#else
    #define nqGetSharesOnHost nqGetSharesOnHostA
#endif
NQ_BOOL nqGetSharesOnHostA(NQ_CHAR *hostName, NQ_CHAR *listBuffer, NQ_COUNT bufferSize, NQ_INT *count);     /* ASCII version */
NQ_BOOL nqGetSharesOnHostW(NQ_WCHAR *hostName, NQ_WCHAR *listBuffer, NQ_COUNT bufferSize, NQ_INT *count);   /* UNICODE version */

/* Description
   This function is called by application to get information
   about a particular share on the specified host. This call is
   a triplet call (see <link Summary>).
   Parameters
   hostName :      Host name.
   shareName :     Share name.
   type :          Share types as\:<p />0 \- directory tree<p />1
                   \- print queue<p />2 \- serial device<p />3 \-
                   IPC<p />0x80000000 \- hidden share
   remarkBuffer :  Buffer to place the share remark into. 
   bufferSize :    Size of the remark buffer. The recommended
                   value is 256 characters.
   Returns
   This function returns TRUE if the share information is
   obtained successfully or FALSE otherwise. Application can
   examine the error code for the failure reason.
   Note
   This function is deprecated. Use new Browser API instead. The
   functions of the new Browser API are designated with a <i>ccNetwork...
   </i>prefix.                                                            */
#ifdef UD_CM_UNICODEAPPLICATION
    #define nqGetShareInfo nqGetShareInfoW
#else
    #define nqGetShareInfo nqGetShareInfoA
#endif
NQ_BOOL nqGetShareInfoA(NQ_CHAR *hostName, NQ_CHAR *shareName, NQ_UINT16 *type, NQ_CHAR *remarkBuffer, NQ_INT bufferSize);      /* ASCII version */
NQ_BOOL nqGetShareInfoW(NQ_WCHAR *hostName, NQ_WCHAR *shareName, NQ_UINT16 *type, NQ_WCHAR *remarkBuffer, NQ_INT bufferSize);   /* UNICODE version */

#endif /* UD_CC_INCLUDEOLDBROWSERAPI */

#ifdef UD_NQ_USETRANSPORTNETBIOS

/* Description
   This function is called by application to start enumerating
   domains/workgroups. It executes necessary transactions to
   withdraw domains/workgroups announced on the network. After
   successful return from this call, NQ Client creates a list of
   domains/workgroups designated by an abstract handle.
   
   Application may withdraw domain/workgroup names one by one by
   calling <link ccNetworkGetNextItemName, ccNetworkGetNextItemName()>
   with the handle obtained in the current call. When finished
   with domain enumeration, application must call <link ccNetworkCloseHandle@NQ_HANDLE, ccNetworkCloseHandle()>
   to release resources associated with this handle.
   Returns
   This function returns an enumeration handle. Application
   should use this abstract handle in subsequent calls to <link ccNetworkGetNextItemName, ccNetworkGetNextItemName()>.
   On error this function returns a NULL handle. Application can
   examine the error code for the failure reason.
   Note
   The resulted handle is not thread-safe.
   Note
   This function is only avaiable when NQ supports the NetBIOS transport. 
   See Also
   <link ccNetworkGetNextItemName, ccNetworkGetNextItemName()>
   
   <link ccNetworkCloseHandle@NQ_HANDLE, ccNetworkCloseHandle(>                                                          */
NQ_HANDLE ccNetworkEnumerateDomains(void);

#endif /* UD_NQ_USETRANSPORTNETBIOS */

/* Description
   This function is called by application to start enumerating
   servers of a particular domain/workgroups. It executes
   necessary transactions to withdraw the server list. After
   successful return from this call, NQ Client creates a list of
   servers designated by an abstract handle.
   
   Application may withdraw server names one by one by calling <link ccNetworkGetNextItemName, ccNetworkGetNextItemName()>
   with the handle obtained in the current call. When finished
   with domain enumeration, application must call <link ccNetworkCloseHandle@NQ_HANDLE, ccNetworkCloseHandle()>
   to release resources associated with this handle.
   
   This call is a triplet call (see <link Summary>).
   Parameters
   domain :  Domain/workgroup name. This call will return a list
             of servers for this domain/workgroup.
   Returns
   This function returns an enumeration handle. Application
   should use this abstract handle in subsequent calls to <link ccNetworkGetNextItemName, ccNetworkGetNextItemName()>.
   On error this function returns a NULL handle. Application can
   examine the error code for the failure reason.
   Note
   The resulted handle is not thread-safe.
   See Also
   <link ccNetworkGetNextItemName, ccNetworkGetNextItemName()>
   
   <link ccNetworkCloseHandle@NQ_HANDLE, ccNetworkCloseHandle>                                                               */
#ifdef UD_CM_UNICODEAPPLICATION
    #define ccNetworkEnumerateServers ccNetworkEnumerateServersW
#else
    #define ccNetworkEnumerateServers ccNetworkEnumerateServersA
#endif
NQ_HANDLE ccNetworkEnumerateServersA(const NQ_CHAR * domain); 			/* ASCII version */
NQ_HANDLE ccNetworkEnumerateServersW(const NQ_WCHAR * domain); 			/* UNICODE version */

/* Description
   This function is called by application to start enumerating
   shares on a particular server. It executes necessary
   transactions to withdraw the list of shares. After successful
   return from this call, NQ Client creates a list of shares
   designated by an abstract handle.
   
   Application may withdraw share names one by one by calling <link ccNetworkGetNextItemName, ccNetworkGetNextItemName()>
   with the handle obtained in the current call. When finished
   with domain enumeration, application must call <link ccNetworkCloseHandle@NQ_HANDLE, ccNetworkCloseHandle()>
   to release resources associated with this handle.
   
   This call is a triplet call (see <link Summary>).
   Parameters
   server :  Server name. This call will return a list of shares
             for this domain/workgroup.
   Returns
   This function returns an enumeration handle. Application
   should use this abstract handle in subsequent calls to <link ccNetworkGetNextItemName, ccNetworkGetNextItemName()>.
   On error this function returns a NULL handle. Application can
   examine the error code for the failure reason.
   Note
   The resulted handle is not thread-safe.
   See Also
   <link ccNetworkGetNextItemName, ccNetworkGetNextItemName()>
   
   <link ccNetworkCloseHandle@NQ_HANDLE, ccNetworkCloseHandle()>                                                            */
#ifdef UD_CM_UNICODEAPPLICATION
    #define ccNetworkEnumerateShares ccNetworkEnumerateSharesW
#else
    #define ccNetworkEnumerateShares ccNetworkEnumerateSharesA
#endif
NQ_HANDLE ccNetworkEnumerateSharesA(const NQ_CHAR * server); 				/* ASCII version */
NQ_HANDLE ccNetworkEnumerateSharesW(const NQ_WCHAR * server);				/* UNICODE version */ 

/* Description
   Application calls this function after successfully staring a
   browser enumeration ( <link ccNetworkEnumerateDomains, ccNetworkEnumerateDomains()>,
   <link ccNetworkEnumerateServers, ccNetworkEnumerateServers()>
   or <link ccNetworkEnumerateShares, ccNetworkEnumerateShares()>).
   .
   
   Application may withdraw share names one by one by calling <link ccNetworkGetNextItemName, ccNetworkGetNextItemName()>
   with the handle obtained in the current call. When finished
   with domain enumeration, application must call <link ccNetworkCloseHandle@NQ_HANDLE, ccNetworkCloseHandle()>
   to release resources associated with this handle.
   
   This call is a triplet call (see <link Summary>).
   Parameters
   handle :  Enumeration handle as obtained in one of Browser
             enumeration calls. 
   Returns
   This function returns a pointer to the next item name in the
   enumeration. Item type depends on the handle source - one of
   the browser enumeration calls. This function returns a NULL
   pointer when NQ Client reaches the end of enumeration.
   See Also
   <link ccNetworkEnumerateDomains, ccNetworkEnumerateDomains()>
   
   <link ccNetworkEnumerateServers, ccNetworkEnumerateServers()>
   
   <link ccNetworkEnumerateShares, ccNetworkEnumerateShares()>                                                            */
#ifdef UD_CM_UNICODEAPPLICATION
    #define ccNetworkGetNextItemName ccNetworkGetNextItemNameW
#else
    #define ccNetworkGetNextItemName ccNetworkGetNextItemNameA
#endif
const NQ_CHAR * ccNetworkGetNextItemNameA(NQ_HANDLE handle);			/* ASCII version */
const NQ_WCHAR * ccNetworkGetNextItemNameW(NQ_HANDLE handle);			/* UNICODE version */

/* Description
   This function is called by application to get information
   about a particular share on the specified host. This call is
   a triplet call (see <link Summary>).
   Parameters
   server :        Server name.
   share :         Share name.
   type :          Share types as\:<p />0 \- directory tree<p />1
                   \- print queue<p />2 \- serial device<p />3 \-
                   IPC<p />0x80000000 \- hidden share
   remarkBuffer :  Buffer to place the share remark into.
   bufferSize :    Size of the remark buffer. The recommended
                   value is 256 characters.
   Returns
   This function returns TRUE if the share information is
   obtained successfully or FALSE otherwise. Application can
   examine the error code for the failure reason.                 */
#ifdef UD_CM_UNICODEAPPLICATION
    #define ccNetworkGetShareInfo ccNetworkGetShareInfoW
#else
    #define ccNetworkGetShareInfo ccNetworkGetShareInfoA
#endif
NQ_BOOL ccNetworkGetShareInfoA(const NQ_CHAR * server, const NQ_CHAR * share, NQ_UINT16 * type, NQ_CHAR * remarkBuffer, NQ_INT bufferSize);      /* ASCII version */
NQ_BOOL ccNetworkGetShareInfoW(const NQ_WCHAR * server, const NQ_WCHAR * share, NQ_UINT16 * type, NQ_WCHAR * remarkBuffer, NQ_INT bufferSize);   /* UNICODE version */

/* Description
   This function is called by application to finish a browser
   enumeration and release all resources (e.g., - item names)
   associated with that enumeration.
   Parameters
   handle :  An abstract handle as obtained from one of the
             browser enumeration calls.
   Returns
   TRUE on success or FALSE on error.
   Note
   Currently, this function always return TRUE.
   See Also
   <link ccNetworkEnumerateDomains, ccNetworkEnumerateDomains()>
   
   <link ccNetworkEnumerateServers, ccNetworkEnumerateServers()>
   
   <link ccNetworkEnumerateShares, ccNetworkEnumerateShares()>   */
NQ_BOOL ccNetworkCloseHandle(NQ_HANDLE handle);

/* Description
   This function is called by application to restart a browser
   enumeration designated by an abstract handle. If this handle
   was already used in one or more of the <link ccNetworkGetNextItemName, ccNetworkGetNextItemName()>
   calls, NQ Client will revert it to the state it has right
   after the respective Browser enumeration call (see below).
   Parameters
   handle :  An abstract handle as obtained from one of the
             browser enumeration calls.
   Returns
   TRUE on success or FALSE on error.
   Note
   Currently, this function always return TRUE.
   See Also
   <link ccNetworkEnumerateDomains, ccNetworkEnumerateDomains()>
   
   <link ccNetworkEnumerateServers, ccNetworkEnumerateServers()>
   
   <link ccNetworkEnumerateShares>                                                                    */
NQ_BOOL ccNetworkResetHandle(NQ_HANDLE handle);

/* Description
   This function is called by application to set the NQ CIFS
   Client security configuration. Before this function is called
   NQ CIFS Client uses the default security configuration (<link NQ_CC_AUTH_LM_AND_NTLM>
   and no message signing).
   Parameters
   authenticationLevel :  LAN Manager authentication level. The
                          value of this parameter can be one of
                          the following\:<p /><link NQ_CC_AUTH_LM_AND_NTLM><p /><link NQ_CC_AUTH_NTLM><p /><link NQ_CC_AUTH_NTLM_V2><p /><link NQ_CC_AUTH_SPNEGO_KERBEROS>
   messageSigning :       Message signing. The value of this
                          parameter can be one of the following\:<p />TRUE
                          – sign messages if server supports
                          signing<p />FALSE – do not sign if
                          server does not require signing
   Returns
   None                                                                                                                                                                    */
void nqSetSecurityParams(NQ_INT authenticationLevel, NQ_BOOL messageSigning);

/* Description
   This function is called by application to get the current
   Message Signing mode.
   Returns
   This function returns TRUE if the current mode is set to sign
   messages if server supports signing or FALSE if it is set to
   not sign if server does not require signing.                  */
NQ_BOOL nqGetMessageSigning(void);

/* Description
   This function is called by application to get the current
   Authentication Level.
   Returns
   This function returns the current Authentication Level (see
   ???).                                                       */
NQ_INT nqGetAuthenticationLevel(void);

/* Description
   This function is called by application to verify that the
   user credentials supplied by udGetCredentials() are
   sufficient on the specified server (Domain Controller).
   
   This call is a triplet call (see <link Summary>).
   Parameters
   server :  Server name the credentials should be verified
             against. If this parameter is NULL then CIFS Client
             will try to automatically discover the Domain
             Controller and verify the credentials against it.
   Returns
   This function returns TRUE if the user is successfully
   authenticated or FALSE otherwise. The application can inspect
   the error code for the failure reason.
   Note
   This function is deprecated. Use new Browser API instead. The
   functions of the new Browser API are designated with a <i>ccNetwork...
   </i>prefix.                                                            */
#ifdef UD_CM_UNICODEAPPLICATION
    #define nqCheckClientUserCredentials nqCheckClientUserCredentialsW
#else
    #define nqCheckClientUserCredentials nqCheckClientUserCredentialsA
#endif
NQ_BOOL nqCheckClientUserCredentialsA(NQ_CHAR *server);     /* ASCII version */
NQ_BOOL nqCheckClientUserCredentialsW(NQ_WCHAR *server);    /* UNICODE version */

/* Description
   This function is called by application to close all open
   connections and to release resources associated with them. In
   this function call NQ will do the following:
     * Close all files;
     * Release outstanding searches;
     * Disconnect from shares (trees);
     * Logoff users;
     * Disconnect from servers.
   Returns
   None.                                                         */
void ccCloseAllConnections(void);

/* Description
   This function is called by application to those connections
   that were used implicitly and are not associated with any
   mount. For instance, upon this call NQ will close those
   connections that were open solely for network browsing. NQ
   will release all resources associated with the connections
   being closed, namely:
     * Close open files;
     * Release outstanding searches;
     * Disconnect from shares (trees);
     * Logoff users;
     * Disconnect from servers.
   Returns
   None.                                                       */
void ccCloseHiddenConnections(void);

/* Description
   Set SMB timeout for waiting a response.
   Parameters
   secs :  Number of seconds to wait for an SMB response. The
           default value is 15 seconds.
   Returns
   None                                                       */
void ccConfigSetTimeout(NQ_TIME secs);

/* Description
   Get the current value of SMB timeout.
   Returns 
   Number of seconds to wait for an SMB response. The default value is 15 seconds.
 */
NQ_TIME ccConfigGetTimeout(void);

#ifdef UD_CC_INCLUDEDOMAINMEMBERSHIP

/* Description
   This function performs target computer to the domain.
   
   After successfully joining domain, this function returns a
   computer password obtained from domain controller to be used
   for further logging into domain. This operation requires
   domain administrative credentials.
   
   This call is a triplet call (see <link Summary>).
   Parameters
   domain :    Name of the domain to join. This may be a fully
               qualified name.
   computer :  Name of the computer (host) that joins.
   admin :     Administrative credentials for tis domain.
   secret :    Buffer for computer password. This buffer should
               accommodate at least 16 bytes .
   Returns
   This function returns TRUE if computer succeeded to join the
   domain or FALSE otherwise. The application can inspect the
   error code for the failure reason.
   See Also
   <link ccDomainLogon, ccDomainLogon()>
   
   <link ccDomainLeave, ccDomainLeave()>
   
   <link CCCredentials, CCCredentials structure>                */
#ifdef UD_CM_UNICODEAPPLICATION
    #define ccDomainJoin ccDomainJoinW
#else
    #define ccDomainJoin ccDomainJoinA
#endif

NQ_BOOL ccDomainJoinA(const NQ_CHAR *domain, const NQ_CHAR *computer, 
                      const AMCredentialsA *admin, NQ_BYTE secret[16]);     /* ASCII version */
NQ_BOOL ccDomainJoinW(const NQ_WCHAR *domain, const NQ_WCHAR *computer,
                      const AMCredentialsW *admin, NQ_BYTE secret[16]);     /* UNICODE version */

/* Description
   This function cancels domain membership of the target
   computer. This call is a triplet call (see <link Summary>).
   Parameters
   domain :    Name of the domain to leave.
   computer :  Name of the computer (host) that leaves.
   admin :     Administrative credentials for tis domain.
   Returns
   This function returns TRUE if computer successfully leaves
   the domain or FALSE otherwise. The application can inspect
   the error code for the failure reason.
   See Also
   <link ccDomainJoin, ccDomainJoin()>
   
   <link CCCredentials, CCCredentials structure>               */
#ifdef UD_CM_UNICODEAPPLICATION
    #define ccDomainLeave ccDomainLeaveW
#else
    #define ccDomainLeave ccDomainLeaveA
#endif
NQ_BOOL ccDomainLeaveA(const NQ_CHAR *domain, const NQ_CHAR *computer, const AMCredentialsA *admin);    /* ASCII version */
NQ_BOOL ccDomainLeaveW(const NQ_WCHAR *domain, const NQ_WCHAR *computer, const AMCredentialsW *admin);  /* UNICODE version */  

/* Description
   This function performs domain logon operation supplying a
   password obtained from domain controller by calling <link ccDomainJoin, ccDomainJoin()>.
   This call is a triplet call (see <link Summary>).
   Parameters
   domain :    Name of the domain to log on.
   computer :  Computer (host) name.
   user :      User credentials.
   secret :    Password as obtained when joining domain.
   Returns
   This function returns TRUE if the computer has successfully
   logged with the domain controller or FALSE otherwise. The
   application can inspect the error code for the failure
   reason.
   See Also
   <link ccDomainJoin, ccDomainJoin()>
   
   <link CCCredentials, CCCredentials structure>                                            */
#ifdef UD_CM_UNICODEAPPLICATION
    #define ccDomainLogon ccDomainLogonW
#else
    #define ccDomainLogon ccDomainLogonA
#endif
NQ_BOOL ccDomainLogonA(const NQ_CHAR * domain, const NQ_CHAR * computer, 
                       const AMCredentialsA * admin, NQ_BYTE secret[16]);      /* ASCII version */
NQ_BOOL ccDomainLogonW(const NQ_WCHAR *domain, const NQ_WCHAR * computer,
                       const AMCredentialsW * admin, NQ_BYTE secret[16]        /* UNICODE version */
    );

#endif /* UD_CC_INCLUDEDOMAINMEMBERSHIP */

#ifdef UD_CC_INCLUDESECURITYDESCRIPTORS

/* Description
   This function sets or removes exclusive access rights or
   restores default access rights.
   
   This function applies access rights to a file. When
   makeExclusive parameter is TRUE the following access rights
   will be applied:
   
   • Owner – full access
   
   • Administrators (group) – full access
   
   • All others – no access
   
   • When applied to a folder, access rights will be propagated
   down to subfolders/files, unless they have non-inheriting
   security descriptors
   
   • The ownership is changed to the user authenticated.
   
   • Access rights of the parent directory will be no more
   inherited.
   
   When the second parameter is FALSE file descriptor is
   modified so that all access rights are inherited from the
   parent directory.
   
   When this function returns TRUE it means that the remote
   server has accepted new access rights but it does not
   guarantee that those rights were effectively modified. To
   check the latter use <link ccIsExclusiveAccessToFile, ccIsExclusiveAccessToFile()>.
   
   This call is a triplet call (see <link Summary>).
   Parameters
   fileName :       Path to the file.
   makeExclusive :  TRUE to set exclusive access, FALSE to revert
                    to default access rights.
   Returns
   TRUE when operation succeeded, FALSE on error. The
   application can inspect the error code for the failure
   reason.                                                                             */
#ifdef UD_CM_UNICODEAPPLICATION
    #define ccSetExclusiveAccessToFile ccSetExclusiveAccessToFileW
#else
    #define ccSetExclusiveAccessToFile ccSetExclusiveAccessToFileA
#endif
NQ_BOOL ccSetExclusiveAccessToFileA(NQ_CHAR *fileName, NQ_BOOL makeExclusive);  /* ASCII version */
NQ_BOOL ccSetExclusiveAccessToFileW(NQ_WCHAR *fileName, NQ_BOOL makeExclusive); /* UNICODE version */

/* Description
   This function is called by application to determine whether
   the file/directory specified by the parameter has exclusive
   access rights. This call is a triplet call (see <link Summary>).
   Parameters
   fileName :  Path to the file.
   Returns
   TRUE if the file specified by the parameter has exclusive
   access rights or FALSE otherwise.
   See Also
   <link ccSetExclusiveAccessToFile, ccSetExclusiveAccessToFile()>  */
#ifdef UD_CM_UNICODEAPPLICATION
    #define ccIsExclusiveAccessToFile ccIsExclusiveAccessToFileW
#else
    #define ccIsExclusiveAccessToFile ccIsExclusiveAccessToFileA
#endif
NQ_BOOL ccIsExclusiveAccessToFileA(NQ_CHAR *fileName);  /* ASCII version */
NQ_BOOL ccIsExclusiveAccessToFileW(NQ_WCHAR *fileName); /* UNICODE version */

#endif /* UD_CC_INCLUDESECURITYDESCRIPTORS */

/* Description
   Register the current system thread.

   This function creates an NQ object describing the current system (application) thread. 
   NQ expects the application to call cmThreadUnsubscribe() to release NQ resources accosiated with
   this thread. If this thread was alreday registered, nothing will happen. 
   Returns
   None.                                      */
void ccThreadSubscribe(void);

/* Description
   Release the resources accosiated with the current system thread.

   NQ assumes that the current system (application) thread was registered with a 
   cmThreadSubscribe() call. If this is not true, nothing will happen. 
   Returns
   None.                                      */
void ccThreadUnsubscribe(void);

#endif /* _CCAPI_H_ */

