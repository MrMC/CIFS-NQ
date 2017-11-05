
/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Upper-level functions
 *--------------------------------------------------------------------
 * MODULE        : CS - CIFS Server
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 29-June-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _NQAPI_H_
#define _NQAPI_H_

#include "cmapi.h"

SY_STARTAPI

NQ_INT nqAddShareA(const NQ_CHAR * name, const NQ_CHAR * path, NQ_BOOL printQueue, const NQ_CHAR * comment, const NQ_CHAR * reserved); /* ASCII version */
NQ_INT nqAddShareW(const NQ_WCHAR * name, const NQ_WCHAR * path, NQ_BOOL printQueue, const NQ_WCHAR * comment, const NQ_CHAR * reserved); /* UNICODE version */

/* Description
   This function adds another share to NQ Server.
   Parameters
   name :        Name for new share.
   path :        Local path to the share root.
   printQueue :  FALSE for file system, TRUE for print queue.
   comment :     Share description as a free text.
   reserved :    For future use. This value is currently ignored
                 and may be any, including NULL. 
   
   Returns
   <table>
   0 - Success
   \-1 the DB was not initialized
   \-2 parameter error (string too long)
   \-3 share table full
   \-6 share already exists
   </table>
  
   Note
   This function should be called from the context of NQ Server
   thread. It is recommended to sue it on NQ Server startup
   only.                                                       */
#ifdef UD_CM_UNICODEAPPLICATION
    #define nqAddShare nqAddShareW
#else
    #define nqAddShare nqAddShareA
#endif

NQ_INT nqRemoveShareA(const NQ_CHAR * name);	/* ASCII version */
NQ_INT nqRemoveShareW(const NQ_WCHAR* name);	/* UNICODE version */

/* Description
   This function removes an existing share from NQ Server.
   Parameters
   name :  Name of the share to remove.
   Returns
   <table>
   0       Success
   \-1     NQ Server was not initialized
   \-2     parameter error (share not found)
   </table>
   Note
   This function should be called from the context of NQ Server
   thread. It is recommended to sue it on NQ Server startup
   only.                                                        */
#ifdef UD_CM_UNICODEAPPLICATION
    #define nqRemoveShare nqRemoveShareW
#else
    #define nqRemoveShare nqRemoveShareA
#endif

#ifdef UD_NQ_INCLUDESMB3

NQ_INT nqSetShareEncryptionA(const NQ_CHAR * name, NQ_BOOL isEncrypted); /* ASCII version */
NQ_INT nqSetShareEncryptionW(const NQ_WCHAR * name, NQ_BOOL isEncrypted); /* UNICODE version */

/* Description
   This function enables or disables encryption for a particular
   share. An encrypted share may be only accessed over SMB3.0.
   
   This function is applicable to any share regardless of way it
   was created.
   Parameters
   name :         Share name or NULL for global encryption.
   isEncrypted :  TRUE to enable encryption on this share, FALSE
                  to disable encryption. NQ does not consider the
                  previous encryption status.
   Returns
   <table>
   0 - Success
   \-1 NQ Server was not initialized
   \-2 parameter error (share not found)
   </table>
   Note
     * This function should be called from the context of NQ
       Server thread. It is recommended to sue it on NQ Server
       startup only.
     * This function is available when NQ was compiled with SMB3
       support as designated by the UD_NQ_INCLUDESMB3 parameter (see
       <link References, Referenced Documents>).                    */
#ifdef UD_CM_UNICODEAPPLICATION
    #define nqSetShareEncryption nqSetShareEncryptionW
#else
    #define nqSetShareEncryption nqSetShareEncryptionA
#endif

#endif /* UD_NQ_INCLUDESMB3 */


/* start NQ system */

NQ_INT                         /* 0 on success */
nqStart(
    void
    );

/* stop NQ system */

NQ_INT                         /* 0 on success */
nqStop(
    void
    );

/* Description
   This function is called to register an abstract NetBIOS name.
   An abstract name is registered in addition to the host name
   and is served as its alias.
   Parameters
   name :  Pointer to the name to register as a NetBIOS name.
   Returns
   NQ_SUCCESS or NQ_FAIL
   See Also
   <link nqReleaseNetBiosName@NQ_CHAR*, nqReleaseNetBiosName>    */
NQ_STATUS nqRegisterNetBiosName(const NQ_CHAR* name);

/* Description
   This function is called to unregister an abstract NetBIOS
   name.
   Parameters
   name :  Pointer to the name to release as a NetBIOS name.
   Returns
   NQ_SUCCESS or NQ_FAIL
      
   Note
   No check is made that the name to release was registered with
   a <link nqRegisterNetBiosName@NQ_CHAR*, nqRegisterNetBiosName>
   call. It is possible to release the basic host name with this
   call.   
   
   See Also
   <link nqRegisterNetBiosName@NQ_CHAR*, nqRegisterNetBiosName>   */
NQ_STATUS nqReleaseNetBiosName(const NQ_CHAR* name);

/**** NetBIOS name type and postfixes ****/

#define CM_NB_GROUP                         0x80
#define CM_NB_UNIQUE                        0x40

#define CM_NB_POSTFIX_WORKSTATION           0x0
#define CM_NB_POSTFIX_SERVER                0x20
#define CM_NB_POSTFIX_DOMAINMASTERBROWSER   0x1b
#define CM_NB_POSTFIX_DOMAINCONTROLLER      0x1c
#define CM_NB_POSTFIX_MASTERBROWSER         0x1d

/* Description
   This function is called to register an abstract NetBIOS name.
   An abstract name is registered in addition to the host name
   and is served as its alias. This is an extended version of 
   <link nqRegisterNetBiosName@NQ_CHAR*, nqRegisterNetBiosName>.
   Parameters
   name :  Pointer to the name to register as a NetBIOS name.
   flags : Combination of flags to designate unique or group name 
           and postfix (e.g. CM_NB_UNIQUE|CM_NB_POSTFIX_SERVER)
   Returns
   NQ_SUCCESS or NQ_FAIL
   See Also
   <link nqReleaseNetBiosNameEx@NQ_CHAR*, nqReleaseNetBiosNameEx>*/
   NQ_STATUS nqRegisterNetBiosNameEx(const NQ_CHAR* name, const NQ_BYTE flags);

/* Description
   This function is called to unregister an abstract NetBIOS
   name. This is an extended version of 
   <link nqReleaseNetBiosName@NQ_CHAR*, nqReleaseNetBiosName>.
   Parameters
   name :  Pointer to the name to release as a NetBIOS name.
   flags : Combination of flags to designate unique or group name 
   and postfix (e.g. CM_NB_UNIQUE|CM_NB_POSTFIX_SERVER)

   Returns
   NQ_SUCCESS or NQ_FAIL
      
   Note
   No check is made that the name to release was registered with
   a <link nqRegisterNetBiosNameEx@NQ_CHAR*, nqRegisterNetBiosNameEx>
   call. It is possible to release the basic host name with this
   call.
   
   See Also
   <link nqRegisterNetBiosNameEx@NQ_CHAR*, nqRegisterNetBiosNameEx>   */
NQ_STATUS nqReleaseNetBiosNameEx(const NQ_CHAR* name, const NQ_BYTE flags);

/* <b>Description</b>

   This structure holds open file or directory info.
   NQ holds one file entry per successful create request. This file info gives
   general info per entry.                                       */
typedef struct {
	NQ_WCHAR  fileNamePath[CM_BUFFERLENGTH(NQ_WCHAR, UD_FS_FILENAMELEN)];    /* file name buffer */
	NQ_WCHAR  userName[CM_BUFFERLENGTH(NQ_WCHAR, CM_USERNAMELENGTH)];    /* file name buffer */
    NQ_WCHAR  IP [CM_BUFFERLENGTH(NQ_WCHAR, CM_IPADDR_MAXLEN)]; /* IP buffer */
    NQ_BOOL	  isDirectory; 			/* Is this a directory or a file */
} FileDataW_t;  /* UNICODE version */

/* <b>Description</b> */
/* file data - ASCII version */
typedef struct {
	NQ_CHAR   fileNamePath[CM_BUFFERLENGTH(NQ_CHAR, UD_FS_FILENAMELEN)];    /* file name and path buffer */
	NQ_CHAR   userName[CM_BUFFERLENGTH(NQ_CHAR, CM_USERNAMELENGTH)];    /* user name buffer */
    NQ_CHAR   IP [CM_BUFFERLENGTH(NQ_CHAR, CM_IPADDR_MAXLEN)]; /* IP buffer */
    NQ_BOOL	  isDirectory; 			/* Is this a directory or a file */
} FileDataA_t;  /* ASCII version */

/* This structure is used when calling <link nqEnumerateOpenFiles1, nqEnumerateOpenFiles1()>      */


/* Description
   This function is used to retrieve all open files and directories.
   Call this function inside a loop and continue till False result is returned.
   On first call index should be 0, advance index by one per call to this function.

   File data will be filled in function parameter fileData, unless
   returned value is false.

   If  a file is opened or closed during the loop calling this function,
   the returned values might not exactly reflect the open files
   situation.

   This call is a triplet call (see <link Summary>).
   Parameters
   index :         index is indicating which open file data to return.
   	   	   	   	   Upon 2nd call the 2nd open file in the internal DB will be returned.
   	   	   	   	   On call x, the x'th open file will be returned.
   fileData :      Pointer to a structure, where NQ places the
                   file data for this index. See <link FileData_t, FileData_t structure.>

   Returns
   This function returns TRUE if the requested file index exists.
   False - if the requested file index doesn't exist.

   See Also
   <link FileData_t, FileData_t structure>

   <link nqEnumerateOpenFiles1, nqEnumerateOpenFiles1()>

   Note
   Be sure to start any loop call to this function with index 0.
                                                                                                 */
#ifdef UD_CM_UNICODEAPPLICATION
    #define nqEnumerateOpenFiles1 nqEnumerateOpenFilesW
#else
    #define nqEnumerateOpenFiles1 nqEnumerateOpenFilesA
#endif
NQ_BOOL nqEnumerateOpenFilesA(NQ_UINT index, FileDataA_t *fileData);   /* ASCII version */
NQ_BOOL nqEnumerateOpenFilesW(NQ_UINT index, FileDataW_t *fileData);   /* UNICODE version */

#ifdef UD_CM_UNICODEAPPLICATION
    #define FileData_t FileDataW_t
#else
    #define FileData_t FileDataA_t
#endif


#ifdef UD_NQ_INCLUDEEVENTLOG

/* <b>Description</b>
   
   This structure designates one share connection entry. A share
   connection entry is created by NQ Server upon a successful TreeConnect
   request.                                                      */

typedef struct {
    NQ_WCHAR userName[256];                 /* User name buffer. This buffer should be 256 characters long at least. */
    NQ_WCHAR shareName[UD_FS_MAXSHARELEN];  /* Share name buffer. This buffer should be 256 characters long at least. */
    NQ_IPADDRESS ip;                        /* Next side (client) IP address. */
    NQ_BOOL ipc;                            /* IPC flag. This flag is TRUE for the IPC$ share and FALSE for
                                               a file share.                                                */
    NQ_BOOL printQueue;                     /* Printer flag. When TRUE, this entry designates a printer
                                               share. For a file share this flag is FALSE.              */
} NQShareConnectionEntry;

/* <b>Description</b>
   
   This structure designates one file entry. A file
   entry is created by NQ Server upon a successful file open.                                                      */

typedef struct {
    NQ_WCHAR userName[256];                 /* User name buffer. */
    NQ_WCHAR fileName[UD_FS_FILENAMELEN];   /* File name buffer. This buffer will be filled with full file path. should be 300 characters long at least.  */
    NQ_WCHAR shareName[UD_FS_MAXSHARELEN];  /* Share name buffer. his buffer should be 256 characters long at least. */
    NQ_IPADDRESS ip;                        /* Next side (client) IP address. */
    NQ_UINT16 access;                       /* Access bits as indicated by the open operation. */
} NQOpenFileEntry;

/* Description
   This function reads share connection entries
   Parameters
   maxEntries :  Buffer capacity.
   buffer :      Buffer pointer.
   Returns
   Number of entries read.
   Note
     * This function is only available when NQ was compiled with
       Event Log support as indicated by the UD_NQ_INCLUDEEVENTLOG
       parameter (see <link References, Referenced Documents>).
     * This function uses NQ_WCHAR strings whose definition
       depends on the UD_CM_UNICODEAPPLICATION parameter (see <link References, Referenced Documents>). */

NQ_COUNT                            
nqEnumerateConnectedShares (
    NQ_COUNT maxEntries,            
    NQShareConnectionEntry* buffer  
    );

/* Description
   This function reads entries
   Parameters
   maxEntries :  Buffer capacity.
   buffer :      Buffer pointer.
   Returns
   Number of entries read.
   Note
     * This function is only available when NQ was compiled with
       Event Log support as indicated by the UD_NQ_INCLUDEEVENTLOG
       parameter (see <link References, Referenced Documents>).
     * This function uses NQ_WCHAR strings whose definition
       depends on the UD_CM_UNICODEAPPLICATION parameter (see <link References, Referenced Documents>). */

NQ_COUNT                            
nqEnumerateOpenFiles (
    NQ_COUNT maxEntries,            
    NQOpenFileEntry* buffer         
    );


#endif /* UD_NQ_INCLUDEEVENTLOG */

/* Description
   This function closes all connections initiated by a user
   with the given name close user's existing connections to NQ
   server
   Parameters
   name :          User name.
   isDomainUser :  TRUE for a domain or FALSE for a local user.
   
   Note
   This function uses NQ_WCHAR strings whose definition depends
   on the UD_CM_UNICODEAPPLICATION parameter (see <link References, Referenced Documents>). */

#ifdef UD_CM_UNICODEAPPLICATION
    #define nqCleanUserServerConnections nqCleanUserServerConnectionsW
#else
    #define nqCleanUserServerConnections nqCleanUserServerConnectionsA
#endif

NQ_STATUS                           /*  NQ_SUCCESS or error code */
nqCleanUserServerConnectionsW(
    const NQ_WCHAR *name,           /* user name */
    NQ_BOOL isDomainUser            /* domain or local user */
    );

NQ_STATUS                           /*  NQ_SUCCESS or error code */ 
nqCleanUserServerConnectionsA(
    const NQ_CHAR *name,           /* user name */
    NQ_BOOL isDomainUser            /* domain or local user */
    );

#ifdef UD_NQ_INCLUDETRACE
/* Description
   This defines trace availability
   Parameters
   on :  Trace availability (TRUE for On, FALSE for off).
   Returns
   Note
     * This function is only available when NQ was compiled with
       Internal Trace support as indicated by the NQ_INTERNALTRACE
       parameter (see <link Referencies, Referenced Documents>). */

void nqEnableTraceLog(NQ_BOOL on);
#endif /* UD_NQ_INCLUDETRACE */


SY_ENDAPI

#endif  /* _NQAPI_H_ */
