
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

/* add another share */

NQ_INT                         /* 0 on success */
nqAddShareA(
    const NQ_CHAR* name,       /* share name */
    const NQ_CHAR* path,       /* share path */
    NQ_BOOL printQueue,        /* 0  for file system, 1 for print queue */
    const NQ_CHAR* comment,    /* share descripton */
    const NQ_CHAR* reserved    /* for future use */
    );

NQ_INT                         /* 0 on success */
nqAddShareW(
    const NQ_WCHAR* name,       /* share name */
    const NQ_WCHAR* path,       /* share path */
    NQ_BOOL printQueue,         /* 0  for file system, 1 for print queue */
    const NQ_WCHAR* comment,    /* share descripton */
    const NQ_CHAR* reserved     /* for future use */
    );

#ifdef UD_CM_UNICODEAPPLICATION
    #define nqAddShare nqAddShareW
#else
    #define nqAddShare nqAddShareA
#endif

/* remove share by name */

NQ_INT                         /* 0 on success */
nqRemoveShareA(
    const NQ_CHAR* name        /* share name */
    );

NQ_INT                         /* 0 on success */
nqRemoveShareW(
    const NQ_WCHAR* name        /* share name */
    );

#ifdef UD_CM_UNICODEAPPLICATION
    #define nqRemoveShare nqRemoveShareW
#else
    #define nqRemoveShare nqRemoveShareA
#endif

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

/* register an abstract NetBIOS name */
NQ_STATUS
nqRegisterNetBiosName(
    const NQ_CHAR* name   /* pointer to name to register as NetBIOS name */
    );

/* remove an abstract NetBIOS name */
NQ_STATUS
nqReleaseNetBiosName(
    const NQ_CHAR* name   /* pointer to name to release as NetBIOS name */
    );

#ifdef UD_NQ_INCLUDEEVENTLOG
/*
 * Server statistics
 * -----------------
 */

typedef struct {
    NQ_TCHAR userName[256];                 /* user name buffer */
    NQ_TCHAR shareName[UD_FS_MAXSHARELEN];  /* share name buffer */
    NQ_IPADDRESS ip;                        /* next side IP address */
    NQ_BOOL ipc;                            /* IPC flag */
    NQ_BOOL printQueue;                     /* printer flag */
} NQShareConnectionEntry;

typedef struct {
    NQ_TCHAR userName[256];                 /* user name buffer */
    NQ_TCHAR fileName[UD_FS_FILENAMELEN];   /* file name buffer (full path) */
    NQ_TCHAR shareName[UD_FS_MAXSHARELEN];  /* share name buffer */
    NQ_IPADDRESS ip;                        /* next side IP address */
    NQ_UINT16 access;                       /* access bits */
} NQOpenFileEntry;

/* read share connection entries */

NQ_COUNT                            /* number of entries */
nqEnumerateConnectedShares (
    NQ_COUNT maxEntries,            /* buffer capacity */
    NQShareConnectionEntry* buffer  /* buffer pointer */
    );

/* read open file entries */

NQ_COUNT                            /* number of entries */
nqEnumerateOpenFiles (
    NQ_COUNT maxEntries,            /* buffer capacity */
    NQOpenFileEntry* buffer         /* buffer pointer */
    );

#endif /* UD_NQ_INCLUDEEVENTLOG */

/* close user's existing connections to NQ server */

NQ_STATUS                           /*  NQ_SUCCESS or error code */ 
nqCleanUserServerConnections(
    const NQ_TCHAR *name,           /* user name */
    NQ_BOOL isDomainUser            /* domain or local user */
    );    

SY_ENDAPI

#endif  /* _NQAPI_H_ */
