/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Server database
 *--------------------------------------------------------------------
 * MODULE        : CS - CIFS Server
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 29-June-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "csdataba.h"
#include "csparams.h"
#include "csdispat.h"
#include "nqapi.h"
#include "csutils.h"
#include "csnotify.h"
#ifdef UD_CS_INCLUDERPC
#include "csdcerpc.h"
#endif
#ifdef UD_CS_INCLUDESECURITYDESCRIPTORS
#include "cmsdescr.h"
#endif /* UD_CS_INCLUDESECURITYDESCRIPTORS */
#ifdef UD_CS_INCLUDERPC_SPOOLSS
#include "csspools.h"
#endif /* UD_CS_INCLUDERPC_SPOOLSS */

#ifdef UD_NQ_INCLUDECIFSSERVER

/* This file implements the following NQ Server API functions:
    nqAddShare
    nqRemoveShare
 */

/* This code implements the server "Database". It consists a static array
   per each structure type, representing an object class. The following objects are supported:
    - Share
    - User
    - Session
    - Tree
    - File name name descriptor (used for sharing control - multiple openings of the same file)
    - File (or directory)
    - Search context
   An array element (a slot) may either represent an object or be empty. Objects are
   identified by their IDs (UID, SID, TID, FID, etc.) A special value represents and empty
   slot. Object ID is its index in the appropiate array.
   Per-object functions provide:
    - object allocation (i.e. - taking a slot for a new object
    - object release - the object slot becomes avaiable for allocation - use also on
      clean-up
    - one or more search functions
    Search functions for connection-dependent objects (session, user, file, search, tree)
    use two levels of an object identification. First, an object is found
    directly by means of its ID. Then the current socket is compared with the socket of the
    object's session.
*/

/*
    Static data
    -----------

   Arrays of session and user slots.
   each slot has a "self" index. A value of -1 means an empty slot.
 */

typedef struct
{
    CSSession sessions[UD_FS_NUMSERVERSESSIONS]; /* list of connected clients */
    CSUser users[UD_FS_NUMSERVERUSERS];          /* list of logged users */
    CSTree trees[UD_FS_NUMSERVERTREES];          /* list of tree connections */
    CSName names[UD_FS_NUMSERVERFILENAMES];      /* list of unique files */
    CSFile files[UD_FS_NUMSERVERFILEOPEN];       /* list of opened files */
    CSSearch searches[UD_FS_NUMSERVERSEARCHES];  /* list of active search operations */
    CSShare shares[UD_FS_NUMSERVERSHARES];       /* list of shares */
    CSShare share;
    CSShare *adminShare;                         /* C$ share */
    NQ_BOOL isReady;                             /* whether the DB was initialized */
    SYMutex dbGuard;                             /* mutex for exclusive access to the DB */
    NQ_INT numShares;                            /* number of shares */
    NQ_INT numUsers;                             /* number of shares */
    NQ_INT numFiles;                             /* number of files  */
    NQ_INT numUniqueFiles;                       /* number of unique files */
    NQ_INT nextNotify;                           /* index of the next file in the notify search */
#ifdef UD_NQ_INCLUDESMB2
    CMUuid uuid;
    CMTime serverStartTime;
#endif
#ifdef UD_CS_MESSAGESIGNINGPOLICY
    NQ_BOOL signingEnabled;                      /* whether message signing is enabled */
    NQ_BOOL signingRequired;                     /* whether message signing is required */
#endif    
}
StaticData;

#ifdef SY_FORCEALLOCATION
static StaticData* staticData = NULL;
#else  /* SY_FORCEALLOCATION */
static StaticData staticDataSrc;
static StaticData* staticData = &staticDataSrc;
#endif /* SY_FORCEALLOCATION */

/* TCHAR share functions */

static NQ_INT
addShareT(
    const NQ_TCHAR* name,       /* share name */
    const NQ_TCHAR* path,       /* share map */
    NQ_BOOL printQueue,         /* whether this share is a printer */
    const NQ_TCHAR* comment,    /* share comment */
    const NQ_CHAR* reserved     /* for future use */
    );

static NQ_INT
removeShareT(
    const NQ_TCHAR* name        /* share name */
    );

/* callback functions to pause and resume the server: called when application performs
   changes in the database */

static void (*pauseServer)();
static void (*resumeServer)();

/* converting FIDs to indexes and vice versa */

#define fid2Index(_fid)    ((_fid) == CS_ILLEGALID? CS_ILLEGALID:(_fid) - 0x4001)
#define index2Fid(_idx)    ((_idx) == CS_ILLEGALID? CS_ILLEGALID:(_idx) + 0x4001)

/* converting UIDs to indexes and vice versa */

#define Uid2Index(_uid)    ((_uid) == CS_ILLEGALID? CS_ILLEGALID:(_uid) - 500)
#define Index2Uid(_idx)    ((_idx) == CS_ILLEGALID? CS_ILLEGALID:(_idx) + 500)

/*====================================================================
 * PURPOSE: Add share to the database
 *--------------------------------------------------------------------
 * PARAMS:  IN share name
 *          IN share path
 *          IN 0 for file system, 1 for print queue
 *          IN share comment
 *          IN reserved (for future use)
 *
 * RETURNS: 0 - OK
 *          -1 the DB was not initialized
 *          -2 parameter error (string too long)
 *          -3 share table full
 *          -6 share already exists
 *
 * NOTES:
 *====================================================================
 */

NQ_INT
nqAddShareA(
    const NQ_CHAR* name,
    const NQ_CHAR* path,
    NQ_BOOL printQueue,
    const NQ_CHAR* comment,
    const NQ_CHAR* reserved
    )
{
    NQ_TCHAR tname[CM_BUFFERLENGTH(NQ_TCHAR, UD_FS_MAXSHARELEN)];
    NQ_TCHAR tpath[CM_BUFFERLENGTH(NQ_TCHAR, UD_FS_MAXPATHLEN)];
    NQ_TCHAR tcomment[CM_BUFFERLENGTH(NQ_TCHAR, UD_FS_MAXDESCRIPTIONLEN)];

    cmAnsiToTchar(tname, name);
    cmAnsiToTchar(tpath, path);
    cmAnsiToTchar(tcomment, comment);
    return addShareT(tname, tpath, printQueue, tcomment, reserved);
}

/*====================================================================
 * PURPOSE: Add share to the database
 *--------------------------------------------------------------------
 * PARAMS:  IN share name
 *          IN share path
 *          IN 0 for file system, 1 for print queue
 *          IN share comment
 *          IN reserved (for future use)
 *
 * RETURNS: 0 - OK
 *          -1 the DB was not initialized
 *          -2 parameter error (string too long)
 *          -3 share table full
 *          -6 share already exists
 *
 * NOTES:
 *====================================================================
 */

NQ_INT
nqAddShareW(
    const NQ_WCHAR* name,
    const NQ_WCHAR* path,
    NQ_BOOL printQueue,
    const NQ_WCHAR* comment,
    const NQ_CHAR* reserved
    )
{
    NQ_TCHAR tname[CM_BUFFERLENGTH(NQ_TCHAR, UD_FS_MAXSHARELEN)];
    NQ_TCHAR tpath[CM_BUFFERLENGTH(NQ_TCHAR, UD_FS_MAXPATHLEN)];
    NQ_TCHAR tcomment[CM_BUFFERLENGTH(NQ_TCHAR, UD_FS_MAXDESCRIPTIONLEN)];

    cmUnicodeToTchar(tname, name);
    cmUnicodeToTchar(tpath, path);
    cmUnicodeToTchar(tcomment, comment);
    return addShareT(tname, tpath, printQueue, tcomment, reserved);
}

/*====================================================================
 * PURPOSE: Add share to the database
 *--------------------------------------------------------------------
 * PARAMS:  IN share name
 *          IN share path
 *          IN 0 for file system, 1 for print queue
 *          IN share comment
 *          IN reserved (for future use)
 *
 * RETURNS: 0 - OK
 *          -1 the DB was not initialized
 *          -2 parameter error (string too long)
 *          -3 share table full
 *          -6 share already exists
 *
 * NOTES:
 *====================================================================
 */

static NQ_INT
addShareT(
    const NQ_TCHAR* name,
    const NQ_TCHAR* path,
    NQ_BOOL printQueue,
    const NQ_TCHAR* comment,
    const NQ_CHAR* reserved
    )
{
    NQ_INT i;       /* share index */
    NQ_TCHAR ipc[6];

    if (!staticData->isReady)
    {
        TRC("Unable to add share - not initialized");
        sySetLastError(NQ_ERR_NOTREADY);
        return -1;
    }

    cmAnsiToTchar(ipc, "IPC$");

    if (   ((cmTStrlen(name) + sizeof(NQ_TCHAR)) > sizeof(staticData->shares[0].name))
        || ((cmTStrlen(path) + sizeof(NQ_TCHAR)) > sizeof(staticData->shares[0].map))
        || ((cmTStrlen(comment) + sizeof(NQ_TCHAR)) > sizeof(staticData->shares[0].description))
       )
    {
        TRC("Unable to add share - invalid parameter");
        sySetLastError(NQ_ERR_BADPARAM);
        return -1;
    }

    syMutexTake(&staticData->dbGuard);
    (*pauseServer)();

    if (csGetShareByName(name) != NULL)
    {
        (*resumeServer)();
        syMutexGive(&staticData->dbGuard);
        TRC1P("Unable to add share. Share %s already exists", cmTDump(name));
        sySetLastError(NQ_ERR_OBJEXISTS);
        return -1;
    }

    /* find empty slot */

    for (i = 0; i < UD_FS_NUMSERVERSHARES; i++)
    {
        if (staticData->shares[i].isFree)
        {
            cmTStrcpy(staticData->shares[i].name, name);
            cmTStrcpy(staticData->shares[i].map, path);
            cmTStrcpy(staticData->shares[i].description, comment);
            staticData->shares[i].ipcFlag = (cmTStrcmp(name, ipc) == 0);
            staticData->shares[i].isPrintQueue = printQueue;
            staticData->shares[i].isHidden = (cmTStrchr(name, cmTChar('$')) && !staticData->shares[i].ipcFlag && !printQueue) ? TRUE : FALSE;
            if (staticData->shares[i].isHidden)
                staticData->adminShare = &staticData->shares[i];
#ifdef UD_CS_INCLUDESECURITYDESCRIPTORS
            if (staticData->shares[i].isHidden)
            {
                cmSdGetAdminonlyShareSecurityDescriptor(&staticData->shares[i].sd);
            }
            else
            {
                staticData->shares[i].sd.length = udLoadShareSecurityDescriptor(
                    staticData->shares[i].name,
                    staticData->shares[i].sd.data,
                    sizeof(staticData->shares[i].sd.data));
                if (0 == staticData->shares[i].sd.length || !cmSdIsValid(&staticData->shares[i].sd))
                {
                    TRC1P("Cannot load security descriptor for share: %s", cmTDump(staticData->shares[i].name));
                    cmSdGetShareSecurityDescriptor(&staticData->shares[i].sd);
                }
            }
#ifdef UD_CS_INCLUDERPC_SPOOLSS
            if (staticData->shares[i].isPrintQueue)
            {
                NQ_STATIC CMSdSecurityDescriptor sd;
                SYPrinterHandle handle = syGetPrinterHandle(staticData->shares[i].map);

                /* do not allow adding this share id the printer is not available */
                if (!syIsValidPrinter(handle))
                    break;

                cmSdGetDefaultSecurityDescriptor(&sd);
                syPrinterSetSecurityDescriptor(handle, sd.data, sd.length);
            }
#endif /* UD_CS_INCLUDERPC_SPOOLSS */
#endif /* UD_CS_INCLUDESECURITYDESCRIPTORS */
            staticData->shares[i].isFree = FALSE;

            TRC2P("share %s added to slot %d", cmTDump(name), i);

            staticData->numShares++;
            staticData->shares[i].isFree = FALSE;
            (*resumeServer)();
            syMutexGive(&staticData->dbGuard);
            sySetLastError(NQ_ERR_OK);
            return 0;
        }
    }

    (*resumeServer)();
    syMutexGive(&staticData->dbGuard);
    TRC("Unable to add share - no empty slots");
    sySetLastError(NQ_ERR_NORESOURCE);
    return -1;
}

/*====================================================================
 * PURPOSE: Remove share from the database
 *--------------------------------------------------------------------
 * PARAMS:  IN share name
 *
 * RETURNS: 0 - OK
 *          -1 the DB was not initialized
 *          -2 parameter error (share not found)
 *
 * NOTES:
 *====================================================================
 */

NQ_INT
nqRemoveShareA(
    const NQ_CHAR* name
    )
{
    NQ_TCHAR tname[CM_BUFFERLENGTH(NQ_TCHAR, UD_FS_MAXSHARELEN)];

    cmAnsiToTchar(tname, name);
    return removeShareT(tname);
}

/*====================================================================
 * PURPOSE: Remove share from the database
 *--------------------------------------------------------------------
 * PARAMS:  IN share name
 *
 * RETURNS: 0 - OK
 *          -1 the DB was not initialized
 *          -2 parameter error (share not found)
 *
 * NOTES:
 *====================================================================
 */

NQ_INT
nqRemoveShareW(
    const NQ_WCHAR* name
    )
{
    NQ_TCHAR tname[CM_BUFFERLENGTH(NQ_TCHAR, UD_FS_MAXSHARELEN)];

    cmUnicodeToTchar(tname, name);
    return removeShareT(tname);
}

/*====================================================================
 * PURPOSE: Remove share from the database
 *--------------------------------------------------------------------
 * PARAMS:  IN share name
 *
 * RETURNS: 0 - OK
 *          -1 the DB was not initialized
 *          -2 parameter error (share not found)
 *
 * NOTES:
 *====================================================================
 */

static NQ_INT
removeShareT(
    const NQ_TCHAR* name
    )
{
    CSShare* pShare;    /* pointer to the share structure */
    NQ_INT i;           /* index in trees */

    if (!staticData->isReady)
    {
        TRC("Unable to remove share - not initialized");
        sySetLastError(NQ_ERR_NOTREADY);
        return -1;
    }

    syMutexTake(&staticData->dbGuard);
    (*pauseServer)();

    if ((pShare = csGetShareByName(name)) == NULL)
    {
        TRC("Unable to remove share - share not exists");
        (*resumeServer)();
        syMutexGive(&staticData->dbGuard);
        sySetLastError(NQ_ERR_BADPARAM);
        return -1;
    }

    if (pShare == staticData->adminShare)
    {
        TRC("Unable to remove hidden administrative share");
        (*resumeServer)();
        syMutexGive(&staticData->dbGuard);
        sySetLastError(NQ_ERR_BADPARAM);
        return -1;
    }

    pShare->isFree = TRUE;

    for (i = 0; i < UD_FS_NUMSERVERTREES; i++)
    {
        if (staticData->trees[i].tid != CS_ILLEGALID && staticData->trees[i].share == pShare)
        {
            csReleaseTree(staticData->trees[i].tid , FALSE);
        }
    }

    staticData->numShares--;
    (*resumeServer)();
    syMutexGive(&staticData->dbGuard);
    sySetLastError(NQ_ERR_OK);
    TRC1P("share %s removed", cmTDump(name));
    return 0;
}

/*====================================================================
 * PURPOSE: Whether hidden administrative share (e.g. C$) is present
 *--------------------------------------------------------------------
 * PARAMS:  IN none
 *
 * RETURNS: TRUE or FALSE
 *
 * NOTES:
 *====================================================================
 */

NQ_BOOL
csHasAdminShare(
    void
    )
{
    return staticData->adminShare != NULL;
}

/*====================================================================
 * PURPOSE: Initialize data
 *--------------------------------------------------------------------
 * PARAMS:  IN callback function for pausing the server
 *          IN callback function for resumimg the server
 *
 * RETURNS: None
 *
 * NOTES:   1) sets "self" index to -1
 *          2) read shares
 *====================================================================
 */

NQ_STATUS
csInitDatabase(
    void (*pause)(),
    void (*resume)()
    )
{
    NQ_UINT16 i;


    TRCB();

    /* allocate memory */
#ifdef SY_FORCEALLOCATION
    staticData = (StaticData *)syCalloc(1, sizeof(*staticData));
    if (NULL == staticData)
    {
        TRCERR("Unable to allocate database table");
        TRCE();
        return NQ_FAIL;
    }
#endif /* SY_FORCEALLOCATION */

#ifdef UD_NQ_INCLUDESMB2
    /* todo: get server GUID properly (the following line is a temporary solution for getting server GUID) */
    cmGenerateUuid(&staticData->uuid);
    /* server start time */
    cmGetCurrentTime(&staticData->serverStartTime);
#endif

    staticData->isReady = FALSE;

    /* create mutex for exclusive access to the DB */
    syMutexCreate(&staticData->dbGuard);

    syMutexTake(&staticData->dbGuard);

    staticData->numShares = 0;
    staticData->numUsers = 0;
    staticData->numFiles = 0;
    staticData->numUniqueFiles = 0;
    staticData->isReady = TRUE;
    staticData->adminShare = NULL;

    /* save callbacks */

    pauseServer = pause;
    resumeServer = resume;

    /* set "self" indexes */

    for (i=0; i < UD_FS_NUMSERVERSESSIONS; i++)
        staticData->sessions[i].key = CS_ILLEGALID;

    for (i=0; i < UD_FS_NUMSERVERUSERS; i++)
        staticData->users[i].uid = CS_ILLEGALID;

    for (i=0; i < UD_FS_NUMSERVERTREES; i++)
        staticData->trees[i].tid = CS_ILLEGALID;

    for (i=0; i < UD_FS_NUMSERVERFILENAMES; i++)
        staticData->names[i].nid = CS_ILLEGALID;

    for (i=0; i < UD_FS_NUMSERVERFILEOPEN; i++)
    {
        staticData->files[i].fid = CS_ILLEGALID;
        syInvalidateFile(&staticData->files[i].file);
        syInvalidateDirectory(&staticData->files[i].directory);
    }

    for (i=0; i < UD_FS_NUMSERVERSEARCHES; i++)
        staticData->searches[i].sid = CS_ILLEGALID;

    for (i = 0; i < UD_FS_NUMSERVERSHARES; i++)
    {
        staticData->shares[i].idx = i;
        staticData->shares[i].isFree = TRUE;
    }

    syMutexGive(&staticData->dbGuard);

    /* add the default share */
    nqAddShareA("IPC$", "", FALSE, "IPC Service", "");

    /* add user defined shares */
    {
        CSShare *s = &staticData->share;
        
        for (i = 1; i < UD_FS_NUMSERVERSHARES; i++)
        {
            if (!udGetNextShare(s->name, s->map, &s->isPrintQueue, s->description))
                break;
    
            nqAddShare(s->name, s->map, s->isPrintQueue, s->description, NULL);
        }
    }

#ifdef UD_CS_MESSAGESIGNINGPOLICY
    /* set message signing */
    staticData->signingEnabled = UD_CS_MESSAGESIGNINGPOLICY > 0;
    staticData->signingRequired = UD_CS_MESSAGESIGNINGPOLICY == 2;
#endif

    TRCE();
    return NQ_SUCCESS;
}

/*====================================================================
 * PURPOSE: Release data
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: None
 *
 * NOTES:
 *====================================================================
 */

void
csCloseDatabase(
    void
    )
{
    /* delete mutex */
    syMutexDelete(&staticData->dbGuard);

    /* release memory */
#ifdef SY_FORCEALLOCATION
    if (NULL != staticData)
        syFree(staticData);
    staticData = NULL;
#endif /* SY_FORCEALLOCATION */
}

/*====================================================================
 * PURPOSE: Obtain an empty session slot
 *--------------------------------------------------------------------
 * PARAMS:  IN master session
 *
 * RETURNS: Pointer to a slot or NULL
 *
 * NOTES:   Assignes session key to the slot as this slot index in
 *          the array of slots
 *====================================================================
 */

CSSession*
csGetNewSession(
    void
    )
{
    NQ_UINT32 i;      /* just an index */

    for (i=0; i < UD_FS_NUMSERVERSESSIONS; i++)
    {
        CSSession *s = &staticData->sessions[i];

        if (s->key == CS_ILLEGALID)
        {
            s->key = i;  /* set "self" index */
            s->socket = csDispatchGetSocket();
            syMemcpy(&s->ip, csDispatchGetSocketIp(), sizeof(NQ_IPADDRESS));
            s->smb2 = FALSE;
#if defined(UD_CS_INCLUDEPASSTHROUGH) && defined(UD_CS_INCLUDEEXTENDEDSECURITY)
            s->usePassthrough = TRUE;
#endif          
#ifdef UD_CS_MESSAGESIGNINGPOLICY
            s->isBsrspyl = TRUE;
            s->signingOn = FALSE;
            s->sequenceNum = s->sequenceNumRes = 0;
#endif
            return s;
        }
    }

    TRCERR("No more session slots");
    return NULL;
}

/*====================================================================
 * PURPOSE: find a session with the same socket
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: Pointer to a slot or NULL
 *
 * NOTES:
 *====================================================================
 */

CSSession*
csGetSessionBySocket(
    void
    )
{
    NQ_INT i;      /* just an index */

    TRCB();

    for (i=0; i < UD_FS_NUMSERVERSESSIONS; i++)
    {
        if (   staticData->sessions[i].key != CS_ILLEGALID
            && staticData->sessions[i].socket == csDispatchGetSocket()
           )
        {
            TRCE();
            return &staticData->sessions[i];
        }
    }

    TRCERR("No session with the same socket");
    TRCE();
    return NULL;
}

/*====================================================================
 * PURPOSE: find a session with the same socket as requested
 *--------------------------------------------------------------------
 * PARAMS:  IN socket
 *
 * RETURNS: Pointer to a slot or NULL
 *
 * NOTES:
 *====================================================================
 */

CSSession*                  /* pointer or NULL */
csGetSessionBySpecificSocket(
    NSSocketHandle* socket
    )
{
    NQ_INT i;      /* just an index */

    TRCB();

    for (i=0; i < UD_FS_NUMSERVERSESSIONS; i++)
    {
        if (   staticData->sessions[i].key != CS_ILLEGALID
            && staticData->sessions[i].socket == socket
           )
        {
            TRCE();
            return &staticData->sessions[i];
        }
    }

    TRCERR("No session with requested socket");
    TRCE();
    return NULL;
}

/*====================================================================
 * PURPOSE: find a session by ID
 *--------------------------------------------------------------------
 * PARAMS:  IN session id (key)
 *
 * RETURNS: Pointer to a slot or NULL
 *
 * NOTES:
 *====================================================================
 */

CSSession*
csGetSessionById(
    CSSessionKey id
    )
{
    if (id >= UD_FS_NUMSERVERSESSIONS || staticData->sessions[id].key != id)
    {
        TRCERR("Illegal session key value, id: %ld", id);
        return NULL;
    }

    return &staticData->sessions[id];
}

/*====================================================================
 * PURPOSE: find a session by client IP address
 *--------------------------------------------------------------------
 * PARAMS:  IN pointer to client IP
 *
 * RETURNS: Pointer to a slot or NULL
 *
 * NOTES:
 *====================================================================
 */

CSSession*
csGetSessionByIp(
    const NQ_IPADDRESS* pIp
    )
{
    NQ_INT i;                   /* just an index */

    for (i=0; i < UD_FS_NUMSERVERSESSIONS; i++)
    {
        if (   staticData->sessions[i].key != CS_ILLEGALID
            && CM_IPADDR_EQUAL(staticData->sessions[i].ip, *pIp)
           )
        {
            return &staticData->sessions[i];
        }
    }
    return NULL;
}

/*====================================================================
 * PURPOSE: checks whether this session already exists
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: Pointer to a slot or NULL
 *
 * NOTES:   Checks if the current socket is alreday used in one of active sessions
 *====================================================================
 */

NQ_BOOL
csSessionExists(
    void
    )
{
    NQ_INT i;                   /* just an index */
    NSSocketHandle socket;      /* current socket */

    socket = csDispatchGetSocket();

    for (i=0; i < UD_FS_NUMSERVERSESSIONS; i++)
    {
        if (staticData->sessions[i].key != CS_ILLEGALID && staticData->sessions[i].socket == socket)
        {
            return TRUE;
        }
    }
    return FALSE;
}
/*====================================================================
 * PURPOSE: release session assotiated with a given socket
 *--------------------------------------------------------------------
 * PARAMS:  IN the socket to release resources for
 *
 * RETURNS: NONE
 *
 * NOTES:
 *====================================================================
 */

void
csReleaseSessions(
    NSSocketHandle socket,
    NQ_BOOL expected
    )
{
    NQ_INT session;        /* index in sessions */

    for (session = 0; session < UD_FS_NUMSERVERSESSIONS; session++)
    {
        if (staticData->sessions[session].socket == socket && staticData->sessions[session].key != CS_ILLEGALID)
        {
            CSUid user;   /* index in users */

            for (user = 0; user < UD_FS_NUMSERVERUSERS; user++)
            {
                if (    staticData->users[user].uid != (CSUid)CS_ILLEGALID
                     && staticData->users[user].session == staticData->sessions[session].key
                   )
                {
                    csReleaseUser((CSUid)Index2Uid(user) , expected);
                }
            }
        #ifdef UD_NQ_INCLUDEEVENTLOG
            udEventLog(UD_LOG_MODULE_CS,
            UD_LOG_CLASS_CONNECTION,
            UD_LOG_CONNECTION_DISCONNECT,
            NULL,
            &staticData->sessions[session].ip,
            expected ? NQ_SUCCESS : SMB_STATUS_USER_SESSION_DELETED,
            NULL);
        #endif
            TRC("Session data released !!!");

            staticData->sessions[session].key = CS_ILLEGALID;
        }
    }
}

/*====================================================================
 * PURPOSE: Obtain an empty user slot
 *--------------------------------------------------------------------
 * PARAMS:  IN session for a new user
 *
 * RETURNS: Pointer to a slot or NULL
 *
 * NOTES:   assigns UID to the slot as this slot index in the
 *          array of slots
 *====================================================================
 */

CSUser*
csGetNewUser(
    const CSSession* session
    )
{
    NQ_UINT16 i;      /* just an index */

    TRCB();
    
    for (i = 0; i < UD_FS_NUMSERVERUSERS; i++)
    {
        CSUser *u = &staticData->users[i];

        if (u->uid == (CSUid)CS_ILLEGALID)
        {
            u->uid = (CSUid)Index2Uid(i);   /* set "self" index */
            u->session = session->key;
            u->ip = &session->ip;
#ifdef UD_NQ_INCLUDESMB2
            u->createdTime = (NQ_TIME)syGetTime();
            u->authenticated = FALSE;
#endif            
            u->isAnonymous = FALSE;
            u->token.isAnon = FALSE;
            u->isDomainUser = FALSE;
            u->isGuest = FALSE;
            u->rid = CS_ILLEGALID;
#ifdef UD_CS_INCLUDEPASSTHROUGH
            u->authBySamlogon = FALSE;
#endif     
#ifdef UD_CS_INCLUDEEXTENDEDSECURITY
            u->isExtendSecAuth = FALSE;   
#endif
            staticData->numUsers++;
            TRCE();
            return u;
        }
    }
    


    TRCERR("No more user slots");
#ifdef UD_NQ_INCLUDESMB2
    /* find expired user slot */
    if (session->smb2)
    {
        CSUser* expUser = csGetExpiredUser();
        if (expUser != NULL)
        {
            CSUid uid = expUser->uid;
            csReleaseUser(expUser->uid , FALSE);
            expUser->uid = uid;   /* set "self" index */
            expUser->session = session->key;
            expUser->ip = &session->ip;
            expUser->createdTime = (NQ_TIME)syGetTime();
            staticData->numUsers++;
            return expUser;
        }
    }
#endif    
#ifdef UD_NQ_INCLUDEEVENTLOG
    udEventLog(UD_LOG_MODULE_CS,
        UD_LOG_CLASS_USER,
        UD_LOG_USER_LOGON,
        NULL,
        &session->ip,
        (NQ_UINT32)SMB_STATUS_INSUFFICIENT_RESOURCES,
        NULL);
#endif /* UD_NQ_INCLUDEEVENTLOG */

    TRCE();
    return NULL;
}

/*====================================================================
 * PURPOSE: find a user providing user name and credentials
 *--------------------------------------------------------------------
 * PARAMS:  IN user name
 *          IN user credentials to compare (two passwords)
 *          IN total credential length
 *
 * RETURNS: Pointer to a slot or NULL
 *
 * NOTES:
 *====================================================================
 */

CSUser*
csGetUserByNameAndCredentials(
    const NQ_TCHAR* name,
    const NQ_BYTE* credentials,
    NQ_INT credentialsLen
    )
{
    NQ_INT i;      /* just an index */

    for (i=0; i < UD_FS_NUMSERVERUSERS; i++)
    {
        if (   staticData->users[i].uid != CS_ILLEGALID
            && 0 == cmTStrcmp(staticData->users[i].name, name)
            && staticData->sessions[staticData->users[i].session].socket == csDispatchGetSocket()
            && (   0 == credentialsLen
                || 0 == syMemcmp(staticData->users[i].credentials, credentials, (NQ_UINT)credentialsLen)
               )
           )
        {
            return &staticData->users[i];
        }
    }

    return NULL;
}

/*====================================================================
 * PURPOSE: find a user providing user name and session
 *--------------------------------------------------------------------
 * PARAMS:  IN user name
 *          IN session key
 *
 * RETURNS: Pointer to a slot or NULL
 *
 * NOTES:
 *====================================================================
 */

CSUser*
csGetUserByNameAndSession(
    const NQ_TCHAR* name,
    CSSessionKey sessKey
    )
{
    NQ_INT i;      /* just an index */

    for (i=0; i < UD_FS_NUMSERVERUSERS; i++)
    {
        if (   staticData->users[i].uid != CS_ILLEGALID
            && 0 == cmTStrcmp(staticData->users[i].name, name)
            && staticData->users[i].session == sessKey
           )
        {
            return &staticData->users[i];
        }
    }

    return NULL;
}

/*====================================================================
 * PURPOSE: find a user providing UID
 *--------------------------------------------------------------------
 * PARAMS:  IN user ID
 *
 * RETURNS: Pointer to a slot or NULL
 *
 * NOTES:
 *====================================================================
 */

CSUser*
csGetUserByUid(
    CSUid uid
    )
{
    if (Uid2Index(uid) >= UD_FS_NUMSERVERUSERS || Uid2Index(uid) < 0)
    {
        TRCERR("Illegal UID value, uid: %d", uid);
        return NULL;
    }

    if (staticData->users[Uid2Index(uid)].uid != uid)
    {
        TRCERR("Illegal UID in the slot, expected: %d, is: %d", uid, staticData->users[Uid2Index(uid)].uid);
        return NULL;
    }

    if (staticData->sessions[staticData->users[Uid2Index(uid)].session].socket != csDispatchGetSocket())
    {
        TRCERR("UID for unexpected socket, expected: %d, is: %d", staticData->sessions[staticData->users[Uid2Index(uid)].session].socket, csDispatchGetSocket());
        return NULL;
    }
    return &staticData->users[Uid2Index(uid)];
}


/*====================================================================
 * PURPOSE: find a user providing session
 *--------------------------------------------------------------------
 * PARAMS:  IN user ID
 *
 * RETURNS: Pointer to a slot or NULL
 *
 * NOTES:   returns first user within provided session
 *====================================================================
 */
CSUser*
csGetUserBySession(
    CSSession *pSession
    )
{
    NQ_COUNT i;

    for (i = 0; pSession && i < UD_FS_NUMSERVERUSERS; i++)
    {
        if (staticData->users[i].uid != CS_ILLEGALID && staticData->users[i].session == pSession->key)
            return &staticData->users[i];
    }
    return NULL;
}

/*====================================================================
 * PURPOSE: release user slot
 *--------------------------------------------------------------------
 * PARAMS:  IN user slot pointer
 *
 * RETURNS: None
 *
 * NOTES:
 *====================================================================
 */

void
csReleaseUser(
    CSUid uid,
    NQ_BOOL expected
    )
{
    CSTid tree;   /* index in trees */
#ifdef UD_NQ_INCLUDEEVENTLOG
    UDUserAccessEvent eventInfo;
#endif /*UD_NQ_INCLUDEEVENTLOG*/

    if (Uid2Index(uid) >= UD_FS_NUMSERVERUSERS || Uid2Index(uid) < 0)
    {
        TRCERR("Illegal UID value, uid: %d", uid);
        return;
    }
    if (staticData->users[Uid2Index(uid)].uid != uid)
    {
        TRCERR("Illegal UID in the slot, expected: %d, is: %d", uid, staticData->users[Uid2Index(uid)].uid);
        return;
    }

#ifdef UD_CS_INCLUDERPC_SPOOLSS
    csRpcSpoolssCleanupUser(uid);
#endif /* UD_CS_INCLUDERPC_SPOOLSS */
    for (tree = 0; tree < UD_FS_NUMSERVERTREES; tree++)
    {
        if (   staticData->trees[tree].tid != (CSTid)CS_ILLEGALID
            && staticData->trees[tree].uid == uid
            )
        {
            csReleaseTree(tree , expected);
        }
    }
#ifdef UD_NQ_INCLUDEEVENTLOG
    eventInfo.rid = csGetUserRid(&staticData->users[Uid2Index(uid)]);
    udEventLog(UD_LOG_MODULE_CS,
    		   UD_LOG_CLASS_USER,
    		   UD_LOG_USER_LOGOFF,
    		   staticData->users[Uid2Index(uid)].name,
    		   staticData->users[Uid2Index(uid)].ip,
    		   (NQ_UINT32) expected ? NQ_SUCCESS : SMB_STATUS_USER_SESSION_DELETED,
    		   (const NQ_BYTE *)&eventInfo
    		   );
#endif
    staticData->users[Uid2Index(uid)].uid = CS_ILLEGALID;
    staticData->numUsers--;
}

/*====================================================================
 * PURPOSE: release user slot and disconnect the server if there are
 *          no more users
 *--------------------------------------------------------------------
 * PARAMS:  IN user slot pointer
 *
 * RETURNS: None
 *
 * NOTES:
 *====================================================================
 */

void
csReleaseUserAndDisconnect(
    CSUid uid,
    NQ_BOOL expected
    )
{
    NQ_INT user;           /* index in users */
    CSSessionKey session;  /* session key */
    CSSession* pSess;      /* session pointer */

    if (Uid2Index(uid) >= UD_FS_NUMSERVERUSERS || Uid2Index(uid) < 0)
    {
        TRCERR("Illegal UID value, uid: %d", uid);
        return;
    }
    if (staticData->users[Uid2Index(uid) < 0].uid != uid)
    {
        TRCERR("Illegal UID in the slot, expected: %d, is: %d", uid, staticData->users[Uid2Index(uid) < 0].uid);
        return;
    }

    session = staticData->users[Uid2Index(uid) < 0].session;
    csReleaseUser(uid , expected);

    for (user = 0; user < UD_FS_NUMSERVERUSERS; user++)
    {
        if (   staticData->users[user].uid != (CSUid)CS_ILLEGALID
            && staticData->users[user].session == session
            )
            return;
    }
    pSess = csGetSessionById(session);
    if (NULL != pSess)
    {
        pSess->key = (CSSessionKey)CS_ILLEGALID;
        nsClose(pSess->socket);
        pSess->socket = NULL;
#ifdef UD_NQ_INCLUDEEVENTLOG
		udEventLog(UD_LOG_MODULE_CS,
				   UD_LOG_CLASS_CONNECTION,
				   UD_LOG_CONNECTION_DISCONNECT,
				   staticData->users[Uid2Index(uid)].name,
				   staticData->users[Uid2Index(uid)].ip,
				   (NQ_UINT32) expected ? NQ_SUCCESS : SMB_STATUS_USER_SESSION_DELETED,
				   NULL
				   );
#endif
    }
}

#ifdef UD_NQ_INCLUDESMB2
/*
 *====================================================================
 * PURPOSE: get first expired user (session in smb2 terms)
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: pointer to a slot or NULL
 *
 * NOTES:
 *====================================================================
 */
 
CSUser*
csGetExpiredUser(
    )
{
    NQ_INDEX i;     

    TRCB();

    for (i = 0; i < UD_FS_NUMSERVERUSERS; i++)
    {
        CSUser *u = &staticData->users[i];

        if ((u->uid != (CSUid)CS_ILLEGALID) && (CS_SMB2_SESSIONEXPIRATIONTIME < ((NQ_TIME)syGetTime() - u->createdTime)))
        {
            TRCE();
            return u;
        }
    }

    TRCERR("No expired sessions");
    TRCE();
    return NULL;
}

/*
 *====================================================================
 * PURPOSE: check whether user (session in smb2 terms) has expired 
 *--------------------------------------------------------------------
 * PARAMS:  IN user ID
 *
 * RETURNS: TRUE if user has expired, FALSE otherwise
 *
 * NOTES:
 *====================================================================
 */

NQ_BOOL
csUserHasExpired(
    CSUid uid
    )
{   
    TRCB();
    
    if ((uid != (CSUid)CS_ILLEGALID) && (CS_SMB2_SESSIONEXPIRATIONTIME < ((NQ_TIME)syGetTime() - staticData->users[uid].createdTime)))
    {
        TRCE();
        return TRUE;
    }
    
    TRCE();
    return FALSE;
}

/*
 *====================================================================
 * PURPOSE: renew user (session in smb2 terms) time stamp 
 *--------------------------------------------------------------------
 * PARAMS:  IN pointer to user slot
 *
 * RETURNS: NONE
 *
 * NOTES:
 *====================================================================
 */

void
csRenewUserTimeStamp(
    CSUser* pUser
    )
{   
    TRCB();
    
    if (pUser && (pUser->uid != (CSUid)CS_ILLEGALID))
    {
        pUser->createdTime = (NQ_TIME)syGetTime();
    }
    
    TRCE();
}


#endif /* UD_NQ_INCLUDESMB2 */

/*
 *====================================================================
 * PURPOSE: enumerate users
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: number of users
 *
 * NOTES:
 *====================================================================
 */

NQ_UINT
csGetUsersCount(
    void
    )
{
    return (NQ_UINT)staticData->numUsers;
}

/*====================================================================
 * PURPOSE: Obtain an empty tree slot
 *--------------------------------------------------------------------
 * PARAMS:  IN user for this tree
 *
 * RETURNS: Pointer to a slot or NULL
 *
 * NOTES:   assigns TID to the slot as this slot index in the
 *          array of slots
 *====================================================================
 */

CSTree*
csGetNewTree(
    const CSUser* pUser
    )
{
    NQ_UINT16 i;      /* just an index */

    for (i=0; i < UD_FS_NUMSERVERTREES; i++)
    {
        if (staticData->trees[i].tid == (CSTid)CS_ILLEGALID)
        {
            staticData->trees[i].tid = i;   /* set "self" index */
            staticData->trees[i].uid = pUser->uid;
            staticData->trees[i].session = pUser->session;
            return &staticData->trees[i];
        }
    }

    TRCERR("No more tree slots");
    return NULL;
}

/*====================================================================
 * PURPOSE: find a tree providing TID
 *--------------------------------------------------------------------
 * PARAMS:  IN tree ID
 *
 * RETURNS: Pointer to a slot or NULL
 *
 * NOTES:
 *====================================================================
 */

CSTree*
csGetTreeByTid(
    CSTid tid
    )
{
    TRCB(); 
    
    if (tid >= UD_FS_NUMSERVERTREES)
    {
        TRCERR("Illegal TID value: %d", tid);
        TRCE();
        return NULL;
    }

    if (staticData->trees[tid].tid != tid)
    {
        TRCERR("Illegal TID in the slot, expected: %d, is: %d", tid, staticData->trees[tid].tid);
        TRCE();
        return NULL;
    }

    if (staticData->sessions[staticData->trees[tid].session].socket != csDispatchGetSocket())
    {
        TRCERR("TID for unexpected socket, expected: %d, is: %d", staticData->sessions[staticData->trees[tid].session].socket, csDispatchGetSocket());
        TRCE();
        return NULL;
    }
    TRCE();
    return &staticData->trees[tid];
}

/*====================================================================
 * PURPOSE: enumerate trees for a given share
 *--------------------------------------------------------------------
 * PARAMS:  IN share desriptor
 *          IN tree ID to start from or CS_ILLEGALID to start from the
 *             beginning
 *
 * RETURNS: Pointer to a slot or NULL
 *
 * NOTES:
 *====================================================================
 */

CSTree*
csGetNextTreeByShare(
    const CSShare* pShare,
    CSTid tid
    )
{
    NQ_INT i;      /* just an index */

    for (i= tid==CS_ILLEGALID? 0 : tid + 1;
         i < UD_FS_NUMSERVERTREES;
         i++
        )
    {
        if (staticData->trees[i].tid == (CSTid)CS_ILLEGALID)
            continue;
        if (staticData->trees[i].share == pShare)
            return &staticData->trees[i];
    }

    return NULL;
}

/*====================================================================
 * PURPOSE: release tree slot
 *--------------------------------------------------------------------
 * PARAMS:  IN tree ID
 *
 * RETURNS: None
 *
 * NOTES:
 *====================================================================
 */

void
csReleaseTree(
    CSTid tid,
    NQ_BOOL expected
    )
{
    NQ_UINT16 idx;       /* index in files */
#ifdef UD_NQ_INCLUDEEVENTLOG
    UDShareAccessEvent eventInfo;
    CSUser * 		   pUser;
#endif /* UD_NQ_INCLUDEEVENTLOG*/

    if (tid >= UD_FS_NUMSERVERTREES)
    {
        TRCERR("Illegal TID value, tid: %d", tid);
        return;
    }
    if (staticData->trees[tid].tid != tid)
    {
        TRCERR("Illegal TID in the slot, expected: %d, is: %d", tid, staticData->trees[tid].tid);
        return;
    }
#ifdef UD_NQ_INCLUDEEVENTLOG
    eventInfo.shareName = staticData->trees[tid].share->name;
    eventInfo.ipc = staticData->trees[tid].share->ipcFlag;
    eventInfo.printQueue = staticData->trees[tid].share->isPrintQueue;
    eventInfo.tid = tid;
    pUser = csGetUserByUid(staticData->trees[tid].uid);
    eventInfo.rid = (pUser != NULL) ? csGetUserRid((CSUser *)pUser) : CS_ILLEGALID;
#endif /* UD_NQ_INCLUDEEVENTLOG*/
    for (idx = 0; idx < UD_FS_NUMSERVERFILEOPEN; idx++)
    {
        if (   staticData->files[idx].fid != (CSFid)CS_ILLEGALID
            && staticData->files[idx].tid == tid
           )
        {
#ifdef UD_CS_INCLUDEPERSISTENTFIDS
            if (staticData->files[idx].durableFlags & CS_DURABLE_REQUIRED)
                staticData->files[idx].durableFlags |= CS_DURABLE_DISCONNECTED;
            else
#endif
                csReleaseFile(staticData->files[idx].fid);
        }
    }
    for (idx = 0; idx < UD_FS_NUMSERVERSEARCHES; idx++)
    {
        if (   staticData->searches[idx].sid != (CSSid)CS_ILLEGALID
            && staticData->searches[idx].tid == tid
           )
        {
            csReleaseSearch(idx);
        }
    }
#ifdef UD_NQ_INCLUDEEVENTLOG
    if (pUser != NULL)
    {
		udEventLog(UD_LOG_MODULE_CS,
			UD_LOG_CLASS_SHARE,
			UD_LOG_SHARE_DISCONNECT,
			(NQ_TCHAR *)&pUser->name,
			pUser->ip,
			(NQ_UINT32)expected ? NQ_SUCCESS : SMB_STATUS_USER_SESSION_DELETED,
			(const NQ_BYTE *)&eventInfo);
    }
#endif /* UD_NQ_INCLUDEEVENTLOG*/
    staticData->trees[tid].tid = CS_ILLEGALID;
}

/*====================================================================
 * PURPOSE: Obtain an empty name slot
 *--------------------------------------------------------------------
 * PARAMS:  IN file name
 *          IN first client UID
 *
 * RETURNS: Pointer to a slot or NULL
 *
 * NOTES:   assigns TID to the slot as this slot index in the
 *          array of slots
 *====================================================================
 */

CSName*
csGetNewName(
    const NQ_TCHAR* name,
    CSUid uid
    )
{
    NQ_UINT16 i;      /* just an index */

    for (i=0; i < UD_FS_NUMSERVERFILENAMES; i++)
    {
        if (staticData->names[i].nid == (CSNid)CS_ILLEGALID || staticData->names[i].first == NULL)
        {
            staticData->names[i].nid = i;   /* set "self" index */
            cmTStrcpy(staticData->names[i].name, name);
            staticData->names[i].first = NULL;
            staticData->names[i].uid = uid;
            staticData->names[i].markedForDeletion = FALSE;
            staticData->names[i].isDirty = FALSE;
            staticData->names[i].wasOplockBroken = FALSE;
            syMemset(&staticData->names[i].time, 0, sizeof(staticData->names[i].time));
            staticData->numUniqueFiles++;
#ifdef UD_NQ_INCLUDEEVENTLOG
			{
				NQ_IPADDRESS zeroIP = CM_IPADDR_ZERO;
				
	            staticData->names[i].deletingUserRid = CS_ILLEGALID;
	            staticData->names[i].deletingTid = CS_ILLEGALID;
				cmIpToAscii(staticData->names[i].deletingIP, &zeroIP);
			}
#endif /* UD_NQ_INCLUDEEVENTLOG */          
            return &staticData->names[i];
        }
    }

    TRCERR("No more name slots");
    return NULL;
}

/*====================================================================
 * PURPOSE: Determine whether a file was marked ofr deletion
 *--------------------------------------------------------------------
 * PARAMS:  IN file name
 *
 * RETURNS: TRUE if there is a file marked for deletion with this full path
 *
 * NOTES:   assigns TID to the slot as this slot index in the
 *          array of slots
 *====================================================================
 */

NQ_BOOL
csFileMarkedForDeletion(
    const NQ_TCHAR* name
    )
{
    NQ_INT i;      /* just an index */

    for (i=0; i < UD_FS_NUMSERVERFILENAMES; i++)
    {
        if (staticData->names[i].nid != (CSNid)CS_ILLEGALID && staticData->names[i].first != NULL)
        {
            if (staticData->names[i].markedForDeletion && cmTStrcmp(name, staticData->names[i].name)==0)
            {
                return TRUE;
            }
        }
    }
    return FALSE;
}

/*====================================================================
 * PURPOSE: Find next file in the name's chain of opened files
 *--------------------------------------------------------------------
 * PARAMS:  IN previous FID or CS_ILLEGALID to start from the very first
 *
 * RETURNS: next FID or CS_ILLEGALID when no more openings available
 *
 * NOTES:
 *====================================================================
 */

CSFid
csGetNextFileOpen(
    CSFid fid
    )
{
    fid = (CSFid)fid2Index(fid);
    if (fid == CS_ILLEGALID)
        fid = 0;
    else
        fid++;
    for (; fid < UD_FS_NUMSERVERFILEOPEN; fid++)
    {
        if (staticData->files[fid].fid != CS_ILLEGALID)
            return (CSFid)index2Fid(fid);
    }
    return index2Fid(CS_ILLEGALID);
}


/*====================================================================
 * PURPOSE: Find next file in the name's chain of opened files
 *--------------------------------------------------------------------
 * PARAMS:  IN file name
 *
 * RETURNS: Pointer to a slot or NULL
 *
 * NOTES:   assigns TID to the slot as this slot index in the
 *          array of slots
 *====================================================================
 */

CSFile*
csGetNextFileByName(
    CSFid fid
    )
{
    if (fid2Index(fid) >= UD_FS_NUMSERVERFILEOPEN || fid2Index(fid) < 0)
    {
        TRCERR("Illegal FID value, fid: %d", fid);
        return NULL;
    }
    return staticData->files[fid2Index(fid)].next;
}

/*====================================================================
 * PURPOSE: release name descriptor
 *--------------------------------------------------------------------
 * PARAMS:  IN user pointer
 *          IN slot ID
 *
 * RETURNS:
 *
 * NOTES:   name may be released only of there is no more opened files
 *====================================================================
 */

void
csReleaseName(
#ifdef UD_NQ_INCLUDEEVENTLOG
    CSUser* pUser,
    CSTid tid,
#endif /* UD_NQ_INCLUDEEVENTLOG */
    CSNid nid
    )
{
#ifdef UD_NQ_INCLUDEEVENTLOG
    UDFileAccessEvent eventInfo;            /* share event information */
#endif /* UD_NQ_INCLUDEEVENTLOG */
    CSName *pName;

    TRCB();
    
    if (nid >= UD_FS_NUMSERVERFILENAMES)
    {
        TRCERR("Illegal NID value, nid: %d", nid);
        TRCE();
        return;
    }
	pName = &staticData->names[nid];
    if (pName->nid != nid)
    {
        TRCERR("Illegal NID in the slot, expected: %d, is: %d", nid, pName->nid);
        TRCE();
        return;
    }

    /* if the file was marked for deletion - delete it now */

    if (pName->markedForDeletion)
    {
        SYFileInformation fileInfo;             /* for distingusihing between a file and a folder */
        NQ_STATUS status = NQ_SUCCESS;          /* last status */

#ifdef UD_NQ_INCLUDEEVENTLOG
	    eventInfo.fileName = pName->name;
	    eventInfo.access = 0;
	    if (pUser != NULL)
	    	eventInfo.rid = csGetUserRid(pUser);
	    eventInfo.tid = tid;
#endif /* UD_NQ_INCLUDEEVENTLOG */
		
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
	    if (NULL != pUser)
		{
	    	eventInfo.before = TRUE;
			udEventLog(
					UD_LOG_MODULE_CS,
					UD_LOG_CLASS_FILE,
					UD_LOG_FILE_ATTRIBGET,
					pUser->name,
					pUser->ip,
					0,
					(const NQ_BYTE*)&eventInfo
					);
		}
	    eventInfo.before = FALSE;
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */

        status = syGetFileInformationByName(pName->name, &fileInfo);

#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
		if (NULL != pUser)
		{
			udEventLog(
					UD_LOG_MODULE_CS,
					UD_LOG_CLASS_FILE,
					UD_LOG_FILE_ATTRIBGET,
					pUser->name,
					pUser->ip,
					(NQ_SUCCESS == status) ? 0 : csErrorGetLast(),
					(const NQ_BYTE*)&eventInfo
					);
		}
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */
        if (NQ_SUCCESS == status)
        {
#ifdef UD_NQ_INCLUDEEVENTLOG
		    NQ_TCHAR* pUserName = NULL;
			const NQ_IPADDRESS *pIp = NULL;

			if (NULL != pUser)
			{
			    NQ_IPADDRESS deletingIp;	
				NQ_IPADDRESS zeroIp = CM_IPADDR_ZERO;

				cmAsciiToIp(pName->deletingIP, &deletingIp);
			    if (pName->deletingUserRid == CS_ILLEGALID && CM_IPADDR_EQUAL(deletingIp, zeroIp))
		    	{
					pUserName = pUser->name;
					pIp = pUser->ip;
		    	}
				else
				{
				    pUserName = (pName->deletingUserRid == csGetUserRid(pUser)) ? pUser->name : NULL;			    
					pIp = &deletingIp;
					eventInfo.rid = pName->deletingUserRid;
					eventInfo.tid = pName->deletingTid;
				}
			}
			eventInfo.before = TRUE;
			if (NULL != pUser)
			{
				udEventLog(
						UD_LOG_MODULE_CS,
						UD_LOG_CLASS_FILE,
						UD_LOG_FILE_DELETE,
						pUserName,
						pIp,
						0,
						(const NQ_BYTE*)&eventInfo
						);
			}
			eventInfo.before = FALSE;
#endif /* UD_NQ_INCLUDEEVENTLOG */

        	if (fileInfo.attributes & SMB_ATTR_DIRECTORY)
            {
                status = syDeleteDirectory(pName->name);
            }
            else
            {
                status = syDeleteFile(pName->name);
            }
			
#ifdef UD_NQ_INCLUDEEVENTLOG
			if (NULL != pUser)
			{
				udEventLog(
						UD_LOG_MODULE_CS,
						UD_LOG_CLASS_FILE,
						UD_LOG_FILE_DELETE,
						pUserName,
						pIp,
						status == NQ_SUCCESS ? 0 : csErrorGetLast(),
						(const NQ_BYTE*)&eventInfo
						);
			}
#endif /* UD_NQ_INCLUDEEVENTLOG */
        }
        if (status == NQ_FAIL)
        {
            TRCERR("File was marked for deletion but deletion failed");
        }

        csNotifyImmediatelly(pName->name, SMB_NOTIFYCHANGE_REMOVED, SMB_NOTIFYCHANGE_NAME);
    }
    else if (pName->isDirty)
    {
        csNotifyImmediatelly(pName->name, SMB_NOTIFYCHANGE_MODIFIED, SMB_NOTIFYCHANGE_LAST_WRITE);
    }

    pName->nid = (CSNid)CS_ILLEGALID;
    staticData->numUniqueFiles--;

    TRCE();
}

/*
 *====================================================================
 * PURPOSE: get open unique files count
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: number of open unique files
 *
 * NOTES:
 *====================================================================
 */

NQ_UINT                     /* number of files */
csGetUniqueFilesCount(
    void
    )
{
    return (NQ_UINT)staticData->numUniqueFiles;
}

/*====================================================================
 * PURPOSE: find a filename providing NID
 *--------------------------------------------------------------------
 * PARAMS:  IN filename ID
 *
 * RETURNS: Pointer to a slot or NULL
 *
 * NOTES:
 *====================================================================
 */

CSName*
csGetNameByNid(
    CSNid nid
    )
{
    if (nid >= UD_FS_NUMSERVERFILENAMES)
    {
        TRCERR("Illegal NID value, nid: %d", nid);
        return NULL;
    }

    if (staticData->names[nid].nid != nid)
    {
        TRCERR("Illegal NID in the slot, expected: %d, is: %d", nid, staticData->names[nid].nid);
        return NULL;
    }

    return &staticData->names[nid];
}

/*====================================================================
 * PURPOSE: find a file name descriptor providing file name
 *--------------------------------------------------------------------
 * PARAMS:  IN file name to look for
 *
 * RETURNS: Pointer to a slot or NULL
 *
 * NOTES:
 *====================================================================
 */

CSName*
csGetNameByName(
    const NQ_TCHAR* name
    )
{
    NQ_INT i;  /* index in staticData->files */

    for (i = 0; i < UD_FS_NUMSERVERFILENAMES; i++)
    {
        if (   (staticData->names[i].nid != CS_ILLEGALID
            && staticData->names[i].first != NULL)
            && (cmTStrcmp(name, staticData->names[i].name) == 0)
           )
        {
            return &staticData->names[i];
        }
    }
    return NULL;
}

/*====================================================================
 * PURPOSE: Obtain an empty file slot
 *--------------------------------------------------------------------
 * PARAMS:  IN master tree
 *          IN file name structure
 *          IN file access bits (share bitset is actually used)
 *
 * RETURNS: Pointer to a slot or NULL
 *
 * NOTES:   assigns FID to the slot as this slot index in the
 *          array of slots
 *          insert file in the front of the file chain of the file name descriptor.
 *          Name descriptor's access bits are Or-ed with the file access bits
 *          This will "worsen" the share restrictions.
 *====================================================================
 */

CSFile*
csGetNewFile(
    const CSTree* pTree,
    CSName* name,
    NQ_UINT16 access
    )
{
    NQ_INT i;      /* just an index */
    NQ_INT candidate = CS_ILLEGALID;
#ifdef UD_NQ_INCLUDEEVENTLOG
    CSUser  *   pUser;
    UDFileAccessEvent   eventInfo;
#endif /* UD_NQ_INCLUDEEVENTLOG */

    for (i = 0; i < UD_FS_NUMSERVERFILEOPEN; i++)
    {
        if (staticData->files[i].fid == (CSFid)CS_ILLEGALID)
        {
            candidate = i;
            break;
        }
#ifdef UD_CS_INCLUDEPERSISTENTFIDS
        else if (staticData->files[i].durableFlags & CS_DURABLE_DISCONNECTED)
        {
            candidate = i;
        }
#endif /* UD_CS_INCLUDEPERSISTENTFIDS */
    }
    if (candidate != CS_ILLEGALID)
    {
#ifdef UD_CS_INCLUDEPERSISTENTFIDS
        if (staticData->files[candidate].fid != (CSFid)CS_ILLEGALID)
        {
            csReleaseFile(staticData->files[candidate].fid);
            staticData->files[candidate].durableFlags = 0;
        }
#endif /* UD_CS_INCLUDEPERSISTENTFIDS */
        staticData->files[candidate].fid = (CSFid)index2Fid(candidate);   /* set "self" index */
        syInvalidateFile(&staticData->files[candidate].file);

#ifdef UD_CS_INCLUDERPC
        {
            NQ_INT p;      /* just an index */

            staticData->files[candidate].isPipe = FALSE;
            /* clear all pipe contexts */
            for (p = 0; p < CM_RPC_MAXNUMBEROFCONTEXTS; p++)
                staticData->files[candidate].pipes[p] = CS_INVALIDPIPE;
        }
#endif /* UD_CS_INCLUDERPC */
        staticData->files[candidate].access = access;
        staticData->files[candidate].tid = pTree->tid;
        staticData->files[candidate].uid = pTree->uid;
        staticData->files[candidate].session = pTree->session;
        staticData->files[candidate].nid = name->nid;
        staticData->files[candidate].next = name->first;
        staticData->files[candidate].prev = NULL;
        if (staticData->files[candidate].next != NULL)
        {
            staticData->files[candidate].next->prev = &staticData->files[candidate];
        }
        staticData->files[candidate].offsetLow = 0;
        staticData->files[candidate].offsetHigh = 0;
        staticData->files[candidate].notifyPending = FALSE;
        name->first = &staticData->files[candidate];
#ifdef UD_CS_INCLUDERPC_SPOOLSS
        staticData->files[candidate].isPrint = FALSE;
        syInvalidatePrinter(&staticData->files[candidate].printerHandle);
#endif
#ifdef UD_NQ_INCLUDESMB2
        staticData->files[candidate].sid = (CSSid)CS_ILLEGALID;
#endif
        staticData->files[candidate].oplockGranted = FALSE;
        staticData->files[candidate].pFileOplockBreaker = NULL;
        staticData->numFiles++;
        return &staticData->files[candidate];
    }
#ifdef UD_NQ_INCLUDEEVENTLOG
    pUser = csGetUserBySession(csGetSessionById(pTree->session));
    eventInfo.rid = csGetUserRid(pUser);
    udEventLog(
        UD_LOG_MODULE_CS,
        UD_LOG_CLASS_FILE,
        UD_LOG_FILE_CREATE,
        pUser->name,
        pUser->ip,
        (NQ_UINT32)SMB_STATUS_INSUFFICIENT_RESOURCES,
        (const NQ_BYTE *)&eventInfo
        );
#endif /* UD_NQ_INCLUDEEVENTLOG */

    TRCERR("No more file slots");
    return NULL;
}

/*====================================================================
 * PURPOSE: obtain file name providing FID
 *--------------------------------------------------------------------
 * PARAMS:  IN file ID
 *          IN TID
 *          IN UID
 *
 * RETURNS: Pointer to a slot or NULL
 *
 * NOTES:
 *====================================================================
 */

const NQ_TCHAR*
csGetFileName(
    CSFid fid
    )
{
    if (fid2Index(fid) >= UD_FS_NUMSERVERFILEOPEN || fid2Index(fid) < 0)
    {
        TRCERR("Illegal FID value, fid: %d", fid);
        return NULL;
    }
    if (staticData->files[fid2Index(fid)].nid >= UD_FS_NUMSERVERFILENAMES)
    {
        TRCERR("Illegal NID value, fid: %d", staticData->files[fid2Index(fid)].nid);
        return NULL;
    }
    return staticData->names[staticData->files[fid2Index(fid)].nid].name;
}

/*====================================================================
 * PURPOSE: find a file providing FID
 *--------------------------------------------------------------------
 * PARAMS:  IN file ID
 *          IN TID
 *          IN UID
 *
 * RETURNS: Pointer to a slot or NULL
 *
 * NOTES:
 *====================================================================
 */

CSFile*
csGetFileByFid(
    CSFid fid,
    CSTid tid,
    CSUid uid
    )
{
    if (fid2Index(fid) >= UD_FS_NUMSERVERFILEOPEN || fid2Index(fid) < 0)
    {
        TRCERR("Illegal FID value, fid: %d", fid);
        return NULL;
    }

    if (staticData->files[fid2Index(fid)].fid != fid)
    {
        TRCERR("Illegal FID in the slot, expected: %d, is: %d", fid, staticData->files[fid2Index(fid)].fid);
        return NULL;
    }

    if (staticData->sessions[staticData->files[fid2Index(fid)].session].socket != csDispatchGetSocket())
    {
        TRCERR("FID for unexpected socket");
        return NULL;
    }
    if (staticData->files[fid2Index(fid)].tid != tid)
    {
        TRCERR("TID does not match, Is: %d, expected: %d", staticData->files[fid2Index(fid)].tid, tid);
        TRCE();
        return NULL;
    }
    if (staticData->files[fid2Index(fid)].uid != uid)
    {
        TRCERR("UID does not match, Is: %d, expected: %d", staticData->files[fid2Index(fid)].uid, uid);
        TRCE();
        return NULL;
    }

    return &staticData->files[fid2Index(fid)];
}

/*====================================================================
 * PURPOSE: find a file providing FID
 *--------------------------------------------------------------------
 * PARAMS:  IN file ID
 *
 * RETURNS: Pointer to a slot or NULL
 *
 * NOTES:
 *====================================================================
 */

CSFile*
csGetFileByJustFid(
    CSFid fid
    )
{
    if (fid2Index(fid) >= UD_FS_NUMSERVERFILEOPEN)
    {
        TRCERR("Illegal FID value, fid: %d", fid);
        return NULL;
    }
    if (staticData->files[fid2Index(fid)].fid != fid)
    {
        TRCERR("Illegal FID in the slot, expected: %d, is: %d", fid, staticData->files[fid2Index(fid)].fid);
        return NULL;
    }
    return &staticData->files[fid2Index(fid)];
}

/*====================================================================
 * PURPOSE: find a file providing PID 
 *--------------------------------------------------------------------
 * PARAMS:  IN PID
 * 			IN MID
 *          IN TID
 *          IN UID
 *
 * RETURNS: Pointer to a slot or NULL
 *
 * NOTES:
 *====================================================================
 */

CSFile*
csGetFileByContext(
    CSPid pid,
    CSMid mid,
    CSTid tid,
    CSUid uid
    )
{
    NQ_INT i;

    for (i = 0; i < UD_FS_NUMSERVERFILEOPEN; i++)
    {
        if (   staticData->files[i].fid != CS_ILLEGALID
            && staticData->files[i].notifyPending
            && staticData->files[i].notifyContext.prot.smb1.pid == pid
            && staticData->files[i].notifyContext.prot.smb1.mid == mid
            && staticData->files[i].tid == tid
            && staticData->files[i].uid == uid
           )
        {
            return &staticData->files[i];
        }
    }
    return NULL;
}

/*====================================================================
 * PURPOSE: find a file providing PID SMB2 version
 *--------------------------------------------------------------------
 * PARAMS:  IN TID
 *          IN UID
 *
 * RETURNS: Pointer to a slot or NULL
 *
 * NOTES:
 *====================================================================
 */

#ifdef UD_NQ_INCLUDESMB2

CSFile*
cs2GetFileByContext(
    NQ_UINT64 aid,
    CSUid uid
    )
{
    NQ_INT i;

    for (i = 0; i < UD_FS_NUMSERVERFILEOPEN; i++)
    {
        if (   staticData->files[i].fid != CS_ILLEGALID
            && staticData->files[i].notifyPending
            && staticData->files[i].notifyAid.low == aid.low
            && staticData->files[i].notifyAid.high == aid.high
            && staticData->files[i].uid == uid
           )
        {
            return &staticData->files[i];
        }
    }
    return NULL;
}

#endif /* UD_NQ_INCLUDESMB2 */

/*====================================================================
 * PURPOSE: find a file providing PID and previous FID
 *--------------------------------------------------------------------
 * PARAMS:  IN process ID
 *          IN fid to start after. If CS_ILLEGALID - start from the
 *             beginning
 *
 * RETURNS: Pointer to a slot or NULL
 *
 * NOTES:
 *====================================================================
 */

CSFile*
csGetNextFileByPid(
    CSPid pid,
    CSFid fid
    )
{
    NQ_INT i;  /* index in files */

    if (fid == CS_ILLEGALID)
        fid = index2Fid(0);
    else
        fid++;
    for (i = fid2Index(fid); i < UD_FS_NUMSERVERFILEOPEN; i++)
    {
        if (   staticData->files[i].fid != CS_ILLEGALID
            && staticData->files[i].pid == pid
           )
        {
            return &staticData->files[i];
        }
    }
    return NULL;
}

/*====================================================================
 * PURPOSE: release file slot
 *--------------------------------------------------------------------
 * PARAMS:  IN file ID
 *
 * RETURNS: None
 *
 * NOTES:
 *====================================================================
 */

void
csReleaseFile(
    CSFid fid
    )
{
#ifdef UD_NQ_INCLUDEEVENTLOG
    CSUser* pUser;                    /* user structure pointer */
    UDFileAccessEvent eventInfo;            /* share event information */
#endif /* UD_NQ_INCLUDEEVENTLOG */
    CSFile * pFile;                         /* file pointer */

    TRCB();
    
    if (fid2Index(fid) >= UD_FS_NUMSERVERFILEOPEN)
    {
        TRCERR("Illegal FID value, fid: %d", fid);
        TRCE();
        return;
    }
    if (staticData->files[fid2Index(fid)].fid != fid)
    {
        TRCERR("Illegal FID in the slot, expected: %d, is: %d", fid, staticData->files[fid2Index(fid)].fid);
        TRCE();
        return;
    }
    pFile = &staticData->files[fid2Index(fid)];

#ifdef UD_NQ_INCLUDEEVENTLOG
    eventInfo.fileName = staticData->names[pFile->nid].name;
    eventInfo.access = 0;
    pUser = csGetUserByUid(pFile->uid);
    if (pUser != NULL)
    {
    	eventInfo.rid = csGetUserRid(pUser);
    	eventInfo.tid = pFile->tid;
    }
#endif /* UD_NQ_INCLUDEEVENTLOG */

#ifdef UD_CS_INCLUDERPC_SPOOLSS
    if (pFile->isPrint)
    {
        if (syEndPrintJob(pFile->printerHandle, (NQ_UINT32)pFile->file) != NQ_SUCCESS)
        {
            TRCERR("Failed to end print job");
        }
    }
    else
    {
#endif
        if (syIsValidDirectory(pFile->directory))
        {
#ifdef UD_NQ_INCLUDEEVENTLOG
			if (pUser != NULL)
			{
				eventInfo.before = TRUE;
				udEventLog(
						UD_LOG_MODULE_CS,
						UD_LOG_CLASS_FILE,
						UD_LOG_FILE_CLOSE,
						pUser->name,
						pUser->ip,
						0,
						(const NQ_BYTE*)&eventInfo
						);
				eventInfo.before = FALSE;
			}
#endif /* UD_NQ_INCLUDEEVENTLOG */
            if (syCloseDirectory(pFile->directory) != NQ_SUCCESS)
            {
#ifdef UD_NQ_INCLUDEEVENTLOG
                if (NULL != pUser)
                {
                    udEventLog(
                    UD_LOG_MODULE_CS,
                    UD_LOG_CLASS_FILE,
                    UD_LOG_FILE_CLOSE,
                    pUser->name,
                    pUser->ip,
                    syGetLastError(),
                    (const NQ_BYTE*)&eventInfo
                    );
                }
#endif /* UD_NQ_INCLUDEEVENTLOG */
                    TRCERR("Close operation failed, Directory name %s", cmTDump(staticData->names[staticData->files[fid2Index(fid)].nid].name));
            }
#ifdef UD_NQ_INCLUDEEVENTLOG
            else
            {
                if (NULL != pUser)
                {
                    udEventLog(
                    UD_LOG_MODULE_CS,
                    UD_LOG_CLASS_FILE,
                    UD_LOG_FILE_CLOSE,
                    pUser->name,
                    pUser->ip,
                    0,
                    (const NQ_BYTE*)&eventInfo
                    );
                }
            }
#endif /* UD_NQ_INCLUDEEVENTLOG */
        }
        if (syIsValidFile(pFile->file))
        {
#ifdef UD_NQ_INCLUDEEVENTLOG
			if (pUser != NULL)
			{
				eventInfo.before = TRUE;
				udEventLog(
						UD_LOG_MODULE_CS,
						UD_LOG_CLASS_FILE,
						UD_LOG_FILE_CLOSE,
						pUser->name,
						pUser->ip,
						0,
						(const NQ_BYTE*)&eventInfo
						);
				eventInfo.before = FALSE;
			}
#endif /* UD_NQ_INCLUDEEVENTLOG */
            if (syCloseFile(staticData->files[fid2Index(fid)].file) != NQ_SUCCESS)
            {
#ifdef UD_NQ_INCLUDEEVENTLOG
                if (NULL != pUser)
                {
                    udEventLog(
                    UD_LOG_MODULE_CS,
                    UD_LOG_CLASS_FILE,
                    UD_LOG_FILE_CLOSE,
                    pUser->name,
                    pUser->ip,
                    syGetLastError(),
                    (const NQ_BYTE*)&eventInfo
                    );
                }
#endif /* UD_NQ_INCLUDEEVENTLOG */
                TRCERR("Close operation failed, File name: %s, file ID: %d", cmTDump(staticData->names[staticData->files[fid2Index(fid)].nid].name), staticData->files[fid2Index(fid)].file);
            }
#ifdef UD_NQ_INCLUDEEVENTLOG
            else
            {
                if (NULL != pUser)
                {
                    udEventLog(
                    UD_LOG_MODULE_CS,
                    UD_LOG_CLASS_FILE,
                    UD_LOG_FILE_CLOSE,
                    pUser->name,
                    pUser->ip,
                    0,
                    (const NQ_BYTE*)&eventInfo
                    );
                }
            }
#endif /* UD_NQ_INCLUDEEVENTLOG */
        }
#ifdef UD_CS_INCLUDERPC
        if (staticData->files[fid2Index(fid)].isPipe)
            csDcerpcClosePipe(&staticData->files[fid2Index(fid)]);
#endif
#ifdef UD_CS_INCLUDERPC_SPOOLSS    
    }
#endif

    /* notify */
    if (staticData->names[pFile->nid].markedForDeletion)
        csNotifyImmediatelly(staticData->names[pFile->nid].name, SMB_NOTIFYCHANGE_REMOVED, SMB_NOTIFYCHANGE_NAME);


    /* release from the chain in the file name */

    if (staticData->files[fid2Index(fid)].nid != (CSNid)CS_ILLEGALID)
    {
        if (staticData->files[fid2Index(fid)].prev == NULL && staticData->files[fid2Index(fid)].next == NULL)
        {
            staticData->names[staticData->files[fid2Index(fid)].nid].first = staticData->files[fid2Index(fid)].next;
            if (staticData->files[fid2Index(fid)].next == NULL)
                csReleaseName(
#ifdef UD_NQ_INCLUDEEVENTLOG
                    pUser,
                    pFile->tid,
#endif /* UD_NQ_INCLUDEEVENTLOG */
                    pFile->nid
                    );
        }
        else
        {
            if (staticData->files[fid2Index(fid)].next != NULL)
            {
                staticData->files[fid2Index(fid)].next->prev = staticData->files[fid2Index(fid)].prev;
            }
            if (staticData->files[fid2Index(fid)].prev != NULL)
            {
                staticData->files[fid2Index(fid)].prev->next = staticData->files[fid2Index(fid)].next;
            }
            else
            {
                staticData->names[staticData->files[fid2Index(fid)].nid].first = staticData->files[fid2Index(fid)].next;
            }
        }
    }

    /* clean up */

    syInvalidateFile(&staticData->files[fid2Index(fid)].file);
    syInvalidateDirectory(&staticData->files[fid2Index(fid)].directory);
    staticData->files[fid2Index(fid)].fid = (CSFid)CS_ILLEGALID;
    staticData->files[fid2Index(fid)].user = NULL;
#ifdef UD_NQ_INCLUDESMB2
    if (staticData->files[fid2Index(fid)].sid != (CSSid)CS_ILLEGALID)
    {
        csReleaseSearch(staticData->files[fid2Index(fid)].sid);
    }
#endif
    staticData->numFiles--;

    TRCE();
}

/*
 *====================================================================
 * PURPOSE: get open files count
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: number of open files
 *
 * NOTES:
 *====================================================================
 */

NQ_UINT
csGetFilesCount(
    void
    )
{
    return (NQ_UINT)staticData->numFiles;
}

/*====================================================================
 * PURPOSE: Find a share by name
 *--------------------------------------------------------------------
 * PARAMS:  IN share name in TCHAR
 *
 * RETURNS: Share descriptor or NULL
 *
 * NOTES:
 *====================================================================
 */

CSShare*
csGetShareByName(
    const NQ_TCHAR* name
    )
{
    NQ_INT i;  /* just an index */

    for (i = 0; i < UD_FS_NUMSERVERSHARES; i++)
    {
        if (!staticData->shares[i].isFree && (cmTStricmp(name, staticData->shares[i].name) == 0))
        {
            return &staticData->shares[i];
        }
    }
    return NULL;
}

/*====================================================================
 * PURPOSE: Find share mapping by UID and TID
 *--------------------------------------------------------------------
 * PARAMS:  IN UID
 *          IN TID
 *
 * RETURNS: Share or NULL
 *
 * NOTES:
 *====================================================================
 */

const CSShare*
csGetShareByUidTid(
    CSUid uid,
    CSTid tid
    )
{
    CSTree* tree;

    if ((tree = csGetTreeByTid(tid)) == NULL)
    {
        return NULL;
    }

    if (staticData->sessions[staticData->trees[tid].session].socket != csDispatchGetSocket())
    {
        TRCERR("TID for unexpected socket");
        return NULL;
    }

/*    if (tree->uid != uid)
    {
        TRCERR("UID does not match");
        TRC2P("  expected: %d, is: %d", tree->uid, uid);
        return NULL;
    }*/

    if (tree->share == NULL || tree->share->map == NULL)
    {
        TRCERR("Tree has no share or share has no mapping");
        return NULL;
    }
    return tree->share;
}

#ifdef UD_CS_INCLUDESECURITYDESCRIPTORS

/*
 *====================================================================
 * PURPOSE: change share security descriptor
 *--------------------------------------------------------------------
 * PARAMS:  IN share pointer
 *          IN security descriptor pointer
 *          IN security descriptor length
 *
 * RETURNS: TRUE on success and false on overflow
 *
 * NOTES:
 *====================================================================
 */

NQ_BOOL
csSetShareSecurityDescriptor(
    CSShare* share
    )
{
    udSaveShareSecurityDescriptor(share->name, share->sd.data, (NQ_COUNT)share->sd.length);
    return TRUE;
}

/*
 *====================================================================
 * PURPOSE: load share security descriptor
 *--------------------------------------------------------------------
 * PARAMS:  IN share pointer
 *          IN security descriptor pointer
 *          IN security descriptor length
 *
 * RETURNS: TRUE
 *
 * NOTES:
 *====================================================================
 */

NQ_BOOL
csLoadShareSecurityDescriptor(
    CSShare* share
    )
{
    staticData->shares[share->idx].sd.length = udLoadShareSecurityDescriptor(
        staticData->shares[share->idx].name,
        staticData->shares[share->idx].sd.data,
        sizeof(staticData->shares[share->idx].sd.data));
    if (0 == staticData->shares[share->idx].sd.length || !cmSdIsValid(&staticData->shares[share->idx].sd))
    {
        TRC1P("Cannot load security descriptor for share: %s", cmTDump(staticData->shares[share->idx].name));
        TRC("   loading default security descriptor");
        cmSdGetShareSecurityDescriptor(&staticData->shares[share->idx].sd);
    }
    return TRUE;
}

#endif /* UD_CS_INCLUDESECURITYDESCRIPTORS */

/*
 *====================================================================
 * PURPOSE: enumerate shares
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: number of shares
 *
 * NOTES:
 *====================================================================
 */

NQ_UINT
csGetSharesCount(
    void
    )
{
    return (NQ_UINT)staticData->numShares;
}

/*
 *====================================================================
 * PURPOSE: get hidden share by mapping
 *--------------------------------------------------------------------
 * PARAMS:  IN share mapping in TCHAR
 *
 * RETURNS: Share or NULL
 *
 * NOTES: searches through hidden shares while matching mapping
 *====================================================================
 */

CSShare*
csGetHiddenShareByMap(
        const NQ_TCHAR* map
    )
{
    NQ_INT i;  /* just an index */

    for (i = 0; i < UD_FS_NUMSERVERSHARES; i++)
    {
        if (!staticData->shares[i].isFree && staticData->shares[i].isHidden == TRUE && (cmTStrincmp(staticData->shares[i].map, map, (NQ_COUNT)cmTStrlen(staticData->shares[i].map)) == 0))
        {
            return &staticData->shares[i];
        }
    }
    return NULL;
}


/*
 *====================================================================
 * PURPOSE: enumerate sessions
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: number of sessions
 *
 * NOTES:
 *====================================================================
 */

NQ_UINT
csGetSessionsCount(
    void
    )
{
    NQ_UINT count = 0;  /* result */
    NQ_INT i;           /* just an index */

    for (i=0; i < UD_FS_NUMSERVERSESSIONS; i++)
    {
        if (staticData->sessions[i].key != CS_ILLEGALID)
        {
            count++;
        }
    }

    return count;
}

/*
 *====================================================================
 * PURPOSE: get a share by index
 *--------------------------------------------------------------------
 * PARAMS:  IN share index
 *
 * RETURNS: pointer to a share descriptor or NULL
 *
 * NOTES:
 *====================================================================
 */

CSShare*
csGetShareByIndex(
    NQ_UINT idx
    )
{
    NQ_INT i;       /* just a counter */

    for (i = 0; i < UD_FS_NUMSERVERSHARES; i++)
    {
        if (!staticData->shares[i].isFree)
        {
            if (0 == idx--)
                return &staticData->shares[i];
        }
    }
    return NULL;
}

/*
 *====================================================================
 * PURPOSE: get a user by index
 *--------------------------------------------------------------------
 * PARAMS:  IN user index
 *
 * RETURNS: pointer to a user descriptor or NULL
 *
 * NOTES:
 *====================================================================
 */

CSUser*
csGetUserByIndex(
    NQ_UINT idx
    )
{
    NQ_INT i;       /* just a counter */

    for (i = 0; i < UD_FS_NUMSERVERUSERS; i++)
    {
        if (staticData->users[i].uid != CS_ILLEGALID)
        {
            if (0 == idx--)
            {

                return &staticData->users[i];
            }
        }
    }
    return NULL;
}

/*
 *====================================================================
 * PURPOSE: get a number of opened files for this share
 *--------------------------------------------------------------------
 * PARAMS:  IN share pointer
 *
 * RETURNS: number of opened files
 *
 * NOTES:
 *====================================================================
 */

NQ_COUNT
csGetNumberOfShareFiles(
    const CSShare* share
    )
{
    NQ_UINT i;                                 /* index in files */
    NQ_COUNT num = 0;                          /* the result */

    for (i = 0; i < UD_FS_NUMSERVERFILENAMES; i++)
    {
        if (staticData->names[i].first != NULL)
        {
            if (staticData->trees[staticData->names[i].first->tid].share == share)
                num++;
        }
    }

    return num;
}

/*
 *====================================================================
 * PURPOSE: get a number of opened files for this user
 *--------------------------------------------------------------------
 * PARAMS:  IN user pointer
 *
 * RETURNS: number of opened files
 *
 * NOTES:
 *====================================================================
 */

NQ_COUNT
csGetNumberOfUserFiles(
    const CSUser* user
    )
{
    NQ_UINT i;                                 /* index in files */
    NQ_COUNT num = 0;                          /* the result */

    for (i = 0; i < UD_FS_NUMSERVERFILENAMES; i++)
    {
        if (   staticData->names[i].nid != (CSNid)CS_ILLEGALID
            && staticData->names[i].first != NULL
            && staticData->names[i].first->uid == user->uid
           )
            num++;
    }

    return num;
}

/*
 *====================================================================
 * PURPOSE: get a number of users for this share
 *--------------------------------------------------------------------
 * PARAMS:  IN share pointer
 *
 * RETURNS: number of users
 *
 * NOTES:
 *====================================================================
 */

NQ_COUNT
csGetNumberOfShareUsers(
    const CSShare* share
    )
{
    NQ_UINT i;                                  /* index in users and trees */
    NQ_COUNT num;                               /* the result */
    NQ_STATIC NQ_BOOL shareUsers[UD_FS_NUMSERVERUSERS];
                                                /* flags for each user */

    /* mark initially all users as "not guilty" */

    for (i = 0; i < UD_FS_NUMSERVERUSERS; i++)
        shareUsers[i] = FALSE;

    /* pass all trees marking their users as "guilty" */

    for (i = 0; i < UD_FS_NUMSERVERTREES; i++)
    {
        if (staticData->trees[i].share == share)
        {
            shareUsers[staticData->trees[i].uid] = TRUE;
        }
    }

    /* count those users that are revealed as connected */

    num = 0;
    for (i = 0; i < UD_FS_NUMSERVERUSERS; i++)
        if (shareUsers[i])
            num++;

    return num;
}

/*====================================================================
 * PURPOSE: Obtain an empty search slot
 *--------------------------------------------------------------------
 * PARAMS:  IN master tree
 *
 * RETURNS: Pointer to a slot or NULL
 *
 * NOTES:   assigns SID to the slot as this slot index in the
 *          array of slots
 *====================================================================
 */

CSSearch*
csGetNewSearch(
    const CSTree* pTree
    )
{
    NQ_UINT16 i;      /* just an index */

    for (i=0; i < UD_FS_NUMSERVERSEARCHES; i++)
    {
        if (staticData->searches[i].sid == (CSSid)CS_ILLEGALID)
        {
            staticData->searches[i].sid = i;   /* set "self" index */
            staticData->searches[i].tid = pTree->tid;
            staticData->searches[i].session = pTree->session;
            staticData->searches[i].enumeration.isReady = FALSE;

            return &staticData->searches[i];
        }
    }

    TRCERR("No more search slots");
    return NULL;
}

/*====================================================================
 * PURPOSE: find a search operation providing SID
 *--------------------------------------------------------------------
 * PARAMS:  IN search ID
 *
 * RETURNS: Pointer to a slot or NULL
 *
 * NOTES:
 *====================================================================
 */

CSSearch*
csGetSearchBySid(
    CSSid sid
    )
{
    if (sid >= UD_FS_NUMSERVERSEARCHES)
    {
        TRCERR("Illegal SID value  sid: %d", sid);
        return NULL;
    }

    if (staticData->searches[sid].sid != sid)
    {
        TRCERR("Illegal SID in the slot,  expected: %d, is: %d", sid, staticData->searches[sid].sid);
        return NULL;
    }

    if (staticData->sessions[staticData->searches[sid].session].socket != csDispatchGetSocket())
    {
        TRCERR("SID for unexpected socket");
        return NULL;
    }

    return &staticData->searches[sid];
}

/*====================================================================
 * PURPOSE: release search slot
 *--------------------------------------------------------------------
 * PARAMS:  IN search ID
 *
 * RETURNS: None
 *
 * NOTES:
 *====================================================================
 */

void
csReleaseSearch(
    CSSid sid
    )
{
    TRCB();
    
    if (sid >= UD_FS_NUMSERVERSEARCHES)
    {
        TRCERR("Illegal SID value  sid: %d", sid);
        TRCE();
        return;
    }
    if (staticData->searches[sid].sid != sid)
    {
        TRCERR("Illegal SID in the slot, expected: %d, is: %d", sid, staticData->searches[sid].sid);
        TRCE();
        return;
    }

    csCancelEnumeration(&staticData->searches[sid].enumeration);

    staticData->searches[sid].sid = CS_ILLEGALID;
    TRCE();
}

/*====================================================================
 * PURPOSE: Start enumerating opened directories with notify request pending
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: None
 *
 * NOTES:
 *====================================================================
 */

void
csStartNotifyRequestSearch(
    void
    )
{
    staticData->nextNotify = 0;
}

/*====================================================================
 * PURPOSE: Get next opened directory with notify request pending
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: pointer to the file structure or NULL if no more pending notify exist
 *
 * NOTES:
 *====================================================================
 */

CSFile*
csEnumerateNotifyRequest(
    void
    )
{
    NQ_INT i;

    for (i = staticData->nextNotify; i < UD_FS_NUMSERVERFILEOPEN; i++)
    {
        if (staticData->files[i].fid != CS_ILLEGALID && staticData->files[i].notifyPending)
        {
            staticData->nextNotify = i + 1;
            return &staticData->files[i];
        }
    }

    staticData->nextNotify = UD_FS_NUMSERVERFILEOPEN;
    return NULL;
}

#ifdef UD_NQ_INCLUDEEVENTLOG

static const NQ_TCHAR questionMark[] = {cmTChar('?'), 0};

/*====================================================================
 * PURPOSE: Read share connection entries
 *--------------------------------------------------------------------
 * PARAMS:  IN buffer capacity
 *          OUT buffer pointer
 *
 * RETURNS: number of entries
 *
 * NOTES:
 *====================================================================
 */

NQ_COUNT
nqEnumerateConnectedShares (
    NQ_COUNT maxEntries,
    NQShareConnectionEntry* buffer
    )
{
    NQ_COUNT numEntries = 0;    /* function result */
    NQ_INT i;                   /* index in files */

    for (i = 0; numEntries < maxEntries && i < UD_FS_NUMSERVERTREES; i++)
    {
        if (staticData->trees[i].tid != (CSTid)CS_ILLEGALID)
        {
            const CSUser* pUser = csGetUserByUid(staticData->trees[i].uid);

            cmTStrncpy(
                buffer->userName,
                NULL == pUser? questionMark : pUser->name,
                sizeof(buffer->userName) / sizeof(NQ_TCHAR)
                );
            cmTStrncpy(
                buffer->shareName,
                staticData->trees[i].share->name,
                sizeof(buffer->shareName) / sizeof(NQ_TCHAR)
                );
            if (NULL == pUser)
            {
                syMemset(&buffer->ip, 0, sizeof(buffer->ip));
            }
            else
            {
                syMemcpy(&buffer->ip, pUser->ip, sizeof(buffer->ip));
            }
            buffer->ipc = staticData->trees[i].share->ipcFlag;
            buffer->printQueue = staticData->trees[i].share->isPrintQueue;
            numEntries++;
            buffer++;
        }
    }
    return numEntries;
}

/*====================================================================
 * PURPOSE: Read open file entries
 *--------------------------------------------------------------------
 * PARAMS:  IN buffer capacity
 *          OUT buffer pointer
 *
 * RETURNS: number of entries
 *
 * NOTES:
 *====================================================================
 */

NQ_COUNT
nqEnumerateOpenFiles (
    NQ_COUNT maxEntries,
    NQOpenFileEntry* buffer
    )
{
    NQ_COUNT numEntries = 0;    /* function result */
    NQ_INT i;                   /* index in files */

    syMutexTake(&staticData->dbGuard);

    for (i = 0; numEntries < maxEntries && i < UD_FS_NUMSERVERFILEOPEN; i++)
    {
        if (staticData->files[i].fid != (CSFid)CS_ILLEGALID)
        {
            const CSUser* pUser = csGetUserByUid(staticData->files[i].uid);

            cmTStrncpy(
                buffer->fileName,
                staticData->names[staticData->files[i].nid].name,
                sizeof(buffer->fileName) / sizeof(NQ_TCHAR)
                );
            cmTStrncpy(
                buffer->userName,
                NULL == pUser? questionMark : pUser->name,
                sizeof(buffer->userName) / sizeof(NQ_TCHAR)
                );
            cmTStrncpy(
                buffer->shareName,
                staticData->trees[staticData->files[i].tid].share->name,
                sizeof(buffer->shareName) / sizeof(NQ_TCHAR)
                );
            if (NULL == pUser)
            {
                syMemset(&buffer->ip, 0, sizeof(buffer->ip));
            }
            else
            {
                syMemcpy(&buffer->ip, pUser->ip, sizeof(buffer->ip));
            }
            buffer->access = staticData->files[i].access;
            numEntries++;
            buffer++;
        }
    }

    syMutexGive(&staticData->dbGuard);
	
    return numEntries;
}

#endif /* UD_NQ_INCLUDEEVENTLOG */

/*====================================================================
 * PURPOSE: Printout the current database state
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: None
 *
 * NOTES:
 *====================================================================
 */

#if SY_DEBUGMODE

void
csDumpDatabase(
    void
    )
{
    NQ_INT i;

    syPrintf("\n======== Database Dump ============\n\n");
    syPrintf(" List of connected clients\n");
    for (i=0; i < UD_FS_NUMSERVERSESSIONS; i++)
    {
        syPrintf("Key: %ld\n", staticData->sessions[i].key);
    }
    syPrintf(" List of logged users\n");
    for (i=0; i < UD_FS_NUMSERVERUSERS; i++)
    {
        syPrintf("Uid: %d, session: %ld\n", staticData->users[i].uid, staticData->users[i].session);
    }
    syPrintf(" List of tree connections\n");
    for (i=0; i < UD_FS_NUMSERVERTREES; i++)
    {
        syPrintf("Tid: %d, session: %ld, uid: %d, share: %p\n", staticData->trees[i].tid, staticData->trees[i].session, staticData->trees[i].uid, (void *) staticData->trees[i].share);
    }
    syPrintf(" List of unique files\n");
    for (i=0; i < UD_FS_NUMSERVERFILENAMES; i++)
    {
        syPrintf("Nid: %d, name: %s, first: %p\n", staticData->names[i].nid, cmTDump(staticData->names[i].name), (void *) staticData->names[i].first);
    }
    syPrintf(" List of opened files\n");
    for (i=0; i < UD_FS_NUMSERVERFILEOPEN; i++)
    {
        syPrintf("fid: %d, nid: %d, tid: %d nxt: %p, pr: %p, ntfy: %d, pid: %ld\n", staticData->files[i].fid, staticData->files[i].nid, staticData->files[i].tid, (void *) staticData->files[i].next, (void *) staticData->files[i].prev, staticData->files[i].notifyPending, staticData->files[i].pid);
    }
    syPrintf(" List of active search operations\n");
    for (i=0; i < UD_FS_NUMSERVERSEARCHES; i++)
    {
        syPrintf("Sid: %d, session: %ld, tid: %d\n", staticData->searches[i].sid, staticData->searches[i].session, staticData->searches[i].tid);
    }
    syPrintf(" List of shares\n");
    for (i = 0; i < UD_FS_NUMSERVERSHARES; i++)
    {
        syPrintf("Addr: %p, Name: %s, ", (void *) &staticData->shares[i], cmTDump(staticData->shares[i].name));
        syPrintf("path: %s, ", cmTDump(staticData->shares[i].map));
        syPrintf("description: %s, ipc: %d\n", cmTDump(staticData->shares[i].description), staticData->shares[i].ipcFlag);
    }

    syPrintf("======== End ============\n\n");
}

#endif /* SY_DEBUGMODE */

#ifdef UD_NQ_INCLUDESMB2
const CMUuid *cs2GetServerUuid(void)
{
    return &staticData->uuid;
}

const CMTime *cs2GetServerStartTime(void)
{
    return &staticData->serverStartTime;
}
#endif /* UD_NQ_INCLUDESMB2 */

/*====================================================================
 * PURPOSE: Close user's existing connections to NQ server
 *--------------------------------------------------------------------
 * PARAMS:  IN user name
 *          IN domain/local user
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:
 *====================================================================
 */
NQ_STATUS
nqCleanUserServerConnections(
    const NQ_TCHAR *name,
    NQ_BOOL isDomainUser
    )
{
    NQ_INT i; 
    NQ_STATUS result = NQ_FAIL;

    /* find all user slots by user name and user type (domain or local), 
       release user and optionally disconnect if there are no more users within the session */
    for (i = 0; i < UD_FS_NUMSERVERUSERS; i++)
    {
        if (   staticData->users[i].uid != CS_ILLEGALID
            && 0 == cmTStrcmp(staticData->users[i].name, name)
            && isDomainUser == staticData->users[i].isDomainUser
            && !staticData->users[i].isAnonymous
           )
       {
            csReleaseUserAndDisconnect(staticData->users[i].uid , FALSE);
            result = NQ_SUCCESS;
       }
    }
    return result;
}

#ifdef UD_CS_MESSAGESIGNINGPOLICY

NQ_BOOL
csIsMessageSigningEnabled(
  )
{
    return staticData->signingEnabled;
}


NQ_BOOL
csIsMessageSigningRequired(
  )
{
    return staticData->signingRequired;
}

void
csSetMessageSigningRequired(
		NQ_BOOL isTRUE
		)
{
	staticData->signingRequired = isTRUE;
}

void
csSetMessageSigningEnabled(
		NQ_BOOL isTRUE
  )
{
    staticData->signingEnabled = isTRUE;
}

void
csSetMessageSigningPolicy(
		NQ_INT newPolicy
		)
{
	switch (newPolicy)
	{
	case (0):
			csSetMessageSigningEnabled(FALSE);
			csSetMessageSigningRequired(FALSE);
			break;
	case (1):
			csSetMessageSigningEnabled(TRUE);
			csSetMessageSigningRequired(FALSE);
			break;
	case (2):
			csSetMessageSigningEnabled(TRUE);
			csSetMessageSigningRequired(TRUE);
			break;
	}
}
#endif

NQ_UINT32
csGetUserRid(
    const CSUser * pUser
    )
{
	return pUser->rid;
}


#endif /* UD_NQ_INCLUDECIFSSERVER */

