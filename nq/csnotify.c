/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Implementation of the NOTIFY CHANGE mechanism
 *--------------------------------------------------------------------
 * MODULE        : CS - CIFS Server
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 21-August-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "csnotify.h"
#include "csdispat.h"
#include "csnttran.h"
#include "csdataba.h"
#include "csparams.h"
#ifdef UD_NQ_INCLUDESMB2
#include "cs2notify.h"
#endif /* UD_NQ_INCLUDESMB2 */


#ifdef UD_NQ_INCLUDECIFSSERVER

/* NOTIFY_CHANGE consists of the following:
    1) NT_TRANSACTION subcommand NOTIFY_CHANGE  - csNtTransactionNotifyChange
        places a notify request (identified by MID)
    2) CIFS command NT_CANCEL                   - csComNtCancel()
        cancels the notify request with the same MID (if any)
    3) notification functions:
    - csNotifyImmediatelly()
    These functions identify a relevant notify request, compose and send a response.

    Notification is always for the results of the current CIFS command and it never crosses
    a one command boundary. This means, in particular, that NT_CANCEL always cancels a
    notification and never "hurries it up". All notified files are expected to reside in the
    same directory.
 */

/*
    Static functions and data
    -------------------------
 */

typedef struct
{
    NQ_BYTE notifyResponse[CM_NB_DATAGRAMBUFFERSIZE - sizeof(CMCifsHeader)];/* buffer for notify response */
    NQ_BYTE* pFirstFileInfo;                 /* pointer in this buffer to the first file
                                                   information structure */
    NQ_BYTE* pNextFileInfo;                  /* pointer in this buffer to the next file
                                                   information structure */
    NQ_BYTE* pPrevFileInfo;                  /* pointer in this buffer to the previous file
                                                   information structure */
    NQ_BOOL headerSet;                       /* singleton flag for setting up the response header */
    NQ_WCHAR notifyPath[UD_FS_FILENAMELEN + 1];  /* full path to the directory to notify */
    NQ_BOOL pathSet;                         /* singleton flag for setting up the path */
    NQ_UINT32 completionFilter;              /* value to match the request (the same for all entries) */
    NQ_BOOL notifyPending;                   /* TRUE when notify information is ready to be sent */
    NQ_UINT32 action;                        /* action to notify */
}
StaticData;

#ifdef SY_FORCEALLOCATION
static StaticData* staticData = NULL;
#else  /* SY_FORCEALLOCATION */
static StaticData staticDataSrc;
static StaticData* staticData = &staticDataSrc;
#endif /* SY_FORCEALLOCATION */

/*====================================================================
 * PURPOSE: initialize resources
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:
 *====================================================================
 */

NQ_STATUS
csNotifyInit(
    void
    )
{
    TRCB();

    /* allocate memory */
#ifdef SY_FORCEALLOCATION
    staticData = (StaticData *)syMalloc(sizeof(*staticData));
    if (NULL == staticData)
    {
        TRCE();
        return NQ_FAIL;
    }
#endif /* SY_FORCEALLOCATION */

    staticData->headerSet = FALSE;
    staticData->pathSet = FALSE;
    staticData->notifyPending = FALSE;

#ifdef UD_NQ_INCLUDESMB2
    if (NQ_SUCCESS != cs2NotifyInit())
        return NQ_FAIL;
#endif
    TRCE();
    return NQ_SUCCESS;
}

/*====================================================================
 * PURPOSE: release resources
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: None
 *
 * NOTES:
 *====================================================================
 */

void
csNotifyExit(
    void
    )
{
    TRCB();

    /* release memory */
#ifdef SY_FORCEALLOCATION
    if (NULL != staticData)
        syFree(staticData);
    staticData = NULL;
#endif /* SY_FORCEALLOCATION */

#ifdef UD_NQ_INCLUDESMB2
    cs2NotifyExit();
#endif
    TRCE();
}

/*====================================================================
 * PURPOSE: Perform NT_CANCEL command
 *--------------------------------------------------------------------
 * PARAMS:  IN pointer to the command in the message
 *          IN header of the outgoing message
 *          IN/OUT double pointer to the response
 *
 * RETURNS: 0 on success or error code in NT format
 *
 * NOTES:   Function cancels a pending NOTIFY_CHANGE request
 *          Inconsistent CANCEL requests may come from different Windows versions.
 *          For instance: some NT versions issue multiple notify requests for the same directory.
 *          Therefore, we send a positive response even if there is no pending notify request.
 *====================================================================
 */

NQ_UINT32
csComNtCancel(
    NQ_BYTE* pRequest,
    CMCifsHeader* pHeaderOut,
    NQ_BYTE** pResponse
    )
{
    CSFile* pFile;                  /* file name pointer (notify request) */
    CSUid uid;                      /* required UID */
    CSTid tid;                      /* required TID */    
    CSPid pid;                      /* required PID */
    CSMid mid;                      /* required MID */
    const NQ_BYTE errorResponse[] = {0, 0, 0};  /* word count + byte count */
    NQ_COUNT dataLen;               /* length of the response */
#ifdef UD_CS_MESSAGESIGNINGPOLICY
    CSSession * pSession;           /* current session */
#endif /* UD_CS_MESSAGESIGNINGPOLICY */

    TRCB();

    /* look for a pending notify request */

    uid = cmLtoh16(cmGetSUint16(pHeaderOut->uid));
    tid = cmLtoh16(cmGetSUint16(pHeaderOut->tid));
    pid = cmLtoh16(cmGetSUint16(pHeaderOut->pid));
    mid = cmLtoh16(cmGetSUint16(pHeaderOut->mid));
    pFile = csGetFileByContext(pid, mid, tid, uid);
    if (pFile != NULL)
    {
        pFile->notifyPending = FALSE;
        csDispatchPrepareLateResponse(&pFile->notifyContext);
        dataLen = sizeof(errorResponse);
        syMemcpy(pFile->notifyContext.commandData, errorResponse, dataLen);

        if (!csDispatchSendLateResponse(&pFile->notifyContext, SMB_STATUS_CANCELLED, dataLen))
        {
            TRCERR("Error sending NOTIFY CHANGE response");
        }
    }

#ifdef UD_CS_MESSAGESIGNINGPOLICY
    pSession = csGetSessionBySocket();

    if (NULL != pSession)
    {
        pSession->sequenceNum -= 1; 
    }
#endif /* UD_CS_MESSAGESIGNINGPOLICY */

    TRCE();
    return csErrorReturn(SMB_STATUS_NORESPONSE, 0);
}

/*====================================================================
 * PURPOSE: Perform NT_TRANSACT_NOTIFY_CHANGE subcommand of
 *          NT_TRANSACTION protocol
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT structure with subcommand parameters:
 *              IN pointer to the CIFS header
 *              IN pointer to the parameter area
 *              OUT pointer to the data area
 *              OUT length of the parameter area
 *              OUT length of the data area
 *
 * RETURNS: SMB error or 0 on success
 *
 * NOTES:
 *====================================================================
 */

NQ_UINT32
csNtTransactionNotifyChange(
    CSNtTransactionDescriptor* descriptor
    )
{
    CMCifsNtTransactionNotifyRequest* notifyRequest;    /* casted request */
    CMCifsStatus error;             /* for composing DOS-style error */
    CSFile* pFile;                  /* pointer to file descriptor */
    CSFid fid;                      /* required FID */
    CSUid uid;                      /* required UID */
    CSTid tid;                      /* required TID */
    CSUser *pUser;                  /* pointer to user structure */

    TRCB(); 

    /* cast pointers */
    notifyRequest = (CMCifsNtTransactionNotifyRequest*) ((NQ_BYTE*)(descriptor->requestData + 1) - 2);

    fid = cmLtoh16(cmGetSUint16(notifyRequest->fid));
    uid = cmLtoh16(cmGetSUint16(descriptor->pHeaderOut->uid));
    tid = cmLtoh16(cmGetSUint16(descriptor->pHeaderOut->tid));

    /* disable for NT */
    if ((pUser = csGetUserByUid(uid)) == NULL || !pUser->supportsNotify)
    {
        TRCERR("We do not support Notify for Windows NT clients");
        TRCE();
        return csErrorReturn(SMB_STATUS_NOT_SUPPORTED, (NQ_UINT32)SRV_ERRnosupport);
    }

    /* start with the open file */
    pFile = csGetFileByFid(fid, tid, uid);
    if (pFile == NULL)
    {
        TRCERR("Illegal FID");
        TRC1P("  value %d", fid);
        TRCE();
        return csErrorReturn(SMB_STATUS_INVALID_HANDLE, DOS_ERRbadfid);
    }

    {
        CSName* pName;          /* pointer to the file name descriptor */

        pName = csGetNameByNid(pFile->nid);
        if (pName == NULL)
        {
            TRCE();
            return csErrorReturn(SMB_STATUS_UNSUCCESSFUL, SRV_ERRerror);
        }
        if (pName->markedForDeletion)
        {
            TRCE();
            return csErrorReturn(SMB_STATUS_DELETE_PENDING, DOS_ERRbadfid);
        }
    }

    /* write request information into the file descriptor */

    csDispatchSaveResponseContext(&pFile->notifyContext);
    pFile->notifyPending = TRUE;
    pFile->notifyFilter = cmLtoh32(cmGetSUint32(notifyRequest->completionFilter));
    pFile->notifyTree = notifyRequest->watchTree;

    /* set up the response header for the first time */

    if (!staticData->headerSet)
    {
        CMCifsNtTransactionResponse* ntResponse;    /* pointer to NT Tran structure in the
                                                       response */
        staticData->headerSet = TRUE;

        /* prepare NT TRANSACT response */

        ntResponse = (CMCifsNtTransactionResponse*)staticData->notifyResponse;
        staticData->pFirstFileInfo = (NQ_BYTE*)(ntResponse + 1);
        staticData->pFirstFileInfo = cmAllignTwo(staticData->pFirstFileInfo);
        ntResponse->wordCount = SMB_NTTRANSACTION_RESPONSE_WORDCOUNT;
        cmPutSUint32(ntResponse->totalDataCount, 0);
        cmPutSUint32(
            ntResponse->parameterOffset,
            cmHtol32((NQ_UINT32)(staticData->pFirstFileInfo - (NQ_BYTE*)staticData->notifyResponse) + (NQ_UINT32)sizeof(CMCifsHeader))
            );
        cmPutSUint32(ntResponse->parameterDisplacement, 0);
        cmPutSUint32(ntResponse->dataCount, 0);
        cmPutSUint32(ntResponse->dataDisplacement, 0);
        ntResponse->setupCount = 0;
        *(NQ_BYTE*)(ntResponse + 1) = 3;    /* undocumented feature - should be this value */
    }

    /* we do not respond on this request right now */

    descriptor->parameterCount = 0;
    descriptor->dataCount = 0;
    error = SMB_STATUS_NORESPONSE;      /* do not respond */

    TRCE();
    return error;
}

/*====================================================================
 * PURPOSE: Initialize the list of notify
 *--------------------------------------------------------------------
 * PARAMS:  IN completion filter as required by CIFS
 *
 * RETURNS: None (errors are ignored)
 *
 * NOTES:   the action will be used to match with the completion filter
 *          of requests.
 *====================================================================
 */

static void
csNotifyStart(
    NQ_UINT32 filter
    )
{
    TRCB();

    staticData->completionFilter = filter;
    staticData->pathSet = FALSE;
    staticData->pNextFileInfo = staticData->pFirstFileInfo;
    staticData->pPrevFileInfo = NULL;
    staticData->notifyPending = FALSE;
#ifdef UD_NQ_INCLUDESMB2
    cs2NotifyStart(filter);
#endif

    TRCE();
}

/*====================================================================
 * PURPOSE: Close notification list and send notification
 *--------------------------------------------------------------------
 * PARAMS:  IN action taken as required by CIFS
 *
 * RETURNS: None (errors are ignored)
 *
 * NOTES:   the action will be used to match with the completion filter
 *          of requests.
 *====================================================================
 */

static void
csNotifyEnd(
    void
    )
{
#ifdef UD_NQ_INCLUDESMB2
    cs2NotifyEnd();
#endif
/*    csNotifysendNotify(); */
}

/*====================================================================
 * PURPOSE: Prepare notification on one file, do not send so far
 *--------------------------------------------------------------------
 * PARAMS:  IN file name
 *          IN action taken
 *          IN FALSE to notify this file, TRUE to notify its parent folder
 *
 * RETURNS: None (errors are ignored)
 *
 * NOTES:
 *====================================================================
 */

static void
csNotifyFile(
    const NQ_WCHAR* fileName,
    NQ_UINT32 action,
    NQ_BOOL notifyParent
    )
{
    TRCB();

    staticData->notifyPending = TRUE;

    /* set notify directory name for the first time */

    if (!staticData->pathSet)
    {
        NQ_WCHAR* pSeparator;

        staticData->pathSet = TRUE;
        syWStrncpy(staticData->notifyPath, fileName, sizeof(staticData->notifyPath)/sizeof(NQ_WCHAR));
        if (notifyParent)
        {
            pSeparator = syWStrrchr(staticData->notifyPath, cmWChar(SY_PATHSEPARATOR));
            if (pSeparator == NULL)
            {
                TRCERR("Illegal path");
                TRC1P("  path %s", cmWDump(staticData->notifyPath));
            }
            else
            {
                *pSeparator = (NQ_WCHAR)0;
            }
        }
        staticData->action = action;
    }

#ifdef UD_NQ_INCLUDESMB2
    cs2NotifyFile(fileName, action, notifyParent);
#endif
    /* Windows tends to crash the explorer on a formally valid NOTIFY CHANGE response with
       file information set. Therefore, we use instead an "enumerate directory" response
       with an empty NOTIFY CHANGE structure. The "proper" code below is saved for future use.
       */
#if 0
    /* calculate length of the file info and check space in the buffer */

    pFileName = cmStrrchr(fileName, cmWChar(SY_PATHSEPARATOR));
    if (pFileName == NULL)
    {
        pFileName = fileName;
    }
    else
    {
        pFileName++;
    }
    nameLen = sizeof(NQ_WCHAR) * cmStrlen(pFileName);
    infoLen = nameLen + sizeof(*pFileInfo);
    if ((staticData->pNextFileInfo + infoLen) > (staticData->notifyResponse + sizeof(staticData->notifyResponse)))
    {
        sendNotify();
    }

    pFileInfo = (CMCifsNtTransactionFileNotify*)staticData->pNextFileInfo;

    pFileInfo->nextEntryOffset = cmHtol32(infoLen);
    pFileInfo->action = action;
    pFileInfo->fileNameLength = cmHtol32(nameLen);
    cmToUnicode((NQ_WCHAR*)(pFileInfo + 1), pFileName);

    staticData->pPrevFileInfo = staticData->pNextFileInfo;
    staticData->pNextFileInfo += infoLen;
#endif

    TRCE();
}

/*====================================================================
 * PURPOSE: Send notification info gathered so far
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: None (errors are ignored)
 *
 * NOTES:   scan all directories with notify request and match directory as a
 *          a part of the notify path.
 *====================================================================
 */

static void
csNotifySend(
    void
    )
{
    CSFile* nextDir;        /* open directory descriptor */
    CSName* pName;          /* descriptor of this directory's file */
    NQ_COUNT dataLen;       /* number of bytes to send */
    CMCifsNtTransactionFileNotify* pFileInfo;   /* casted pointer to the last file info */
    NSSocketHandle savedSocket; /* saved socket */

    TRCB();

#ifdef UD_NQ_INCLUDESMB2
    cs2NotifySend();
#endif /* UD_NQ_INCLUDESMB2 */

    if (!staticData->notifyPending)
    {
        TRCE();
        return;
    }

    /* fix NT_TRANSACT fields */

    if (staticData->pFirstFileInfo != NULL)
    {
        CMCifsNtTransactionResponse* ntResponse;    /* pointer to NT Tran structure in the
                                                       response */
        NQ_UINT16 byteCount;                        /* temporary ByteCount */

        ntResponse = (CMCifsNtTransactionResponse*) staticData->notifyResponse;
        cmPutSUint32(ntResponse->parameterCount, cmHtol32((NQ_UINT32)(staticData->pNextFileInfo - staticData->pFirstFileInfo)));
        cmPutSUint32(
            ntResponse->dataOffset,
            cmHtol32((NQ_UINT32)(staticData->pNextFileInfo - (NQ_BYTE*)staticData->notifyResponse) + (NQ_UINT32)sizeof(CMCifsHeader))
            );
        byteCount = (NQ_UINT16)(staticData->pNextFileInfo - (NQ_BYTE*)(ntResponse + 1));
        cmPutSUint16(ntResponse->byteCount, cmHtol16(byteCount));

        /* zero the offset in the last file info structure */

        pFileInfo = (CMCifsNtTransactionFileNotify*)staticData->pPrevFileInfo;
        if (pFileInfo != NULL)
        {
            cmPutSUint32(pFileInfo->nextEntryOffset, 0);
        }
    }

    /* save socket */
    savedSocket = csDispatchGetSocket();

    csStartNotifyRequestSearch();
    while ((nextDir = csEnumerateNotifyRequest()) != NULL)
    {
#ifdef UD_NQ_INCLUDESMB2
        CSSession * pSess;                /* to distinguish between SMB1 and SMB2 */
#endif /* UD_NQ_INCLUDESMB2 */

        pName = csGetNameByNid(nextDir->nid);
        if (pName == NULL)
        {
            TRCERR("Internal error: name not found for an opened file");
            TRC1P(" nid: %d", nextDir->nid);
            break;
        }

        /* match the directory with the notify path */

        if (syWStrncmp(staticData->notifyPath, pName->name, syWStrlen(pName->name)) != 0)
        {
            /* the directory name does not match the notify path or its beginning */
            continue;
        }

        if (syWStrlen(staticData->notifyPath) > syWStrlen(pName->name))
        {
            /* directory is above the notify path in the tree */

            if (!nextDir->notifyTree)
            {
                /* tree traversing was not requested for this directory */
                continue;
            }

            if (*(staticData->notifyPath + syWStrlen(pName->name)) != cmWChar(SY_PATHSEPARATOR))
            {
                /* directory is not an exact super-directory of the notify path */
                continue;
            }
        }

        /* match completion filter with the action taken */

#if 0
        if ((nextDir->notifyFilter & staticData->completionFilter) == 0)
        {
            /* was not requested */
            continue;
        }
#endif

        /* prepare and send the response */

#ifdef UD_NQ_INCLUDESMB2
        pSess = csGetSessionById(nextDir->session);
        if (NULL != pSess && pSess->dialect == CS_DIALECT_SMB1)
        {
#endif /* UD_NQ_INCLUDESMB2 */
            csDispatchSetSocket(nextDir->notifyContext.socket);
            csDispatchPrepareLateResponse(&nextDir->notifyContext);
            dataLen = (NQ_COUNT)(staticData->pNextFileInfo - staticData->notifyResponse);
            syMemcpy(nextDir->notifyContext.commandData, staticData->notifyResponse, dataLen);
            if (!csDispatchSendLateResponse(
                &nextDir->notifyContext, 
                ((staticData->action & SMB_NOTIFYCHANGE_ACTIONMASK) == SMB_NOTIFYCHANGE_REMOVED)? SMB_STATUS_DELETE_PENDING : 0, 
                dataLen)
               )
            {
                TRCERR("Error sending NOTIFY CHANGE response");
            }
            /* clear notify request */
            nextDir->notifyPending = FALSE;
#ifdef UD_NQ_INCLUDESMB2
        }
#endif /* UD_NQ_INCLUDESMB2 */

    }

    /* restore socket */
    csDispatchSetSocket(savedSocket);

    staticData->notifyPending = FALSE;
    staticData->pNextFileInfo = staticData->pFirstFileInfo;

    TRCE();
}

/*====================================================================
 * PURPOSE: Immediately notify a single file
 *--------------------------------------------------------------------
 * PARAMS:  IN file name
 *          IN action taken
 *          IN completion filter
 *
 * RETURNS: None (errors are ignored)
 *
 * NOTES:
 *====================================================================
 */

void
csNotifyImmediatelly(
    const NQ_WCHAR* fileName,
    NQ_UINT32 action,
    NQ_UINT32 filter
    )
{
    TRCB();

    csNotifyStart(filter);
    csNotifyFile(fileName, SMB_NOTIFYCHANGE_MODIFIED, TRUE);  /* notify parent folder */
    csNotifyEnd();
    csNotifySend();
    csNotifyStart(filter);
    csNotifyFile(fileName, action, FALSE);   /* notify this file */
    csNotifyEnd();
    csNotifySend();

    TRCE();
}

#endif /* UD_NQ_INCLUDECIFSSERVER */

