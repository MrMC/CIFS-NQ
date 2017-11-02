/*********************************************************************
 *
 *           Copyright (c) 2008 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : SMB2 Notify and Cancel command handlers
 *--------------------------------------------------------------------
 * MODULE        : CS2
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 04-Jan-2009
 ********************************************************************/

#include "csparams.h"
#include "csutils.h"
#include "csdcerpc.h"
#include "cs2disp.h"
#include "cmsmb2.h"

#if defined(UD_NQ_INCLUDECIFSSERVER) && defined(UD_NQ_INCLUDESMB2)

/*
    Static functions and data
    -------------------------
 */

#define FLAGS_RECURSIVE 1

typedef struct
{
    NQ_BYTE notifyResponse[CM_NB_DATAGRAMBUFFERSIZE - sizeof(CMCifsHeader)];/* buffer for notify reponse */
    CMBufferWriter writer;                   /* for packing file entries */
    NQ_BOOL commonFieldsSet;                 /* singleton flag for setting up common fields */
    NQ_TCHAR notifyPath[UD_FS_FILENAMELEN + 1];  /* full path to the directory to notify */
    NQ_BOOL pathSet;                         /* singleton flag for seting up the path */
    NQ_UINT32 completionFilter;              /* value to match the request (the same for all entries) */
    NQ_BOOL notifyPending;                   /* TRUE when notofy information is ready to be sent */
    NQ_BYTE * bufferStart;                   /* pointer to the start of file entries */ 
    NQ_BYTE * nextEntryOffset;               /* pointer to the next entry offset field */
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
cs2NotifyInit(
    void
    )
{
    LOGFB(CM_TRC_LEVEL_FUNC_TOOL);

    /* allocate memory */
#ifdef SY_FORCEALLOCATION
    staticData = (StaticData *)syCalloc(1, sizeof(*staticData));
    if (NULL == staticData)
    {
        TRCE();
        return NQ_FAIL;
    }
#endif /* SY_FORCEALLOCATION */

    staticData->commonFieldsSet = FALSE;
    staticData->pathSet = FALSE;
    staticData->notifyPending = FALSE;

    LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
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
cs2NotifyExit(
    void
    )
{
    LOGFB(CM_TRC_LEVEL_FUNC_TOOL);

    /* release memory */
#ifdef SY_FORCEALLOCATION
    if (NULL != staticData)
        syFree(staticData);
    staticData = NULL;
#endif /* SY_FORCEALLOCATION */

    LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
}

/*====================================================================
 * PURPOSE: Perform Notify processing
 *--------------------------------------------------------------------
 * PARAMS:  IN in - pointer to the parsed SMB2 header descriptor
 *          OUT out - pointer to the response header structure
 *          IN reader - request reader pointing to the second command field
 *          IN connection - pointer to the session structure
 *          IN user - pointer to the user structure
 *          IN tree - pointer to the tree structure
 *          OUT writer - pointer to the response writer
 *
 * RETURNS: 0 on success or error code in NT format
 *
 * NOTES:   This function is called on SMB2 Create command.
 *====================================================================
 */

NQ_UINT32 csSmb2OnChangeNotify(CMSmb2Header *in, CMSmb2Header *out, CMBufferReader *reader, CSSession *connection, CSUser *user, CSTree *tree, CMBufferWriter *writer)
{
    CSFile * pFile;                 /* pointer to file descriptor */
    CSFid fid;                      /* required FID */
    NQ_UINT32 completionFilter;     /* completion filter */
    NQ_UINT16 flags;                /* notify flags */
    NQ_UINT32 bufferLength;         /* outout buffer length */

    LOGFB(CM_TRC_LEVEL_FUNC_TOOL);

    /* parse request */

    cmBufferReadUint16(reader, &flags);
    cmBufferReadUint32(reader, &bufferLength);
    cmBufferReadUint16(reader, &fid);
    cs2ParseFid(&fid);
    cmBufferReaderSkip(reader, 14); /* rest of fid area */
    cmBufferReadUint32(reader, &completionFilter);

    /* disable for NT */
    if (user == NULL || !user->supportsNotify)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "We do not support Notify for Windows NT clients");
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
        return SMB_STATUS_NOT_SUPPORTED;
    }

    /* start with the open file */
    pFile = csGetFileByFid(fid, tree->tid, user->uid);
    if (pFile == NULL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Illegal FID: 0x%x", fid);
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
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

    /* we send interim response now */
    out->flags |= SMB2_FLAG_ASYNC_COMMAND;
    cs2GenerateNextAsyncId(&out->aid);

    /* write request information into the file descriptor */
    cs2DispatchSaveResponseContext(&pFile->notifyContext, out);
    pFile->notifyPending = TRUE;
    pFile->notifyFilter = completionFilter;
    pFile->notifyTree = flags & FLAGS_RECURSIVE;
    pFile->notifyAid = out->aid;

    LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
    return SMB_STATUS_PENDING;
}

/*====================================================================
 * PURPOSE: Perform Cancel processing
 *--------------------------------------------------------------------
 * PARAMS:  IN in - pointer to the parsed SMB2 header descriptor
 *          OUT out - pointer to the response header structure
 *          IN reader - request reader pointing to the second command field
 *          IN connection - pointer to the session structure
 *          IN user - pointer to the user structure
 *          IN tree - pointer to the tree structure
 *          OUT writer - pointer to the response writer
 *
 * RETURNS: 0 on success or error code in NT format
 *
 * NOTES:   This function is called on SMB2 Create command.
 *====================================================================
 */

NQ_UINT32 csSmb2OnCancel(CMSmb2Header *in, CMSmb2Header *out, CMBufferReader *reader, CSSession *connection, CSUser *user, CSTree *tree, CMBufferWriter *writer)
{
    CSFile* pFile;                  /* file name pointer (notify request) */
    
    LOGFB(CM_TRC_LEVEL_FUNC_TOOL);

    /* look for a pending notify request */
    pFile = cs2GetFileByContext(in->aid, user->uid);
    if (pFile != NULL)
    {
        /* cancel pending notify */
        pFile->notifyPending = FALSE;
        out->mid = pFile->notifyContext.prot.smb2.mid;
        out->command = SMB2_CMD_CHANGENOTIFY;     /* simulate NOTIFY response */
    }
    
    LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
    return SMB_STATUS_CANCELLED;
}


/*====================================================================
 * PURPOSE: Initalize the list of notify
 *--------------------------------------------------------------------
 * PARAMS:  IN completion filter as required by CIFS
 *
 * RETURNS: None (errors are ignored)
 *
 * NOTES:   the action will be used to match with the completion filter
 *          of requests.
 *====================================================================
 */

void
cs2NotifyStart(
    NQ_UINT32 filter
    )
{
    LOGFB(CM_TRC_LEVEL_FUNC_TOOL);

    staticData->completionFilter = filter;
    staticData->pathSet = FALSE;
    staticData->notifyPending = FALSE;

    /* set writer */
    cmBufferWriterInit(&staticData->writer, staticData->notifyResponse, UD_NS_BUFFERSIZE - SMB2_HEADERSIZE);
    
    /* write common fields */
    cmBufferWriteUint16(&staticData->writer, 9);    /* structure size */
    cmBufferWriteUint16(&staticData->writer, SMB2_HEADERSIZE + 4 + 2 * 2);  /* buffer offset */
    cmBufferWriteUint32(&staticData->writer, 0);    /* buffer length */
    cmBufferWriteByte(&staticData->writer, 0xff);   /* error data */
    staticData->bufferStart = cmBufferWriterGetPosition(&staticData->writer);

    /* mark first entry */
    staticData->nextEntryOffset = NULL;

    LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
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

void
cs2NotifyEnd(
    void
    )
{
}

/*====================================================================
 * PURPOSE: Prepare notification on one file, do not send so far
 *--------------------------------------------------------------------
 * PARAMS:  IN file name
 *          IN action taken
 *          IN FALSE to notify thsi file, TRUE to notify its parent folder
 *
 * RETURNS: None (errors are ignored)
 *
 * NOTES:
 *====================================================================
 */

void
cs2NotifyFile(
    const NQ_TCHAR* fileName,
    NQ_UINT32 action,
    NQ_BOOL notifyParent        
    )
{
    LOGFB(CM_TRC_LEVEL_FUNC_TOOL);

    staticData->notifyPending = TRUE;

    /* set notify directory name for the first time */
    if (!staticData->pathSet)
    {
        NQ_TCHAR* pSeparator;

        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "NOTIFY: %s", cmTDump(fileName));
        staticData->pathSet = TRUE;
        cmTStrncpy(staticData->notifyPath, fileName, sizeof(staticData->notifyPath)/sizeof(NQ_TCHAR));
        if (notifyParent)
        {
            pSeparator = cmTStrrchr(staticData->notifyPath, cmTChar(SY_PATHSEPARATOR));
            if (pSeparator == NULL)
            {
                LOGERR(CM_TRC_LEVEL_ERROR, "Illegal path %s", cmTDump(staticData->notifyPath));
            }
            else
            {
                *pSeparator = (NQ_TCHAR)0;
            }
        }
        staticData->action = action;
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "PATH: %s", cmTDump(staticData->notifyPath));
    }
    
    LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
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

void
cs2NotifySend(
    void
    )
{
    CSFile* nextDir;        /* open directory descriptor */
    CSName* pName;          /* descriptor of this directory's file */
    NQ_COUNT dataLen;       /* number of bytes to send */
    NQ_BYTE * savedPtr;     /* saved pointer in the writer */
    NSSocketHandle savedSocket; /* saved socket */

    LOGFB(CM_TRC_LEVEL_FUNC_TOOL);

    if (!staticData->notifyPending)
    {
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
        return;
    }

    /* finalize Notify response */
    savedPtr = cmBufferWriterGetPosition(&staticData->writer);
    cmBufferWriterInit(&staticData->writer, staticData->notifyResponse, UD_NS_BUFFERSIZE - SMB2_HEADERSIZE);
    cmBufferWriterSkip(&staticData->writer, 2 * 2);    /* structure size + buffer offset */
    cmBufferWriteUint32(&staticData->writer, (NQ_UINT32)(savedPtr - staticData->bufferStart));    /* buffer length */
    dataLen = (NQ_COUNT)(savedPtr - staticData->notifyResponse - 4);
    
    /* mark first entry */
    staticData->nextEntryOffset = NULL;

    /* save socket */
    savedSocket = csDispatchGetSocket();

    csStartNotifyRequestSearch();
    while ((nextDir = csEnumerateNotifyRequest()) != NULL)
    {
        CSSession * pSess;                /* to distinguish between SMB1 and SMB2 */

        pName = csGetNameByNid(nextDir->nid);
        if (pName == NULL)
        {
            TRCERR("Internal error: name not found for an opened file");
            TRC1P(" nid: %d", nextDir->nid);
            break;
        }

        /* match the directory with the notify path */

        if (cmTStrncmp(staticData->notifyPath, pName->name, cmTStrlen(pName->name)) != 0)
        {
            /* the directory name does not match the notify path or its beginning */
            continue;
        }

        if (cmTStrlen(staticData->notifyPath) > cmTStrlen(pName->name))
        {
            /* directory is above the notify path in the tree */

            if (!nextDir->notifyTree)
            {
                /* tree traversing was not requested for this directory */
                continue;
            }

            if (*(staticData->notifyPath + cmTStrlen(pName->name)) != cmTChar(SY_PATHSEPARATOR))
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

        pSess = csGetSessionById(nextDir->session);
        if (NULL != pSess && pSess->smb2)
        {
            csDispatchSetSocket(nextDir->notifyContext.socket);
            cs2DispatchPrepareLateResponse(
                &nextDir->notifyContext, 
                ((staticData->action & SMB_NOTIFYCHANGE_ACTIONMASK) == SMB_NOTIFYCHANGE_REMOVED)? SMB_STATUS_DELETE_PENDING : SMB_STATUS_ENUMDIR
                );
            syMemcpy(nextDir->notifyContext.commandData, staticData->notifyResponse, dataLen);
            if (!cs2DispatchSendLateResponse(&nextDir->notifyContext, dataLen))
            {
                TRCERR("Error sending NOTIFY CHANGE response");
            }
            /* clear notify request */
            nextDir->notifyPending = FALSE;
        }
    }

    /* restore socket */
    csDispatchSetSocket(savedSocket);

    staticData->notifyPending = FALSE;
    staticData->nextEntryOffset = NULL;

    LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
}

#endif /* defined(UD_NQ_INCLUDECIFSSERVER) && defined(UD_NQ_INCLUDESMB2) */

