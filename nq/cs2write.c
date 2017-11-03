/*********************************************************************
 *
 *           Copyright (c) 2008 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : SMB2 Write command handler
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

#if defined(UD_NQ_INCLUDECIFSSERVER) && defined(UD_NQ_INCLUDESMB2)

/* 
 * Local functions and data
 * ------------------------
 */ 

static NQ_UINT32 dataCount;     /* number of bytes in WRITE */
static CSFile* pFile;           /* pointer to file descriptor */

#ifdef UD_CS_INCLUDERPC

/* saving late response for Write */
static void
lateResponseSave(
    CSLateResponseContext* context
    );

/* preparing late response for Write */
static NQ_BOOL
lateResponsePrepare(
    CSLateResponseContext* context
    );

/* sending late response for Write */
static NQ_BOOL
lateResponseSend(
    CSLateResponseContext* context,
    NQ_UINT32 status,
    NQ_COUNT dataLength
    );

#endif /* UD_CS_INCLUDERPC */

#define RESPONSE_LENGTH 16  /* length of the read response not including data */

/*====================================================================
 * PURPOSE: Perform Write processing
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

NQ_UINT32 csSmb2OnWrite(CMSmb2Header *in, CMSmb2Header *out, CMBufferReader *reader, CSSession *connection, CSUser *user, CSTree *tree, CMBufferWriter *writer)
{
    CSFid fid;                              /* fid of the file to close */
    NQ_UINT32 minCount;                     /* buffer length */
    NQ_UINT16 dataOffset;                   /* offset of the data portion from SMB2 start*/
    NQ_UINT64 offset;                       /* write offset */
    CMCifsStatus error;                     /* for composing DOS-style error */
    NQ_BYTE * pData;                        /* pointer to the buffer */
#ifdef UD_CS_FORCEINTERIMRESPONSES
    NQ_UINT32 asyncId = 0;                  /* generated Async ID */
#endif /* UD_CS_FORCEINTERIMRESPONSES */
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
    UDFileAccessEvent	eventInfo;
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL);

    /* parse request */
    cmBufferReadUint16(reader, &dataOffset);
    cmBufferReadUint32(reader, &dataCount);
    cmBufferReadUint64(reader, &offset);
    cmBufferReadUint16(reader, &fid);
    cs2ParseFid(&fid);
    cmBufferReaderSkip(reader, 14); /* the rest of the file ID */
    cmBufferReadUint32(reader, &minCount);
    pData = in->_start + dataOffset;
#ifndef UD_CS_INCLUDEDIRECTTRANSFER
    if (dataCount > (CIFS_MAX_DATA_SIZE - SMB2_HEADERSIZE - 16))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Buffer overflow: write length too big");
        LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
        return SMB_STATUS_INVALID_PARAMETER;
    }
#endif /* UD_CS_INCLUDEDIRECTTRANSFER */
    
    /* find file descriptor */
    pFile = csGetFileByFid(fid, tree->tid, user->uid);
    if (pFile == NULL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unknown FID");
        LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
        return SMB_STATUS_INVALID_HANDLE;
    }

    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "pFile:%p file:%d dataCount:%d offset:%d", pFile, pFile->file, dataCount, offset);

#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
    eventInfo.fileName = csGetFileName(pFile->fid);
    eventInfo.tid = tree->tid;
    eventInfo.rid = csGetUserRid(user);
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */

#ifdef UD_CS_INCLUDERPC
    if (pFile->isPipe)
    {
        NQ_UINT32 returnValue;  /* RPC return code */

#ifdef UD_CS_INCLUDEDIRECTTRANSFER
        /* discard possible DirectTransfer and read the payload */
        csDispatchDtDiscard();
#endif /* UD_CS_INCLUDEDIRECTTRANSFER */

        csDcerpcSetLateResponseCallbacks(
            lateResponseSave,
            lateResponsePrepare, 
            lateResponseSend
        );
        returnValue = csDcerpcWrite(
                pFile, 
                pData, 
                (NQ_UINT)dataCount, 
                FALSE 
                );
        if (returnValue != 0)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "error writing to pipe");
            LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
            return returnValue;
        }
    }
    else
#endif /* UD_CS_INCLUDERPC */
    {
#ifdef UD_CS_INCLUDERPC_SPOOLSS
        if (pFile->isPrint)
        {
            NQ_COUNT written;
            CSDcerpcResponseContext *rctx = NULL;
            void *p = NULL;

#ifdef UD_CS_INCLUDEDIRECTTRANSFER
            /* discard possible DirectTransfer and read the payload */
            csDispatchDtDiscard();
#endif /* UD_CS_INCLUDEDIRECTTRANSFER */

            csDcerpcSetLateResponseCallbacks(
                  lateResponseSave,
                  lateResponsePrepare, 
                  lateResponseSend
                  );
            written = (NQ_COUNT)syWritePrintData(pFile->printerHandle, (NQ_UINT32)pFile->file, pData, dataCount, &p);
            rctx = (CSDcerpcResponseContext *)p;
            if (written <= 0)
            {
                if (written == 0)
                {
                    /* 0 bytes written or response has to be delayed */
                    if (rctx != NULL)
                    {
                      /* response has to be delayed */
                        csDcerpcSaveResponseContext(FALSE, NULL, rctx);
                        TRCE();
                        return SMB_STATUS_NORESPONSE;
                    }
                }
                TRCERR("WRITE failed (syWritePrintData)");
                TRCE();
                return csErrorGetLast();
             }
        }
        else
#endif /* UD_CS_INCLUDERPC_SPOOLSS */       
        {
            /* send interim response */
#ifdef UD_CS_FORCEINTERIMRESPONSES
            asyncId = csSmb2SendInterimResponse(in);
            if (0 == asyncId)
            {
                LOGERR(CM_TRC_LEVEL_ERROR, "error sending interim write response");
                LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
                return SMB_STATUS_INVALID;
            }
            out->flags |= SMB2_FLAG_ASYNC_COMMAND;
            out->aid.low = asyncId;
            out->aid.high = 0;
            out->credits = 0;
#endif /* UD_CS_FORCEINTERIMRESPONSES */

            if (dataCount == 0)
            {
                /* truncate file */
                error = csTruncateFile(pFile, NULL, offset.low, offset.high);
                if (error != NQ_SUCCESS)
                {
                    LOGERR(CM_TRC_LEVEL_ERROR, "truncate failed");
                    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
                    return error;
                }
            }
            else
            {
                /* shift to the write position */
                if (pFile->offsetLow != offset.low || pFile->offsetHigh != offset.high)
                {
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
					eventInfo.offsetLow = offset.low;
					eventInfo.offsetHigh = offset.high;
					eventInfo.before = TRUE;
					udEventLog(
						UD_LOG_MODULE_CS,
						UD_LOG_CLASS_FILE,
						UD_LOG_FILE_SEEK,
						user->name,
						user->ip,
						0,
						(const NQ_BYTE*)&eventInfo
					);
					eventInfo.before = FALSE;
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */
                    if (sySeekFileStart(pFile->file, offset.low, offset.high) == (NQ_UINT32)NQ_FAIL)
                    {
                        error = csErrorGetLast();
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
						udEventLog(
							UD_LOG_MODULE_CS,
							UD_LOG_CLASS_FILE,
							UD_LOG_FILE_SEEK,
							user->name,
							user->ip,
							error,
							(const NQ_BYTE*)&eventInfo
						);
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */
                        LOGERR(CM_TRC_LEVEL_ERROR, "LSEEK failed");
                        LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
                        return error;
                    }
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
					udEventLog(
						UD_LOG_MODULE_CS,
						UD_LOG_CLASS_FILE,
						UD_LOG_FILE_SEEK,
						user->name,
						user->ip,
						0,
						(const NQ_BYTE*)&eventInfo
					);
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */
                    pFile->offsetLow = offset.low;
                    pFile->offsetHigh = offset.high;
                }
        
                /* write to file */
#ifdef UD_CS_INCLUDEDIRECTTRANSFER
                if (csDispatchIsDtIn())
                {
                    csDispatchDtSet(pFile->file, dataCount);
                }
                else
#endif /* UD_CS_INCLUDEDIRECTTRANSFER */
                {
                    dataCount = (NQ_UINT32)syWriteFile(pFile->file, pData, (NQ_COUNT)dataCount);
                    if ((NQ_INT)dataCount < 0)
                    {
                        error = csErrorGetLast();
                        TRCERR("WRITE_ANDX failed");
                        TRCE();
                        return error;
                    }
                }
                if ((NQ_INT)dataCount < 0)
                {
                    error = csErrorGetLast();
                    LOGERR(CM_TRC_LEVEL_ERROR, "WRITE failed");
                    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
                    return error;
                }
                csGetNameByNid(pFile->nid)->isDirty = TRUE;   
            }
    
            /* update file offsets */
            pFile->offsetHigh = offset.high;
            pFile->offsetLow = offset.low + dataCount;
            if (pFile->offsetLow < offset.low)
            {
                pFile->offsetHigh++;
            }
        }
    }

    /* compose the response */
    cmBufferWriteUint16(writer, 17);            /* structure length */
    cmBufferWriteUint16(writer, 0);             /* reserved */
    cmBufferWriteUint32(writer, dataCount);
    cmBufferWriteUint32(writer, 0);             /* remaining */
    cmBufferWriteUint16(writer, 0);             /* WriteChannelInfoOffset - unused*/
    cmBufferWriteUint16(writer, 0);             /* WriteChannelInfoLength - unused */
    
    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
    return 0;
}

#ifdef UD_CS_INCLUDERPC

/*====================================================================
 * PURPOSE: save IOCTL parameters in late response context
 *--------------------------------------------------------------------
 * PARAMS:  IN pointer to the saved context
 *
 * RETURNS: NONE
 *
 * NOTES:   skips Transact header
 *====================================================================
 */

static void
lateResponseSave(
    CSLateResponseContext* context
    )
{
    CMSmb2Header * pHeader;
    pHeader = cs2DispatchGetCurrentHeader();
    pHeader->aid.low = csSmb2SendInterimResponse(pHeader);
    pHeader->aid.high = 0;
    context->prot.smb2.commandData.write.dataCount = dataCount;
    context->file = pFile;

    /* write request information into the file descriptor */
    csDispatchSaveResponseContext(context);

    return;
}

/*====================================================================
 * PURPOSE: calculate command data pointer and size
 *--------------------------------------------------------------------
 * PARAMS:  IN pointer to the saved context
 *
 * RETURNS: NQ_SUCCESS or error code
 *
 * NOTES:   skips Transact header
 *====================================================================
 */

static NQ_STATUS
lateResponsePrepare(
    CSLateResponseContext* context
    )
{
    csDispatchPrepareLateResponse(context);
    context->commandData += RESPONSE_LENGTH;
    context->commandDataSize -= RESPONSE_LENGTH;

    return NQ_SUCCESS;
}

/*====================================================================
 * PURPOSE: send a response using saved context
 *--------------------------------------------------------------------
 * PARAMS:  IN pointer to the saved context
 *          IN status to return
 *          IN number of bytes to return in the data section
 *
 * RETURNS: TRUE on success
 *
 * NOTES:   data is ignored
 *====================================================================
 */

static NQ_BOOL
lateResponseSend(
    CSLateResponseContext* context,
    NQ_UINT32 status,
    NQ_COUNT dataLength
    )
{
    CMBufferWriter writer;

    /* save response for subsequent READ */
    csDcerpcSaveCompleteResponse((CSFile*)context->file, context->commandData, dataLength);
    
    /* compose Write response */    
    context->commandData -= RESPONSE_LENGTH;
    cmBufferWriterInit(&writer, context->commandData, RESPONSE_LENGTH + 10);
    cmBufferWriteUint16(&writer, 17);            /* structure length */
    cmBufferWriteUint16(&writer, 0);             /* reserved */
    cmBufferWriteUint32(&writer, context->prot.smb2.commandData.write.dataCount);
    cmBufferWriteUint32(&writer, 0);             /* remaining */
    cmBufferWriteUint16(&writer, 0);             /* WriteChannelInfoOffset - unused*/
    cmBufferWriteUint16(&writer, 0);             /* WriteChannelInfoL:ength - unused */

    return csDispatchSendLateResponse(context, status, RESPONSE_LENGTH);
}

#endif /* UD_CS_INCLUDERPC */

#endif /* defined(UD_NQ_INCLUDECIFSSERVER) && defined(UD_NQ_INCLUDESMB2) */

