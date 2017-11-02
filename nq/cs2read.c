/*********************************************************************
 *
 *           Copyright (c) 2008 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : SMB2 Read command handler
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

#define RESPONSE_LENGTH 16  /* length of the read response not including data */

/*====================================================================
 * PURPOSE: Perform Read processing
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

NQ_UINT32 csSmb2OnRead(CMSmb2Header *in, CMSmb2Header *out, CMBufferReader *reader, CSSession *connection, CSUser *user, CSTree *tree, CMBufferWriter *writer)
{
    CSFile* pFile;                          /* pointer to file descriptor */
    CSFid fid;                              /* fid of the file to close */
    NQ_UINT32 dataCount;                    /* requested data count */
    NQ_UINT32 maxCount;                     /* available data count */
    NQ_UINT32 minCount;                     /* buffer length */
    NQ_UINT64 offset;                       /* read offset */
    CMCifsStatus error;                     /* for composing DOS-style error */
    NQ_BYTE * pDataCount;                   /* saved pointer to data length in response */
    NQ_BYTE * pData;                        /* pointer to the buffer */
#ifdef UD_CS_FORCEINTERIMRESPONSES
    NQ_UINT32 asyncId = 0;                  /* generated Async ID */
#endif /* UD_CS_FORCEINTERIMRESPONSES */
    NQ_UINT32 readCount;                    /* read count */
    NQ_INT immediateDataCount;              /* number of bytes in the packet (not including DT) */
#ifdef UD_CS_INCLUDEDIRECTTRANSFER
    NQ_BOOL doDt;                           /* perform Direct Transfer */
    SYFileInformation info;                 /* file information structure */
#endif /* UD_CS_INCLUDEDIRECTTRANSFER */
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
    UDFileAccessEvent	eventInfo;
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL);

    /* parse request */
    cmBufferReaderSkip(reader, 2);  /* paddding + reserved */
    cmBufferReadUint32(reader, &dataCount);
    cmBufferReadUint64(reader, &offset);
    cmBufferReadUint16(reader, &fid);
    cs2ParseFid(&fid);
    cmBufferReaderSkip(reader, 14); /* the rest of the file ID */
    cmBufferReadUint32(reader, &minCount);
   
    if (dataCount > (CIFS_MAX_DATA_SIZE - SMB2_HEADERSIZE - 16))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Buffer overflow: read length too big");
        LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
        return SMB_STATUS_INVALID_PARAMETER;
    }
    
    /* find file descriptor */
    pFile = csGetFileByFid(fid, tree->tid, user->uid);
    if (pFile == NULL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unknown FID");
        LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
        return SMB_STATUS_INVALID_HANDLE;
    }

#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
    eventInfo.fileName = csGetFileName(pFile->fid);
    eventInfo.tid = tree->tid;
    eventInfo.rid = csGetUserRid(user);
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */

    /* check available room in the buffer */
    maxCount = CS_SMB2_MAX_READ_SIZE;
    if (dataCount > maxCount)
        dataCount = maxCount;

    /* start composing response */
    cmBufferWriteUint16(writer, 17);   /* structure length */
    cmBufferWriteByte(writer, SMB2_HEADERSIZE + RESPONSE_LENGTH);
    cmBufferWriteByte(writer, 0);   /* reserved */
    pDataCount = cmBufferWriterGetPosition(writer);
    cmBufferWriteUint32(writer, 0); /* data count - initially */
    cmBufferWriteUint32(writer, 0); /* remaining */
    cmBufferWriterSkip(writer, 4);  /* reserved 2 */
    pData = cmBufferWriterGetPosition(writer);

#ifdef UD_CS_INCLUDERPC
    if (pFile->isPipe)
    {
        /* read from pipe */
        readCount = csDcerpcRead(pFile, pData, (NQ_UINT)dataCount, NULL);
        if (readCount == 0)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "error reading from pipe");
            LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
            return SMB_STATUS_INVALID_PIPE_STATE;
        }
        immediateDataCount = (NQ_INT)readCount;
    }
    else
#endif /* UD_CS_INCLUDERPC */
    {
        /* send interim response */
#ifdef UD_CS_FORCEINTERIMRESPONSES
        asyncId = csSmb2SendInterimResponse(in);
        if (0 == asyncId)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "error sending interim read response");
            LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
            return SMB_STATUS_INVALID;
        }
        out->flags |= SMB2_FLAG_ASYNC_COMMAND;
        out->aid.low = asyncId;
        out->aid.high = 0;
#endif /* UD_CS_FORCEINTERIMRESPONSES */

        /* position to the offset */
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
            if ((maxCount = (NQ_UINT32)sySeekFileStart(pFile->file, offset.low, offset.high)) != offset.low)
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
                LOGERR(CM_TRC_LEVEL_ERROR, "Seek failed. Expected: %d, returned %d", offset.low, maxCount);
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
        }

        /* read from file */
#ifdef UD_CS_INCLUDEDIRECTTRANSFER
        doDt = FALSE;
        if (csDispatchIsDtOut() && dataCount > 0)
        {
            CSName * pName;
            pName = csGetNameByNid(pFile->nid);
            if (NULL != pName && NQ_SUCCESS == csGetFileInformation(pFile, pName->name, &info))
            {
                doDt = TRUE;
            }
        }
        if (doDt)
        {
            NQ_UINT64 remaining;
            remaining.high = info.sizeHigh - offset.high;
            remaining.low = info.sizeLow;
            if (remaining.low >= offset.low)
            {
                remaining.low -= offset.low;
            }
            else
            {
                remaining.high -= 1;
                remaining.low = (NQ_UINT32)(-1) - (offset.low - remaining.low);
            }
            if (remaining.low == 0)
            {
                return csErrorReturn(SMB_STATUS_END_OF_FILE, SRV_ERRqeof);
            }
            if (remaining.high == 0 && remaining.low < dataCount)
            {
                dataCount = remaining.low;
            }
            csDispatchDtSet(pFile->file, dataCount);
            immediateDataCount = 0;
            readCount = dataCount;
        }
        else
#endif /* UD_CS_INCLUDEDIRECTTRANSFER */
        {
            readCount = (NQ_UINT32)syReadFile(pFile->file, pData, (NQ_COUNT)dataCount);
            if (readCount == 0 && dataCount != 0)
            {
                LOGERR(CM_TRC_LEVEL_ERROR, "Read failed: end of file");

                /* update file pointer */
                pFile->offsetHigh = pFile->offsetLow = 0;
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
                eventInfo.offsetLow = pFile->offsetLow;
                eventInfo.offsetHigh = pFile->offsetHigh;
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
                sySeekFileStart(pFile->file, pFile->offsetLow, pFile->offsetHigh);
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

                LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
                return SMB_STATUS_END_OF_FILE;
            }
            if ((NQ_INT)readCount < 0)
            {
                error = csErrorGetLast();
                LOGERR(CM_TRC_LEVEL_ERROR, "Read failed");
                LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
                return error;
            }
            immediateDataCount = (NQ_INT)readCount;
        }
        
        /* update file offsets */
        pFile->offsetHigh = offset.high;
        pFile->offsetLow = offset.low + readCount;
        if (pFile->offsetLow < offset.low)
        {
            pFile->offsetHigh++;
        }
    }

    /* compose the response */
    pData += immediateDataCount;
    cmBufferWriterSetPosition(writer, pDataCount);
    cmBufferWriteUint32(writer, readCount);
    cmBufferWriterSetPosition(writer, pData);
    
    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
    return 0;
}

#endif /* defined(UD_NQ_INCLUDECIFSSERVER) && defined(UD_NQ_INCLUDESMB2) */

