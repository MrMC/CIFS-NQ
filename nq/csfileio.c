/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Implementation of file access command
 *--------------------------------------------------------------------
 * MODULE        : CS - CIFS Server
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 30-June-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "csdataba.h"
#include "csparams.h"
#include "csdispat.h"
#include "csutils.h"
#include "csbreak.h"
#include "csdcerpc.h"
#include "csutils.h"

#ifdef UD_NQ_INCLUDECIFSSERVER

/* 
 * Local functions and data
 * ------------------------
 */ 

/* two following variables are used between command processing and saving late response (see below) */
static NQ_UINT32 dataCount;     /* number of bytes in WRITE(AndX) */
static CSFile* pFile;           /* pointer to file descriptor */

#ifdef UD_CS_INCLUDERPC

/* saving late response for Write */
static void
writeLateResponseSave(
    CSLateResponseContext* context
    );

/* preparing late response for Write */
static NQ_BOOL
writeLateResponsePrepare(
    CSLateResponseContext* context
    );

/* sending late response for Write */
static NQ_BOOL
writeLateResponseSend(
    CSLateResponseContext* context,
    NQ_UINT32 status,
    NQ_COUNT dataLength
    );

/* saving late response for WriteAndX */
static void
writeAndXLateResponseSave(
    CSLateResponseContext* context
    );

/* preparing late response for WriteAndX */
static NQ_BOOL
writeAndXLateResponsePrepare(
    CSLateResponseContext* context
    );

/* sending late response for WriteAndX */
static NQ_BOOL
writeAndXLateResponseSend(
    CSLateResponseContext* context,
    NQ_UINT32 status,
    NQ_COUNT dataLength
    );

#endif /* UD_CS_INCLUDERPC */

/* This code implements file read/write/seek commands
*/

/*====================================================================
 * PURPOSE: Perform FLUSH command
 *--------------------------------------------------------------------
 * PARAMS:  IN pointer to the command in the message
 *          IN header of the outgoing message
 *          IN/OUT double pointer to the response
 *
 * RETURNS: 0 on success or error code in NT format
 *
 * NOTES:   Function parses the command pointed by the second parameter.
 *          It composes a response and places it from the response pointer,
 *          increasing it so that it will point after the response.
 *====================================================================
 */

NQ_UINT32
csComFlush(
    NQ_BYTE* pRequest,
    CMCifsHeader* pHeaderOut,
    NQ_BYTE** pResponse
    )
{
    CMCifsFlushFileRequest* flushRequest;   /* casted request */
    CMCifsFlushFileResponse* flushResponse; /* casted response */
    NQ_UINT32 returnValue;                     /* error code in NT format or 0 for no error */
    CMCifsStatus error;                     /* for composing DOS-style error */
    CSFile* pFile;                          /* pointer to file descriptor */
    CSFid fid;                              /* required FID */
    CSPid pid;                              /* required PID */

    TRCB();

    /* check space in output buffer */

    if ((returnValue = csDispatchCheckSpace(pHeaderOut, *pResponse, sizeof(*flushResponse))
        ) != 0
       )
    {
        TRCE();
        return returnValue;
    }

    /* cast pointers */

    flushRequest = (CMCifsFlushFileRequest*) pRequest;
    flushResponse = (CMCifsFlushFileResponse*) *pResponse;

    /* check format */

    if (   flushRequest->wordCount != SMB_FLUSHFILE_REQUEST_WORDCOUNT
        || cmGetSUint16(flushRequest->byteCount) != 0
       )
    {
        TRCERR("Illegal WordCount or ByteCount");
        TRCE();
        return csErrorReturn(SMB_STATUS_UNSUCCESSFUL, SRV_ERRerror);
    }

    /* find file descriptor(s) */

    fid  = cmLtoh16(cmGetSUint16(flushRequest->fid));

    error = 0;      /* no errors yet */

    if (fid == 0xFFFF)      /* flush all files from the same PID */
    {
        NQ_INT numFiles = 0;

        pid = (CSPid)csGetPidFromHeader(pHeaderOut);
        fid = CS_ILLEGALID;

        /* cycle by all files of the same PID and flush them */

        while ((pFile = csGetNextFileByPid(pid, fid)) != NULL)
        {
            fid = pFile->fid;
            numFiles++;
            if (syFlushFile(pFile->file) != NQ_SUCCESS)
            {
                error = csErrorGetLast();
            }

            /* even on error continue flushing */
        }

        if (numFiles == 0)                          /* no files flushed */
        {
            error = csErrorReturn(SMB_STATUS_INVALID_HANDLE, DOS_ERRbadfid);
        }

        if (error == 0)                     /* on any error - exit */
        {
            return error;
        }
    }
    else
    {
        pFile = csGetFileByFid(fid, cmLtoh16(cmGetSUint16(pHeaderOut->tid)), cmLtoh16(cmGetSUint16(pHeaderOut->uid)));
        if (pFile == NULL)
        {
            TRCERR("Unknown FID");
            TRCE();
            return csErrorReturn(SMB_STATUS_INVALID_HANDLE, DOS_ERRbadfid);
        }

        /* flush file */

        if (syFlushFile(pFile->file) != NQ_SUCCESS)
        {
            error = csErrorGetLast();
            TRCERR("Flush error");
            TRCE();
            return error;
        }
    }

    /* compose the response */

    flushResponse->wordCount = 0;
    cmPutSUint16(flushResponse->byteCount, 0);

    /* advance the outgoing response pointer */

    *pResponse += sizeof(*flushResponse);

    TRCE();
    return 0;
}

/*====================================================================
 * PURPOSE: Perform READ command
 *--------------------------------------------------------------------
 * PARAMS:  IN pointer to the command in the message
 *          IN header of the outgoing message
 *          IN/OUT double pointer to the response
 *
 * RETURNS: 0 on success or error code in NT format
 *
 * NOTES:   Function parses the command pointed by the second parameter.
 *          It composes a response and places it from the response pointer,
 *          increasing it so that it will point after the response.
 *====================================================================
 */

NQ_UINT32
csComRead(
    NQ_BYTE* pRequest,
    CMCifsHeader* pHeaderOut,
    NQ_BYTE** pResponse
    )
{
    CMCifsReadFileRequest* readRequest;     /* casted request */
    CMCifsReadFileResponse* readResponse;   /* casted response */
    CMCifsStatus error;                     /* for composing DOS-style error */
    NQ_INT32 dataCount;                     /* number of bytes to read */
    CMCifsData* pDataBlock;                 /* DATA BLOCK pointer for response */
    CSFile* pFile;                          /* pointer to the file descriptor */
    NQ_INT32 actualCount;                   /* available data count */
    NQ_UINT32 offset;                       /* low bit portion of the offset */
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
    UDFileAccessEvent	eventInfo;
    CSUser			*	pUser;
#endif /* UD_NQ_INCLUDEEVENTLOG */

    TRCB();

    /* cast pointers */

    readRequest = (CMCifsReadFileRequest*) pRequest;
    readResponse = (CMCifsReadFileResponse*) *pResponse;

    /* check format */

    if (   readRequest->wordCount != SMB_READFILE_REQUEST_WORDCOUNT
        || cmGetSUint16(readRequest->byteCount) != 0
       )
    {
        TRCERR("Illegal WordCount or ByteCount");
        TRCE();
        return csErrorReturn(SMB_STATUS_UNSUCCESSFUL, SRV_ERRerror);
    }

    /* check available room in the buffer */

    dataCount = cmLtoh16(cmGetSUint16(readRequest->count));
    actualCount =   CS_MAXBUFFERSIZE
                  - sizeof(*readResponse)
                  - sizeof (*pHeaderOut)
                  - sizeof(*pDataBlock);
    if (dataCount > actualCount)
        dataCount = actualCount;

    /* find file */

    if ((pFile = csGetFileByFid(cmLtoh16(cmGetSUint16(readRequest->fid)), cmLtoh16(cmGetSUint16(pHeaderOut->tid)), cmLtoh16(cmGetSUint16(pHeaderOut->uid)))) == NULL)
    {
        TRCERR("Unknown FID");
        TRCE();
        return csErrorReturn(SMB_STATUS_INVALID_HANDLE, DOS_ERRbadfid);
    }

#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
    eventInfo.fileName = csGetFileName(pFile->fid);
    eventInfo.tid = cmLtoh16(cmGetSUint16(pHeaderOut->tid));
    pUser = csGetUserByUid(cmLtoh16(cmGetSUint16(pHeaderOut->uid)));
    eventInfo.rid = csGetUserRid(pUser);
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */

    pDataBlock = (CMCifsData*)(readResponse + 1);

#ifdef UD_CS_INCLUDERPC
    if (pFile->isPipe)
    {
        /* read from pipe */

        dataCount = cmLtoh16(cmGetSUint16(pDataBlock->length));
        dataCount = (NQ_INT32)csDcerpcRead(pFile, (NQ_BYTE*)(pDataBlock + 1), (NQ_UINT)dataCount, NULL);
        if (dataCount == 0)
        {
            TRCERR("error reading from pipe");
            return csErrorReturn(SMB_STATUS_INVALID_PIPE_STATE, DOS_ERRbadpipe);
        }
    }
    else
#endif /* UD_CS_INCLUDERPC */
    {
        /* read from file */

        offset = cmLtoh32(cmGetSUint32(readRequest->offset));

#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
        	eventInfo.offsetLow = offset;
        	eventInfo.offsetHigh = 0;
            eventInfo.before = TRUE;
			udEventLog(
				UD_LOG_MODULE_CS,
				UD_LOG_CLASS_FILE,
				UD_LOG_FILE_SEEK,
				pUser->name,
				pUser->ip,
				0,
				(const NQ_BYTE*)&eventInfo
			);
			eventInfo.before = FALSE;
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */
        if ((actualCount = (NQ_INT32)sySeekFileStart(pFile->file, offset, 0)) != (NQ_INT)cmLtoh32(cmGetSUint32(readRequest->offset)))
        {
            error = csErrorGetLast();
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
			udEventLog(
				UD_LOG_MODULE_CS,
				UD_LOG_CLASS_FILE,
				UD_LOG_FILE_SEEK,
				pUser->name,
				pUser->ip,
				error,
				(const NQ_BYTE*)&eventInfo
			);
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */
            TRCERR("LSEEK failed");
            TRC2P("Required: %ld, returned: %d", cmLtoh32(cmGetSUint32(readRequest->offset)), actualCount);
            TRCE();
            return error;
        }
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
		udEventLog(
			UD_LOG_MODULE_CS,
			UD_LOG_CLASS_FILE,
			UD_LOG_FILE_SEEK,
			pUser->name,
			pUser->ip,
			0,
			(const NQ_BYTE*)&eventInfo
		);
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */

    dataCount = syReadFile(pFile->file, (NQ_BYTE*)(pDataBlock + 1), (NQ_COUNT)dataCount);
    if (dataCount < 0)
    {
      error = csErrorGetLast();
      TRCERR("READ failed");
      TRCE();
      return error;
    }
        
        /* update file offsets */
        
        pFile->offsetLow = offset + (NQ_UINT32)dataCount;
        if (pFile->offsetLow < offset)
        {
            pFile->offsetHigh++;
        }
    }
    /* compose the response */

    readResponse->wordCount = SMB_READFILE_RESPONSE_WORDCOUNT;
    cmPutSUint16(readResponse->count, cmHtol16((NQ_UINT16)dataCount));
    {
        NQ_INT i;  /* just a counter */

        for (i = 0; i < 4; i++)
            cmPutSUint16(readResponse->reserved[i], 0);
    }
    cmPutSUint16(readResponse->byteCount, cmHtol16((NQ_UINT16)(dataCount +(NQ_UINT16) sizeof(*pDataBlock))));
    pDataBlock->identifier = SMB_FIELD_DATABLOCK;
    cmPutSUint16(pDataBlock->length, cmHtol16((NQ_UINT16)dataCount));

    /* advance the outgoing response pointer */

    *pResponse += (NQ_UINT)(sizeof(*readResponse) + sizeof(*pDataBlock) + (NQ_UINT)dataCount);

    TRCE();
    return 0;
}

/*====================================================================
 * PURPOSE: Perform READ ANDX command
 *--------------------------------------------------------------------
 * PARAMS:  IN pointer to the command in the message
 *          IN header of the outgoing message
 *          IN/OUT double pointer to the response
 *
 * RETURNS: 0 on success or error code in NT format
 *
 * NOTES:   Function parses the command pointed by the second parameter.
 *          It composes a response and places it from the response pointer,
 *          increasing it so that it will point after the response.
 *====================================================================
 */

NQ_UINT32
csComReadAndX(
    NQ_BYTE* pRequest,
    CMCifsHeader* pHeaderOut,
    NQ_BYTE** pResponse
    )
{
    CMCifsReadAndXRequest* readRequest;     /* casted request */
    CMCifsReadAndXResponse* readResponse;   /* casted response */
    CMCifsStatus error;                     /* for composing DOS-style error */
    NQ_UINT32 immediateDataCount;           /* number of bytes in the packet (not including DT) */
    CSFile* pFile;                          /* pointer to the file descriptor */
    NQ_BYTE* dataPtr;                       /* pointer to the data buffer */
    NQ_UINT32 actualCount;                  /* available data count */
    NQ_UINT32 offsetLow;                    /* low bit portion of the offset */
    NQ_UINT32 offsetHigh;                   /* high bit portion of the offset */
    NQ_UINT padding;                        /* number of padded bytes */
#ifdef UD_CS_INCLUDEDIRECTTRANSFER
    NQ_BOOL doDt;                           /* perform Direct Transfer */
    SYFileInformation info;                 /* file information structure */
#endif /* UD_CS_INCLUDEDIRECTTRANSFER */
    NQ_UINT32 dataLength = 0;               /* data length total */
    CSSession *session;                     /* session pointer */
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
    UDFileAccessEvent	eventInfo;
    CSUser			*	pUser;
#endif /* UD_NQ_INCLUDEEVENTLOG */

    TRCB();

    /* cast pointers */
    readRequest = (CMCifsReadAndXRequest*) pRequest;
    readResponse = (CMCifsReadAndXResponse*) *pResponse;

    /* calculate alignment and fill the padding with zeroes */
    
    dataPtr = (NQ_BYTE*)(readResponse + 1);
    dataPtr += (UD_FS_BUFFERALIGNMENT + 1) - ((NQ_ULONG)dataPtr & UD_FS_BUFFERALIGNMENT);
    padding = (NQ_UINT)((NQ_ULONG)dataPtr - (NQ_ULONG)(readResponse + 1));

    /* get data length */

    session = csGetSessionBySocket(); 
    if (session && !(session->capabilities & SMB_CAP_LARGE_READX) && cmLtoh16(cmGetSUint16(readRequest->maxCountHigh)) > 0)
    {
        TRCERR("Requested data count is 64K or more");
        TRCE();
        return csErrorReturn(SMB_STATUS_ACCESS_DENIED, DOS_ERRnoaccess);
    }

    /* check the next AndX command */

    if (readRequest->andXCommand != SMB_COM_CLOSE && readRequest->andXCommand != 0xFF)
    {
        TRCERR("Illegal next AndX command");
        TRCE();
        return csErrorReturn(SMB_STATUS_UNSUCCESSFUL, SRV_ERRerror);
    }

    /* find file */

    if ((pFile = csGetFileByFid(cmLtoh16(cmGetSUint16(readRequest->fid)), cmLtoh16(cmGetSUint16(pHeaderOut->tid)), cmLtoh16(cmGetSUint16(pHeaderOut->uid)))) == NULL)
    {
        TRCERR("Unknown FID");
        TRCE();
        return csErrorReturn(SMB_STATUS_INVALID_HANDLE, DOS_ERRbadfid);
    }
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
    eventInfo.fileName = csGetFileName(pFile->fid);
    eventInfo.tid = cmLtoh16(cmGetSUint16(pHeaderOut->tid));
    pUser = csGetUserByUid(cmLtoh16(cmGetSUint16(pHeaderOut->uid)));
    eventInfo.rid = csGetUserRid(pUser);
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */

    dataLength = (NQ_UINT32)(cmLtoh16(cmGetSUint16(readRequest->maxCount)));
    TRC("dataLengthHigh: %d, dataLengthLow: %d, total: %d", cmLtoh16(cmGetSUint16(readRequest->maxCountHigh)), cmLtoh16(cmGetSUint16(readRequest->maxCount)), dataLength);

    /* check available room in the buffer */

    actualCount = (NQ_UINT32)(CS_MAXBUFFERSIZE - sizeof(*readResponse) - sizeof (*pHeaderOut) - padding);
    if (dataLength > actualCount)
        dataLength = actualCount;
#ifdef UD_CS_INCLUDERPC
    if (pFile->isPipe)
    {
        /* read from pipe */
		/* do not use dataCountHigh since it is Timeout */
        dataLength = (NQ_UINT32)csDcerpcRead(pFile, dataPtr, (NQ_UINT)dataLength, NULL);
        if (dataLength == 0)
        {
            TRCERR("error reading from pipe");
            return csErrorReturn(SMB_STATUS_INVALID_PIPE_STATE, DOS_ERRbadpipe);
        }
        immediateDataCount = dataLength;
    }
    else
#endif /* UD_CS_INCLUDERPC */
    {
    	NQ_UINT16    maxCountHigh;
		/* use dataCountHigh */
    	maxCountHigh = cmLtoh16(cmGetSUint16(readRequest->maxCountHigh));
    	maxCountHigh = maxCountHigh == 0xffff ? 0 : maxCountHigh;
		dataLength |= ((NQ_UINT32)maxCountHigh << 16);
        /* shift to the read position */

        if (readRequest->wordCount == SMB_READANDX_REQUEST_WORDCOUNT1)
            offsetHigh = cmLtoh32(cmGetSUint32(((CMCifsReadAndXRequest1*)readRequest)->offsetHigh));
        else
            offsetHigh = 0;
        offsetLow = cmLtoh32(cmGetSUint32(readRequest->offset));

        if (pFile->offsetLow != offsetLow || pFile->offsetHigh != offsetHigh)
        {
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
        	eventInfo.offsetLow = offsetLow;
        	eventInfo.offsetHigh = offsetHigh;
            eventInfo.before = TRUE;
			udEventLog(
				UD_LOG_MODULE_CS,
				UD_LOG_CLASS_FILE,
				UD_LOG_FILE_SEEK,
				pUser->name,
				pUser->ip,
				0,
				(const NQ_BYTE*)&eventInfo
			);
			eventInfo.before = FALSE;
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */
            if (sySeekFileStart(pFile->file, offsetLow, offsetHigh) == NQ_FAIL)
            {
                error = csErrorGetLast();
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
				udEventLog(
					UD_LOG_MODULE_CS,
					UD_LOG_CLASS_FILE,
					UD_LOG_FILE_SEEK,
					pUser->name,
					pUser->ip,
					error,
					(const NQ_BYTE*)&eventInfo
				);
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */
                TRCERR("LSEEK failed");
                TRCE();
                return error;
            }
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
			udEventLog(
				UD_LOG_MODULE_CS,
				UD_LOG_CLASS_FILE,
				UD_LOG_FILE_SEEK,
				pUser->name,
				pUser->ip,
				0,
				(const NQ_BYTE*)&eventInfo
			);
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */
            pFile->offsetLow = offsetLow;
            pFile->offsetHigh = offsetHigh;
        }

        /* read from file */

#ifdef UD_CS_INCLUDEDIRECTTRANSFER
        doDt = FALSE;
        if (csDispatchIsDtOut() && dataLength > 0)
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
            NQ_UINT32 remainingHigh = info.sizeHigh - offsetHigh;
            NQ_UINT32 remainingLow = info.sizeLow;
            if (offsetHigh > info.sizeHigh || (offsetHigh == info.sizeHigh && offsetLow >= info.sizeLow))
            {
                /* an offset is greater or equal than a file size */
                dataLength = 0;
            }
            else
            {
                if (remainingLow >= offsetLow)
                {
                    remainingLow -= offsetLow;
                }
                else
                {
                    if (offsetHigh < remainingHigh)
                    {
                        remainingHigh -= 1;
                        remainingLow = (NQ_UINT32)(-1) - (offsetLow - remainingLow);
                    }
                    else
                        remainingLow = 0;
                }
            }
            if (remainingLow == 0)
            {
                return csErrorReturn(SMB_STATUS_END_OF_FILE, SRV_ERRqeof);
            }
            if (remainingHigh == 0 && remainingLow < dataLength)
            {
                dataLength = remainingLow;
            }
            csDispatchDtSet(pFile->file, (NQ_COUNT)dataLength);
            immediateDataCount = 0;
        }
        else
#endif /* UD_CS_INCLUDEDIRECTTRANSFER */
        {
            dataLength = (NQ_UINT32)syReadFile(pFile->file, dataPtr, (NQ_COUNT)dataLength);
            if (dataLength < 0)
            {
                error = csErrorGetLast();
                TRCERR("READ failed");
                TRCE();
                return error;
            }
            immediateDataCount = dataLength;
        }
        
        /* update file offsets */
        pFile->offsetLow += (NQ_UINT32)dataLength;
        if (pFile->offsetLow < offsetLow)
        {
            pFile->offsetHigh++;
        }
    }

    /* compose the response */

    readResponse->wordCount = SMB_READANDX_RESPONSE_WORDCOUNT;
    readResponse->andXCommand = readRequest->andXCommand;
    readResponse->andXReserved = 0;
    if (readResponse->andXCommand == 0xFF)
    {
        cmPutSUint16(readResponse->andXOffset, 0);
    }
    else
    {
        NQ_UINT16 offset;   /* for calculating offsets */

        offset = (NQ_UINT16)(*pResponse - (NQ_BYTE*)pHeaderOut);
        cmPutSUint16(readResponse->andXOffset, cmHtol16(offset));
    }

    cmPutSUint16(readResponse->remaining, cmHtol16(0xFFFF));     /* as required by CIFS */
    cmPutSUint16(readResponse->dataCompactionMode, 0);
    cmPutSUint16(readResponse->reserved1, 0);

    cmPutSUint16(readResponse->dataLength, cmHtol16((NQ_UINT16)dataLength & 0xFFFF));
    {
        NQ_UINT16 offset;   /* for calculating offsets */

        offset = (NQ_UINT16)(dataPtr - (NQ_BYTE*)pHeaderOut);
        cmPutSUint16(readResponse->dataOffset, cmHtol16(offset));
    }

    {
        NQ_INT i = 0;

        if (dataLength >= 0x00010000)  /* more or equal to 64K */
            cmPutSUint16(readResponse->reserved2[i++], cmHtol16((NQ_UINT16)((dataLength & 0xFFFF0000) >> 16))); /* dataLength high */
        for (   ; i < 5; i++)
            cmPutSUint16(readResponse->reserved2[i], 0);
    }

    cmPutSUint16(
        readResponse->byteCount,
        cmHtol16((NQ_UINT16)(dataPtr + dataLength  - (NQ_BYTE*)(&readResponse->byteCount) - (NQ_UINT16)sizeof(readResponse->byteCount)))
        );

    /* advance the outgoing response pointer */

    *pResponse = dataPtr + immediateDataCount;

    TRCE();
    return 0;
}

/*====================================================================
 * PURPOSE: Perform WRITE command
 *--------------------------------------------------------------------
 * PARAMS:  IN pointer to the command in the message
 *          IN header of the outgoing message
 *          IN/OUT double pointer to the response
 *
 * RETURNS: 0 on success or error code in NT format
 *
 * NOTES:   Function parses the command pointed by the second parameter.
 *          It composes a response and places it from the response pointer,
 *          increasing it so that it will point after the response.
 *====================================================================
 */

NQ_UINT32
csComWrite(
    NQ_BYTE* pRequest,
    CMCifsHeader* pHeaderOut,
    NQ_BYTE** pResponse
    )
{
    CMCifsWriteBytesRequest* writeRequest;  /* casted request */
    NQ_UINT32 returnValue;                  /* error code in NT format or 0 for no error */
    CMCifsStatus error;                     /* for composing DOS-style error */
    CMCifsData* pDataBlock;                 /* DATA BLOCK pointer for response */
    NQ_UINT32 offset;                       /* required offset */
    CMCifsWriteBytesResponse* writeResponse;/* casted response */
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
    UDFileAccessEvent	eventInfo;
    CSUser	*			pUser;
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */

    TRCB();

    dataCount = 0;                   /* number of bytes to read */
        
    /* check available room in the buffer and set response flags */

    writeResponse = (CMCifsWriteBytesResponse*) *pResponse;
    returnValue = csDispatchCheckSpace(
                                pHeaderOut,
                                *pResponse,
                                sizeof(*writeResponse)
                                );

    /* cast pointers */

    writeRequest = (CMCifsWriteBytesRequest*) pRequest;
    pDataBlock = (CMCifsData*)(writeRequest + 1);

    /* check format */

    if (   writeRequest->wordCount != SMB_WRITEBYTES_REQUEST_WORDCOUNT
        || pDataBlock->identifier != SMB_FIELD_DATABLOCK
       )
    {
        TRCERR("Illegal WordCount or BufferFormat");
        TRCE();
        return csErrorReturn(SMB_STATUS_UNSUCCESSFUL, SRV_ERRerror);
    }

    /* find file */

    if ((pFile = csGetFileByFid(cmLtoh16(cmGetSUint16(writeRequest->fid)), cmLtoh16(cmGetSUint16(pHeaderOut->tid)), cmLtoh16(cmGetSUint16(pHeaderOut->uid)))) == NULL)
    {
        TRCERR("Unknown FID");
        TRCE();
        return csErrorReturn(SMB_STATUS_INVALID_HANDLE, DOS_ERRbadfid);
    }

#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
    eventInfo.fileName = csGetFileName(pFile->fid);
    eventInfo.tid = cmLtoh16(cmGetSUint16(pHeaderOut->tid));
    pUser = csGetUserByUid(cmLtoh16(cmGetSUint16(pHeaderOut->uid)));
    eventInfo.rid = csGetUserRid(pUser);
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */

    offset = cmLtoh32(cmGetSUint32(writeRequest->offset));

#ifdef UD_CS_INCLUDERPC
    if (pFile->isPipe)
    {
        NQ_UINT32 returnValue;  /* RPC return code */

        dataCount = cmLtoh16(cmGetSUint16(pDataBlock->length));
        csDcerpcSetLateResponseCallbacks(
            writeLateResponseSave,
            writeLateResponsePrepare,
            writeLateResponseSend
        );
#ifdef UD_CS_INCLUDEDIRECTTRANSFER
        /* discard possible DirectTransfer and read the payload */
        csDispatchDtDiscard();
#endif /* UD_CS_INCLUDEDIRECTTRANSFER */
        returnValue = csDcerpcWrite(
            pFile, (NQ_BYTE*)(pDataBlock + 1),
            cmLtoh16(cmGetSUint16(pDataBlock->length)),
            FALSE
            );
        if (returnValue != 0)
        {
            TRCERR("error writing to pipe");
            return returnValue;
        }
    }
    else
#endif /* UD_CS_INCLUDERPC */
    {
#ifdef UD_CS_INCLUDERPC_SPOOLSS
        if (pFile->isPrint)
        {
            NQ_INT32 written;
            CSDcerpcResponseContext *rctx = NULL;
            void *p = NULL;
            
            dataCount = cmLtoh16(cmGetSUint16(pDataBlock->length));
            csDcerpcSetLateResponseCallbacks(
                writeLateResponseSave,
                writeLateResponsePrepare,
                writeLateResponseSend
            );
#ifdef UD_CS_INCLUDEDIRECTTRANSFER
            /* discard possible DirectTransfer and read the payload */
            csDispatchDtDiscard();
#endif /* UD_CS_INCLUDEDIRECTTRANSFER */
            written = syWritePrintData(pFile->printerHandle, (NQ_UINT32)pFile->file, (NQ_BYTE*)(pDataBlock + 1), cmLtoh16(cmGetSUint16(pDataBlock->length)), &p);
            rctx =  (CSDcerpcResponseContext *)p;
            
            if (written != dataCount)
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
                if (written >= 0)
                {
                    TRC2P("Required: %d bytes, written: %d bytes", cmLtoh16(cmGetSUint16(pDataBlock->length)), written);
                }
                TRCE();
                return csErrorGetLast();
            }
        }
        else
#endif /* UD_CS_INCLUDERPC_SPOOLSS */       
        {
            if (returnValue !=0)
            {
                TRCE();
                return returnValue;
            }

            if (cmGetSUint16(writeRequest->count) == 0)
            {
                /* truncate file */
                error = csTruncateFile(pFile, NULL, offset, 0);

                if (error != NQ_SUCCESS)
                {
                    TRCERR("truncate failed");
                    TRCE();
                    return error;
                }
            }
            else
            {
                /* check buffer size */

#ifndef UD_CS_INCLUDEDIRECTTRANSFER
                if (cmLtoh16(cmGetSUint16(pDataBlock->length)) >
                    (  CIFS_MAX_DATA_SIZE16
                     - sizeof(*writeRequest)
                     - sizeof(*pDataBlock)
                     - sizeof (*pHeaderOut)
                    )
                   )
                {
                    TRCERR("Data overflow");
                    TRCE();
                    return csErrorReturn(SMB_STATUS_BUFFER_TOO_SMALL, DOS_ERRinsufficientbuffer);
                }
#endif /* UD_CS_INCLUDEDIRECTTRANSFER */

                /* write to file */
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
        	eventInfo.offsetLow = offset;
        	eventInfo.offsetHigh = 0;
            eventInfo.before = TRUE;
			udEventLog(
				UD_LOG_MODULE_CS,
				UD_LOG_CLASS_FILE,
				UD_LOG_FILE_SEEK,
				pUser->name,
				pUser->ip,
				0,
				(const NQ_BYTE*)&eventInfo
			);
			eventInfo.before = FALSE;
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */
                if (sySeekFileStart(pFile->file, offset, 0) != offset)
                {
                    error = csErrorGetLast();
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
					udEventLog(
						UD_LOG_MODULE_CS,
						UD_LOG_CLASS_FILE,
						UD_LOG_FILE_SEEK,
						pUser->name,
						pUser->ip,
						error,
						(const NQ_BYTE*)&eventInfo
					);
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */
                    TRCERR("LSEEK failed");
                    TRCE();
                    return error;
                }
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
				udEventLog(
					UD_LOG_MODULE_CS,
					UD_LOG_CLASS_FILE,
					UD_LOG_FILE_SEEK,
					pUser->name,
					pUser->ip,
					0,
					(const NQ_BYTE*)&eventInfo
				);
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */

#ifdef UD_CS_INCLUDEDIRECTTRANSFER
                if (csDispatchIsDtIn())
                {
                    csDispatchDtSet(pFile->file, dataCount);
                }
                else
#else /* UD_CS_INCLUDEDIRECTTRANSFER */
                {
                    dataCount = (NQ_UINT32)syWriteFile(pFile->file, (NQ_BYTE*)(pDataBlock + 1), cmLtoh16(cmGetSUint16(pDataBlock->length)));
                    if (dataCount != cmLtoh16(cmGetSUint16(pDataBlock->length)))
                    {
                        error = csErrorGetLast();
                        TRCERR("WRITE failed");
                        if (dataCount >= 0)
                        {
                            TRC2P("Required: %d bytes, written: %d bytes", cmLtoh16(cmGetSUint16(pDataBlock->length)), dataCount);
                        }
                        TRCE();
                        return error;
                    }
                }
#endif /* UD_CS_INCLUDEDIRECTTRANSFER */
                csGetNameByNid(pFile->nid)->isDirty = TRUE;
            }

            /* update file offsets */

            pFile->offsetLow = offset + dataCount;
            if (pFile->offsetLow < offset)
            {
                pFile->offsetHigh++;
            }
        }              
    }
   
    /* compose the response */

    writeResponse->wordCount = SMB_WRITEBYTES_RESPONSE_WORDCOUNT;
    cmPutSUint16(writeResponse->count, cmHtol16((NQ_UINT16)dataCount));
    cmPutSUint16(writeResponse->byteCount, 0);

    /* advance the outgoing response pointer */

    *pResponse += sizeof(*writeResponse);

    TRCE();
    return 0;
}

/*====================================================================
 * PURPOSE: Perform WRITE command
 *--------------------------------------------------------------------
 * PARAMS:  IN pointer to the command in the message
 *          IN header of the outgoing message
 *          IN/OUT double pointer to the response
 *
 * RETURNS: 0 on success or error code in NT format
 *
 * NOTES:   Function parses the command pointed by the second parameter.
 *          It composes a response and places it from the response pointer,
 *          increasing it so that it will point after the response.
 *====================================================================
 */

NQ_UINT32
csComWriteAndX(
    NQ_BYTE* pRequest,
    CMCifsHeader* pHeaderOut,
    NQ_BYTE** pResponse
    )
{
    CMCifsWriteAndXRequest* writeRequest;   /* casted request */
    CMCifsWriteAndXResponse* writeResponse; /* casted response */
    NQ_UINT32 returnValue;                  /* error code in NT format or 0 for no error */
    CMCifsStatus error;                     /* for composing DOS-style error */
    NQ_UINT32 offsetLow;                    /* required offset - low bits */
    NQ_UINT32 offsetHigh;                   /* required offset - high bits */
    NQ_BYTE* pData;                         /* pointer to the data block */
    NQ_UINT32 dataLength = 0;               /* data length total */
    NQ_UINT32 dataWritten = 0;              /* data written */
    CSSession *session;                     /* session pointer */
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
    UDFileAccessEvent	eventInfo;
    CSUser			*	pUser;
#endif /* UD_NQ_INCLUDEEVENTLOG */
    
    TRCB();
        
    /* check available room in the buffer and set response flags */

    returnValue = csDispatchCheckSpace(
                                pHeaderOut,
                                *pResponse,
                                sizeof(*writeResponse)
                                );
    if (returnValue !=0)
    {
        TRCE();
        return returnValue;
    }

    /* cast pointers */

    writeRequest = (CMCifsWriteAndXRequest*) pRequest;
    writeResponse = (CMCifsWriteAndXResponse*) *pResponse;

    /* check the next AndX command */

    switch(writeRequest->andXCommand)
    {
    case SMB_COM_READ:
    case SMB_COM_READ_ANDX:
    case SMB_COM_LOCK_AND_READ:
    case SMB_COM_WRITE_ANDX:
    case SMB_COM_CLOSE:
    case 0xFF:
        break;
    default:
        TRCERR("Illegal next AndX command");
        TRCE();
        return csErrorReturn(SMB_STATUS_UNSUCCESSFUL, SRV_ERRerror);
    }

    /* find file */

    if ((pFile = csGetFileByFid(cmLtoh16(cmGetSUint16(writeRequest->fid)), cmLtoh16(cmGetSUint16(pHeaderOut->tid)), cmLtoh16(cmGetSUint16(pHeaderOut->uid)))) == NULL)
    {
        TRCERR("Unknown FID");
        TRCE();
        return csErrorReturn(SMB_STATUS_INVALID_HANDLE, DOS_ERRbadfid);
    }

    /* get data length */

    session = csGetSessionBySocket(); 
    if (session && !(session->capabilities & SMB_CAP_LARGE_WRITEX) && cmLtoh16(cmGetSUint16(writeRequest->dataLengthHigh)) > 0)
    {
        TRCERR("Requested data count is 64K or more");
        TRCE();
        return csErrorReturn(SMB_STATUS_ACCESS_DENIED, DOS_ERRnoaccess);
    }
    dataLength = (NQ_UINT32)(cmLtoh16(cmGetSUint16(writeRequest->dataLength))) | ((NQ_UINT32)cmLtoh16(cmGetSUint16(writeRequest->dataLengthHigh)) << 16);
    TRC("dataLengthHigh: %d, dataLengthLow: %d, total: %d", cmLtoh16(cmGetSUint16(writeRequest->dataLengthHigh)), cmLtoh16(cmGetSUint16(writeRequest->dataLength)), dataLength);

#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
    eventInfo.fileName = csGetFileName(pFile->fid);
    eventInfo.tid = cmLtoh16(cmGetSUint16(pHeaderOut->tid));
    pUser = csGetUserByUid(cmLtoh16(cmGetSUint16(pHeaderOut->uid)));
    eventInfo.rid = csGetUserRid(pUser);
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */

    /* check buffer size */

#ifndef UD_CS_INCLUDEDIRECTTRANSFER
    if (dataLength > (NQ_INT32)(CS_MAXBUFFERSIZE - sizeof(*writeRequest) - sizeof(*pHeaderOut)))
    {
        TRCERR("Data overflow");
        TRCE();
        return csErrorReturn(SMB_STATUS_BUFFER_TOO_SMALL, DOS_ERRinsufficientbuffer);
    }
#endif /* UD_CS_INCLUDEDIRECTTRANSFER */

    pData = pRequest - sizeof(CMCifsHeader) + cmLtoh16(cmGetSUint16(writeRequest->dataOffset));

#ifdef UD_CS_INCLUDERPC
    if (pFile->isPipe)
    {
        NQ_UINT32 returnValue;  /* RPC return code */

#ifdef UD_CS_INCLUDEDIRECTTRANSFER
        /* discard possible DirectTransfer and read the payload */
        csDispatchDtDiscard();
#endif /* UD_CS_INCLUDEDIRECTTRANSFER */

        csDcerpcSetLateResponseCallbacks(
            writeAndXLateResponseSave,
            writeAndXLateResponsePrepare,
            writeAndXLateResponseSend
        );
        returnValue = csDcerpcWrite(
                pFile, 
                pData, 
                (NQ_UINT)dataLength, 
                FALSE
                );
        if (returnValue != 0)
        {
            TRCERR("error writing to pipe");
            return returnValue;
        }
		dataWritten = dataLength;
    }
    else
#endif /* UD_CS_INCLUDERPC */
    {
#ifdef UD_CS_INCLUDERPC_SPOOLSS
        if (pFile->isPrint)
        {
            NQ_INT32 written;
            CSDcerpcResponseContext *rctx = NULL;
            void *p = NULL;

#ifdef UD_CS_INCLUDEDIRECTTRANSFER
      /* discard possible DirectTransfer and read the payload */
      csDispatchDtDiscard();
#endif /* UD_CS_INCLUDEDIRECTTRANSFER */

      csDcerpcSetLateResponseCallbacks(
                writeAndXLateResponseSave,
                writeAndXLateResponsePrepare,
                writeAndXLateResponseSend
            );
            written = syWritePrintData(pFile->printerHandle, (NQ_UINT32)pFile->file, pData, dataLength, &p);
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
            offsetLow = cmLtoh32(cmGetSUint32(writeRequest->offset));
            if (writeRequest->wordCount == SMB_WRITEANDX_REQUEST_WORDCOUNT1)
                offsetHigh = cmLtoh32(cmGetSUint32(((CMCifsWriteAndXRequest1*)writeRequest)->offsetHigh));
            else
                offsetHigh = 0;

            if (dataLength == 0)
            {
                /* truncate file */
                error = csTruncateFile(pFile, NULL, offsetLow, offsetHigh);

                if (error != NQ_SUCCESS)
                {
                    TRCERR("truncate failed");
                    TRCE();
                    return error;
                }
            }
            else
            {
                /* shift to the write position */
                
                if (pFile->offsetLow != offsetLow || pFile->offsetHigh != offsetHigh)
                {
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
					eventInfo.offsetLow = offsetLow;
					eventInfo.offsetHigh = offsetHigh;
					eventInfo.before = TRUE;
					udEventLog(
						UD_LOG_MODULE_CS,
						UD_LOG_CLASS_FILE,
						UD_LOG_FILE_SEEK,
						pUser->name,
						pUser->ip,
						0,
						(const NQ_BYTE*)&eventInfo
					);
					eventInfo.before = FALSE;
#endif /* UD_NQ_INCLUDEEVENTLOG */
                    if (sySeekFileStart(pFile->file, offsetLow, offsetHigh) == NQ_FAIL)
                    {
                    	error = csErrorGetLast();
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
						udEventLog(
							UD_LOG_MODULE_CS,
							UD_LOG_CLASS_FILE,
							UD_LOG_FILE_SEEK,
							pUser->name,
							pUser->ip,
							error,
							(const NQ_BYTE*)&eventInfo
						);
#endif /* UD_NQ_INCLUDEEVENTLOG */
                        TRCERR("LSEEK failed");
                        TRCE();
                        return error;
                    }
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
					udEventLog(
						UD_LOG_MODULE_CS,
						UD_LOG_CLASS_FILE,
						UD_LOG_FILE_SEEK,
						pUser->name,
						pUser->ip,
						0,
						(const NQ_BYTE*)&eventInfo
					);
#endif /* UD_NQ_INCLUDEEVENTLOG */
                    pFile->offsetLow = offsetLow;
                    pFile->offsetHigh = offsetHigh;
                }

                /* write to file */

#ifdef UD_CS_INCLUDEDIRECTTRANSFER
                if (csDispatchIsDtIn())
                {
                  csDispatchDtSet(pFile->file, dataLength);
                  dataWritten = dataLength;
                }
                else
#else /* UD_CS_INCLUDEDIRECTTRANSFER */
                {
                  dataWritten = (NQ_UINT32)syWriteFile(pFile->file, pData, (NQ_COUNT)dataLength);
                  if ((NQ_INT)dataWritten < 0)
                  {
                    error = csErrorGetLast();
                    TRCERR("WRITE_ANDX failed");
                    TRCE();
                    return error;
                  }
               }
#endif /* UD_CS_INCLUDEDIRECTTRANSFER */
                csGetNameByNid(pFile->nid)->isDirty = TRUE;   
            }
            
            /* update file offsets */

            pFile->offsetLow += dataWritten;
            if (pFile->offsetLow < offsetLow)
            {
                pFile->offsetHigh++;
            }
        }
    }

    /*  reset times for file */
    /*csResetFileTimes(csGetNameByNid(pFile->nid));*/

    /* advance the outgoing response pointer */

    *pResponse += sizeof(*writeResponse);

    /* compose the response */

    writeResponse->wordCount = SMB_WRITEANDX_RESPONSE_WORDCOUNT;
    writeResponse->andXCommand = writeRequest->andXCommand;
    if (writeResponse->andXCommand == 0xFF)
    {
        cmPutSUint16(writeResponse->andXOffset, 0);
    }
    else
    {
        NQ_UINT16 offset;

        offset = (NQ_UINT16)(*pResponse - (NQ_BYTE*)pHeaderOut);
        cmPutSUint16(writeResponse->andXOffset, cmHtol16(offset));
    }
    writeResponse->andXReserved = 0;
    cmPutSUint16(writeResponse->count, cmHtol16(dataWritten & 0xFFFF));
    cmPutSUint16(writeResponse->remaining, cmHtol16(0xFFFF)); /* should be -1 */
    cmPutSUint16(writeResponse->countHigh, cmHtol16((dataWritten & 0xFFFF0000) >> 16));
    cmPutSUint16(writeResponse->reserved, 0);
    cmPutSUint16(writeResponse->byteCount, 0);

    TRCE();
    return 0;
}

/*====================================================================
 * PURPOSE: Perform SEEK command
 *--------------------------------------------------------------------
 * PARAMS:  IN pointer to the command in the message
 *          IN header of the outgoing message
 *          IN/OUT double pointer to the response
 *
 * RETURNS: 0 on success or error code in NT format
 *
 * NOTES:   Function parses the command pointed by the second parameter.
 *          It composes a response and places it from the response pointer,
 *          increasing it so that it will point after the response.
 *====================================================================
 */

NQ_UINT32
csComSeek(
    NQ_BYTE* pRequest,
    CMCifsHeader* pHeaderOut,
    NQ_BYTE** pResponse
    )
{
    CMCifsSeekRequest* seekRequest;         /* casted request */
    CMCifsSeekResponse* seekResponse;       /* casted response */
    NQ_UINT32 returnValue;                  /* error code in NT format or 0 for no error */
    CMCifsStatus error;                     /* for composing DOS-style error */
    CSFile* pFile;                          /* pointer to the file descriptor */
    NQ_UINT32 offset;                       /* required offset */
    NQ_UINT16 mode;                         /* positioning mode */
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
    UDFileAccessEvent	eventInfo;
    CSUser			*	pUser;
#endif /* UD_NQ_INCLUDEEVENTLOG */

    TRCB();

    /* check available room in the buffer and set response flags */

    returnValue = csDispatchCheckSpace(
                             pHeaderOut,
                             *pResponse,
                             sizeof(*seekResponse)
                             );
    if (returnValue !=0)
    {
        TRCE();
        return returnValue;
    }

    /* cast pointers */

    seekRequest = (CMCifsSeekRequest*) pRequest;
    seekResponse = (CMCifsSeekResponse*) *pResponse;

    /* check format */

    if (seekRequest->wordCount != SMB_SEEK_REQUEST_WORDCOUNT)
    {
        TRCERR("Illegal WordCount or BufferFormat");
        TRCE();
        return csErrorReturn(SMB_STATUS_UNSUCCESSFUL, SRV_ERRerror);
    }

    /* find file */

    if ((pFile = csGetFileByFid(cmLtoh16(cmGetSUint16(seekRequest->fid)), cmLtoh16(cmGetSUint16(pHeaderOut->tid)), cmLtoh16(cmGetSUint16(pHeaderOut->uid)))) == NULL)
    {
        TRCERR("Unknown FID");
        TRCE();
        return csErrorReturn(SMB_STATUS_INVALID_HANDLE, DOS_ERRbadfid);
    }

#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
    eventInfo.fileName = csGetFileName(pFile->fid);
    eventInfo.tid = cmLtoh16(cmGetSUint16(pHeaderOut->tid));
    pUser = csGetUserByUid(cmLtoh16(cmGetSUint16(pHeaderOut->uid)));
    eventInfo.rid = csGetUserRid(pUser);
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */

    /* position the file */
    mode = cmLtoh16(cmGetSUint16(seekRequest->mode));
    offset = cmLtoh32(cmGetSUint32(seekRequest->offset));

#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
	eventInfo.offsetLow = offset;
	eventInfo.offsetHigh = 0;
	eventInfo.before = TRUE;
	udEventLog(
		UD_LOG_MODULE_CS,
		UD_LOG_CLASS_FILE,
		UD_LOG_FILE_SEEK,
		pUser->name,
		pUser->ip,
		0,
		(const NQ_BYTE*)&eventInfo
	);
	eventInfo.before = FALSE;
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */

    switch (mode)
    {
    case SMB_SEEK_START:
        offset = sySeekFileStart(pFile->file, offset, 0);
        break;
    case SMB_SEEK_CURRENT:
        offset = sySeekFileCurrent(pFile->file, (NQ_INT32)offset, 0);
        break;
    case SMB_SEEK_END:
        offset = sySeekFileEnd(pFile->file, (NQ_INT32)offset, 0);
        break;
    default:
        TRCERR("Illegal mode");
        TRCE();
        return csErrorReturn(SMB_STATUS_UNSUCCESSFUL, SRV_ERRerror);
    }
    if (offset == (NQ_UINT32)NQ_FAIL)
    {
        error = csErrorGetLast();
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
		udEventLog(
			UD_LOG_MODULE_CS,
			UD_LOG_CLASS_FILE,
			UD_LOG_FILE_SEEK,
			pUser->name,
			pUser->ip,
			error,
			(const NQ_BYTE*)&eventInfo
		);
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */
        TRCERR("LSEEK failed");
        TRCE();
        return error;
    }
#ifdef UD_NQ_INCLUDEEXTENDEDEVENTLOG
	udEventLog(
		UD_LOG_MODULE_CS,
		UD_LOG_CLASS_FILE,
		UD_LOG_FILE_SEEK,
		pUser->name,
		pUser->ip,
		0,
		(const NQ_BYTE*)&eventInfo
	);
#endif /* UD_NQ_INCLUDEEXTENDEDEVENTLOG */

    /* compose the response */

    seekResponse->wordCount = SMB_SEEK_RESPONSE_WORDCOUNT;
    cmPutSUint32(seekResponse->offset, cmHtol32(offset));
    cmPutSUint16(seekResponse->byteCount, 0);

    /* advance the outgoing response pointer */

    *pResponse += sizeof(*seekResponse);

    TRCE();
    return 0;
}

/*====================================================================
 * PURPOSE: Perform LOCKING ANDX command
 *--------------------------------------------------------------------
 * PARAMS:  IN pointer to the command in the message
 *          IN header of the outgoing message
 *          IN/OUT double pointer to the response
 *
 * RETURNS: 0 on success or error code in NT format
 *
 * NOTES:   Function parses the command pointed by the second parameter.
 *          It composes a response and places it from the response pointer,
 *          increasing it so that it will point after the response.
 *====================================================================
 */

NQ_UINT32
csComLockingAndX(
    NQ_BYTE* pRequest,
    CMCifsHeader* pHeaderOut,
    NQ_BYTE** pResponse
    )
{
    CMCifsLockingAndXRequest* lockingRequest;   /* casted request */
    CMCifsLockingAndXResponse* lockingResponse; /* casted response */
    NQ_UINT32 returnValue;                      /* error code in NT format or 0 for no error */
    CMCifsStatus error;                         /* for composing DOS-style error */
    CSFile* pFile;                              /* pointer to the file descriptor */
    NQ_BYTE lockType;                           /* lock type required */
    CMCifsLockingAndXRange* pRange;             /* pointer to a locking range */
    CMCifsLockingAndXLongRange* pLongRange;     /* pointer to a long locking range */
    NQ_UINT numLocks;                           /* number of locks */
    NQ_UINT numUnlocks;                         /* number of unlocks */
#ifdef	UD_NQ_INCLUDEEVENTLOG
    CSUser *			pUser;
    UDFileAccessEvent	eventInfo;
#endif	/*UD_NQ_INCLUDEEVENTLOG*/
    TRCB();

    /* cast pointers */

    lockingRequest = (CMCifsLockingAndXRequest*) pRequest;
    lockingResponse = (CMCifsLockingAndXResponse*) *pResponse;

    /* check format */

    if (lockingRequest->wordCount != SMB_LOCKINGANDX_REQUEST_WORDCOUNT)
    {
        TRCERR("Illegal WordCount");
        TRCE();
        return csErrorReturn(SMB_STATUS_UNSUCCESSFUL, SRV_ERRerror);
    }

    /* check available room in the buffer */

    returnValue = csDispatchCheckSpace(
                    pHeaderOut,
                    *pResponse,
                    sizeof(*lockingResponse)
                    );
    if (returnValue != 0)
    {
        TRCE();
        return returnValue;
    }

    /* check the next AndX command */

    switch(lockingRequest->andXCommand)
    {
    case SMB_COM_READ:
    case SMB_COM_CLOSE:
    case SMB_COM_WRITE:
    case SMB_COM_FLUSH:
    case SMB_COM_READ_ANDX:
    case SMB_COM_WRITE_ANDX:
    case SMB_COM_LOCKING_ANDX:
    case 0xFF:
        break;
    default:
        TRCERR("Illegal next AndX command");
        TRCE();
        return csErrorReturn(SMB_STATUS_UNSUCCESSFUL, SRV_ERRerror);
    }

    /* withdraw parameters */

    lockType = lockingRequest->lockType;
    numUnlocks = cmLtoh16(cmGetSUint16(lockingRequest->numOfUnlocks));
    numLocks = cmLtoh16(cmGetSUint16(lockingRequest->numOfLocks));

    /* find file */

    if ((pFile = csGetFileByFid(cmLtoh16(cmGetSUint16(lockingRequest->fid)), cmLtoh16(cmGetSUint16(pHeaderOut->tid)), cmLtoh16(cmGetSUint16(pHeaderOut->uid)))) == NULL)
    {
        TRCERR("Unknown FID");
        TRCE();
        return csErrorReturn(SMB_STATUS_INVALID_HANDLE, DOS_ERRbadfid);
    }
#ifdef	UD_NQ_INCLUDEEVENTLOG

    eventInfo.before   = TRUE;
    eventInfo.fileName = csGetFileName(pFile->fid);
    eventInfo.tid	   = pFile->tid;
    pUser = pFile->user;
    if (pUser == NULL)
    {
    	pUser = csGetUserByUid((CSUid)cmGetSUint16(pHeaderOut->uid));
    }
    if (pUser != NULL)
    {
		eventInfo.rid = csGetUserRid(pUser);
		udEventLog(
				UD_LOG_MODULE_CS,
				UD_LOG_CLASS_FILE,
				UD_LOG_FILE_LOCK,
				pUser->name,
				pUser->ip,
				0,
				(const NQ_BYTE*)&eventInfo
				);
    }
    eventInfo.before   = FALSE;
#endif	/*UD_NQ_INCLUDEEVENTLOG*/
    /* complete oplock break operation (send late response) if required */

    if (numLocks == 0 && numUnlocks == 0 && pFile->oplockGranted && pFile->pFileOplockBreaker)
    {
        csBreakComplete(&pFile->pFileOplockBreaker->breakContext, NULL);
        pFile->oplockGranted = FALSE;
        TRC("Oplock break completed");
        TRCE();
        return SMB_STATUS_NORESPONSE;
    }

    /* locking file */

    {
        NQ_UINT i;                                 /* just a counter */
        NQ_STATUS status = NQ_SUCCESS;             /* system operation status */
        
        if (lockType & SMB_LOCKINGANDX_LARGEFILES)
        {
            pLongRange = (CMCifsLockingAndXLongRange*)(lockingRequest + 1);
            for (i = numUnlocks; i>0; i--, pLongRange++)
            {
#ifdef UD_NQ_INCLUDEEVENTLOG
                eventInfo.offsetHigh = cmGetSUint32(pLongRange->highOffset);
                eventInfo.offsetLow  = cmGetSUint32(pLongRange->lowOffset);
#endif /* UD_NQ_INCLUDEVENTLOG*/
                status = syUnlockFile(
                    pFile->file,
                    cmLtoh32(pLongRange->highOffset),
                    cmLtoh32(pLongRange->lowOffset),
                    cmLtoh32(pLongRange->highLength),
                    cmLtoh32(pLongRange->lowLength),
                    cmLtoh16(cmGetSUint32(lockingRequest->timeout))
                    );
                if (status == NQ_FAIL)
                {
                    error = csErrorGetLast();
#ifdef UD_NQ_INCLUDEEVENTLOG
                    if (pUser != NULL)
                    {
						udEventLog(
								UD_LOG_MODULE_CS,
								UD_LOG_CLASS_FILE,
								UD_LOG_FILE_UNLOCK,
								pUser->name,
								pUser->ip,
								error,
								(const NQ_BYTE*)&eventInfo
								);
                    }
#endif /* UD_NQ_INCLUDEVENTLOG*/
                    TRCERR("Unlock failed");
                    TRCE();
                    return error;
                }
#ifdef UD_NQ_INCLUDEEVENTLOG
                if (pUser != NULL)
                {
					udEventLog(
								UD_LOG_MODULE_CS,
								UD_LOG_CLASS_FILE,
								UD_LOG_FILE_UNLOCK,
								pUser->name,
								pUser->ip,
								0,
								(const NQ_BYTE*)&eventInfo
							);
                }
#endif /* UD_NQ_INCLUDEVENTLOG*/
            }
            for (i = numLocks; i>0; i--, pLongRange++)
            {
#ifdef UD_NQ_INCLUDEEVENTLOG
                eventInfo.offsetHigh = cmGetSUint32(pLongRange->highOffset);
                eventInfo.offsetLow  = cmGetSUint32(pLongRange->lowOffset);
#endif /* UD_NQ_INCLUDEVENTLOG*/
                status = syLockFile(
                    pFile->file,
                    cmGetSUint32(cmLtoh32(pLongRange->highOffset)),
                    cmGetSUint32(cmLtoh32(pLongRange->lowOffset)),
                    cmGetSUint32(cmLtoh32(pLongRange->highLength)),
                    cmGetSUint32(cmLtoh32(pLongRange->lowLength)),
                    lockType,
                    lockingRequest->oplockLevel
                    );
                if (status == NQ_FAIL)
                {
                    error = csErrorGetLast();
#ifdef UD_NQ_INCLUDEEVENTLOG
                    if (pUser != NULL)
                    {
						udEventLog(
								UD_LOG_MODULE_CS,
								UD_LOG_CLASS_FILE,
								UD_LOG_FILE_LOCK,
								pUser->name,
								pUser->ip,
								error,
								(const NQ_BYTE*)&eventInfo
								);
                    }
#endif /* UD_NQ_INCLUDEVENTLOG*/
                    TRCERR("Lock failed");
#ifdef UD_NQ_INCLUDEEVENTLOG
                    if (pUser != NULL)
                    {
						udEventLog(
								UD_LOG_MODULE_CS,
								UD_LOG_CLASS_FILE,
								UD_LOG_FILE_LOCK,
								pUser->name,
								pUser->ip,
								error,
								(const NQ_BYTE*)&eventInfo
								);
                    }
#endif /* UD_NQ_INCLUDEVENTLOG*/
                    TRCE();
                    return error;
                }
#ifdef UD_NQ_INCLUDEEVENTLOG
                if (pUser != NULL)
                {
					udEventLog(
								UD_LOG_MODULE_CS,
								UD_LOG_CLASS_FILE,
								UD_LOG_FILE_LOCK,
								pUser->name,
								pUser->ip,
								0,
								(const NQ_BYTE*)&eventInfo
							);
                }
#endif /* UD_NQ_INCLUDEVENTLOG*/
            }
        }
        else
        {
            pRange = (CMCifsLockingAndXRange*)(lockingRequest + 1);
            for (i = numUnlocks; i>0; i--, pRange++)
            {
                status = syUnlockFile(
                    pFile->file,
                    0L,
                    cmLtoh32(pRange->offset),
                    0L,
                    cmLtoh32(pRange->length),
                    cmLtoh16(cmGetSUint32(lockingRequest->timeout))
                    );
                if (status == NQ_FAIL)
                {
                    error = csErrorGetLast();
#ifdef UD_NQ_INCLUDEEVENTLOG
                    if (pUser != NULL)
                    {
						udEventLog(
								UD_LOG_MODULE_CS,
								UD_LOG_CLASS_FILE,
								UD_LOG_FILE_LOCK,
								pUser->name,
								pUser->ip,
								error,
								(const NQ_BYTE*)&eventInfo
								);
                    }
#endif /* UD_NQ_INCLUDEVENTLOG*/
                    TRCERR("Unlock failed");
                    TRCE();
                    return error;
                }
#ifdef UD_NQ_INCLUDEEVENTLOG
                if (pUser != NULL)
                {
					udEventLog(
								UD_LOG_MODULE_CS,
								UD_LOG_CLASS_FILE,
								UD_LOG_FILE_LOCK,
								pUser->name,
								pUser->ip,
								0,
								(const NQ_BYTE*)&eventInfo
							);
                }
#endif /* UD_NQ_INCLUDEVENTLOG*/
            }
            for (i = numLocks; i>0; i--, pRange++)
            {
                status = syLockFile(
                    pFile->file,
                    0L,
                    cmLtoh32(pRange->offset),
                    0L,
                    cmLtoh32(pRange->length),
                    lockType,
                    lockingRequest->oplockLevel
                    );
                if (status == NQ_FAIL)
                {
                    error = csErrorGetLast();
                    TRCERR("Lock failed");
                    TRCE();
                    return error;
                }
#ifdef UD_NQ_INCLUDEEVENTLOG
                if (pUser != NULL)
                {
					udEventLog(
								UD_LOG_MODULE_CS,
								UD_LOG_CLASS_FILE,
								UD_LOG_FILE_LOCK,
								pUser->name,
								pUser->ip,
								0,
								(const NQ_BYTE*)&eventInfo
							);
                }
#endif /* UD_NQ_INCLUDEVENTLOG*/
            }
        }
    }

    /* advance the outgoing response pointer */

    *pResponse += sizeof(*lockingResponse);

    /* compose the response */

    lockingResponse->wordCount = SMB_LOCKINGANDX_RESPONSE_WORDCOUNT;
    lockingResponse->andXCommand = lockingRequest->andXCommand;
    lockingResponse->andXReserved = 0;
    if (lockingResponse->andXCommand == 0xFF)
    {
        cmPutSUint16(lockingResponse->andXOffset, 0);
    }
    else
    {
        NQ_UINT16 offset;   /* for calculating offsets */

        offset = (NQ_UINT16)(*pResponse - (NQ_BYTE*)pHeaderOut);
        cmPutSUint16(lockingResponse->andXOffset, cmHtol16(offset));
    }

    cmPutSUint16(lockingResponse->byteCount, 0);

    TRCE();
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
writeLateResponseSave(
    CSLateResponseContext* context
    )
{
    context->prot.smb1.commandData.write.dataCount = dataCount;
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
writeLateResponsePrepare(
    CSLateResponseContext* context
    )
{
    csDispatchPrepareLateResponse(context);
    context->commandData += sizeof(CMCifsWriteBytesResponse);
    context->commandDataSize -= (NQ_COUNT)sizeof(CMCifsWriteBytesResponse);

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
 * NOTES:   composes header and delegates send. Restrictions:
 *          - data section is provided and already placed into the buffer
 *          - parameter section is empty
 *          - setup is empty
 *====================================================================
 */

static NQ_BOOL
writeLateResponseSend(
    CSLateResponseContext* context,
    NQ_UINT32 status,
    NQ_COUNT dataLength
    )
{
    CMCifsWriteBytesResponse* writeResponse;            /* casted response */

    if (context->isRpc)
    {
        /* save response for subsequent READ */
        csDcerpcSaveCompleteResponse((CSFile*)context->file, context->commandData, dataLength);
    }

    /* compose Write response */    
    context->commandData -= sizeof(CMCifsWriteBytesResponse);
    writeResponse = (CMCifsWriteBytesResponse*)context->commandData;
    writeResponse->wordCount = SMB_WRITEBYTES_RESPONSE_WORDCOUNT;
    cmPutSUint16(writeResponse->count, (NQ_UINT16)context->prot.smb1.commandData.write.dataCount);
    cmPutSUint16(writeResponse->byteCount, 0);

    return csDispatchSendLateResponse(context, status, sizeof(*writeResponse));
}

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
writeAndXLateResponseSave(
    CSLateResponseContext* context
    )
{
    context->prot.smb1.commandData.write.dataCount = dataCount;
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
writeAndXLateResponsePrepare(
    CSLateResponseContext* context
    )
{
    csDispatchPrepareLateResponse(context);
    context->commandData += sizeof(CMCifsWriteAndXResponse);
    context->commandDataSize -= (NQ_COUNT)sizeof(CMCifsWriteAndXResponse);

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
 * NOTES:   composes header and delegates send. Restrictions:
 *          - data section is provided and already placed into the buffer
 *          - parameter section is empty
 *          - setup is empty
 *====================================================================
 */

static NQ_BOOL
writeAndXLateResponseSend(
    CSLateResponseContext* context,
    NQ_UINT32 status,
    NQ_COUNT dataLength
    )
{
    CMCifsWriteAndXResponse* writeResponse;            /* casted response */
    NQ_UINT32 count = context->prot.smb1.commandData.write.dataCount;

    if (context->isRpc)
    {
        /* save response for subsequent READ */
        csDcerpcSaveCompleteResponse((CSFile*)context->file, context->commandData, dataLength);
    }

    /* compose Write response */    
    context->commandData -= sizeof(CMCifsWriteAndXResponse);
    writeResponse = (CMCifsWriteAndXResponse*)context->commandData;
    writeResponse->wordCount = SMB_WRITEANDX_RESPONSE_WORDCOUNT;
    writeResponse->andXCommand = 0xFF;
    writeResponse->andXReserved = 0;
    cmPutSUint16(writeResponse->andXOffset, 0);
    cmPutSUint16(writeResponse->count, (count & 0xFFFF));
    cmPutSUint32(writeResponse->countHigh, (count / 0x10000));
    cmPutSUint16(writeResponse->remaining, 0);
    cmPutSUint16(writeResponse->byteCount, 0);

    return csDispatchSendLateResponse(context, status, sizeof(*writeResponse));
}

#endif /* UD_CS_INCLUDERPC */

#endif /* UD_NQ_INCLUDECIFSSERVER */

