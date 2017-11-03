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

#include "ccapi.h"
#include "cmapi.h"
#include "ccfile.h"
#include "cmthread.h"
#include "ccparams.h"
#include "ccread.h"
#include "ccwrite.h"

#ifdef UD_NQ_INCLUDECIFSCLIENT

/* -- Static functions and data -- */

typedef struct
{
    CMItem item;            /* inherited */
    void * context;			/* application context MUST be second for casting */
    NQ_UINT32 totalBytes;    /* total bytes to read */
    NQ_UINT32 actualBytes;    /* actually read */
    NQ_UINT numRequests;    /* number of requests */
    NQ_UINT numResponses;    /* number of responses */
    NQ_STATUS status;        /* last status */
    void (* callback)(NQ_STATUS, NQ_UINT, void *);    /* application callback */
    CCServer * server;      /* used as a critical section */
/* using server as a critical section may be overkill, while using CCFile seems to be more appropriate. However,
   this saves locks/unlocks while it is effectively almost the same as using CCFile. */
}
AsyncReadContext;    /* write operation context */

typedef struct
{
	NQ_BOOL		isPending;  /* was STATUS_PENDING sent - must be first for casting */
    CMThreadCond * cond;    /* sync condition */
    NQ_UINT actualBytes;    /* actually read */
    NQ_STATUS status;        /* operation status */
}
SyncReadContext;    /* write operation context */

/*
 * A callback to synchronize read operation
 */
static void syncToAsyncCallback(NQ_STATUS status, NQ_UINT readSize, void * context)
{
    SyncReadContext * pContext = (SyncReadContext *)context;
    pContext->actualBytes = readSize;
    pContext->status = status;
    cmThreadCondSignal(pContext->cond);
}

/*
 * A callback on response (file)
 */
static void asyncCallback(NQ_STATUS status, NQ_UINT readSize, void * context, NQ_BOOL final)
{
    AsyncReadContext * pRead;    /* context between an application and this module */

    pRead = (AsyncReadContext *)context;

    pRead->numResponses++;
    if (NQ_SUCCESS == status)
    {
        pRead->actualBytes += readSize;
    }
    switch (status)
    {
        case NQ_ERR_QEOF:
            if (pRead->status == NQ_SUCCESS || pRead->status == NQ_ERR_QEOF)
            {
                pRead->status = (pRead->actualBytes > 0) ? NQ_SUCCESS : NQ_ERR_QEOF;
            }
            break;
        case NQ_SUCCESS:
            if (pRead->status == NQ_SUCCESS || pRead->status == NQ_ERR_QEOF)
                pRead->status = NQ_SUCCESS;
            break;
        default:
            pRead->status = status;
    }

    if (pRead->numResponses == pRead->numRequests)
    {
        pRead->callback(pRead->status, (NQ_UINT)pRead->actualBytes, pRead->context);
        cmListItemRemoveAndDispose(&pRead->item);
    }
}

static NQ_BOOL asyncRemoveItem(void * context, CCServer *pServer)
{
	AsyncReadContext * pRead;	/* context between application and this module */
	CMIterator itr;
	NQ_BOOL result = FALSE;

	cmListIteratorStart(&pServer->async, &itr);
	while (cmListIteratorHasNext(&itr))
	{
		pRead = (AsyncReadContext *)cmListIteratorNext(&itr);
		if (pRead->context == context)
		{
			cmListItemRemoveAndDispose(&pRead->item);
			result = TRUE;
			break;
		}
	}
	cmListIteratorTerminate(&itr);

	return result;
}

/*
 * A callback on response (pipe)
 */
static void pipeCallback(NQ_STATUS status, NQ_UINT readSize, void * context, NQ_BOOL final)
{
    SyncReadContext * pRead;    /* context between an application and this module */
    AsyncReadContext * pFakeCtx;

    pFakeCtx = (AsyncReadContext *)context;
    pRead = (SyncReadContext *)pFakeCtx->context;

    pRead->status = status;
    if (NQ_SUCCESS == status)
    {
        pRead->actualBytes = readSize;
    }
    else
    {
    }
    cmThreadCondSignal(pRead->cond);
}

/* -- API functions -- */

NQ_BOOL ccReadStart(void)
{
    return TRUE;
}

void ccReadShutdown(void)
{
}

NQ_BOOL ccReadFile(NQ_HANDLE hndl, NQ_BYTE * buffer, NQ_UINT count, NQ_UINT *readSize)
{
    SyncReadContext syncContext;            /* application level context - we play application here */
    CMThreadCond cond;                  /* sync condition */
    CCFile * pFile;                     /* casted pointer */
    NQ_UINT64 offset;                   /* current file offset */
    NQ_INT i;                           /* retry counter */
    CCServer * pServer;                 /* pointer to server */
    NQ_BOOL result = FALSE;             /* return value */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "handl:%p buff:%p count:%u size:%p", hndl, buffer, count, readSize);

    if (hndl == NULL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "NULL Handle");
        sySetLastError(NQ_ERR_INVALIDHANDLE);
        goto Error1;
    }

    if (!ccValidateFileHandle(hndl))
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "Invalid Handle");
        sySetLastError(NQ_ERR_INVALIDHANDLE);
        goto Error1;
    }

    pFile = (CCFile *)hndl;
    if (pFile->share->isPrinter)
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "Cannot read from a print file");
        sySetLastError(NQ_ERR_BADPARAM);
        goto Error1;
    }
    if (!pFile->open)
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "File is not opened");
        sySetLastError(NQ_ERR_INVALIDHANDLE);
        goto Error1;
    }
    pServer = pFile->share->user->server;
    if (!ccTransportIsConnected(&pServer->transport) && !ccServerReconnect(pServer))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Not connected");
        sySetLastError(NQ_ERR_NOTCONNECTED);
        goto Error1;
    }
    cmListItemTake((CMItem *)pFile);
    syncContext.actualBytes = 0;
    syncContext.isPending = FALSE;

    if (!cmThreadCondSet(&cond))
    {
        sySetLastError(NQ_ERR_GENERAL);
        goto Error2;
    }
    syncContext.cond = &cond;
    for (i = CC_CONFIG_RETRYCOUNT; i > 0; i--)
    {
        if (pFile->isPipe)
        {
            NQ_UINT bytesToRead = count;         /* number of bytes not read yet */
            SyncReadContext read;                /* pointer to operation context */
            const NQ_BYTE * pData = buffer;      /* pointer in the buffer */
            NQ_BOOL isFirstRead = TRUE;

            AsyncReadContext fakeCtx;

            pFile->offset.low = 0;
            pFile->offset.high = 0;
            read.actualBytes = 0;
            read.cond = &cond;
            read.isPending = FALSE;
            if (readSize != NULL)
                *readSize = 0;

            fakeCtx.context = &read;
            while (bytesToRead > 0 || isFirstRead)
            {            	
                NQ_STATUS status;           /* read operation status */
                NQ_UINT readNow;            /* next read size */

				isFirstRead = FALSE;
                readNow = (NQ_UINT)(bytesToRead <= pServer->maxRead? bytesToRead : pServer->maxRead);
                status = pServer->smb->doRead(pFile, pData, readNow, pipeCallback, &fakeCtx, &syncContext);
                if (NQ_SUCCESS != status)
                {
                    sySetLastError((NQ_UINT32)status);
                    goto Exit;
                }
                if (FALSE == cmThreadCondWait(&cond, ccConfigGetTimeout()))
		        {
                	LOGERR(CM_TRC_LEVEL_WARNING , "Read timeout. No response.");
                	pServer->smb->removeReadWriteMatch(&syncContext, pServer, TRUE);
		        	cmListItemGive((CMItem *)pFile);
		        	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		        	return FALSE;
		        }
                if (NQ_ERR_PIPEBUSY == read.status)
                {
                    NSSocketSet sockSet;

                    /* wait 1 second before retry */
                    nsClearSocketSet(&sockSet);
                    nsSelect(&sockSet, 1);
                    continue;
                }
                if (NQ_SUCCESS != read.status)
                {
                    sySetLastError((NQ_UINT32)status);
                    goto Exit;
                }
                if (readSize != NULL)
                    *readSize += read.actualBytes;

                if (read.actualBytes < readNow || read.actualBytes == bytesToRead)
                {
                    result = TRUE;
                    goto Exit;
                }
                pData += readNow;
                bytesToRead -= readNow;
            }
        }
        else
        {
        	NQ_UINT32 adaptiveTimeout = ccConfigGetTimeout() * (count + pServer->maxRead) / pServer->maxRead;
            NQ_BOOL waitSuccess = TRUE;

            offset = ccGetFilePointer(pFile);
            if (ccReadFileAsync(hndl, buffer, count,  &syncContext, syncToAsyncCallback)
				&& (waitSuccess = ccPendingCondWait(&cond , adaptiveTimeout, &syncContext))
               )
            {
                if (pServer->connectionBroke)
                {
                    if(ccServerReconnect(pServer))
                    {
						cmListItemTake((CMItem *)pServer);
						pServer->connectionBroke = FALSE;
						cmListItemGive((CMItem *)pServer);
                    	continue;
                    }

                    cmListItemGive((CMItem *)pFile);

                    sySetLastError((NQ_UINT32)NQ_ERR_NOTCONNECTED);
                        goto Error1;
                }
				
				if (syncContext.status == NQ_ERR_TRYAGAIN)
				{
					/* try again */
					continue;
				}

                if (readSize != NULL)
                    *readSize = syncContext.actualBytes;

                sySetLastError((NQ_UINT32)syncContext.status);
                result = (NQ_SUCCESS == syncContext.status);
                goto Exit;
            }
            else
            {
                ccSetFilePointer(pFile, (NQ_INT32)offset.low, (NQ_INT32 *)&offset.high, SEEK_FILE_BEGIN);

                if (!waitSuccess)
                {
                	LOGERR(CM_TRC_LEVEL_WARNING , "Read timeout. No response.");
                	/* first we remove the match. notice, until we move the match this context might be called. */
                	pServer->smb->removeReadWriteMatch(&syncContext, pServer, TRUE);
                	asyncRemoveItem(&syncContext, pServer);
                }
                if (!ccFileReportDisconnect(pFile))
                {
                    if (syGetLastError() != NQ_ERR_TIMEOUT)
                        sySetLastError(NQ_ERR_RECONNECTREQUIRED);
                    goto Exit;
                }
            }
        }
    }
    sySetLastError(NQ_ERR_TIMEOUT);

Exit:
    cmThreadCondRelease(&cond);

Error2:
	cmListItemGive((CMItem *)pFile);

Error1:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE");
    return result;
}

NQ_BOOL ccReadFileAsync(NQ_HANDLE hndl, NQ_BYTE * buffer, NQ_UINT count, void * context, void (* callback)(NQ_STATUS, NQ_UINT, void *))
{
    AsyncReadContext *  pRead;                      /* pointer to operation context */
    NQ_UINT             bytesToRead = count;        /* number of bytes not read yet */
    CCFile *            pFile;                      /* casted pointer */
    CCServer *          pServer;                    /* pointer to respected server */
    NQ_UINT             maxRead;                    /* read limit applied by server */
    NQ_STATUS           status;                     /* write status */
    NQ_INT              counter;                    /* simple counter */
    NQ_BOOL             result = FALSE;             /* return value */
    NQ_BOOL				isFirstRead = TRUE;
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "handl:%p buff:%p count:%u context:%p callback:%p", hndl, buffer, count, context, callback);

    if (NULL == hndl)
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "NULL Handle");
        sySetLastError(NQ_ERR_INVALIDHANDLE);
        goto Exit;
    }

    if (!ccValidateFileHandle(hndl))
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "Invalid Handle");
        sySetLastError(NQ_ERR_INVALIDHANDLE);
        goto Exit;
    }

    pFile = (CCFile *)hndl;
    if (pFile->share->isPrinter)
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "Cannot read from a print file");
        sySetLastError(NQ_ERR_BADPARAM);
        goto Exit;
    }
    if (!pFile->open)
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "File is not opened");
        sySetLastError(NQ_ERR_INVALIDHANDLE);
        goto Exit;
    }
    pServer = pFile->share->user->server;
    if (!ccTransportIsConnected(&pServer->transport) && !ccServerReconnect(pServer))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Not connected");
        sySetLastError(NQ_ERR_NOTCONNECTED);
        goto Exit;
    }
    pRead = (AsyncReadContext *)cmListItemCreateAndAdd(&pServer->async, sizeof(AsyncReadContext), NULL, NULL, CM_LISTITEM_NOLOCK);
    if (NULL == pRead)
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "Out of memory");
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        goto Exit;
    }
    pRead->totalBytes = count;
    pRead->actualBytes = 0;
    pRead->numRequests = 0;
    pRead->numResponses = 0;
    pRead->status = NQ_SUCCESS;
    pRead->callback = callback;
    pRead->context = context;
    pRead->server = pServer;
    maxRead = (NQ_UINT)pServer->maxRead;

    pRead->numRequests = bytesToRead > maxRead ? (bytesToRead % maxRead != 0 ? bytesToRead / maxRead +1 : bytesToRead / maxRead ):1;

    while (bytesToRead > 0 || isFirstRead)
    {
        NQ_UINT readNow = bytesToRead <= maxRead? bytesToRead : maxRead;
        isFirstRead = FALSE;

        for (counter = 0; counter < CC_CONFIG_RETRYCOUNT; counter++)
        {
            status = pServer->smb->doRead(pFile, buffer, readNow, asyncCallback, pRead, context);
            if ((NQ_STATUS) NQ_ERR_RECONNECTREQUIRED == status)
            {
                pFile->share->user->server->transport.connected = FALSE;
                if (!ccServerReconnect(pServer))
                {
                    sySetLastError((NQ_UINT32)status);
                    goto Exit;
                }
            }
            else
                break;
        }
        if (NQ_SUCCESS != status)
        {
            sySetLastError((NQ_UINT32)status);
            goto Exit;
        }
        bytesToRead -= readNow;
        cmU64AddU32(&pFile->offset, readNow);
        buffer += readNow;
    }
    result = TRUE;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE");
    return result;
}

#endif /* UD_NQ_INCLUDECIFSCLIENT */
