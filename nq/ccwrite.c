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
#include "ccwrite.h"

#ifdef UD_NQ_INCLUDECIFSCLIENT

/* -- Static functions and data -- */

typedef struct
{
    CMItem item;            /* inherited */
    void * context;			/* application context MUST be second for casting */
    NQ_UINT32 totalBytes;	/* total bytes to write */
	NQ_UINT32 actualBytes;	/* actually written */
	NQ_UINT numRequests;	/* number of requests */
	NQ_UINT numResponses;	/* number of responses */
	NQ_STATUS status;		/* last status */
	void (* callback)(NQ_STATUS , NQ_UINT, void *);	/* application callback */
    CCServer * server;      /* used as a critical section */ 
/* using server as a critical section may be overkill, while using CCFile seems to be more appropriate. However,
   this saves locks/unlocks while it is effectively almost the same as using CCFile. */
}
AsyncWriteContext;	/* write operation context */

typedef struct
{
	NQ_BOOL		isPending;  /* was STATUS_PENDING sent - must be first for casting */
	CMThreadCond * cond;	/* sync condition */
	NQ_UINT actualBytes;	/* actually written */
    NQ_STATUS   status; /* last status */
}
SyncWriteContext;	/* write operation context */

/*
 * A callback to synchronize write operation
 */
static void syncToAsyncCallback( NQ_STATUS status,NQ_UINT writtenSize, void * context)
{
	SyncWriteContext * pContext = (SyncWriteContext *)context;
	pContext->actualBytes = writtenSize;
    pContext->status = status;
	cmThreadCondSignal(pContext->cond);
}

/*
 * A callback on response 
 */
static void asyncCallback(NQ_STATUS status, NQ_UINT writtenSize, void * context)
{
	AsyncWriteContext * pWrite;	/* context between application and this module */

	pWrite = (AsyncWriteContext *)context;
 	pWrite->numResponses++;

    if (NQ_SUCCESS == status)
	{
		pWrite->actualBytes += writtenSize;
		/* each write request can trigger a few doWrite calls. if any wasn't succesful we want to keep the unsuccesful status. */
        pWrite->status = (pWrite->status != NQ_SUCCESS) ? pWrite->status : NQ_SUCCESS;
	}
    else
    {
        sySetLastError((NQ_UINT32)status);
        pWrite->status = status;
    }

	if (pWrite->numRequests == pWrite->numResponses)
	{
		pWrite->callback(pWrite->status, (NQ_UINT)pWrite->actualBytes, pWrite->context);
        cmListItemRemoveAndDispose(&pWrite->item);
	}
}

static NQ_BOOL asyncRemoveItem(void * context, CCServer *pServer)
{
	AsyncWriteContext * pWrite;	/* context between application and this module */
	CMIterator itr;
	NQ_BOOL result = FALSE;

	cmListIteratorStart(&pServer->async, &itr);
	while (cmListIteratorHasNext(&itr))
	{
		pWrite = (AsyncWriteContext *)cmListIteratorNext(&itr);
		if (pWrite->context == context)
		{
			cmListItemRemoveAndDispose(&pWrite->item);
			result = TRUE;
			break;
		}
	}
	cmListIteratorTerminate(&itr);

	return result;
}

NQ_BOOL ccPendingCondWait(CMThreadCond * cond, NQ_UINT32 timeout , void * context)
{
	NQ_BOOL waitCondSuccess = FALSE;

	waitCondSuccess = cmThreadCondWait(cond, timeout);
	if (!waitCondSuccess)
	{
		NQ_BOOL * isPending = NULL;

		isPending = (NQ_BOOL *)context;

		if (*isPending)
		{
			NQ_UINT32	secondTimeout = timeout * PENDING_TIMEOUT_EXTENTION;

			return cmThreadCondWait(cond, secondTimeout);
		}
	}
	return waitCondSuccess;
}

/* -- API functions -- */

NQ_BOOL ccWriteStart(void)
{
	return TRUE;
}

void ccWriteShutdown(void)
{
}

NQ_BOOL ccWriteFile(NQ_HANDLE hndl, NQ_BYTE * buffer, NQ_UINT count, NQ_UINT * writtenSize)
{
	SyncWriteContext syncContext;		/* application level context - we play application here */
	CMThreadCond cond;				/* sync condition */
	NQ_UINT64 offset;				/* current file offset */
	NQ_INT i;						/* retry counter */
	CCFile * pFile;                 /* casted pointer */
    CCServer * pServer;             /* pointer to server */
	NQ_BOOL result = FALSE;         /* return result */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "handl:%p buff:%p count:%u written:%p", hndl, buffer, count, writtenSize);

	if (NULL == hndl)
	{
		LOGERR(CM_TRC_LEVEL_ERROR , "Invalid Handle");
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
	if (!pFile->open)
	{
		sySetLastError(NQ_ERR_INVALIDHANDLE);
		goto Exit;
	}
	pServer = pFile->share->user->server;
	cmListItemTake((CMItem *)pFile);
	if (!cmThreadCondSet(&cond))
    {
    	cmListItemGive((CMItem *)pFile);
		sySetLastError(NQ_ERR_OUTOFMEMORY);
		goto Exit;
    }
	syncContext.isPending = FALSE;
	syncContext.cond = &cond;
	syncContext.actualBytes = 0;
	for (i = CC_CONFIG_RETRYCOUNT; i > 0; i--)
    {
		offset = ccGetFilePointer(pFile);
		if (count == 0)
		{
			if (ccSetFileSizeByHandle(hndl, (NQ_UINT32)offset.low, (NQ_UINT32)offset.high))
			{
			    cmThreadCondRelease(&cond);

			    cmListItemGive((CMItem *)pFile);
	            if (writtenSize != NULL)
				    *writtenSize = 0;
					result = TRUE;
					goto Exit;
			}
		}
		else
		{
			NQ_BOOL waitCondSuccess = TRUE; /* success */
			NQ_UINT32 adaptiveTimeout = ccConfigGetTimeout() * (count + pServer->maxWrite) / pServer->maxWrite;

			if (ccWriteFileAsync(hndl, buffer, count,  &syncContext, syncToAsyncCallback)
					&& (waitCondSuccess = ccPendingCondWait(&cond , adaptiveTimeout, &syncContext))
		   	   )
			{
				if (pServer->connectionBroke)
				{
					if (!ccServerReconnect(pServer))
					{
						cmListItemGive((CMItem *)pFile);
						sySetLastError(NQ_ERR_NOTCONNECTED);
						goto Exit;
					}

					cmListItemTake((CMItem *) pServer);
					pServer->connectionBroke = FALSE;
					cmListItemGive((CMItem *)pServer);
					/* server reconnect success - retry send */
					continue;
				}

				if ((NQ_STATUS)NQ_ERR_TRYAGAIN == syncContext.status)
				{
					/* try again */
					continue;
				}
				
				/* write success */
	            sySetLastError((NQ_UINT32)syncContext.status);
			    cmThreadCondRelease(&cond);
	    		cmListItemGive((CMItem *)pFile);
	            if (writtenSize != NULL)
				    *writtenSize = syncContext.actualBytes;
				result = (syncContext.status == NQ_SUCCESS);
				goto Exit;
			}
			else
			{
				/* either write async failed or thread wait returned with false. */
				ccSetFilePointer(pFile, (NQ_INT32)offset.low, (NQ_INT32 *)&offset.high, SEEK_FILE_BEGIN);
				if (FALSE == waitCondSuccess)
				{
					LOGERR(CM_TRC_LEVEL_WARNING , "Write time out (or wait condition failed). Remove write match.");
					pServer->smb->removeReadWriteMatch(&syncContext, pServer, FALSE);
					asyncRemoveItem(&syncContext, pServer);
				}

				if (!ccFileReportDisconnect(pFile))
				{
					/* reconnect failed. exit*/
				    cmThreadCondRelease(&cond);

				    cmListItemGive((CMItem *)pFile);
					if (syGetLastError() != NQ_ERR_TIMEOUT)
						sySetLastError(NQ_ERR_RECONNECTREQUIRED);
					goto Exit;
				}
				/* reconnect success - retry write */
			}
		}
	}
	cmListItemGive((CMItem *)pFile);
	cmThreadCondRelease(&cond);    
	sySetLastError(NQ_ERR_TIMEOUT);

Exit:
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE");
	return result;
}

NQ_BOOL ccWriteFileAsync(NQ_HANDLE hndl, NQ_BYTE * buffer, NQ_UINT count, void * context, void (* callback)(NQ_STATUS , NQ_UINT, void *))
{
	AsyncWriteContext * pWrite;		            /* pointer to operation context */
	NQ_UINT             bytesToWrite = count;	/* number of bytes not written yet */
	CCFile *            pFile;                  /* casted pointer */
	CCServer *          pServer;				/* pointer to respected server */
	NQ_UINT             maxWrite;				/* write limit applied by server */
	NQ_STATUS           status;				    /* write status */
    NQ_INT              counter;                /* simple counter */
	NQ_BOOL             result = FALSE;         /* return value */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "handl:%p buff:%p count:%u context:%p callback:%p", hndl, buffer, count, context, callback);

	if (hndl == NULL)
	{
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
	if (!pFile->open)
	{
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
    pWrite = (AsyncWriteContext *)cmListItemCreateAndAdd(&pServer->async, sizeof(AsyncWriteContext), NULL, NULL, CM_LISTITEM_NOLOCK);
	if (NULL == pWrite)
	{
		sySetLastError(NQ_ERR_OUTOFMEMORY);
		goto Exit;
	}

	pWrite->totalBytes = count;
	pWrite->actualBytes = 0;
	pWrite->numRequests = 0;
	pWrite->numResponses = 0;
	pWrite->status = NQ_SUCCESS;
	pWrite->callback = callback;
	pWrite->context = context;
    pWrite->server = pServer;
    maxWrite = pFile->share->isPrinter ? (NQ_UINT)pServer->maxTrans : (NQ_UINT)pServer->maxWrite;
    
	pWrite->numRequests = bytesToWrite > maxWrite ? (bytesToWrite % maxWrite != 0 ? bytesToWrite / maxWrite +1 : bytesToWrite / maxWrite ):1;
	while (bytesToWrite > 0)
	{
		NQ_UINT writeNow = bytesToWrite <= maxWrite? bytesToWrite : maxWrite;
		
        for (counter = 0; counter < CC_CONFIG_RETRYCOUNT; counter++)
        {
            status = pServer->smb->doWrite(pFile, buffer, writeNow, asyncCallback, pWrite, context);
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
		bytesToWrite -= writeNow;
		cmU64AddU32(&pFile->offset, writeNow);
		buffer += writeNow;
	}
    result = TRUE;

Exit:
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE");
	return result;
}

#endif /* UD_NQ_INCLUDECIFSCLIENT */
