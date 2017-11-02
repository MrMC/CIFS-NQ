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
#include "ccconfig.h" 
#include "ccwrite.h"

#ifdef UD_NQ_INCLUDECIFSCLIENT

/* -- Static functions and data -- */

typedef struct
{
    CMItem item;            /* inherited */
    NQ_UINT32 totalBytes;	/* total bytes to write */
	NQ_UINT32 actualBytes;	/* actually wtitten */
	NQ_UINT numRequests;	/* number of requests */
	NQ_UINT numResponses;	/* number of responses */
	NQ_STATUS status;		/* last status */
	void (* callback)(NQ_STATUS , NQ_UINT, void *);	/* application callback */
	void * context;			/* application context */
    CCServer * server;      /* used as a critical section */ 
/* using server as a critical section may be overkeel, while using CCFile seems to be more appropriate. However, 
   this saves locks/unlocks while it is effetcively almost the same as using CCFile. */
}
AsyncWriteContext;	/* write operation context */

typedef struct
{
	CMThreadCond * cond;	/* sync condition */
	NQ_UINT actualBytes;	/* actually wtitten */
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
    if (status != NQ_ERR_OK)
    {
        sySetLastError((NQ_UINT32)status);
    }
	pWrite->status = status;
	pWrite->numResponses++;
	if (NQ_SUCCESS == status)
	{
		pWrite->actualBytes += writtenSize;
	}
	if (pWrite->numRequests == pWrite->numResponses)
	{
		pWrite->callback(pWrite->status ,pWrite->actualBytes, pWrite->context);
        cmListItemRemoveAndDispose(&pWrite->item);
	}
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
	SyncWriteContext context;		/* application level context - we play application here */
	CMThreadCond cond;				/* sync condition */
	NQ_UINT64 offset;				/* current file offset */
	NQ_INT i;						/* retry counter */
	CCFile * pFile;                 /* casted pointer */
    CCServer * pServer;             /* pointer to server */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	if (hndl == NULL)
	{
		sySetLastError(NQ_ERR_INVALIDHANDLE);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return FALSE;
	}
	pFile = (CCFile *)hndl;
	if (!pFile->open)
	{
		sySetLastError(NQ_ERR_INVALIDHANDLE);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return FALSE;
	}
	pServer = pFile->share->user->server;
	cmListItemTake((CMItem *)pFile);
	if (!cmThreadCondSet(&cond))
    {
    	cmListItemGive((CMItem *)pFile);
		sySetLastError(NQ_ERR_OUTOFMEMORY);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return FALSE;
    }
	context.cond = &cond;
	context.actualBytes = 0;
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
				LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
				return TRUE;
			}
		}
		else
		{
            NQ_TIME adaptiveTimeout = ccConfigGetTimeout() * (count + pServer->maxWrite) / pServer->maxWrite; 

			if (ccWriteFileAsync(hndl, buffer, count,  &context, syncToAsyncCallback) 
                && cmThreadCondWait(&cond, adaptiveTimeout)
		   	   )
			{
	            sySetLastError((NQ_UINT32)context.status);
			    cmThreadCondRelease(&cond);
	    		cmListItemGive((CMItem *)pFile);
	            if (writtenSize != NULL)
				    *writtenSize = context.actualBytes;
				LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
				return context.status == NQ_SUCCESS;
			}
			else
			{
				ccSetFilePointer(pFile, (NQ_INT32)offset.low, (NQ_INT32 *)&offset.high, SEEK_FILE_BEGIN);
				if (!ccFileReportDisconnect(pFile))
				{
				    cmThreadCondRelease(&cond);
					cmListItemGive((CMItem *)pFile);
					if (syGetLastError() != NQ_ERR_TIMEOUT)
						sySetLastError(NQ_ERR_RECONNECTREQUIRED);
					LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
					return FALSE;
				}
			}
		}
	}
	cmListItemGive((CMItem *)pFile);
	cmThreadCondRelease(&cond);    
	sySetLastError(NQ_ERR_TIMEOUT);
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return FALSE;
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
	
	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
	
	if (hndl == NULL)
	{
		sySetLastError(NQ_ERR_INVALIDHANDLE);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return FALSE;
	}
	pFile = (CCFile *)hndl;
	if (!pFile->open)
	{
		sySetLastError(NQ_ERR_INVALIDHANDLE);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return FALSE;
	}
	pServer = pFile->share->user->server;
	if (!ccTransportIsConnected(&pServer->transport) && !ccServerReconnect(pServer))
    {
		LOGERR(CM_TRC_LEVEL_ERROR, "Not connected");
		sySetLastError(NQ_ERR_NOTCONNECTED);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return FALSE;
    }
    pWrite = (AsyncWriteContext *)cmListItemCreateAndAdd(&pServer->async, sizeof(AsyncWriteContext), NULL, NULL , FALSE);
	if (NULL == pWrite)
	{
		sySetLastError(NQ_ERR_OUTOFMEMORY);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return FALSE;
	}
	pWrite->totalBytes = count;
	pWrite->actualBytes = 0;
	pWrite->numRequests = 0;
	pWrite->numResponses = 0;
	pWrite->status = NQ_SUCCESS;
	pWrite->callback = callback;
	pWrite->context = context;
    pWrite->server = pServer;
	maxWrite = pServer->maxWrite;

    
	pWrite->numRequests = bytesToWrite > maxWrite ? (bytesToWrite % maxWrite != 0 ? bytesToWrite / maxWrite +1 : bytesToWrite / maxWrite ):1;

	while (bytesToWrite > 0)
	{
		NQ_UINT writeNow = bytesToWrite <= maxWrite? bytesToWrite : maxWrite;
		
        for (counter = 0; counter < CC_CONFIG_RETRYCOUNT; counter++)
        {
            status = pServer->smb->doWrite(pFile, buffer, writeNow, asyncCallback, pWrite);
            if (NQ_ERR_RECONNECTREQUIRED == status)
            {
                pServer->transport.connected = FALSE;
                if (!ccServerReconnect(pServer))
                {
                    sySetLastError((NQ_UINT32)status);
                    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                    return FALSE;
                }
            }
            else
                break;
        }
		if (NQ_SUCCESS != status)
		{
			sySetLastError((NQ_UINT32)status);
			LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
			return FALSE;
		}
		bytesToWrite -= writeNow;
		cmU64AddU32(&pFile->offset, writeNow);
		buffer += writeNow;
	}
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return TRUE;
}

#endif /* UD_NQ_INCLUDECIFSCLIENT */
