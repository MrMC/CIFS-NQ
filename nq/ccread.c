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
#include "ccread.h"

#ifdef UD_NQ_INCLUDECIFSCLIENT

/* -- Static functions and data -- */

typedef struct
{
    CMItem item;            /* inherited */
	NQ_UINT32 totalBytes;	/* total bytes to read */
	NQ_UINT32 actualBytes;	/* actually read */
	NQ_UINT numRequests;	/* number of requests */
	NQ_UINT numResponses;	/* number of responses */
	NQ_STATUS status;		/* last status */
	void (* callback)(NQ_STATUS, NQ_UINT, void *);	/* application callback */
	void * context;			/* application context */
    CCServer * server;      /* used as a critical section */ 

/* using server as a critical section may be overkill, while using CCFile seems to be more appropriate. However,
   this saves locks/unlocks while it is effectively almost the same as using CCFile. */
}
AsyncReadContext;	/* write operation context */

typedef struct
{
	CMThreadCond * cond;	/* sync condition */
	NQ_UINT actualBytes;	/* actually read */
	NQ_STATUS status;		/* operation status */
}
SyncReadContext;	/* write operation context */

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
	AsyncReadContext * pRead;	/* context between an application and this module */

	pRead = (AsyncReadContext *)context;
    pRead->status = status;
	pRead->numResponses++;
	if (NQ_SUCCESS == status)
	{
		pRead->actualBytes += readSize;
	}
    if (pRead->numResponses == pRead->numRequests)
	{
		pRead->callback(status, pRead->actualBytes, pRead->context);
        cmListItemRemoveAndDispose(&pRead->item);
	}
}

/*
 * A callback on response (pipe)
 */
static void pipeCallback(NQ_STATUS status, NQ_UINT readSize, void * context, NQ_BOOL final)
{
	SyncReadContext * pRead;	/* context between an application and this module */

	pRead = (SyncReadContext *)context;
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
	SyncReadContext context;			/* application level context - we play application here */
	CMThreadCond cond;					/* sync condition */
	CCFile * pFile;                     /* casted pointer */
	NQ_UINT64 offset;					/* current file offset */
	NQ_INT i;							/* retry counter */
    CCServer * pServer;                 /* pointer to server */
	
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
	cmListItemTake((CMItem *)pFile);
	context.actualBytes = 0;
	if (!cmThreadCondSet(&cond))
    {
    	cmListItemGive((CMItem *)pFile);
		sySetLastError(NQ_ERR_OUTOFMEMORY);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return FALSE;
    }
	context.cond = &cond;
	for (i = CC_CONFIG_RETRYCOUNT; i > 0; i--)
    {
        if (pFile->isPipe)
        {
	        NQ_UINT bytesToRead = count;		/* number of bytes not read yet */
        	SyncReadContext read;			    /* pointer to operation context */
            const NQ_BYTE * pData = buffer;     /* pointer in the buffer */ 

            pFile->offset.low = 0;
            pFile->offset.high = 0;
            read.actualBytes = 0;
            read.cond = &cond;
            if (readSize != NULL)
                *readSize = 0;
	        while (bytesToRead > 0)
	        {
                NQ_STATUS status;           /* read operation status */
                NQ_UINT readNow;            /* next read size */
                
		        readNow = bytesToRead <= pServer->maxRead? bytesToRead : pServer->maxRead;
        		status = pServer->smb->doRead(pFile, pData, readNow, pipeCallback, &read);
		        if (NQ_SUCCESS != status)
		        {
                    cmThreadCondRelease(&cond);
					cmListItemGive((CMItem *)pFile);
			        sySetLastError((NQ_UINT32)status);
			        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
			        return FALSE;
		        }
		        cmThreadCondWait(&cond, ccConfigGetTimeout());
                if (NQ_ERR_PIPEBUSY == read.status)
		        {
		            NSSocketSet sockSet;
		            
    		        /* wait for 1 sec before retry */
                    nsClearSocketSet(&sockSet);
                    nsSelect(&sockSet, 1);
                    continue;
                }
		        if (NQ_SUCCESS != read.status)
		        {
                    cmThreadCondRelease(&cond);
					cmListItemGive((CMItem *)pFile);
			        sySetLastError((NQ_UINT32)status);
			        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
			        return FALSE;
		        }
                if (readSize != NULL)
                    *readSize += read.actualBytes;
                if (read.actualBytes < readNow || read.actualBytes == bytesToRead)

                {
                    cmThreadCondRelease(&cond);
					cmListItemGive((CMItem *)pFile);
			        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
			        return TRUE;
                }
		        pData += readNow;
                bytesToRead -= readNow;
			}
        }
        else
        {
            NQ_TIME adaptiveTimeout = ccConfigGetTimeout() * (count + pServer->maxRead) / pServer->maxRead; 

            offset = ccGetFilePointer(pFile);
		    if (   ccReadFileAsync(hndl, buffer, count,  &context, syncToAsyncCallback)
                && cmThreadCondWait(&cond, adaptiveTimeout)
		       )
		    {
		        if (readSize != NULL)
			        *readSize = context.actualBytes;
                cmThreadCondRelease(&cond);
				cmListItemGive((CMItem *)pFile);
			    sySetLastError((NQ_UINT32)context.status);
			    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
			    return NQ_SUCCESS == context.status;
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
    cmThreadCondRelease(&cond);
	cmListItemGive((CMItem *)pFile);
	sySetLastError(NQ_ERR_TIMEOUT);
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return FALSE;
}

NQ_BOOL ccReadFileAsync(NQ_HANDLE hndl, NQ_BYTE * buffer, NQ_UINT count, void * context, void (* callback)(NQ_STATUS, NQ_UINT, void *))
{
	AsyncReadContext *  pRead;			            /* pointer to operation context */
	NQ_UINT             bytesToRead = count;		/* number of bytes not read yet */
	CCFile *            pFile;                  	/* casted pointer */
	CCServer *          pServer;					/* pointer to respected server */
	NQ_UINT             maxRead;					/* read limit applied by server */
	NQ_STATUS           status;					    /* write status */
    NQ_INT              counter;                    /* simple counter */
	
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
    pRead = (AsyncReadContext *)cmListItemCreateAndAdd(&pServer->async, sizeof(AsyncReadContext), NULL, NULL, FALSE);
	if (NULL == pRead)
	{
		sySetLastError(NQ_ERR_OUTOFMEMORY);
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return FALSE;
	}
	pRead->totalBytes = count;
	pRead->actualBytes = 0;
	pRead->numRequests = 0;
	pRead->numResponses = 0;
	pRead->status = NQ_SUCCESS;
	pRead->callback = callback;
	pRead->context = context;
    pRead->server = pServer;
	maxRead = pServer->maxRead;
    
	pRead->numRequests = bytesToRead > maxRead ? (bytesToRead % maxRead != 0 ? bytesToRead / maxRead +1 : bytesToRead / maxRead ):1;
    
	while (bytesToRead > 0)
	{
		NQ_UINT readNow = bytesToRead <= maxRead? bytesToRead : maxRead;
		
        for (counter = 0; counter < CC_CONFIG_RETRYCOUNT; counter++)
        {
		    status = pServer->smb->doRead(pFile, buffer, readNow, asyncCallback, pRead);
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
		bytesToRead -= readNow;
		cmU64AddU32(&pFile->offset, readNow);
		buffer += readNow;
	}
    
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return TRUE;
}

#endif /* UD_NQ_INCLUDECIFSCLIENT */
