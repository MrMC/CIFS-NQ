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
#include "ccsmb20.h"
#include "cctransport.h"
#include "ccserver.h"
#include "ccuser.h"
#include "ccshare.h"
#include "ccfile.h"
#include "ccutils.h"
#include "ccerrors.h"
#include "ccparams.h"
#include "ccsmb2common.h"
#include "ccsearch.h"
#include "ccinfo.h"
#include "cmthread.h"
#include "cmfsutil.h"
#include "cmsmb2.h"
#include "cmbufman.h"
#include "cmcrypt.h"
#include "cmsdescr.h"
#include "ccsmb30.h"
#ifdef UD_NQ_INCLUDESMB311
#include "ccsmb311.h"
#endif /* UD_NQ_INCLUDESMB311 */
#include "nssocket.h"

#ifdef UD_NQ_INCLUDECIFSCLIENT
#ifdef UD_NQ_INCLUDESMB2

static NQ_WCHAR emptyFileName[] = { 0 };	        /* empty file name */

/* CCCifsSmb methods */
static void * allocateContext(CCServer * server);	
static void freeContext(void * context, void * server);	
static void setSolo(NQ_BOOL set);
static NQ_STATUS doNegotiate(CCServer * pServer, CMBlob * blob);
static NQ_STATUS doSessionSetup(CCUser * pUser, const CMBlob * pass1, const CMBlob * pass2);
static NQ_STATUS doSessionSetupExtended(CCUser * pUser, const CMBlob * outBlob, CMBlob * inBlob);
static NQ_STATUS doLogOff(CCUser * pUser);
static NQ_STATUS doTreeConnect(CCShare * pShare);
static NQ_STATUS doTreeDisconnect(CCShare * pShare);
static NQ_STATUS doCreate(CCFile * pFile);
static NQ_STATUS doRestoreHandle(CCFile * pFile);
static NQ_STATUS doClose(CCFile * pFile);
static NQ_STATUS doQueryDfsReferrals(CCShare * share, const NQ_WCHAR * path, CCCifsParseReferral parser, CMList * list);
static NQ_STATUS doFindOpen(CCSearch * pSearch);
static NQ_STATUS doFindMore(CCSearch * pSearch);
static NQ_STATUS doFindClose(CCSearch * pSearch);
static NQ_STATUS doWrite(CCFile * pFile, const NQ_BYTE * data, NQ_UINT bytesToWrite, CCCifsWriteCallback callback, void * context, void *hook);
static NQ_STATUS doRead(CCFile * pFile, const NQ_BYTE * data, NQ_UINT bytesToRead, CCCifsReadCallback callback, void * context, void *hook);
#ifdef UD_CC_INCLUDESECURITYDESCRIPTORS	
static NQ_STATUS doQuerySecurityDescriptor(CCFile * pFile, CMSdSecurityDescriptor * sd);
static NQ_STATUS doSetSecurityDescriptor(CCFile * pFile, const CMSdSecurityDescriptor * sd);
#endif /* UD_CC_INCLUDESECURITYDESCRIPTORS */
static NQ_STATUS doQueryFsInfo(CCShare * pShare, CCVolumeInfo * pInfo);
static NQ_STATUS doQueryFileInfoByName(CCShare * pShare, const NQ_WCHAR * fileName, CCFileInfo * pInfo);
static NQ_STATUS doQueryFileInfoByHandle(CCFile * pFile, CCFileInfo * pInfo);
static NQ_STATUS doSetFileAttributes(CCFile * pFile, NQ_UINT32 attributes);	
static NQ_STATUS doSetFileSize(CCFile * pFile, NQ_UINT64 size);	
static NQ_STATUS doSetFileTime(CCFile * pFile, NQ_UINT64 creationTime, NQ_UINT64 lastAccessTime, NQ_UINT64 lastWriteTime);	
static NQ_STATUS doSetFileDeleteOnClose(CCFile * pFile);	
static NQ_STATUS doRename(CCFile * pFile, const NQ_WCHAR * newName);	
static NQ_STATUS doFlush(CCFile * pFile);	
static NQ_STATUS doRapTransaction(void * pShare, const CMBlob * inData, CMBlob * outParams, CMBlob * outData);
static NQ_STATUS doEcho(CCShare * pShare);
static NQ_BOOL	 validateNegotiate(void *pServ, void *pUser, void *pShare);

/* notification handles */
static void handleBreakNotification(CCServer * pServer, Response * pResponse, CCFile *pFile);
static void handleWaitingNotifyResponse(void *pServer, void *pFile);

/* special call backs */
static void writeCallback(CCServer * pServer, Match * pContext);
static void readCallback(CCServer * pServer, Match * pContext);

static NQ_STATUS sendRequest(CCServer * pServer, CCUser * pUser, Request * pRequest, Match * pMatch, NQ_BOOL (*callback)(CMItem * pItem));
static NQ_STATUS sendReceive(CCServer * pServer, CCUser * pUser, Request * pRequest, Response * pResponse);
static void anyResponseCallback(void * transport);

static void fileInfoResponseParser(CMBufferReader * pReader, CCFileInfo * pInfo, NQ_BYTE level);
static void keyDerivation(void * user);
static void signalAllMatches(void * pTransport);
static NQ_BOOL removeReadWriteMatch(void * context, void *pServer, NQ_BOOL isReadMatch);
#ifdef UD_NQ_INCLUDESMB311
static NQ_STATUS smb311ReadNegotiateContexts(CMBufferReader *reader, CCServer *pServer, NQ_UINT16 contextCount);
#endif
/* -- Static data */

static const NQ_WCHAR rpcPrefix[] = { 0 };  /* value to prefix RPC pipe names */

static const CCCifsSmb dialect = 
{ 
        SMB2_DIALECTSTRING,
        SMB2_DIALECTREVISION,
        16,
		TRUE,
        rpcPrefix,
		(void * (*)(void *))allocateContext, 
		freeContext,  
        setSolo,
		(NQ_STATUS (*)(void *, CMBlob *))doNegotiate,
		(NQ_STATUS (*)(void *, const CMBlob *, const CMBlob *))doSessionSetup,
		(NQ_STATUS (*)(void *, const CMBlob *, CMBlob *))doSessionSetupExtended,
		(NQ_STATUS (*)(void *))doLogOff,
		(NQ_STATUS (*)(void *))doTreeConnect,
		(NQ_STATUS (*)(void *))doTreeDisconnect,
		(NQ_STATUS (*)(void *))doCreate,
		(NQ_STATUS (*)(void *))doRestoreHandle,
		(NQ_STATUS (*)(void *))doClose,
		(NQ_STATUS (*)(void *, const NQ_WCHAR *, CCCifsParseReferral, CMList *))doQueryDfsReferrals,
		(NQ_STATUS (*)(void *))doFindOpen,
		(NQ_STATUS (*)(void *))doFindMore,
		(NQ_STATUS (*)(void *))doFindClose,
		(NQ_STATUS (*)(void *, const NQ_BYTE *, NQ_UINT, CCCifsWriteCallback, void *, void *))doWrite,
		(NQ_STATUS (*)(void *, const NQ_BYTE *, NQ_UINT, CCCifsReadCallback, void *, void *))doRead,
#ifdef UD_CC_INCLUDESECURITYDESCRIPTORS	
		(NQ_STATUS (*)(void *, CMSdSecurityDescriptor *))doQuerySecurityDescriptor,
		(NQ_STATUS (*)(void *, const CMSdSecurityDescriptor *))doSetSecurityDescriptor,
#endif /* UD_CC_INCLUDESECURITYDESCRIPTORS */	
		(NQ_STATUS (*)(void *, void *))doQueryFsInfo, 
		(NQ_STATUS (*)(void *, const NQ_WCHAR *, void *))doQueryFileInfoByName,
		(NQ_STATUS (*)(void *, void *))doQueryFileInfoByHandle,
		(NQ_STATUS (*)(void *, NQ_UINT32))doSetFileAttributes,
		(NQ_STATUS (*)(void *, NQ_UINT64))doSetFileSize,
		(NQ_STATUS (*)(void *, NQ_UINT64, NQ_UINT64, NQ_UINT64))doSetFileTime,

		(NQ_STATUS (*)(void *))doSetFileDeleteOnClose,
		(NQ_STATUS (*)(void *, const NQ_WCHAR *))doRename,
		(NQ_STATUS (*)(void * pFile))doFlush,
		(NQ_STATUS(*)(void *, const CMBlob *, CMBlob *, CMBlob *))doRapTransaction,
        (NQ_STATUS (*)(void *))doEcho,
        (NQ_STATUS (*)(void * pServer, void * pUser, void * pRequest, void * pMatch, NQ_BOOL (*callback)(CMItem * pItem)))sendRequest,
		(NQ_STATUS (*)(void * pServer, void * pUser, void * pRequest, void * pResponse))sendReceive,
		anyResponseCallback,
		keyDerivation,
		signalAllMatches,
		handleWaitingNotifyResponse,
		validateNegotiate,
		removeReadWriteMatch,
        FALSE,
        TRUE
};

static const Command commandDescriptors[] = /* SMB2 descriptor */
{
#ifdef UD_NQ_INCLUDESMB311
	{ 190, 36, 65, NULL, NULL}, 				/* SMB2 NEGOTIATE 0x0000 with extra contexts */
#else
	{ 128, 36, 65, NULL, NULL}, 				/* SMB2 NEGOTIATE 0x0000 */
#endif
	{ 26, 25, 9, NULL, NULL},					/* SMB2 SESSION_SETUP 0x0001 */
	{ 6, 4, 4, NULL, NULL},					    /* SMB2 LOGOFF 0x0002 */
	{ 10, 9, 16, NULL, NULL},					/* SMB2 TREE_CONNECT 0x0003 */
	{ 6, 4, 4, NULL, NULL},					    /* SMB2 TREE_DISCONNECT 0x0004 */
	{ 4096, 57, 89, NULL, NULL},				/* SMB2 CREATE 0x0005 */
	{ 26, 24, 60, NULL, NULL},				    /* SMB2 CLOSE 0x0006 */
	{ 26, 24, 4, NULL, NULL},					/* SMB2 FLUSH 0x0007 */
	{ 64, 49, 17, readCallback, NULL},		    /* SMB2 READ 0x0008 */	 
	{ 64, 49, 17, writeCallback, NULL},		    /* SMB2 WRITE 0x0009 */		 
	{ 0, 0, 0, NULL, NULL},					    /* SMB2 LOCK 0x000A */		 
	{ 100, 57, 49, NULL, NULL},				    /* SMB2 IOCTL 0x000B */		 
	{ 0, 0, 0, NULL, NULL},					    /* SMB2 CANCEL 0x000C */		 
	{ 4, 4, 4, NULL, NULL},					    /* SMB2 ECHO 0x000D */		 
	{ 40, 33, 9, NULL, NULL},					/* SMB2 QUERY_DIRECTORY 0x000E */
	{ 0, 0, 0, NULL, NULL},					    /* SMB2 CHANGE_NOTIFY 0x000F */		 
	{ 44, 41, 9, NULL, NULL},					/* SMB2 QUERY_INFO 0x0010 */
	{ 80, 33, 2, NULL, NULL},					/* SMB2 SET_INFO 0x0011 */		 
	{ 100, 24, 0, NULL, handleBreakNotification },/* SMB2 OPLOCK_BREAK 0x0012 */ 
};


/* -- API Functions */

NQ_BOOL ccSmb20Start()
{
	return TRUE;
}

NQ_BOOL ccSmb20Shutdown()
{
	return TRUE;
}

const CCCifsSmb * ccSmb20GetCifs(void)
{
	return &dialect;
}

/* -- Static functions -- */

static void * allocateContext(CCServer * server)
{
	Context * pContext;
	if (NULL == (pContext = (Context *)cmMemoryAllocate(sizeof(Context))))
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
		goto Exit;
	}
	cmU64Zero(&pContext->mid);
    cmU64Inc(&pContext->mid);

Exit:
	return pContext;
}

static void freeContext(void * context, void * server)
{
	CCServer * pServer = (CCServer *)server;	/* casted pointer */
	Context * pContext = (Context *)context;
	
	if (NULL != pContext)
	{
		cmMemoryFree(context);
		pServer->smbContext = NULL;
	}
}

/*
 * Callback for unhandled break Item dispose:
 *  - free response memory
 */
static NQ_BOOL waitingResponseItemDispose(CMItem * pItem)
{
	waitingResponse *pRespItem = (waitingResponse *)pItem;

	cmBufManGive(pRespItem->notifyResponse->buffer);
	cmBufManGive((NQ_BYTE *)pRespItem->notifyResponse);
    return TRUE;
}

static void setSolo(NQ_BOOL set)
{
    /* do nothing */
}

#ifdef UD_NQ_INCLUDESMB3
static NQ_UINT16 calculateCreditCharge(CCServer * pServer, NQ_UINT32 requestLength)
{
    NQ_UINT16 creditCharge;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "server:%p requestLength:%d", pServer, requestLength);
    
    creditCharge = (NQ_UINT16)((requestLength > 0) ? (1 + ((requestLength - 1) / 65536)) : 1);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "credit charge:%d", creditCharge);
    return creditCharge;
}
#endif /* UD_NQ_INCLUDESMB3 */

static NQ_BOOL prepareSingleRequest(CCServer * pServer, CCUser * pUser, Request * pRequest, NQ_UINT16 command)
{
	NQ_BYTE * pBuffer;		/* allocated request buffer */ 
	NQ_COUNT bufferSize;	/* this buffer size */
	NQ_BOOL result = FALSE; /* return value */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "server:%p user:%p request:%p command:0x%x", pServer, pUser, pRequest, command);

	/* this call:
	 * - allocates request buffer
	 * - creates request header
	 */
	/* allocate buffer for request */
	bufferSize = (NQ_COUNT)(commandDescriptors[command].requestBufferSize + SMB2_HEADERSIZE + 4);
	pBuffer = cmBufManTake(bufferSize);
	if (NULL == pBuffer)
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
		goto Exit;
	}
	cmBufferWriterInit(&pRequest->writer, pBuffer, bufferSize);
	pRequest->buffer = pBuffer;
	pRequest->command = command;
	pRequest->tail.data = NULL;
	pRequest->tail.len = 0;
	pRequest->encrypt = (NULL == pUser) ? FALSE : pUser->isEncrypted;
	cmBufferWriterSkip(&pRequest->writer, 4);	/* NBT header */
	cmSmb2HeaderInitForRequest(&pRequest->header, &pRequest->writer, command);
#ifdef UD_NQ_INCLUDESMB3
    if (pServer && (pServer->capabilities & CC_CAP_LARGEMTU))
    {
        pRequest->header.creditCharge = 1;
    }
#endif /* UD_NQ_INCLUDESMB3 */
	if (NULL == pUser)
    {
        pRequest->header.sid.low = 0;
        pRequest->header.sid.high = 0;
    }
    else
    {
        pRequest->header.sid = pUser->uid;
    }
    pRequest->header.flags = (NQ_UINT16)((command != SMB2_CMD_SESSIONSETUP && pServer && ccServerUseSignatures(pServer) && pUser && ccUserUseSignatures(pUser))
                                ? SMB2_FLAG_SIGNED : 0
#ifdef UD_CC_INCLUDEDFS
                                | ((pServer && (pServer->capabilities & CC_CAP_DFS)) ? SMB2_FLAG_DFS_OPERATIONS : 0)
#endif /* UD_CC_INCLUDEDFS */                               
                                );
	result = TRUE;

Exit:
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE");
	return result;
}

static NQ_BOOL prepareSingleRequestByShare(Request * pRequest, const CCShare * pShare, NQ_UINT16 command, NQ_UINT32 dataLen)
{
	NQ_BOOL result = FALSE;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "pRequest:%p pShare:%p command:0x%X dataLen:%d", pRequest, pShare, command, dataLen);

	if (!prepareSingleRequest(pShare->user->server, pShare->user, pRequest, command))
	{
		goto Exit;
	}
	pRequest->encrypt = pShare->user->isEncrypted ? TRUE : pShare->encrypt;
#ifdef UD_CC_INCLUDEDFS
    if (pShare->flags & CC_SHARE_IN_DFS)
        pRequest->header.flags |= SMB2_FLAG_DFS_OPERATIONS;
    else
        pRequest->header.flags =  (NQ_UINT32)(pRequest->header.flags & (NQ_UINT32)~SMB2_FLAG_DFS_OPERATIONS);
#endif /* UD_CC_INCLUDEDFS */
#ifdef UD_NQ_INCLUDESMB3
    if (pShare->user->server->capabilities & CC_CAP_LARGEMTU)
    {
        switch (command)
        {
        case SMB2_CMD_READ:
        case SMB2_CMD_WRITE:
        case SMB2_CMD_QUERYDIRECTORY:
            pRequest->header.creditCharge = calculateCreditCharge(pShare->user->server, dataLen);
            break;
        default:
            pRequest->header.creditCharge = 1;
            break;
        } 
        if (pRequest->header.creditCharge > 1)
            pRequest->header.credits = pRequest->header.creditCharge;
    }
#endif /* UD_NQ_INCLUDESMB3 */
	pRequest->header.tid = pShare->tid;
	result = TRUE;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE");
	return result;
}

static void writeHeader(Request * pRequest)
{
	cmSmb2HeaderWrite(&pRequest->header, &pRequest->writer);
	cmBufferWriteUint16(&pRequest->writer, commandDescriptors[pRequest->command].requestStructSize);
}

static NQ_STATUS sendRequest(CCServer * pServer, CCUser * pUser, Request * pRequest, Match * pMatch, NQ_BOOL (*callback)(CMItem * pItem))
{
	NQ_UINT32 packetLen;              /* packet length of both in and out packets */
	CMBufferWriter writer;            /* to write down MID */
    Context * pContext;               /* server context */
	NQ_STATUS result = NQ_SUCCESS;    /* return value */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "server:%p user:%p request:%p match:%p", pServer, pUser, pRequest, pMatch);

	if (NULL == pServer->smbContext)
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "smbContext in CCServer object is missing");
        result = NQ_ERR_NOTCONNECTED;
        goto Exit;
	}

	if (!ccServerWaitForCredits(pServer, 1))
    {
        result = NQ_ERR_TIMEOUT;
        goto Exit;
    }

	cmListItemTake(&pServer->item);
	ccTransportLock(&pServer->transport);


    if (!pServer->transport.connected || !pUser->logged)
	{
		if (!pServer->transport.connected)
		{
			LOGERR(CM_TRC_LEVEL_ERROR, " transport isn't connected");
			result = NQ_ERR_NOTCONNECTED;
			goto Exit1;
		}
		if (!pUser->logged && pRequest->header.command != SMB2_CMD_SESSIONSETUP)
		{
			LOGERR(CM_TRC_LEVEL_ERROR, "User: %s isn't logged, probably reconnect failed.", cmWDump(pUser->credentials->user));
			result = NQ_ERR_NOTCONNECTED;
			goto Exit1;
		}
	}

    /* set response as not received */
    pMatch->response->wasReceived = FALSE;

    /* write down MID */
    pContext = (Context *)pServer->smbContext;
    pRequest->header.mid = pMatch->mid = pContext->mid;
    packetLen = cmBufferWriterGetDataCount(&pRequest->writer) - 4;	/* NBT header */
    cmBufferWriterInit(&writer, pRequest->buffer + SEQNUMBEROFFSET, (NQ_COUNT)packetLen);
    cmBufferWriteUint64(&writer, &pContext->mid);
    
    /* add match to list only after mid was set */
    cmListItemAdd(&pServer->expectedResponses, (CMItem *)pMatch, callback);

    /* prepare MID for next request */
    cmU64Inc(&pContext->mid);
     
	/* compose signature */
	if (ccServerUseSignatures(pServer) && ccUserUseSignatures(pUser) && (pRequest->header.command != SMB2_CMD_SESSIONSETUP))
	{
		cmSmb2CalculateMessageSignature(
			pUser->macSessionKey.data, 
			pUser->macSessionKey.len, 
			pRequest->buffer + 4, 
			(NQ_UINT)packetLen,
			pRequest->tail.data,
			pRequest->tail.len, 
			pRequest->header._start + SMB2_SECURITY_SIGNATURE_OFFSET
			);
	}
	
#ifdef UD_NQ_INCLUDESMBCAPTURE
    pServer->captureHdr.receiving = FALSE;
    cmCapturePacketWriteStart(&pServer->captureHdr , (NQ_UINT)(packetLen + pRequest->tail.len));
    cmCapturePacketWritePacket( pRequest->buffer + 4, (NQ_UINT)packetLen);
    if (pRequest->tail.len > 0)
    	cmCapturePacketWritePacket(pRequest->tail.data, pRequest->tail.len);
    cmCapturePacketWriteEnd();
#endif /* UD_NQ_INCLUDESMBCAPTURE */
    
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Request: command=%u, credit charge=%d, credits req=%d, mid=%u/%u, sid.low=0x%x, signed:%d, async:%d, pid(async.high)=0x%x, tid(async.low)=0x%x",
        pRequest->header.command, pRequest->header.creditCharge, pRequest->header.credits, pRequest->header.mid.high, pRequest->header.mid.low, pRequest->header.sid.low, (pRequest->header.flags & SMB2_FLAG_SIGNED) > 0,
        (pRequest->header.flags & SMB2_FLAG_ASYNC_COMMAND) > 0,
        pRequest->header.flags & SMB2_FLAG_ASYNC_COMMAND ? pRequest->header.aid.high : pRequest->header.pid,
        pRequest->header.flags & SMB2_FLAG_ASYNC_COMMAND ? pRequest->header.aid.low : pRequest->header.tid);

	if (!ccTransportSend(
			&pServer->transport, 
			pRequest->buffer, 
			(NQ_COUNT)(packetLen + pRequest->tail.len),
			(NQ_COUNT)packetLen
			)
		)
	{

        result = (NQ_STATUS)syGetLastError();
        goto Exit1;
	}

	if (0 != pRequest->tail.len && 
		!ccTransportSendTail(&pServer->transport, pRequest->tail.data, pRequest->tail.len)
		)
	{

        result = (NQ_STATUS)syGetLastError();

	}

Exit1:
	ccTransportUnlock(&pServer->transport);

Exit:
	cmListItemGive(&pServer->item);
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
	return result;
}

static NQ_STATUS sendReceive(CCServer * pServer, CCUser * pUser, Request * pRequest, Response * pResponse)
{
	NQ_STATUS res;				/* send result */
    CMThread * pThread;         /* current thread */
    Match * pMatch;             /* match structure pointer */
	
	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "server:%p user:%p request:%p response:%p", pServer, pUser, pRequest, pResponse);

	pResponse->buffer = NULL;
    pThread = cmThreadGetCurrent();
    if (NULL == pThread)
    {
		LOGERR(CM_TRC_LEVEL_ERROR, ">>>No thread object.");
		res = NQ_ERR_GETDATA;
		goto Exit;
	}

    pMatch = (Match *)cmThreadGetContextAsStatItem(pThread, sizeof(Match));
    if (NULL == pMatch)
    {
		LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
		res = NQ_ERR_OUTOFMEMORY;
		goto Exit;
    }

    pMatch->thread = pThread;
	pMatch->response = pResponse;
	pMatch->cond = &pThread->syncCond;
    pMatch->server = pServer; 
    pMatch->isResponseAllocated = FALSE;
    pMatch->item.guard = NULL;
    pMatch->matchExtraInfo = MATCHINFO_NONE;

	cmThreadCondClear(pMatch->cond); /* Cleaning up the condition socket before sending*/

	res = pServer->smb->sendRequest(pServer, pUser, pRequest, pMatch, NULL);
	if (NQ_SUCCESS != res)
	{
		if (NULL != pMatch->thread->element.item.guard)
		{
			syMutexDelete(pMatch->thread->element.item.guard);
			cmMemoryFree(pMatch->thread->element.item.guard);
			pMatch->thread->element.item.guard = NULL;
		}
	    cmListItemRemove((CMItem *)pMatch);
		goto Exit;
	}
	
    if (!cmThreadCondWait(pMatch->cond, ccConfigGetTimeout()))
	{
    	pServer->smb->signalAllMatch(&pServer->transport);
		if ((!pServer->transport.connected || NULL == pResponse->buffer) 
            && pRequest->command != SMB2_CMD_NEGOTIATE && pRequest->command != SMB2_CMD_SESSIONSETUP
           )
        {
            if (!ccServerReconnect(pServer))
            {
				res = NQ_ERR_NOTCONNECTED;
				goto Exit;
            }
        }
		res = NQ_ERR_TIMEOUT;
		goto Exit;
	}

    if (pServer->connectionBroke)
	{
		if (!ccServerReconnect(pServer))
		{
			res = NQ_ERR_NOTCONNECTED;
			goto Exit;
		}

		cmListItemTake((CMItem *) pServer);
		pServer->connectionBroke = FALSE;
		cmListItemGive((CMItem *)pServer);
		res = NQ_ERR_TIMEOUT;
		goto Exit;
	}

	/* check connection */
    if (!pServer->transport.connected)
    {
    	pServer->smb->signalAllMatch(&pServer->transport);
        if (pRequest->command != SMB2_CMD_NEGOTIATE && pRequest->command != SMB2_CMD_SESSIONSETUP)
        {
            if (ccServerReconnect(pServer))
            {
				/* simulate timeout - causing retry */
				res = NQ_ERR_TIMEOUT;
				goto Exit;
            }
        }
		res = NQ_ERR_NOTCONNECTED;
		goto Exit;
    }

    if (FALSE == pMatch->response->wasReceived)
	{
		if (NULL != pMatch->thread->element.item.guard)
		{
			syMutexDelete(pMatch->thread->element.item.guard);
			cmMemoryFree(pMatch->thread->element.item.guard);
			pMatch->thread->element.item.guard = NULL;
		}
		res = NQ_ERR_GETDATA;
		cmListItemRemove((CMItem *)pMatch);
		goto Exit;
	}

    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Response: command=%u, credit charge=%d, credits granted=%d, mid=%u/%u, sid.low=0x%x, status=0x%x, signed:%d, async:%d, pid(async.high)=0x%x, tid(async.low)=0x%x",
        pResponse->header.command, pResponse->header.creditCharge, pResponse->header.credits, pResponse->header.mid.high, pResponse->header.mid.low, pResponse->header.sid.low, pResponse->header.status, (pResponse->header.flags & SMB2_FLAG_SIGNED) > 0,
        (pResponse->header.flags & SMB2_FLAG_ASYNC_COMMAND) > 0,
        pResponse->header.flags & SMB2_FLAG_ASYNC_COMMAND ? pResponse->header.aid.high : pResponse->header.pid,
        pResponse->header.flags & SMB2_FLAG_ASYNC_COMMAND ? pResponse->header.aid.low : pResponse->header.tid);

    /* check signatures */
    if (ccServerUseSignatures(pServer) && ccUserUseSignatures(pUser) 
        && (pResponse->header.flags & SMB2_FLAG_SIGNED) && (pResponse->header.command != SMB2_CMD_SESSIONSETUP))
	{
		NQ_BYTE * pSignature = pMatch->hdrBuf + SMB2_SECURITY_SIGNATURE_OFFSET;
		
		cmSmb2CalculateMessageSignature(
			pUser->macSessionKey.data, 
			pUser->macSessionKey.len,
            pMatch->hdrBuf,
            HEADERANDSTRUCT_SIZE,
			pResponse->buffer, 
			pResponse->tailLen, 
			pSignature
			);
		if (0 != syMemcmp(pResponse->header.signature, pSignature, sizeof(pResponse->header.signature)))
		{
     		LOGERR(CM_TRC_LEVEL_ERROR, "bad incoming signature");
			res = NQ_ERR_SIGNATUREFAIL;
			goto Exit;
		}
	}

	res = (NQ_STATUS)ccErrorsStatusToNq(pResponse->header.status, TRUE);	
	sySetLastError((NQ_UINT32)res);

Exit:
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", res);
	return res;
}

static NQ_STATUS exchangeEmptyCommand(CCShare * pShare, NQ_UINT16 command)
{
	Request request;		/* request descriptor */
	Response response;		/* response descriptor */
	CCServer * pServer;		/* server object pointer */

	NQ_STATUS res;			/* exchange status */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "share:%p command:0x%x", pShare, command);

	pServer = pShare->user->server;
	if (!prepareSingleRequestByShare(&request, pShare, command, 0))
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
		res = NQ_ERR_OUTOFMEMORY;
		goto Exit;
	}
	
	/* compose request */
	writeHeader(&request);
	cmBufferWriteUint16(&request.writer, 0);		/* reserved */
	request.tail.len = 0;
	request.tail.data = NULL;
	
	res = pServer->smb->sendReceive(pServer, pShare->user, &request, &response);
	cmBufManGive(request.buffer);
	cmBufManGive(response.buffer);

Exit:
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", res);
	return res;
}

/*
	 * Server sends notify responses == response without request. Ex: break notification
	 * If file ID for sent response isn't found. we save the response and try again on newly created files.
	 * To avoid missing a break notification that is handled while file creation on our side still in process.
	 */
static void handleWaitingNotifyResponse(void *pserver, void *pfile)
{
	CMIterator responseIterator;
	CCServer * pServer = (CCServer *)pserver;
	CCFile *pFile = (CCFile *) pfile;

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	cmListIteratorStart(&pServer->waitingNotifyResponses, &responseIterator);

	while(cmListIteratorHasNext(&responseIterator))
	{
		waitingResponse *pResponsItem;
		pResponsItem = (waitingResponse *) cmListIteratorNext(&responseIterator);
		if (0 == syMemcmp(pResponsItem->fid, pFile->fid, sizeof(pFile->fid)))
		{
			/* parse notification */
			if(NULL == commandDescriptors[pResponsItem->notifyResponse->header.command].notificationHandle)
			{
				LOGERR(CM_TRC_LEVEL_ERROR, "Wrong response saved in list, %d", pResponsItem->notifyResponse->header.command);
				cmListIteratorTerminate(&responseIterator);
				goto Exit;
			}
			LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Handling waiting response.");
			commandDescriptors[pResponsItem->notifyResponse->header.command].notificationHandle(pServer, pResponsItem->notifyResponse, pFile);
			cmListItemRemoveAndDispose((CMItem *)pResponsItem);
		}
	}
	cmListIteratorTerminate(&responseIterator);
Exit:

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

static void handleBreakNotification(CCServer * pServer, Response * notifyResponse, CCFile *pFile)
{
	Request request;		    /* request descriptor */
	NQ_COUNT packetLen;		    /* packet length of both in and out packets */
    NQ_BYTE oplockLevel;        /* new oplock level */
    CCUser * pUser;             /* user pointer */
    CCShare * pShare;           /* share pointer */
    Context * pContext;         /* SMB context */
    NQ_UINT64   negMid = {0xffffffff , 0xffffffff}; /* -1 mid */
	
	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "server:%p response:%p", pServer, notifyResponse);

    /* parse notification */
    cmBufferReadByte(&notifyResponse->reader, &oplockLevel);	/* oplock */

    if ((SMB2_OPLOCK_LEVEL_NONE == oplockLevel && pFile->grantedOplock == SMB2_OPLOCK_LEVEL_II)|| cmU64Cmp(&notifyResponse->header.mid ,&negMid )!= 0)
    {
    	/* don't have to reply - only update oplock */
    	pFile->grantedOplock = oplockLevel;
        goto Exit;
    }
    pFile->grantedOplock = oplockLevel;
    if (pFile->durableState == DURABLE_GRANTED)
    {
    	pFile->durableState = DURABLE_CANCELED;
    	pFile->durableFlags = 0;
    	cmGenerateUuid(&pFile->durableHandle); /* New Handle*/
    }

    pShare = pFile->share;
    pUser = pShare->user;

    /* compose ack */
	if (!prepareSingleRequestByShare(&request, pShare, SMB2_CMD_OPLOCKBREAK, 0))
	{
		goto Exit;
	}

	writeHeader(&request);
	cmBufferWriteByte(&request.writer, oplockLevel);        /* oplock */
	cmBufferWriteZeroes(&request.writer, 5);	            /* reserved + reserved 2 */
	cmBufferWriteBytes(&request.writer, pFile->fid, sizeof(pFile->fid));/* file id */
	packetLen = cmBufferWriterGetDataCount(&request.writer) - 4;	/* NBT header */

    /* write down MID */
    pContext = (Context *)pServer->smbContext;
    request.header.mid = pContext->mid;
    cmBufferWriterSetPosition(&request.writer, request.buffer + SEQNUMBEROFFSET);
    cmBufferWriteUint64(&request.writer, &pContext->mid);

    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Request: command=%u, credit charge=%d, credits req=%d, mid=%u/%u, sid.low=0x%x, signed:%d, async:%d, pid(async.high)=0x%x, tid(async.low)=0x%x",
        request.header.command, request.header.creditCharge, request.header.credits, request.header.mid.high, request.header.mid.low, request.header.sid.low, (request.header.flags & SMB2_FLAG_SIGNED) > 0,
        (request.header.flags & SMB2_FLAG_ASYNC_COMMAND) > 0,
        request.header.flags & SMB2_FLAG_ASYNC_COMMAND ? request.header.aid.high : request.header.pid,
        request.header.flags & SMB2_FLAG_ASYNC_COMMAND ? request.header.aid.low : request.header.tid);

    /* prepare MID for next request */
    cmU64Inc(&pContext->mid);

	/* compose signature */
	if (ccServerUseSignatures(pServer) && ccUserUseSignatures(pUser))
	{
		cmSmb2CalculateMessageSignature(
			pUser->macSessionKey.data, 
			pUser->macSessionKey.len, 
			request.buffer + 4, 
			packetLen, 
			NULL,
			0, 
			request.header._start + SMB2_SECURITY_SIGNATURE_OFFSET
			);
	}

#ifdef UD_NQ_INCLUDESMBCAPTURE
    pServer->captureHdr.receiving = FALSE;
    cmCapturePacketWriteStart(&pServer->captureHdr , packetLen);
    cmCapturePacketWritePacket( request.buffer + 4, packetLen);
    cmCapturePacketWriteEnd();
#endif /* UD_NQ_INCLUDESMBCAPTURE */
    /* send and receive. Since we running inside the receiving thread - this is done inlined */
    ccTransportLock(&pServer->transport);
	if (!ccTransportSendSync(
			&pServer->transport, 
			request.buffer, 
			packetLen,
			packetLen
			)
		)
	{
        ccTransportUnlock(&pServer->transport);
		cmBufManGive(request.buffer);
		goto Exit;
	}
    ccTransportUnlock(&pServer->transport);
	cmBufManGive(request.buffer);

Exit:
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	return;	
}

static void handleNotification(CCServer *pServer, CMSmb2Header *header )
{
	Response* pResponse;
	NQ_BYTE * pFid;             				/* pointer to file ID in the notification */
	CCFile *pFile;
#ifdef UD_NQ_INCLUDESMBCAPTURE
	NQ_BOOL closePacketCapture = TRUE;
#endif

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	/* this is a notification == response without request */
	pResponse = (Response *) cmBufManTake(sizeof (Response));
	if (NULL == pResponse)
	{
		sySetLastError(NQ_ERR_NOMEM);
		LOGERR(CM_TRC_LEVEL_ERROR, "Allocating memory for waiting response failed.");
		goto Exit;
	}

	if (pServer->transport.recv.remaining > 0)
	{
		if (pServer->smbContext == NULL)
		{
			LOGERR(CM_TRC_LEVEL_ERROR, " smbContext in CCServer object is missing");
			goto Exit;
		}

		pResponse->tailLen = pServer->transport.recv.remaining;
		pResponse->buffer = (NQ_BYTE *)cmBufManTake(pResponse->tailLen);
		if (NULL == pResponse->buffer)
		{
			sySetLastError(NQ_ERR_NOMEM);
			LOGERR(CM_TRC_LEVEL_ERROR, "Allocating memory for waiting response failed.");
			goto Exit2;
		}

		if (pResponse->tailLen != ccTransportReceiveBytes(&pServer->transport, pResponse->buffer, pResponse->tailLen))
		{
			LOGERR(CM_TRC_LEVEL_ERROR, "Transport receive failure.");
			goto Exit2;
		}
#ifdef UD_NQ_INCLUDESMBCAPTURE
		cmCapturePacketWritePacket(pResponse->buffer, pResponse->tailLen);
		cmCapturePacketWriteEnd();
		closePacketCapture = FALSE;
#endif /* UD_NQ_INCLUDESMBCAPTURE */
	}

	ccTransportReceiveEnd(&pServer->transport);

	cmBufferReaderInit(&pResponse->reader, pResponse->buffer, pResponse->tailLen);

	pResponse->header = *header;

	/* parse notification and find fid */
	cmBufferReaderSkip(&pResponse->reader, 6);	/* oplock + reserved + reserved 2 */
	pFid = cmBufferReaderGetPosition(&pResponse->reader);

	/* init reader again to take it back to start of packet */
	cmBufferReaderInit(&pResponse->reader, pResponse->buffer, pResponse->tailLen);

	cmListItemTake((CMItem *)pServer);

	/* prepare objects */
	pFile = ccFileFindById(pServer, pFid);
	if (NULL == pFile)
	{
		/* save this response for later handling. relevant file create might be happening concurrently */
		waitingResponse *pWaitingResponse;

		LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "File ID not found, saving response.");
		pWaitingResponse = (waitingResponse *) cmListItemCreateAndAdd(&pServer->waitingNotifyResponses, sizeof(waitingResponse),
					NULL, waitingResponseItemDispose, CM_LISTITEM_NOLOCK);

		cmListItemGive((CMItem *)pServer);
		if (NULL == pWaitingResponse)
		{
			sySetLastError(NQ_ERR_NOMEM);
			LOGERR(CM_TRC_LEVEL_ERROR, "Allocating memory for waiting response failed.");
			goto Exit1;
		}

		pWaitingResponse->notifyResponse = pResponse;
		syMemcpy(pWaitingResponse->fid, pFid, sizeof(pWaitingResponse->fid));

		goto Exit;
	}

	cmListItemGive((CMItem *)pServer);
	/* file found - handle notification message */
	commandDescriptors[header->command].notificationHandle(pServer, pResponse, pFile);

	goto Exit1;

Exit2:
	ccTransportReceiveEnd(&pServer->transport);

Exit1:
	cmBufManGive((NQ_BYTE *)pResponse->buffer);
	cmBufManGive((NQ_BYTE *)pResponse);

Exit:
#ifdef UD_NQ_INCLUDESMBCAPTURE
	if(closePacketCapture)
	{
		cmCapturePacketWriteEnd();
	}
#endif /* UD_NQ_INCLUDESMBCAPTURE */

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

static void anyResponseCallback(void * transport)
{
	CCTransport * pTransport = (CCTransport *)transport; 	/* casted to transport entry */
	CCServer * pServer;							/* casted pointer */
	CMIterator iterator;						/* iterates through expected responses */
	CMSmb2Header header;						/* response header */
	CMBufferReader reader;						/* to parse header */
	NQ_COUNT res;								/* bytes read */
	NQ_BYTE buffer[HEADERANDSTRUCT_SIZE];		/* header + struct size */
	
	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "transport:%p", transport);

	pServer = (CCServer *)pTransport->context;
	
	if (!pTransport->connected) /* proceed disconnect */
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "Connection broken with %s", cmWDump(pServer->item.name));

		/* match with request */
		cmListItemTake((CMItem *)pServer);
		cmListIteratorStart(&pServer->expectedResponses, &iterator);
		while (cmListIteratorHasNext(&iterator))
		{
			Match * pMatch;

			pMatch = (Match *)cmListIteratorNext(&iterator);
			if (pMatch->cond != NULL)
				cmThreadCondSignal(pMatch->cond);
			if (pMatch->isResponseAllocated)
			{
				cmMemoryFree(pMatch->response);
				pMatch->response = NULL;
			}
		}
		cmListIteratorTerminate(&iterator);
		if (NULL != pTransport->cleanupCallback)
			(*pTransport->cleanupCallback)(pTransport->cleanupContext);
		cmListItemGive((CMItem *)pServer);

		LOGERR(CM_TRC_LEVEL_ERROR, "Response not matched. server: %s", cmWDump(pServer->item.name));
		goto Exit1;
	}

    /* read & parse SMB header */
	res = ccTransportReceiveBytes(pTransport, buffer, sizeof(buffer));
	if ((NQ_COUNT) NQ_FAIL == res)
	{
        goto Exit1;
	}
    if (0 != syMemcmp(buffer, cmSmb2ProtocolId, sizeof(cmSmb2ProtocolId)))
    {
		goto Exit1;
    }

#ifdef UD_NQ_INCLUDESMBCAPTURE
	pServer->captureHdr.receiving = TRUE;
	cmCapturePacketWriteStart(&pServer->captureHdr , (NQ_UINT)(HEADERANDSTRUCT_SIZE + pServer->transport.recv.remaining));
	cmCapturePacketWritePacket( buffer, HEADERANDSTRUCT_SIZE);
#endif /* UD_NQ_INCLUDESMBCAPTURE */

	cmBufferReaderInit(&reader, buffer, res); /* starting from SMB header */
	cmSmb2HeaderRead(&header, &reader);
	/* match with request */
	cmListIteratorStart(&pServer->expectedResponses, &iterator);
	while (cmListIteratorHasNext(&iterator))
	{
		Match * pMatch;
		
		pMatch = (Match *)cmListIteratorNext(&iterator);
		if (pMatch->server == pServer && 0 == cmU64Cmp(&pMatch->mid, &header.mid)) 
		{
			NQ_UINT16 length;			/* structure length */
			
			cmListIteratorTerminate(&iterator);
   			pMatch->response->header = header; /* header start address will be wrong */
			cmBufferReadUint16(&reader, &length); /* structure size */
			if (SMB_STATUS_SUCCESS == header.status && length != commandDescriptors[header.command].responseStructSize)
			{
				LOGERR( CM_TRC_LEVEL_ERROR, 
						"Unexpected structure length in response: %d, expected %d command %d",
						length,
						commandDescriptors[header.command].responseStructSize,
						header.command
						);
				pMatch->response->header.status = SMB_STATUS_INVALID;
			}

			/* check for interim response */
			if ((header.flags & SMB2_FLAG_ASYNC_COMMAND) && (header.status == SMB_STATUS_PENDING))
			{
#ifdef UD_NQ_INCLUDESMBCAPTURE
				NQ_BYTE * tempBuf;
				NQ_COUNT len = 0;

				len = pServer->transport.recv.remaining;
				tempBuf = (NQ_BYTE *)cmMemoryAllocate(len);
				ccTransportReceiveBytes(&pServer->transport, tempBuf, len);
				cmCapturePacketWritePacket(tempBuf , len);
				cmCapturePacketWriteEnd();
				cmMemoryFree(tempBuf);
#endif /* UD_NQ_INCLUDESMBCAPTURE */
				ccTransportReceiveEnd(pTransport);

				if (header.command == SMB2_CMD_WRITE || header.command == SMB2_CMD_READ)
				{
					WriteMatch	*	wMatch = NULL;
					void 		**	tmp = NULL;
					NQ_BOOL		*	isPending = NULL;

					wMatch = (WriteMatch *)pMatch;

					tmp = (void **)((CMItem *)wMatch->context + 1);
					isPending = (NQ_BOOL *)*tmp;

					*isPending = TRUE;

					/* when pending response received the timeout is extended. */
					wMatch->setTimeout = wMatch->setTimeout + (wMatch->setTimeout * PENDING_TIMEOUT_EXTENTION);
				}
			}
			else
			{
				cmListItemRemove((CMItem *)pMatch);
				if (pServer->useSigning)
					syMemcpy(pMatch->hdrBuf, buffer, HEADERANDSTRUCT_SIZE);
                pMatch->thread->status = header.status;
                if (NULL != commandDescriptors[header.command].callback)
				{
                	pMatch->response->tailLen = pServer->transport.recv.remaining;
					commandDescriptors[header.command].callback(pServer, pMatch);
				}
				else
				{	
   	                if (pServer->transport.recv.remaining > 0)
	                {
                        Response * pResponse = pMatch->response;  /* associated response */
		                pResponse->tailLen = pServer->transport.recv.remaining;
		                pResponse->buffer = cmBufManTake(pResponse->tailLen);
		                if (NULL != pResponse->buffer)
		                {
		                    if (pResponse->tailLen == ccTransportReceiveBytes(&pServer->transport, pResponse->buffer, pResponse->tailLen))
		                    {
#ifdef UD_NQ_INCLUDESMBCAPTURE
								cmCapturePacketWritePacket( pResponse->buffer, pResponse->tailLen);
#endif /* UD_NQ_INCLUDESMBCAPTURE */
		                        cmBufferReaderInit(&pResponse->reader, pResponse->buffer, pResponse->tailLen);
		                        pResponse->header._start = 	/* set virtual header start */
			                        pResponse->buffer - 
			                        HEADERANDSTRUCT_SIZE;	/* shift back on header size and more structure size */
                            }
                        }
                    }
   	                else
					{
						pMatch->response->tailLen = 0;
					}
#ifdef UD_NQ_INCLUDESMBCAPTURE
					cmCapturePacketWriteEnd();
#endif /* UD_NQ_INCLUDESMBCAPTURE */
	                ccTransportReceiveEnd(&pServer->transport);

	                pMatch->response->wasReceived = TRUE;
					cmThreadCondSignal(pMatch->cond);
				}
			}
            if (header.credits > 0)
                ccServerPostCredits(pServer, header.credits);

			goto Exit;
		}
	}
	cmListIteratorTerminate(&iterator);

	/* No match request matched this response, check if notification message */
    if (NULL != commandDescriptors[header.command].notificationHandle)
    {
    	handleNotification(pServer, &header);
    	goto Exit;
    }
    else
    {
#ifdef UD_NQ_INCLUDESMBCAPTURE
    	cmCapturePacketWriteEnd();
#endif /* UD_NQ_INCLUDESMBCAPTURE */
		/* not matched but recieved credits are still ours. */
    	if (header.credits > 0)
    		ccServerPostCredits(pServer, header.credits);
    	LOGERR(CM_TRC_LEVEL_ERROR, "Response not matched. Mid: %d:%d server: %s", header.mid.high, header.mid.low, cmWDump(pServer->item.name));
    }

Exit1:
	ccTransportReceiveEnd(&pServer->transport);

Exit:

	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

static NQ_STATUS writeQueryInfoRequest(
		Request * pRequest,
		CCFile * pFile,
		NQ_BYTE infoType, 
		NQ_BYTE infoClass, 
		NQ_UINT32 maxResLen,
		NQ_UINT32 addInfo
		)
{
	NQ_STATUS result = NQ_ERR_OUTOFMEMORY;

	if (!prepareSingleRequestByShare(pRequest, pFile->share, SMB2_CMD_QUERYINFO, 0))
	{
		goto Exit;
	}
	
	/* compose request */
	writeHeader(pRequest);
	cmBufferWriteByte(&pRequest->writer, infoType);		/* information type */
	cmBufferWriteByte(&pRequest->writer, infoClass);	/* information class */
	cmBufferWriteUint32(&pRequest->writer, maxResLen);	/* output buffer length */
	cmBufferWriteUint16(&pRequest->writer, 0);			/* input buffer offset  */
	cmBufferWriteUint16(&pRequest->writer, 0);			/* reserved */
	cmBufferWriteUint32(&pRequest->writer, 0);			/* input buffer length */
	cmBufferWriteUint32(&pRequest->writer, addInfo);	/* output buffer length */
	cmBufferWriteUint32(&pRequest->writer, 0);			/* flags */
	cmBufferWriteBytes(&pRequest->writer, pFile->fid, sizeof(pFile->fid));	/* file ID */
	result = NQ_SUCCESS;

Exit:
	return result;
}

static NQ_STATUS writeSetInfoRequest(
		Request * pRequest,
		CCFile * pFile,
		NQ_BYTE infoType, 
		NQ_BYTE infoClass, 
		NQ_UINT32 addInfo,
		NQ_UINT32 dataLen
		)
{
	NQ_BYTE * pBufferOffset;		/* pointer to the buffer offset field */
	NQ_BYTE * pTemp;				/* temporary pointer */
	NQ_UINT16 bufferOffset;			/* buffer offset */
	NQ_STATUS result = NQ_ERR_OUTOFMEMORY;

	if (!prepareSingleRequestByShare(pRequest, pFile->share, SMB2_CMD_SETINFO, 0))
	{
		goto Exit;
	}
	
	/* compose request */
	writeHeader(pRequest);
	cmBufferWriteByte(&pRequest->writer, infoType);		/* information type */
	cmBufferWriteByte(&pRequest->writer, infoClass);	/* information class */
	cmBufferWriteUint32(&pRequest->writer, dataLen);	/* buffer length */
	pBufferOffset = cmBufferWriterGetPosition(&pRequest->writer);
	cmBufferWriteUint16(&pRequest->writer, 0);			/* input buffer offset  */
	cmBufferWriteUint16(&pRequest->writer, 0);			/* reserved */
	cmBufferWriteUint32(&pRequest->writer, addInfo);		/* output buffer length */
	cmBufferWriteBytes(&pRequest->writer, pFile->fid, sizeof(pFile->fid));	/* file ID */
	bufferOffset = (NQ_UINT16)cmSmb2HeaderGetWriterOffset(&pRequest->header, &pRequest->writer);
	pTemp = cmBufferWriterGetPosition(&pRequest->writer);
	cmBufferWriterSetPosition(&pRequest->writer, pBufferOffset);	
	cmBufferWriteUint16(&pRequest->writer, bufferOffset);	/* input buffer offset  */
	cmBufferWriterSetPosition(&pRequest->writer, pTemp);	
	result = NQ_SUCCESS;

Exit:
	return result;
}

static NQ_STATUS doNegotiate(CCServer * pServer, CMBlob * inBlob)
{
	Request request;		    /* request descriptor */
	Response response;		    /* response descriptor */
	const CCCifsSmb ** dialects = NULL;/* pointer to an array of supported dialects */
	NQ_UINT16 numDialects;	    /* number of dialects */
	NQ_COUNT packetLen;		    /* packet length of both in and out packets */
	NQ_STATUS res;				/* exchange status */
	NQ_UINT16 actualDialects;	/* number of dialects to negotiate */
	NQ_COUNT i;					/* just a counter */
    NQ_UINT32 capabilities = 0; /* client capabilities */
#ifdef UD_NQ_INCLUDESMB311
	NQ_UINT contextOffset = 0;  /* offset in bytes */
#endif /* UD_NQ_INCLUDESMB311 */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "server:%p inBlob:%p", pServer, inBlob);

	if (!pServer->useExtendedSecurity)
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "SMB2 requires extended security");
		res = NQ_ERR_NOSUPPORT;
		goto Exit;
	}

	if (!prepareSingleRequest(pServer, NULL, &request, SMB2_CMD_NEGOTIATE))
	{
		res = NQ_ERR_OUTOFMEMORY;
		goto Exit;
	}
	
	numDialects = (NQ_UINT16)ccCifsGetDialects(&dialects);
    for (i = 0, actualDialects = 0; i < numDialects; i++)
	{	
        if (dialects[i] != NULL && dialects[i]->revision != CCCIFS_ILLEGALSMBREVISION)
			actualDialects++;
	}

    /* write down MID and prepare it for next request */
    request.header.mid.low = pServer->smbContext != NULL ? ((Context*)pServer->smbContext)->mid.low++ : 0;

	/* compose request */
	writeHeader(&request);
	cmBufferWriteUint16(&request.writer, actualDialects);	/* number of dialects */
	cmBufferWriteUint16(&request.writer, nqGetMessageSigning()? 1: 0);	/* signing: enabled */
	cmBufferWriteUint16(&request.writer, 0);	/* reserved */
#ifdef UD_NQ_INCLUDESMB3
    capabilities |= (SMB2_CAPABILITY_ENCRYPTION | SMB2_CAPABILITY_LARGE_MTU);
#endif /* UD_NQ_INCLUDESMB3 */
    cmBufferWriteUint32(&request.writer, capabilities);	            	/* capabilities */
	cmBufferWriteUint32(&request.writer, pServer->clientGuidPartial);	/* client GUID */
	cmBufferWriteUint32(&request.writer, 0);	/* client GUID */
	cmBufferWriteUint32(&request.writer, 0);	/* client GUID */
	cmBufferWriteUint32(&request.writer, 0);	/* client GUID */
#ifdef UD_NQ_INCLUDESMB311
	contextOffset = cmSmb2HeaderGetWriterOffset(&request.header, &request.writer);
	contextOffset += (NQ_UINT)(actualDialects * 2) + 4 + 2 + 2; /* 2 bytes per dialect + offset (32) + count (2) + reserved (2)*/
	contextOffset += contextOffset % 8? 8 - contextOffset % 8 : 0;
	cmBufferWriteUint32(&request.writer, contextOffset);	/* context offset in bytes */
	cmBufferWriteUint16(&request.writer, 2);	/* context count - how many */
	cmBufferWriteUint16(&request.writer, 0);	/* reserved */
#else
	cmBufferWriteUint32(&request.writer, 0);	/* client start time */
	cmBufferWriteUint32(&request.writer, 0);	/* client start time */
#endif /* UD_NQ_INCLUDESMB311 */

    /* save current list of active revisions for later validate negotiate usage */
    for (i = 0; i < sizeof(pServer->clientDialectRevision) / sizeof(pServer->clientDialectRevision[0]); i++)
        pServer->clientDialectRevision[i] = CCCIFS_ILLEGALSMBREVISION;

    for (i = 0; numDialects > 0; numDialects--, i++)
	{	
        if (dialects[i]->revision != CCCIFS_ILLEGALSMBREVISION)
		{
            pServer->clientDialectRevision[i] = dialects[i]->revision;
            cmBufferWriteUint16(&request.writer, dialects[i]->revision);   /* write actual dialects */
		}
	}
    if (NULL != dialects)
        cmMemoryFree(dialects);

#ifdef UD_NQ_INCLUDESMB311
	/* context is sent on earlier then 3.1.1 dialects. they should ignore it. */
	cmBufferWriterAlign(&request.writer, request.header._start, 8); 				/* 8 byte alignment */

	/* context 1 - pre-authentication integrity and digest algorithm */
	/*****************************************************************/
	cmBufferWriteUint16(&request.writer, SMB2_PREAUTH_INTEGRITY_CAPABILITIES);		/* context type  */
	cmBufferWriteUint16(&request.writer, SMB2_PREAUTH_INTEGRITY_CONTEXT_LEN_BYTES );/* context length bytes  */
	cmBufferWriteUint32(&request.writer, 0);										/* reserved */
	cmBufferWriteUint16(&request.writer, 1);										/* hash algorithm count */
	cmBufferWriteUint16(&request.writer, SMB2_PREAUTH_INTEGRITY_SALT_SIZE);			/* salt length */
	cmBufferWriteUint16(&request.writer, SHA_512);          					  	/* hash algorithm/s */
	cmBufferWriteRandomBytes(&request.writer, SMB2_PREAUTH_INTEGRITY_SALT_SIZE);	/* salt bytes */
	cmBufferWriterAlign(&request.writer, request.header._start, 8); 				/* 8 byte alignment */

	/* context 2 - cipher type */
	/***************************/
	cmBufferWriteUint16(&request.writer, SMB2_ENCRYPTION_CAPABILITIES);     /* context type */
	cmBufferWriteUint16(&request.writer, SMB2_ENCRYPTION_CCONTEXT_LEN_BYTES); /* data length - cipher count - 2, 1st cipher - 2, 2nd cipher - 2 bytes */
	cmBufferWriteUint32(&request.writer, 0);                                /* reserved(4) */
	cmBufferWriteUint16(&request.writer, 2);                                /* cipher count */
	cmBufferWriteUint16(&request.writer, CIPHER_AES128GCM);                	/* optional cipher */
	cmBufferWriteUint16(&request.writer, CIPHER_AES128CCM);                	/* optional cipher */

#endif /* UD_NQ_INCLUDESMB311 */

	packetLen = cmBufferWriterGetDataCount(&request.writer) - 4;			/* NBT header */

#ifdef UD_NQ_INCLUDESMB311
	/* calculate message hash - for 3.1.1 includes all messages till session setup signing */
	syMemset(pServer->preauthIntegHashVal, 0, sizeof(pServer->preauthIntegHashVal)); /* zero in case this is reconnect */
	cmSmb311CalcMessagesHash(request.header._start, packetLen, pServer->preauthIntegHashVal, NULL);
#endif /* UD_NQ_INCLUDESMB311 */

	/* send and receive. Since no context was established yet - this is done inlined */
#ifdef UD_NQ_INCLUDESMBCAPTURE
	pServer->captureHdr.receiving = FALSE;
	cmCapturePacketWriteStart(&pServer->captureHdr ,packetLen );
	cmCapturePacketWritePacket( request.buffer + 4, packetLen);
	cmCapturePacketWriteEnd();
#endif /* UD_NQ_INCLUDESMBCAPTURE */
/*
	if (!ccServerWaitForCredits(pServer, 1))
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return NQ_ERR_TIMEOUT;
	}
*/
    ccTransportLock(&pServer->transport);
	if (!ccTransportSendSync(
			&pServer->transport, 
			request.buffer, 
			packetLen,
			packetLen
			)
		)
	{
        ccTransportUnlock(&pServer->transport);
		cmBufManGive(request.buffer);
		res = (NQ_STATUS)syGetLastError();
		goto Exit;
	}
	cmBufManGive(request.buffer);
	sySetLastError(0); /* zero error code */
	response.buffer = ccTransportReceiveAll(&pServer->transport, &packetLen);
    ccTransportUnlock(&pServer->transport);
	if (NULL == response.buffer)
	{
		if (syGetLastError() == NQ_ERR_OUTOFMEMORY)
			res = NQ_ERR_OUTOFMEMORY;
		else
			res = NQ_ERR_LOGONFAILURE;
		goto Exit;
	}
#ifdef UD_NQ_INCLUDESMBCAPTURE
	pServer->captureHdr.receiving = TRUE;
	cmCapturePacketWriteStart(&pServer->captureHdr ,packetLen);
	cmCapturePacketWritePacket( response.buffer, packetLen);
	cmCapturePacketWriteEnd();
#endif /* UD_NQ_INCLUDESMBCAPTURE */
	res = ccSmb20DoNegotiateResponse(pServer, response.buffer, packetLen, inBlob);
	cmBufManGive(response.buffer);

Exit:
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", res);
	return res;	
}

NQ_STATUS ccSmb20DoNegotiateResponse(CCServer * pServer, const NQ_BYTE * data, NQ_COUNT len, CMBlob * inBlob)
{
	CMBufferReader reader;	/* response reader */
	CMSmb2Header header;	/* response header */
	NQ_UINT16 tempUint16;	/* for parsing 2-byte values */
	NQ_UINT16 blobOffset;	/* offset from header to the security buffer */
	NQ_UINT16 length;		/* structure length */
	NQ_STATUS res;			/* exchange status */
	CMBlob blob;			/* temporary blob */
#ifdef UD_NQ_INCLUDESMB311
	NQ_UINT16 contextCount;
	NQ_UINT32 tempUint32;
#endif /* UD_NQ_INCLUDESMB311 */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "server:%p data:%p length:%d inBlob:%p", pServer, data, len, inBlob);

	/* initialize correspondence with transports.
       we do it here since this response may come on an SMB1 request */
	ccTransportSetResponseCallback(&pServer->transport, anyResponseCallback, pServer);

    cmBufferReaderInit(&reader, data, len); /* starting from SMB header */
	cmSmb2HeaderRead(&header, &reader);
    if (0 == pServer->credits)
    {
        pServer->credits = 1;        
    }
    pServer->credits += header.credits;

	sySetLastError(ccErrorsStatusToNq(header.status, TRUE));
	res = (NQ_STATUS)ccErrorsStatusToNq(header.status, TRUE);
	if (NQ_SUCCESS != res)
	{
		goto Exit;
	}
	cmBufferReadUint16(&reader, &length); /* structure size */
	if (length != commandDescriptors[0].responseStructSize)
	{
		sySetLastError(NQ_ERR_BADFORMAT);
		res = NQ_ERR_BADFORMAT;
		goto Exit;
	}

	/* parse response */
	pServer->negoSmb = &dialect;
	pServer->capabilities = 0;
	cmBufferReadUint16(&reader, &pServer->serverSecurityMode);			/* security mode */
	if (pServer->serverSecurityMode & 0x001)
	{
		pServer->capabilities |= CC_CAP_MESSAGESIGNING;
	}
	if (NULL == pServer->smbContext)
	{
		pServer->smbContext = pServer->negoSmb->allocateContext(pServer);
		if (NULL == pServer->smbContext)
		{
			sySetLastError(NQ_ERR_OUTOFMEMORY);
			res = NQ_ERR_OUTOFMEMORY; 
			goto Exit;
		}
	}
	cmBufferReadUint16(&reader, &pServer->serverDialectRevision);			/* dialect revision */
	switch (pServer->serverDialectRevision)
	{
#if defined(UD_NQ_INCLUDESMB2) || defined(UD_NQ_INCLUDESMB3)
		case SMB2ANY_DIALECTREVISION:
		{
			res = doNegotiate(pServer, inBlob);
			goto Exit;
			break;
		}
#endif /* defined(UD_NQ_INCLUDESMB2) || defined(UD_NQ_INCLUDESMB3) */
#ifdef UD_NQ_INCLUDESMB3
		case SMB3_DIALECTREVISION:
        case SMB3_0_2_DIALECTREVISION:
			pServer->smb = ccSmb30GetCifs();
			ccTransportSetResponseCallback(&pServer->transport, pServer->smb->anyResponseCallback, pServer);
			break;
#ifdef UD_NQ_INCLUDESMB311
		case SMB3_1_1_DIALECTREVISION:
			pServer->isPreauthIntegOn = TRUE;
			pServer->smb = ccSmb311GetCifs();
			ccTransportSetResponseCallback(&pServer->transport, pServer->smb->anyResponseCallback, pServer);
			break;
#endif /* UD_NQ_INCLUDESMB311 */
#endif /* UD_NQ_INCLUDESMB3 */
		case SMB2_DIALECTREVISION:
        case SMB2_1_DIALECTREVISION:
		default:
			pServer->smb = &dialect;
			break;
	}

	/* make sure both SMB dialects are the same */
	pServer->negoSmb = pServer->smb;

#ifdef UD_NQ_INCLUDESMB311
	if (pServer->isPreauthIntegOn == TRUE)
	{
		/* calculate message hash - for 3.1.1 includes all messages till session setup signing */
		cmSmb311CalcMessagesHash(reader.origin, reader.length, pServer->preauthIntegHashVal, NULL);

		cmBufferReadUint16(&reader, &contextCount);	/* context count */
		if (contextCount < 1)
		{
			LOGERR(CM_TRC_LEVEL_ERROR, "Negotiate packet on dialect 3.1.1 must have at least one context item in negotiate context list");
			sySetLastError(NQ_ERR_BADPARAM);
			res = NQ_ERR_BADFORMAT;
			goto Exit;
		}
	}
	else
#endif /* UD_NQ_INCLUDESMB311 */

	cmBufferReaderSkip(&reader, sizeof(NQ_UINT16));	/* reserved */

	cmBufferReadBytes(&reader, pServer->serverGUID, 4 * sizeof(NQ_UINT32));	/* server GUID */
	cmBufferReadUint32(&reader, &pServer->serverCapabilites);			/* capabilities */
	if (SMB2_CAPABILITY_DFS & pServer->serverCapabilites)
	{
		pServer->capabilities |= CC_CAP_DFS;
	}
#ifdef UD_NQ_INCLUDESMB3
    if ((pServer->smb->revision != CCCIFS_ILLEGALSMBREVISION && pServer->smb->revision >= SMB3_DIALECTREVISION) &&
        (SMB2_CAPABILITY_LARGE_MTU & pServer->serverCapabilites) &&
        (((SocketSlot *)(pServer->transport.socket))->remotePort == CM_NB_SESSIONSERVICEPORTIP))
    {
        pServer->capabilities |= CC_CAP_LARGEMTU;
    }
#endif /* UD_NQ_INCLUDESMB3 */
	cmBufferReadUint32(&reader, &pServer->maxTrans);	
	cmBufferReadUint32(&reader, &pServer->maxRead);	
	cmBufferReadUint32(&reader, &pServer->maxWrite);
#ifdef UD_NQ_INCLUDESMB3
    if (pServer->capabilities & CC_CAP_LARGEMTU)
    {
        pServer->maxRead = pServer->maxRead > 0x100000 ? 0x100000 : pServer->maxRead;
        pServer->maxWrite = pServer->maxWrite > 0x100000 ? 0x100000 : pServer->maxWrite;
        pServer->maxTrans = pServer->maxTrans > 0x100000 ? 0x100000 : pServer->maxTrans;
    }
    else
#endif /* UD_NQ_INCLUDESMB3 */ 
    {
        pServer->maxRead = pServer->maxRead > 0xFFFF ? 0xFFFF : pServer->maxRead;
        pServer->maxWrite = pServer->maxWrite > 0xFFFF ? 0xFFFF : pServer->maxWrite;
        pServer->maxTrans = pServer->maxTrans > 0xFFFF ? 0xFFFF : pServer->maxTrans;
    }
	if (pServer->maxRead == 0 || pServer->maxWrite == 0 || pServer->maxTrans == 0)
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "Bad values in negotiate message. max Read: %d, max write: %d, max transact: %d",
			pServer->maxRead, pServer->maxWrite, pServer->maxTrans);
		sySetLastError(NQ_ERR_BADPARAM);
		res = NQ_ERR_BADPARAM;
		goto Exit;
	}
	cmBufferReaderSkip(&reader, 4 * sizeof(NQ_UINT32));		/* system time + server start time */
	cmBufferReadUint16(&reader, &blobOffset);				/* offset to security buffer */
	cmBufferReadUint16(&reader, &tempUint16);				/* length of security buffer */
#ifdef UD_NQ_INCLUDESMB311
	if (pServer->isPreauthIntegOn == TRUE)
		cmBufferReadUint32(&reader, &tempUint32);			/* offset to context buffer */
#endif /* UD_NQ_INCLUDESMB311 */

	blob.len = tempUint16;
	cmSmb2HeaderSetReaderOffset(&header, &reader, blobOffset);
	blob.data = cmBufferReaderGetPosition(&reader);
	cmMemoryFreeBlob(inBlob);
	if (blob.len > 0)
	{
		*inBlob = cmMemoryCloneBlob(&blob);
		if (NULL != blob.data && NULL == inBlob->data)
		{
			LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
			res = NQ_ERR_OUTOFMEMORY;
			goto Exit;
		}
	}
	else if (blob.len == 0)
	{
		inBlob->len = 0;
		inBlob->data = NULL;
	}

#ifdef UD_NQ_INCLUDESMB311
	if (pServer->isPreauthIntegOn == TRUE) /* meaning 3.1.1 or above was selected */
	{
		/* set reader to context offset */
		cmSmb2HeaderSetReaderOffset(&header, &reader, (NQ_UINT16)tempUint32);
		res = smb311ReadNegotiateContexts(&reader, pServer, contextCount);
	}
	else
#endif /* UD_NQ_INCLUDESMB311 */
		res = NQ_SUCCESS;

Exit:
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", res);
	return res;	
}

static NQ_STATUS doSessionSetup(CCUser * pUser, const CMBlob * pass1, const CMBlob * pass2)
{
	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "user:%p pass1:xxx pass2:xxx", pUser);

	/* not supported */
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", NQ_ERR_NOSUPPORT);
	return NQ_ERR_NOSUPPORT;
}

static NQ_STATUS doSessionSetupExtended(CCUser * pUser, const CMBlob * outBlob, CMBlob * inBlob)
{
	Request request;		/* request descriptor */
	Response response;		/* response descriptor */
	CCServer * pServer;		/* server object pointer */
	NQ_BYTE * blobOffPtr;	/* pointer to blob (buffer) offset */
	NQ_BYTE * savedPtr;		/* for saving current position */
	NQ_UINT16 blobOffset;	/* offset from header to the security buffer */
	CMBlob blob;			/* original security blob */
	NQ_UINT16 tempUint16;	/* for parsing 2-byte values */
	NQ_STATUS res;			/* exchange result */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "user:%p outBlob:%p inBlob:%p", pUser, outBlob, inBlob);

	request.buffer = NULL;
	response.buffer = NULL;
	inBlob->data = NULL;
	pServer = pUser->server;
	if (!prepareSingleRequest(pServer, pUser, &request, SMB2_CMD_SESSIONSETUP))
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
		res = NQ_ERR_OUTOFMEMORY;
		goto Exit;
	}
	
	/* compose request */
	/* ask max num of credits each time, since we don't know the exact num of session setup iterations */
	request.header.credits = (NQ_UINT16)(SMB2_CLIENT_MAX_CREDITS_TO_REQUEST - pServer->credits);

    request.header.sid = pUser->uid;
	writeHeader(&request);
	cmBufferWriteByte(&request.writer, 0);      /* flag session binding - not set */
	cmBufferWriteByte(&request.writer, 1);		/* security mode - message signing enabled */
	cmBufferWriteUint32(&request.writer, 0);	/* capabilities - none */
	cmBufferWriteUint32(&request.writer, 0);	/* channel */
	blobOffPtr = cmBufferWriterGetPosition(&request.writer);
	cmBufferWriterSkip(&request.writer, sizeof(NQ_UINT16));	/* skip buffer offset */
	cmBufferWriteUint16(&request.writer, (NQ_UINT16)outBlob->len);		/* buffer length */
	cmBufferWriteUint32(&request.writer, 0);	/* previous session ID */
	cmBufferWriteUint32(&request.writer, 0);	/* previous session ID */
	savedPtr = cmBufferWriterGetPosition(&request.writer);
	cmBufferWriterSetPosition(&request.writer, blobOffPtr);
	cmBufferWriteUint16(&request.writer, (NQ_UINT16)(savedPtr - cmBufferWriterGetStart(&request.writer) - 4));	/* buffer offset - NBT header */
	cmBufferWriterSetPosition(&request.writer, savedPtr);
	request.tail = *outBlob;

	res = pServer->smb->sendReceive(pServer, pUser, &request, &response);

	if (NQ_SUCCESS != res && NQ_ERR_MOREDATA != res)
	{
	    cmU64Zero(&pUser->uid);
		goto Exit;
	}

	/* parse response */
	pUser->uid = response.header.sid;	
    cmBufferReadUint16(&response.reader, &tempUint16);	            /* parse session flags */
	pUser->isGuest = (tempUint16 & SMB2SESSIONFLAG_IS_GUEST) ? TRUE : FALSE;
    pUser->isEncrypted = (tempUint16 & SMB2SESSIONFLAG_ENCRYPT_DATA) ? TRUE : FALSE;
	cmBufferReadUint16(&response.reader, &blobOffset);				/* offset to security buffer */	
	cmBufferReadUint16(&response.reader, &tempUint16);				/* length of security buffer */
	blob.len = tempUint16;
	cmSmb2HeaderSetReaderOffset(&response.header, &response.reader, blobOffset);
	blob.data = cmBufferReaderGetPosition(&response.reader);
	if (0 != blob.len)
	{
		*inBlob = cmMemoryCloneBlob(&blob);
	    if (NULL != blob.data && NULL == inBlob->data)
	    {
	        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
	        res = NQ_ERR_OUTOFMEMORY;
	        goto Exit;
	    }
    }

Exit:
	cmBufManGive(request.buffer);
	cmBufManGive(response.buffer);
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", res);
	return res;
}

static NQ_STATUS doLogOff(CCUser * pUser)
{
	Request request;		/* request descriptor */
	Response response;		/* response descriptor */
	CCServer * pServer;		/* server object pointer */
	NQ_STATUS res;			/* exchange result */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "user:%p", pUser);

	request.buffer = NULL;
	response.buffer = NULL;

	pServer = pUser->server;
	if (!prepareSingleRequest(pServer, pUser, &request, SMB2_CMD_LOGOFF))
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
		res = NQ_ERR_OUTOFMEMORY;
		goto Exit;
	}
	
	/* compose request */
	request.header.sid = pUser->uid;
	writeHeader(&request);
	cmBufferWriteUint16(&request.writer, 0);		/* reserved */

	res = pServer->smb->sendReceive(pServer, pUser, &request, &response);

	/* parse response - noting to parse */

Exit:
	cmBufManGive(request.buffer);
	cmBufManGive(response.buffer);
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", res);
	return res;
}

static NQ_STATUS doTreeConnect(CCShare * pShare)
{
	Request request;		/* request descriptor */
	Response response;		/* response descriptor */
	CCServer * pServer;		/* server object pointer */
	CCUser * pUser;			/* user object pointer */
    NQ_UINT16 tempUint16;	/* for parsing 2-byte values */
    NQ_UINT32 tempUint32;   /* for parsing 4-byte values */
	NQ_WCHAR * path = NULL; /* full network path */
	NQ_STATUS res;			/* exchange result */
    NQ_WCHAR  * ipW = NULL;
    NQ_CHAR   * ip = NULL;

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "share:%p", pShare);

	request.buffer = NULL;
	response.buffer = NULL;

	pUser = pShare->user;
	pServer = pUser->server;
    if (!prepareSingleRequest(pServer, pUser, &request, SMB2_CMD_TREECONNECT))
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
		res = NQ_ERR_OUTOFMEMORY;
		goto Exit;
	}
	
	/* compose request */
	writeHeader(&request);
	cmBufferWriteUint16(&request.writer, 0);	/* reserved */
	tempUint16 = (NQ_UINT16)cmSmb2HeaderGetWriterOffset(&request.header, &request.writer);
	tempUint16 = (NQ_UINT16)(tempUint16 +(2 * sizeof(NQ_UINT16)));
	cmBufferWriteUint16(&request.writer, tempUint16);	/* path offset */
    if (pServer->useName)
    {
	    path = ccUtilsComposeRemotePathToShare(pServer->item.name, pShare->item.name);
    }
    else
    {
        ip = (NQ_CHAR *)cmMemoryAllocate(CM_IPADDR_MAXLEN * sizeof(NQ_CHAR));
        ipW = (NQ_WCHAR *)cmMemoryAllocate(CM_IPADDR_MAXLEN * sizeof(NQ_WCHAR));
        if (NULL == ip || NULL == ipW)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
			res = NQ_ERR_OUTOFMEMORY;
            goto Exit;
        }
        cmIpToAscii(ip, &pServer->ips[0]);
        cmAnsiToUnicode(ipW, ip);
        path = ccUtilsComposeRemotePathToShare(ipW, pShare->item.name);
    }
    
	if (NULL == path)
	{
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
		res = NQ_ERR_OUTOFMEMORY;
        goto Exit;
	}
	tempUint16 = (NQ_UINT16)(sizeof(NQ_WCHAR) * cmWStrlen(path));
	cmBufferWriteUint16(&request.writer, tempUint16);	/* path length */
	request.tail.data = (NQ_BYTE*)path;
	request.tail.len = (NQ_COUNT)tempUint16;

	res = pServer->smb->sendReceive(pServer, pUser, &request, &response);
	if (NQ_SUCCESS != res)
	{
		goto Exit;
	}

	/* parse response */
	pShare->tid = response.header.tid;
	cmBufferReadByte(&response.reader, &pShare->type);		/* share type */

	if (SMB2_SHARE_TYPE_PRINT == pShare->type)
		pShare->isPrinter = TRUE;

	cmBufferReaderSkip(&response.reader, sizeof(NQ_BYTE));	/* reserved */
    pShare->flags = 0;
	cmBufferReadUint32(&response.reader, &tempUint32);      /* share flags */
    if (tempUint32 & SMB2_SHARE_FLAG_DFS)
        pShare->flags |= CC_SHARE_IN_DFS;
#ifdef UD_NQ_INCLUDESMB3
    if (tempUint32 & SMB2_SHARE_FLAG_ENCRYPT_DATA)
    	pShare->encrypt = TRUE;
#endif /* UD_NQ_INCLUDESMB3 */
	cmBufferReadUint32(&response.reader, &tempUint32);	    /* capabilities */	
    if (tempUint32 & SMB2_SHARE_CAPS_DFS)
        pShare->flags |= CC_SHARE_IN_DFS;
#ifdef UD_NQ_INCLUDESMB3
    if (tempUint32 & SMB2_SHARE_CAP_SCALEOUT)
        pShare->capabilities |= CC_SHARE_SCALEOUT;
#endif /* UD_NQ_INCLUDESMB3 */
	cmBufferReadUint32(&response.reader, &pShare->access);	/* maximal access */	

Exit:
	cmBufManGive(request.buffer);
	cmBufManGive(response.buffer);
    cmMemoryFree(ip);
    cmMemoryFree(ipW);
	cmMemoryFree(path);
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", res);
	return res;
}

static NQ_STATUS doTreeDisconnect(CCShare * pShare)
{
	return exchangeEmptyCommand(pShare, SMB2_CMD_TREEDISCONNECT);
}

/* Create contexts definitions */

typedef enum
{
    DHnQ = 0x00,
    DHnC = 0x01,
    DH2Q = 0x02,
    DH2C = 0x03
}
CreateContextId;

typedef struct _contextdescriptor
{
    CreateContextId id;     /* context enumerator id */
    const NQ_CHAR * name;   /* expected context name */
    void(*pack)(CMBufferWriter *, const struct _contextdescriptor *, CCFile *pFile);         /* pointer to the packer method  */
    NQ_BOOL(*process)(CMBufferReader *, CCFile *pFile);                                      /* pointer to the process method */
    NQ_UINT32 dataSize;     /* the length of the context */
}
ContextDescriptor;

/* SMB2_CREATE_DURABLE_HANDLE_REQUEST */
static void packDHnQ(CMBufferWriter *writer, const ContextDescriptor *ctx, CCFile *pFile)
{
    CMBufferWriter packer;      /* branched context writer */
    NQ_BYTE * pDataOffset;		/* pointer to data offset */
    NQ_UINT16 dataOffset;	    /* data offset */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "writer:%p ctx:%p pFile:%p", writer, ctx, pFile);

    cmBufferWriterBranch(writer, &packer, 0);
    cmBufferWriteUint32(&packer, 0);                    /* next (0 in last or single entry only) */
    cmBufferWriteUint16(&packer, 16);                   /* context name offset always 16*/
    cmBufferWriteUint16(&packer, (NQ_UINT16)syStrlen(ctx->name));  /* context name size */
    cmBufferWriteUint16(&packer, 0);                    /* reserved */
    pDataOffset = cmBufferWriterGetPosition(&packer);   /* save data offset pointer */
    cmBufferWriteUint16(&packer, 0);                    /* data offset for now*/
    cmBufferWriteUint32(&packer, ctx->dataSize);        /* data size */
    cmBufferWriteBytes(&packer, (NQ_BYTE *)ctx->name, (NQ_COUNT)syStrlen(ctx->name));         /* context name */
    cmBufferWriterAlign(&packer, cmBufferWriterGetStart(&packer), 8);               /* align */
    dataOffset = (NQ_UINT16)(cmBufferWriterGetPosition(&packer) - cmBufferWriterGetStart(&packer));
    /* data */
    cmBufferWriteZeroes(&packer, sizeof(CMUuid));
    /* sync with the main writer */
    cmBufferWriterSync(writer, &packer);                
    /* update data offset */
    cmBufferWriterSetPosition(&packer, pDataOffset);
    cmBufferWriteUint16(&packer, dataOffset);
    
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

/* SMB2_CREATE_DURABLE_HANDLE_REQUEST */
static NQ_BOOL processDHnQ(CMBufferReader *reader, CCFile *pFile)
{
    NQ_CHAR name[4];

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "reader:%p pFile:%p", reader, pFile);

    cmBufferReaderSkip(reader, 16);   /* next chain offset, can be skipped when 1 context is only present, name offset size*/
    cmBufferReadBytes(reader, (NQ_BYTE *)name, (NQ_COUNT)sizeof(name));
    pFile->durableState = (syStrncmp(name, "DHnQ", sizeof(name)) == 0)? DURABLE_GRANTED : pFile->durableState;

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", pFile->durableState == DURABLE_GRANTED ? "TRUE" : "FALSE");
    return (pFile->durableState == DURABLE_GRANTED);
}

/* SMB2_CREATE_DURABLE_HANDLE_RECONNECT */
static void packDHnC(CMBufferWriter *writer, const ContextDescriptor *ctx, CCFile *pFile)
{
    CMBufferWriter packer;      /* branched context writer */
    NQ_BYTE * pDataOffset;		/* pointer to data offset */
    NQ_UINT16 dataOffset;	    /* data offset */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "writer:%p ctx:%p pFile:%p", writer, ctx, pFile);

    if (pFile->durableState == DURABLE_GRANTED)
    {
		cmBufferWriterBranch(writer, &packer, 0);
		cmBufferWriteUint32(&packer, 0);                    /* next (0 in last or single entry only) */
		cmBufferWriteUint16(&packer, 16);                   /* context name offset always 16*/
		cmBufferWriteUint16(&packer, (NQ_UINT16)syStrlen(ctx->name));  /* context name size */
		cmBufferWriteUint16(&packer, 0);                    /* reserved */
		pDataOffset = cmBufferWriterGetPosition(&packer);   /* save data offset pointer */
		cmBufferWriteUint16(&packer, 0);                    /* data offset for now*/
		cmBufferWriteUint32(&packer, ctx->dataSize);        /* data size */
		cmBufferWriteBytes(&packer, (NQ_BYTE *)ctx->name, (NQ_UINT16)syStrlen(ctx->name));         /* context name */
		cmBufferWriterAlign(&packer, cmBufferWriterGetStart(&packer), 8);               /* align */
		dataOffset = (NQ_UINT16)(cmBufferWriterGetPosition(&packer) - cmBufferWriterGetStart(&packer));
		/* data */
		cmBufferWriteBytes(&packer, pFile->fid, 8);	        /* persistent FID */
		cmBufferWriteZeroes(&packer, 8);                    /* volatile FID */
		/* sync with the main writer */
		cmBufferWriterSync(writer, &packer);
		/* update data offset */
		cmBufferWriterSetPosition(&packer, pDataOffset);
		cmBufferWriteUint16(&packer, dataOffset);
    }

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

/* SMB2_CREATE_DURABLE_HANDLE_REQUEST_V2 */
static void packDH2Q(CMBufferWriter *writer, const ContextDescriptor *ctx, CCFile *pFile)
{
    CMBufferWriter packer;      /* branched context writer */
    NQ_BYTE * pDataOffset;		/* pointer to data offset */
    NQ_UINT16 dataOffset;	    /* data offset */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "writer:%p ctx:%p pFile:%p", writer, ctx, pFile);

    cmBufferWriterBranch(writer, &packer, 0);
    cmBufferWriteUint32(&packer, 0);                    /* next (0 in last or single entry only) */
    cmBufferWriteUint16(&packer, 16);                   /* context name offset always 16*/
    cmBufferWriteUint16(&packer, (NQ_UINT16)syStrlen(ctx->name));  /* context name size */
    cmBufferWriteUint16(&packer, 0);                    /* reserved */
    pDataOffset = cmBufferWriterGetPosition(&packer);   /* save data offset pointer */
    cmBufferWriteUint16(&packer, 0);                    /* data offset for now*/
    cmBufferWriteUint32(&packer, ctx->dataSize);        /* data size */
    cmBufferWriteBytes(&packer, (NQ_BYTE *)ctx->name, (NQ_UINT16)syStrlen(ctx->name));         /* context name */
    cmBufferWriterAlign(&packer, cmBufferWriterGetStart(&packer), 8);               /* align */
    dataOffset = (NQ_UINT16)(cmBufferWriterGetPosition(&packer) - cmBufferWriterGetStart(&packer));
    /* data */
    cmBufferWriteUint32(&packer, 0);                    /* timeout */
    cmBufferWriteUint32(&packer, pFile->durableFlags);  /* flags: 0 Persistent Handle False*/
    cmBufferWriteZeroes(&packer, 8);                    /* reserved */
    cmBufferWriteUuid(&packer, &pFile->durableHandle);  /* file uuid */
    /* sync with the main writer */
    cmBufferWriterSync(writer, &packer);                
    /* update data offset */
    cmBufferWriterSetPosition(&packer, pDataOffset);
    cmBufferWriteUint16(&packer, dataOffset);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

/* SMB2_CREATE_DURABLE_HANDLE_REQUEST_V2 */
static NQ_BOOL processDH2Q(CMBufferReader *reader, CCFile *pFile)
{
    NQ_CHAR name[4];
    NQ_BOOL result = FALSE;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "reader:%p pFile:%p", reader, pFile);

    cmBufferReaderSkip(reader, 16);      /* next chain offset, can be skipped when 1 context is only present, name offset size*/
    cmBufferReadBytes(reader, (NQ_BYTE *)name, (NQ_COUNT)sizeof(name));
    if (TRUE == (result = (syStrncmp(name, "DH2Q", sizeof(name)) == 0)))
    {
        pFile->durableState = DURABLE_GRANTED;
        pFile->durableFlags = SMB2DHANDLE_FLAG_NOTPERSISTENT;
        cmBufferReaderSkip(reader, 4);
        cmBufferReadUint32(reader, &pFile->durableTimeout);
        cmBufferReadUint32(reader, &pFile->durableFlags);
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "durableTimeout:%d, durableFlags:0x%X", pFile->durableTimeout, pFile->durableFlags);
    }
    else
    {
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "No durable handle granted");
    }

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result == TRUE ? "TRUE" : "FALSE");
    return result;
}


/* SMB2_CREATE_DURABLE_HANDLE_RECONNECT_V2 */
static void packDH2C(CMBufferWriter *writer, const ContextDescriptor *ctx, CCFile *pFile)
{
    CMBufferWriter packer;      /* branched context writer */
    NQ_BYTE * pDataOffset;		/* pointer to data offset */
    NQ_UINT16 dataOffset;	    /* data offset */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "writer:%p ctx:%p pFile:%p", writer, ctx, pFile);

	if (pFile->durableState == DURABLE_GRANTED)
	{
		cmBufferWriterBranch(writer, &packer, 0);
		cmBufferWriteUint32(&packer, 0);                    /* next (0 in last or single entry only) */
		cmBufferWriteUint16(&packer, 16);                   /* context name offset always 16*/
		cmBufferWriteUint16(&packer, (NQ_UINT16)syStrlen(ctx->name));  /* context name size */
		cmBufferWriteUint16(&packer, 0);                    /* reserved */
		pDataOffset = cmBufferWriterGetPosition(&packer);   /* save data offset pointer */
		cmBufferWriteUint16(&packer, 0);                    /* data offset for now*/
		cmBufferWriteUint32(&packer, ctx->dataSize);        /* data size */
		cmBufferWriteBytes(&packer, (NQ_BYTE *)ctx->name, (NQ_UINT16)syStrlen(ctx->name)); /* context name */
		cmBufferWriterAlign(&packer, cmBufferWriterGetStart(&packer), 8);                  /* align */
		dataOffset = (NQ_UINT16)(cmBufferWriterGetPosition(&packer) - cmBufferWriterGetStart(&packer));
		/* data */
		cmBufferWriteBytes(&packer, pFile->fid, 8);	        /* persistent FID */
		cmBufferWriteZeroes(&packer, 8);                    /* volatile FID */
		cmBufferWriteUuid(&packer, &pFile->durableHandle);  /* durable uuid created on previous create */
		cmBufferWriteUint32(&packer, pFile->durableFlags);  /* durable flags granted previoulsy */
		/* sync with the main writer */
		cmBufferWriterSync(writer, &packer);
		/* update data offset */
		cmBufferWriterSetPosition(&packer, pDataOffset);
		cmBufferWriteUint16(&packer, dataOffset);
	}

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

/* SMB2_CREATE_DURABLE_HANDLE_RECONNECT_V2 */
static NQ_BOOL processDH2C(CMBufferReader *reader, CCFile *pFile)
{
    /* no response expected */
    return TRUE;
}

ContextDescriptor createContexts[] = {
    { DHnQ, "DHnQ", packDHnQ, processDHnQ, 16 },  /* SMB2_CREATE_DURABLE_HANDLE_REQUEST       "DHnQ" */
    { DHnC, "DHnC", packDHnC, processDHnQ, 16 },  /* SMB2_CREATE_DURABLE_HANDLE_RECONNECT     "DHnC" */
    { DH2Q, "DH2Q", packDH2Q, processDH2Q, 32 },  /* SMB2_CREATE_DURABLE_HANDLE_REQUEST_V2    "DH2Q" */
    { DH2C, "DH2C", packDH2C, processDH2C, 36 },  /* SMB2_CREATE_DURABLE_HANDLE_RECONNECT_V2  "DH2C" */
};

static NQ_STATUS create(CCFile * pFile, NQ_BOOL setDfsFlag)
{
	Request request;			  /* request descriptor */
	Response response;			  /* response descriptor */
	CCServer * pServer;			  /* server object pointer */
	CCShare * pShare;			  /* share object pointer */
	NQ_WCHAR * pName;             /* pointer to name */
	NQ_BYTE * pNameOffset;		  /* pointer to the name offset field */
	NQ_BYTE * pContextOffset;	  /* pointer to the context offset field */
	NQ_UINT32 contextOffset;	  /* context offset */
	NQ_UINT32 contextLength;	  /* context length */
	NQ_UINT16 nameOffset;		  /* name offset */
	NQ_BYTE * pTemp;			  /* temporary pointer in the writer */
	NQ_UINT16 nameLen;			  /* name length in bytes (not including terminator) */
	NQ_STATUS res;				  /* exchange result */
    CMBufferWriter contextWriter; /* context writer */
    CreateContextId ctxId = DHnQ; /* default context id */
    NQ_BOOL	doContext = (pFile->durableState == DURABLE_REQUIRED);     /* whether to perform context */
    NQ_INT i = 0;                 /* counter */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "file:%p setDfsFlag:%s", pFile, setDfsFlag ? "TRUE" : "FALSE");

	request.buffer = NULL;
	response.buffer = NULL;

	pShare = pFile->share;
	pServer = pShare->user->server;
	pName = (pFile->item.name[0] == cmWChar('\\')) ? pFile->item.name + 1 : pFile->item.name;

	for (i = 0; i < 2; i++)
	{
		if (!prepareSingleRequestByShare(&request, pShare, SMB2_CMD_CREATE, 0))
		{
			LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
			res = NQ_ERR_OUTOFMEMORY;
			goto Exit;
		}

		/* some operations like query fs info require smb2 dfs operations flag to be unset */
		if (!setDfsFlag)
			request.header.flags = (NQ_UINT32)(request.header.flags & (NQ_UINT32)~SMB2_FLAG_DFS_OPERATIONS);
	
		/* compose request */
		writeHeader(&request);
		cmBufferWriteByte(&request.writer, 0);		                /* security flags */
        cmBufferWriteByte(&request.writer, pFile->grantedOplock);   /* oplock */
		cmBufferWriteUint32(&request.writer, SMB2_IMPERSONATION_IMPERSONATION);	/* impersonation */
		cmBufferWriteUint32(&request.writer, 0);	                /* SMB create flags */
		cmBufferWriteUint32(&request.writer, 0);	                /* SMB create flags */
		cmBufferWriteUint32(&request.writer, 0);	                /* reserved */
		cmBufferWriteUint32(&request.writer, 0);	                /* reserved */
		cmBufferWriteUint32(&request.writer, pFile->accessMask);	/* desired access */
		cmBufferWriteUint32(&request.writer, pFile->attributes);	/* file attributes */
		cmBufferWriteUint32(&request.writer, pFile->sharedAccess);	/* shared access */
		cmBufferWriteUint32(&request.writer, pFile->disposition);	/* create disposition */
		cmBufferWriteUint32(&request.writer, pFile->options);		/* create options */
		pNameOffset = cmBufferWriterGetPosition(&request.writer);
		cmBufferWriterSkip(&request.writer, sizeof(NQ_UINT16));		/* name offset */
		nameLen = (NQ_UINT16)(sizeof(NQ_WCHAR) * cmWStrlen(pName));
		cmBufferWriteUint16(&request.writer, nameLen);				/* name length */
		pContextOffset = cmBufferWriterGetPosition(&request.writer);
		cmBufferWriteUint32(&request.writer, 0);		            /* context offset */
		cmBufferWriteUint32(&request.writer, 0);		            /* context length */
		cmBufferWriterAlign(&request.writer, request.header._start, 8);		
		pTemp = cmBufferWriterGetPosition(&request.writer);
		nameOffset = (NQ_UINT16)cmSmb2HeaderGetWriterOffset(&request.header, &request.writer);
		cmBufferWriterSetPosition(&request.writer,pNameOffset);
		cmBufferWriteUint16(&request.writer, nameOffset);			    /* name offset again */
		cmBufferWriterSetPosition(&request.writer, pTemp);
        cmBufferWriteBytes(&request.writer, (NQ_BYTE *)pName, nameLen); /* name */        
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "durable %s required", doContext ? "" : "not");
		if (doContext && !pFile->share->isIpc)
		{
            ctxId = DHnQ;
#ifdef UD_NQ_INCLUDESMB3
            if (pFile->share->user->server->smb->revision != CCCIFS_ILLEGALSMBREVISION && pFile->share->user->server->smb->revision >= SMB3_DIALECTREVISION)
            {
                ctxId = DH2Q;
                pFile->durableFlags = SMB2DHANDLE_FLAG_NOTPERSISTENT;
            }
#endif /* UD_NQ_INCLUDESMB3 */

            cmBufferWriterAlign(&request.writer, request.header._start, 8);
			contextOffset = cmSmb2HeaderGetWriterOffset(&request.header, &request.writer);
			cmBufferWriterBranch(&request.writer, &contextWriter, 0);

            /* so far 1 context supported in request */
            createContexts[ctxId].pack(&contextWriter, &createContexts[ctxId], pFile);

			contextLength = cmBufferWriterGetDataCount(&contextWriter);
			cmBufferWriterSync(&request.writer, &contextWriter);

			/* update contexts offset and length */
			pTemp = cmBufferWriterGetPosition(&request.writer);
			cmBufferWriterSetPosition(&request.writer, pContextOffset);
			cmBufferWriteUint32(&request.writer, contextOffset);		/* context offset */
			cmBufferWriteUint32(&request.writer, contextLength);		/* context length */
			cmBufferWriterSetPosition(&request.writer, pTemp);
		}
		else
		{
			/* update contexts offset and length */
			pTemp = cmBufferWriterGetPosition(&request.writer);
			cmBufferWriterSetPosition(&request.writer, pContextOffset);
			cmBufferWriteUint32(&request.writer, 0);		/* context offset */
			cmBufferWriteUint32(&request.writer, 0);		/* context length */
			cmBufferWriterSetPosition(&request.writer, pTemp);
		}

        res = pServer->smb->sendReceive(pServer, pShare->user, &request, &response);
		cmBufManGive(request.buffer);
		if ((NQ_UINT)res != SMB_STATUS_INVALID_PARAMETER)
		{
			break;
		}
		doContext = FALSE;
	}
	if (NQ_SUCCESS != res)
	{
		goto Exit;
	}

	/* parse response */
	cmBufferReadByte(&response.reader, &pFile->grantedOplock);	/* oplock level */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_BYTE));		/* reserved */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT32));	/* create action */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT64));	/* creation time */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT64));	/* last access time */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT64));	/* last write time */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT64));	/* change time */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT64));	/* allocation size */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT64));	/* end of file */
	cmBufferReadUint32(&response.reader, &pFile->attributes);	/* attributes */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT32));	/* reserved 2 */
	cmBufferReadBytes(&response.reader, pFile->fid, sizeof(pFile->fid));	/* file ID */
    cmBufferReadUint32(&response.reader, &contextOffset);		/* context offset */
    cmBufferReadUint32(&response.reader, &contextLength);		/* context length */    
    /* parse contexts responses */
    if (contextLength > 0 && contextLength <= cmBufferReaderGetRemaining(&response.reader))
    {
        createContexts[ctxId].process(&response.reader, pFile);
    }
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "durable %s granted", pFile->durableState == DURABLE_GRANTED ? "" : "not");

Exit:
	cmBufManGive(response.buffer);
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", res);
	return res;
}

static NQ_STATUS doCreate(CCFile * pFile)
{
    return create(pFile, TRUE);
}

static NQ_STATUS doRestoreHandle(CCFile * pFile)
{
	Request request;			    /* request descriptor */
	Response response;			    /* response descriptor */
	CCServer * pServer;			    /* server object pointer */
	CCShare * pShare;			    /* share object pointer */
	NQ_BYTE * pContextOffset;	    /* pointer to the context offset field */
	NQ_UINT32 contextOffset;	    /* context offset */
	NQ_UINT32 contextLength;	    /* context length */
	NQ_BYTE * pTemp;			    /* temporary pointer in the writer */
	NQ_UINT16 nameLen;			    /* name length in bytes (not including terminator) */
	NQ_STATUS res;				    /* exchange result */
    CMBufferWriter contextWriter;   /* context writer */
    CreateContextId ctxId = DHnC;   /* context id */
#ifdef UD_NQ_INCLUDESMB3
    NQ_BOOL doDurHandleV2 = (pFile->share->user->server->smb->revision != CCCIFS_ILLEGALSMBREVISION && pFile->share->user->server->smb->revision >= SMB3_DIALECTREVISION);   /* durable handle v2 */
    NQ_BOOL doReplay = !pFile->open;/* for replay detection */
#endif /* UD_NQ_INCLUDESMB3 */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "file:%p", pFile);
        
	request.buffer = NULL;
	response.buffer = NULL;

    if (pFile->durableState != DURABLE_GRANTED)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "No durable handle for file");
        res = NQ_FAIL;
        goto Exit;
    }

	pShare = pFile->share;
	pServer = pShare->user->server;
	
    if (!prepareSingleRequestByShare(&request, pShare, SMB2_CMD_CREATE, 0))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        res = NQ_ERR_OUTOFMEMORY;
        goto Exit;
    }

#ifdef UD_NQ_INCLUDESMB3
    if (doDurHandleV2 && doReplay)
    {
        /* no Create response arrived, replay Create request using same DH2Q context */
        request.header.flags |= SMB2_FLAG_REPLAY_OPERATIONS;
    }
#endif /* UD_NQ_INCLUDESMB3 */

	/* compose request */
	writeHeader(&request);
    cmBufferWriteByte(&request.writer, 0);		                    /* security flags */
    cmBufferWriteByte(&request.writer, pFile->grantedOplock);       /* previously granted oplock */
    cmBufferWriteUint32(&request.writer, 0);	                    /* impersonation */
    cmBufferWriteUint32(&request.writer, 0);	                    /* SMB create flags */
    cmBufferWriteUint32(&request.writer, 0);	                    /* SMB create flags */
    cmBufferWriteUint32(&request.writer, 0);	                    /* reserved */
    cmBufferWriteUint32(&request.writer, 0);	                    /* reserved */
#ifdef UD_NQ_INCLUDESMB3
    if (doDurHandleV2)
    {
        /* repeat these fields */
        cmBufferWriteUint32(&request.writer, pFile->accessMask);	/* desired access */
        cmBufferWriteUint32(&request.writer, pFile->attributes);	/* file attributes */
        cmBufferWriteUint32(&request.writer, pFile->sharedAccess);	/* shared access */
        cmBufferWriteUint32(&request.writer, pFile->disposition);	/* create disposition */
        cmBufferWriteUint32(&request.writer, pFile->options);	    /* create options */
    }
    else
#endif /* UD_NQ_INCLUDESMB3 */
    {
        cmBufferWriteZeroes(&request.writer, 20);                   /* all zeroes */
    }
    cmBufferWriteUint16(&request.writer, 120);	/* fixed name offset */
    nameLen = (NQ_UINT16)(sizeof(NQ_WCHAR) * cmWStrlen(pFile->item.name));
    cmBufferWriteUint16(&request.writer, nameLen); /* name length */
	pContextOffset = cmBufferWriterGetPosition(&request.writer);
	cmBufferWriteUint32(&request.writer, 0);	/* context offset */
	cmBufferWriteUint32(&request.writer, 0);	/* context length */
    cmBufferWriteBytes(&request.writer, (NQ_BYTE *)pFile->item.name, nameLen); /* name */
	cmBufferWriterAlign(&request.writer, request.header._start, 8);
    contextOffset = cmSmb2HeaderGetWriterOffset(&request.header, &request.writer);
    cmBufferWriterBranch(&request.writer, &contextWriter, 0);

    if (!pFile->share->isIpc)
    {
        ctxId = DHnC;
#ifdef UD_NQ_INCLUDESMB3
        if (doDurHandleV2)
        {
            ctxId = doReplay ? DH2Q : DH2C;
            pFile->durableFlags = SMB2DHANDLE_FLAG_NOTPERSISTENT;
        }
#endif /* UD_NQ_INCLUDESMB3 */
        /* so far 1 context supported in request */
        createContexts[ctxId].pack(&contextWriter, &createContexts[ctxId], pFile);
    }
    contextLength = cmBufferWriterGetDataCount(&contextWriter);
    cmBufferWriterSync(&request.writer, &contextWriter);

    /* update contexts offset and length */
    pTemp = cmBufferWriterGetPosition(&request.writer);
    cmBufferWriterSetPosition(&request.writer, pContextOffset);
    cmBufferWriteUint32(&request.writer, contextOffset);		/* context offset */
    cmBufferWriteUint32(&request.writer, contextLength);		/* context length */
    cmBufferWriterSetPosition(&request.writer, pTemp);

	res = pServer->smb->sendReceive(pServer, pShare->user, &request, &response);
	if (NQ_SUCCESS != res)
	{
		goto Exit;
	}

	/* parse response */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_BYTE));		/* oplock level */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_BYTE));		/* reserved */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT32));	/* create action */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT64));	/* creation time */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT64));	/* last access time */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT64));	/* last write time */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT64));	/* change time */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT64));	/* allocation size */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT64));	/* end of file */
	cmBufferReadUint32(&response.reader, &pFile->attributes);	/* attributes */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT32));	/* reserved 2 */
	cmBufferReadBytes(&response.reader, pFile->fid, sizeof(pFile->fid));	/* file ID */
    cmBufferReadUint32(&response.reader, &contextOffset);		/* context offset */
    cmBufferReadUint32(&response.reader, &contextLength);		/* context length */
    /* parse contexts responses */
    if (contextLength > 0 && contextLength <= cmBufferReaderGetRemaining(&response.reader))
    {
        createContexts[ctxId].process(&response.reader, pFile);
    }
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "durable %s granted", pFile->durableState == DURABLE_GRANTED ? "" : "not");

Exit:
	cmBufManGive(request.buffer);
	cmBufManGive(response.buffer);
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", res);
	return res;
}

static NQ_STATUS doClose(CCFile * pFile)
{
	Request request;		/* request descriptor */
	Response response;		/* response descriptor */
	CCServer * pServer;		/* server object pointer */
	CCShare * pShare;		/* share object pointer */
	NQ_STATUS res;			/* exchange result */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "file:%p", pFile);

	request.buffer = NULL;
	response.buffer = NULL;

	pShare = pFile->share;
	pServer = pShare->user->server;
	if (!prepareSingleRequestByShare(&request, pShare, SMB2_CMD_CLOSE, 0))
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
		res = NQ_ERR_OUTOFMEMORY;
		goto Exit;
	}
	
	/* compose request */
	writeHeader(&request);
	cmBufferWriteUint16(&request.writer, 0);		/* flags */
	cmBufferWriteUint32(&request.writer, 0);		/* reserved */
	cmBufferWriteBytes(&request.writer, pFile->fid, sizeof(pFile->fid));		/* file ID */

	res = pServer->smb->sendReceive(pServer, pShare->user, &request, &response);

	/* parse response - we ignore response parameters */

Exit:
	cmBufManGive(request.buffer);
	cmBufManGive(response.buffer);
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", res);
	return res;
}

static NQ_STATUS doQueryDfsReferrals(CCShare * share, const NQ_WCHAR * path, CCCifsParseReferral parser, CMList * list)
{
	Request request;		/* request descriptor */
	Response response;		/* response descriptor */
	CCServer * pServer;		/* server object pointer */
	NQ_STATUS res;			/* exchange result */
	NQ_BYTE * pOffset;		/* pointer to the input offset field in the request */
	NQ_UINT32 offset;		/* offset relative to the header */
	NQ_BYTE * pTemp;		/* pointer in the buffer */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "share:%p path:%s parser:%p list:%p", share, cmWDump(path), parser, list);

	request.buffer = NULL;
	response.buffer = NULL;

	pServer = share->user->server;
	if (!prepareSingleRequestByShare(&request, share, SMB2_CMD_IOCTL, 0))
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
		res = NQ_ERR_OUTOFMEMORY;
		goto Exit;
	}
	
	/* compose request */
	request.header.flags |= SMB2_FLAG_DFS_OPERATIONS;
	writeHeader(&request);
	cmBufferWriterSkip(&request.writer, sizeof(NQ_UINT16));			/* reserved */
	cmBufferWriteUint32(&request.writer, SMB_IOCTL_GET_REFERRALS);	/* CtlCode: FSCTL_DFS_GET_REFERRALS */
	cmBufferWriteUint32(&request.writer, 0xFFFFFFFF);				/* file ID */
	cmBufferWriteUint32(&request.writer, 0xFFFFFFFF);				/* file ID */
	cmBufferWriteUint32(&request.writer, 0xFFFFFFFF);				/* file ID */
	cmBufferWriteUint32(&request.writer, 0xFFFFFFFF);				/* file ID */
	pOffset = cmBufferWriterGetPosition(&request.writer);
	cmBufferWriterSkip(&request.writer, sizeof(NQ_UINT32) * 5);		/* InputOffset/Count + MaxInputResponse + OutputOffset/Count */
	cmBufferWriteUint32(&request.writer, 4096);						/* MaxOutputResponse */
	cmBufferWriteUint32(&request.writer, SMB2_0_IOCTL_IS_FSCTL);	/* flags: FSCTL */
	cmBufferWriteUint32(&request.writer, 0);						/* reserved */
	
	/* end of IOCTL header - start of IOCTL payload */
	offset = cmSmb2HeaderGetWriterOffset(&request.header, &request.writer);
	cmBufferWriteUint16(&request.writer, 4);					/* MaxReferralLevel */
	request.tail.data = (NQ_BYTE*)path;
	request.tail.len = (NQ_COUNT)(sizeof(NQ_WCHAR) * (1 + cmWStrlen(path)));
	
	pTemp = cmBufferWriterGetPosition(&request.writer);
	cmBufferWriterSetPosition(&request.writer, pOffset);
	cmBufferWriteUint32(&request.writer, offset);				/* InputOffset */
	cmBufferWriteUint32(&request.writer, (NQ_UINT32)(request.tail.len + sizeof(NQ_UINT16)));	/* InputCount */
	cmBufferWriteUint32(&request.writer, 0);					/* MaxInputResponse */
	cmBufferWriteUint32(&request.writer, offset);				/* OutputOffset */
	cmBufferWriteUint32(&request.writer, 0);					/* Count */
	cmBufferWriterSetPosition(&request.writer, pTemp);

	res = pServer->smb->sendReceive(pServer, share->user, &request, &response);
	if (NQ_SUCCESS != res)
	{
		goto Exit;
	}

	/* parse response */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT16));	/* reserved */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT32));	/* CtlCode */
	cmBufferReaderSkip(&response.reader, 16);					/* FileId */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT32) * 2);/* InputOffset + InputCount */
	cmBufferReadUint32(&response.reader, &offset);				/* OutputOffset */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT32));	/* OutoutCount */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT32) * 2);/* flags + reserved */

	/* end of IOCTL and start of IOCTL payload */
	parser(&response.reader, list);

Exit:
	cmBufManGive(request.buffer);
	cmBufManGive(response.buffer);
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", res);
	return res;
}

static NQ_STATUS doFindOpen(CCSearch * pSearch)
{
	Request request;			/* request descriptor */
	Response response;			/* response descriptor */
	NQ_STATUS res;				/* exchange result */
	SearchContext * pContext;	/* casted pointer */
	NQ_WCHAR * dirName = NULL;  /* parent directory name */
	NQ_BYTE * pNameOffset;	/* pointer to the name offset field */
	NQ_UINT16 nameOffset;	/* name offset */
	NQ_BYTE * pTemp;		/* temporary pointer in the writer */
	NQ_UINT16 nameLen;		/* name length in bytes (not including terminator) */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "search:%p", pSearch);

	request.buffer = NULL;
	response.buffer = NULL;

	/* create context */
	pContext = (SearchContext *)cmMemoryAllocate(sizeof(SearchContext));
	if (NULL == pContext)
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
		res = NQ_ERR_OUTOFMEMORY;
		goto Exit;
	}
	pSearch->context = pContext;
	if (ccUtilsFilePathHasWildcards(pSearch->item.name))
	{
		dirName = ccUtilsFilePathStripWildcards(pSearch->item.name);
	}
	else
	{
		dirName = ccUtilsDirectoryFromPath(pSearch->item.name);
	}
	if (NULL == dirName)
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
		res = NQ_ERR_OUTOFMEMORY;
		goto Exit;
	}
		
	if (!prepareSingleRequestByShare(&request, pSearch->share, SMB2_CMD_CREATE, 0))
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		res = NQ_ERR_OUTOFMEMORY;
		goto Exit;
	}
	
	/* compose request */
	writeHeader(&request);
	cmBufferWriteByte(&request.writer, 0);		/* security flags */
	cmBufferWriteByte(&request.writer, SMB2_OPLOCK_LEVEL_NONE);	/* no oplock */
	cmBufferWriteUint32(&request.writer, SMB2_IMPERSONATION_IMPERSONATION);	/* impersonation */
	cmBufferWriteUint32(&request.writer, 0);	/* SMB create flags */
	cmBufferWriteUint32(&request.writer, 0);	/* SMB create flags */
	cmBufferWriteUint32(&request.writer, 0);	/* reserved */
	cmBufferWriteUint32(&request.writer, 0);	/* reserved */
	cmBufferWriteUint32(&request.writer, 0x00100081);	/* desired access */
	cmBufferWriteUint32(&request.writer, 0);			/* file attributes */
	cmBufferWriteUint32(&request.writer, SMB2_SHAREACCESS_READ | SMB2_SHAREACCESS_WRITE | SMB2_SHAREACCESS_DELETE);	/* shared access */
	cmBufferWriteUint32(&request.writer, 1);			/* open existing */
	cmBufferWriteUint32(&request.writer, SMB2_CREATEOPTIONS_SYNCHRONOUS_OPERATIONS);			/* sync operations */
	pNameOffset = cmBufferWriterGetPosition(&request.writer);
	cmBufferWriterSkip(&request.writer, sizeof(NQ_UINT16));		/* name offset */
	nameLen = (NQ_UINT16)(sizeof(NQ_WCHAR) * cmWStrlen(dirName)); 
	cmBufferWriteUint16(&request.writer, nameLen);				/* name length */
	cmBufferWriteUint32(&request.writer, 0);		/* context offset */
	cmBufferWriteUint32(&request.writer, 0);		/* context length */
	cmBufferWriterAlign(&request.writer, request.header._start, 8);
	nameOffset = (NQ_UINT16)cmSmb2HeaderGetWriterOffset(&request.header, &request.writer);
	pTemp = cmBufferWriterGetPosition(&request.writer);
	cmBufferWriterSetPosition(&request.writer, pNameOffset);
	cmBufferWriteUint16(&request.writer, nameOffset);			/* name offset again */
	cmBufferWriterSetPosition(&request.writer, pTemp);
	if (nameLen == 0)
        cmBufferWriteUint16(&request.writer, 0);		
	request.tail.data = (NQ_BYTE *)dirName;
	request.tail.len = nameLen; 

	res = pSearch->server->smb->sendReceive(pSearch->server, pSearch->share->user, &request, &response);
	if (NQ_SUCCESS != res)
	{
		goto Exit;
	}

	/* parse response */

	cmBufferReaderSkip(&response.reader, sizeof(NQ_BYTE));		/* oplock level */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_BYTE));		/* reserved */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT32));	/* create action */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT64));	/* creation time */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT64));	/* last access time */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT64));	/* last write time */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT64));	/* change time */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT64));	/* allocation size */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT64));	/* end of file */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT32));	/* attributes */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT32));	/* reserved 2 */
	cmBufferReadBytes(&response.reader, pContext->fid, sizeof(pContext->fid));	/* file ID */

	goto Exit;
	
Exit:
	cmMemoryFree(dirName);
	cmBufManGive(request.buffer);
	cmBufManGive(response.buffer);
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", res);
	return res;
}

static NQ_STATUS doFindMore(CCSearch * pSearch)
{
	Request request;			/* request descriptor */
	Response response;			/* response descriptor */
	SearchContext * pContext;	/* casted pointer */
	NQ_WCHAR * pattern = NULL;  /* search pattern */
	NQ_BYTE * pNameOffset;	/* pointer to the name offset field */
	NQ_UINT16 nameOffset;	/* name offset */
	NQ_BYTE * pTemp;		/* temporary pointer in th writer */
	NQ_UINT16 nameLen;		/* name length in bytes (not including terminator) */
	NQ_UINT32 outputLen;	/* output buffer length */
	NQ_STATUS res;			/* exchange result */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "search:%p", pSearch);

	request.buffer = NULL;

	pContext = (SearchContext *)pSearch->context;
	if (NULL == pContext)
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "Search context does not exists");
		res = NQ_ERR_BADFID;
		goto Exit;
	}
	if (ccUtilsFilePathHasWildcards(pSearch->item.name))
	{
		pattern = ccUtilsFilePathGetWildcards(pSearch->item.name);
	}
	else
	{
		pattern = ccUtilsFileFromPath(pSearch->item.name);
	}
	if (NULL == pattern)
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
		res = NQ_ERR_OUTOFMEMORY;
		goto Exit;
	}
    if (!prepareSingleRequestByShare(&request, pSearch->share, SMB2_CMD_QUERYDIRECTORY, 65536))
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
		res = NQ_ERR_OUTOFMEMORY;
		goto Exit;
	}
	
	/* compose request */
	writeHeader(&request);
	cmBufferWriteByte(&request.writer, SMB2_FILEINFO_BOTHDIRECTORY);	/* info class */
	cmBufferWriteByte(&request.writer, pSearch->isFirst? 1 : 0); 		/* flags - restart */
	cmBufferWriteUint32(&request.writer, 0);							/* file index */
	cmBufferWriteBytes(&request.writer, pContext->fid, sizeof(pContext->fid)); /* file ID */
	pNameOffset = cmBufferWriterGetPosition(&request.writer);
	cmBufferWriterSkip(&request.writer, sizeof(NQ_UINT16));		/* name offset */
	nameLen = (NQ_UINT16)(sizeof(NQ_WCHAR) * cmWStrlen(pattern)); 
	cmBufferWriteUint16(&request.writer, nameLen);				/* name length */
	cmBufferWriteUint32(&request.writer, 65536);				/* outout buffer length */
	if (0 == nameLen)
	{
		nameOffset = 0;
	}
	else
	{
		nameOffset = (NQ_UINT16)cmSmb2HeaderGetWriterOffset(&request.header, &request.writer);
	}
	pTemp = cmBufferWriterGetPosition(&request.writer);
	cmBufferWriterSetPosition(&request.writer, pNameOffset);
	cmBufferWriteUint16(&request.writer, nameOffset);			/* name offset */
	cmBufferWriterSetPosition(&request.writer, pTemp);
	request.tail.data = (NQ_BYTE *)pattern;
	request.tail.len = nameLen; 

	res = pSearch->server->smb->sendReceive(pSearch->server, pSearch->share->user, &request, &response);
	if (NQ_SUCCESS != res)
	{
		cmBufManGive(response.buffer);
		goto Exit;
	}

	/* parse response */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT16));	/* output buffer offset */
	cmBufferReadUint32(&response.reader, &outputLen);			/* output buffer length */
	cmBufferReaderInit(
		&pSearch->parser,
		cmBufferReaderGetPosition(&response.reader),
		(NQ_COUNT)outputLen
		);
	
	pSearch->buffer = response.buffer;		/* to be released later */

Exit:
	cmMemoryFree(pattern);
	cmBufManGive(request.buffer);
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", res);
	return res;
}

static NQ_STATUS doFindClose(CCSearch * pSearch)
{
	Request request;			/* request descriptor */
	Response response;			/* response descriptor */
	SearchContext * pContext;	/* casted pointer */
	NQ_STATUS res;			/* exchange result */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "search:%p", pSearch);

	request.buffer = NULL;
	response.buffer = NULL;

	pContext = (SearchContext *)pSearch->context;
	if (NULL == pContext)
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "Search context does not exists");
		res = NQ_ERR_BADFID;
		goto Exit;
	}

	if (!prepareSingleRequestByShare(&request, pSearch->share, SMB2_CMD_CLOSE, 0))
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
		res = NQ_ERR_OUTOFMEMORY;
		goto Exit;
	}
	
	/* compose request */
	writeHeader(&request);
	cmBufferWriteUint16(&request.writer, 0);		/* flags */
	cmBufferWriteUint32(&request.writer, 0);		/* reserved */
	cmBufferWriteBytes(&request.writer, pContext->fid, sizeof(pContext->fid));	/* file ID */

	res = pSearch->server->smb->sendReceive(pSearch->server, pSearch->share->user, &request, &response);

	/* parse response - we ignore response parameters */

Exit:
	cmBufManGive(request.buffer);
	cmBufManGive(response.buffer);
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", res);
	return res;
}

static void writeCallback(CCServer * pServer, Match * pContext)
{
	WriteMatch * pMatch = (WriteMatch *)pContext;	/* casted pointer */
	NQ_BYTE buffer[20];								/* buffer for structure */
	NQ_UINT tailLen = pServer->transport.recv.remaining;	/* bytes remaining */
	Response * pResponse = pContext->response;				/* response structure ptr */
	NQ_UINT32 count = 0;     								/* bytes written */
    NQ_UINT32     currentTime;                    /* Current Time for checking timed-out responses*/

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "server:%p context:%p", pServer, pContext);

	/* receive the rest of command */
	if (tailLen != ccTransportReceiveBytes(&pServer->transport, buffer, tailLen))
	{
    	ccTransportReceiveEnd(&pServer->transport);
		goto Exit;
	}
    ccTransportReceiveEnd(&pServer->transport);
#ifdef UD_NQ_INCLUDESMBCAPTURE
    cmCapturePacketWritePacket( buffer, tailLen);
	cmCapturePacketWriteEnd();
#endif /* UD_NQ_INCLUDESMBCAPTURE */
	cmBufferReaderInit(&pResponse->reader, buffer, tailLen);

	/* parse the response */
	if (SMB_STATUS_SUCCESS == pResponse->header.status)
	{
		cmBufferReaderSkip(&pResponse->reader, sizeof(NQ_UINT16));	/* reserved */
		cmBufferReadUint32(&pResponse->reader, &count);	/* count */
	}
    currentTime = (NQ_UINT32)syGetTimeInSec();


    /* call up - if timeout didn't expire */
	if ((pMatch->timeCreated + pMatch->setTimeout) > currentTime)
    {
	    pMatch->callback(pResponse->header.status == 0? 0 : (NQ_STATUS)ccErrorsStatusToNq(pResponse->header.status, TRUE), (NQ_UINT)count, pMatch->context);
    }
	else
	{
		/* response timed out */
		LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Write response arrived after timeout. Mid:%d Expected:%d arrived:%d. Will not be handled.",
				pMatch->match.mid, (pMatch->timeCreated + pMatch->setTimeout), currentTime);
	}
	/* release context */

Exit:
	if (NULL != pMatch->match.thread->element.item.guard)
	{
		syMutexDelete(pMatch->match.thread->element.item.guard);
		cmMemoryFree(pMatch->match.thread->element.item.guard);
		pMatch->match.thread->element.item.guard = NULL;
	}
	cmMemoryFree(pMatch->match.response);
    cmListItemDispose((CMItem *)pMatch);
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

static NQ_BOOL disposeReadWriteCallback(CMItem * pItem)
{
    Match * pMatch = (Match *)pItem;

    if (NULL != pMatch && NULL != pMatch->response)
    {
        cmMemoryFree(pMatch->response);
        pMatch->response = NULL;
    }

    return TRUE;
}

static NQ_BOOL removeReadWriteMatch(void * hook, void* _pServer, NQ_BOOL isReadMatch)
{
    Match *pMatch;
    NQ_UINT16 matchType;
    CMIterator itr;
    NQ_BOOL result = FALSE;
    CCServer *pServer = (CCServer *)_pServer;

	cmListIteratorStart(&pServer->expectedResponses, &itr);

	if (isReadMatch)
	{
		matchType = MATCHINFO_READ;
		while(cmListIteratorHasNext(&itr))
		{
			pMatch = (Match *)cmListIteratorNext(&itr);
			if ((pMatch->matchExtraInfo & matchType) && (((ReadMatch *)pMatch)->hook == hook))
			{
				result = disposeReadWriteCallback(&pMatch->item);
				cmListItemRemoveAndDispose(&pMatch->item);
				break;
			}
		}
	}
	else
	{
		matchType = MATCHINFO_WRITE;
		while(cmListIteratorHasNext(&itr))
		{
			pMatch = (Match *)cmListIteratorNext(&itr);
			if ((pMatch->matchExtraInfo & matchType) && (((WriteMatch *)pMatch)->hook == hook))
			{
				result = disposeReadWriteCallback(&pMatch->item);
				cmListItemRemoveAndDispose(&pMatch->item);
				break;
			}
		}
	}
    cmListIteratorTerminate(&itr);

    return result;
}


static NQ_STATUS doWrite(CCFile * pFile, const NQ_BYTE * data, NQ_UINT bytesToWrite, CCCifsWriteCallback callback, void * context, void *hook)
{
	Request         request;			/* request descriptor */
	NQ_BYTE     *   pDataOffset;		/* pointer to the data offset field */
	NQ_UINT16       dataOffset;		    /* value in this field */
	NQ_STATUS       res;				/* exchange result */
	NQ_BYTE     *   pTemp;				/* temporary pointer in the writer */
	WriteMatch  *   pMatch;		        /* sync to response */
    CCServer    *   pServer;            /* pointer to server */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "file:%p dtat:%p bytes:%u callback:%p context:%p", pFile, data, bytesToWrite, callback, context);

	request.buffer = NULL;

    if (!prepareSingleRequestByShare(&request, pFile->share, SMB2_CMD_WRITE, (NQ_UINT32)bytesToWrite))
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
		res = NQ_ERR_OUTOFMEMORY;
		goto Exit;
	}

    pServer = pFile->share->user->server;
    
	/* compose request */
	writeHeader(&request);
	pDataOffset = cmBufferWriterGetPosition(&request.writer);
	cmBufferWriterSkip(&request.writer, sizeof(NQ_UINT16));		/* data offset */
	cmBufferWriteUint32(&request.writer, bytesToWrite);			/* length */
	cmBufferWriteUint64(&request.writer, &pFile->offset);		/* offset */
	cmBufferWriteBytes(&request.writer, pFile->fid, sizeof(pFile->fid));	/* file ID */
	cmBufferWriteUint32(&request.writer, 0);					/* channel */
	cmBufferWriteUint32(&request.writer, 0);					/* remaining bytes */
	cmBufferWriteUint16(&request.writer, 0);					/* write channel info offset */
	cmBufferWriteUint16(&request.writer, 0);					/* write channel info length */
	cmBufferWriteUint32(&request.writer, 0);					/* flags */
	dataOffset = (NQ_UINT16)cmSmb2HeaderGetWriterOffset(&request.header, &request.writer);
	pTemp = cmBufferWriterGetPosition(&request.writer);
	cmBufferWriterSetPosition(&request.writer, pDataOffset);
	cmBufferWriteUint16(&request.writer, dataOffset);			/* data offset */
	cmBufferWriterSetPosition(&request.writer, pTemp);
	request.tail.data = (NQ_BYTE *)data;
	request.tail.len = bytesToWrite;

	pMatch = (WriteMatch *)cmListItemCreate(sizeof(WriteMatch), NULL, CM_LISTITEM_NOLOCK);
	if (NULL == pMatch)
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
		res = NQ_ERR_OUTOFMEMORY;
		goto Exit;
	}
	pMatch->match.response = (Response *)cmMemoryAllocate(sizeof(Response));
	if (NULL == pMatch->match.response)
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
		res = NQ_ERR_OUTOFMEMORY;
		goto Exit1;
	}

	pMatch->match.thread = cmThreadGetCurrent();
    if (0 == pMatch->match.thread)
    {
    	LOGERR(CM_TRC_LEVEL_ERROR, ">>>No thread object.");
       	res = NQ_ERR_GETDATA;
       	goto Exit1;
    }

	pMatch->match.server = pFile->share->user->server;
	pMatch->match.isResponseAllocated = TRUE;
	pMatch->match.matchExtraInfo = MATCHINFO_WRITE;
	pMatch->match.cond = NULL;
    pMatch->timeCreated = (NQ_UINT32)syGetTimeInSec();
    pMatch->setTimeout = ccConfigGetTimeout();
	pMatch->callback = callback;
	pMatch->context = context;
	pMatch->hook = hook;

	res = pServer->smb->sendRequest(pFile->share->user->server, pFile->share->user, &request, &pMatch->match, disposeReadWriteCallback);

	if (NQ_SUCCESS != res)
	{
		cmMemoryFree(pMatch->match.response);
		if (pMatch->match.item.master != NULL)
			cmListItemRemoveAndDispose((CMItem *)pMatch);
		else
			cmListItemDispose((CMItem *)pMatch);
	}
	/* responses are processed in the callback */
	goto Exit;

Exit1:
	cmMemoryFree(pMatch);
	pMatch = NULL;

Exit:
	cmBufManGive(request.buffer);
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", res);
	return res;
}

static void readCallback(CCServer * pServer, Match * pContext)
{
#define READSTRUCT_SIZE 14
	ReadMatch * pMatch = (ReadMatch *)pContext;		/* casted pointer */
	NQ_BYTE buffer[64];								/* buffer for structure and padding */
	Response * pResponse = pContext->response;		/* response structure pointer */
	NQ_UINT32 count = 0;							/* bytes read */
	NQ_BYTE offset;									/* data offset */
    NQ_UINT32     currentTime;                      /* Current Time for checking timed-out responses*/

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "server:%p context:%p", pServer, pContext);

	/* receive the structure but not the buffer (payload) */
	if (pResponse->tailLen >= READSTRUCT_SIZE && READSTRUCT_SIZE == ccTransportReceiveBytes(&pServer->transport, buffer, READSTRUCT_SIZE))
	{
#ifdef UD_NQ_INCLUDESMBCAPTURE
		cmCapturePacketWritePacket( buffer,READSTRUCT_SIZE );
#endif /* UD_NQ_INCLUDESMBCAPTURE */
		/* parse the response */
		cmBufferReaderInit(&pResponse->reader, buffer, sizeof(buffer));
		if (NQ_SUCCESS == pResponse->header.status)
		{
			cmBufferReadByte(&pResponse->reader, &offset);				/* data offset */
			cmBufferReaderSkip(&pResponse->reader, sizeof(NQ_BYTE));	/* reserved */
			cmBufferReadUint32(&pResponse->reader, &count);	/* data length */
		    offset = (NQ_BYTE)(offset - (SMB2_HEADERSIZE + 16));	/* bytes to skip */
		    if (offset > 0 )
		    {
			    ccTransportReceiveBytes(&pServer->transport, buffer, (NQ_COUNT)offset);	/* read padding */
#ifdef UD_NQ_INCLUDESMBCAPTURE
				cmCapturePacketWritePacket(buffer,offset );
#endif /* UD_NQ_INCLUDESMBCAPTURE */
		    }
		    ccTransportReceiveBytes(&pServer->transport, pMatch->buffer, (NQ_COUNT)count);	/* read into application buffer */
#ifdef UD_NQ_INCLUDESMBCAPTURE
		    cmCapturePacketWritePacket(pMatch->buffer, (NQ_UINT)count);
			cmCapturePacketWriteEnd();
#endif /* UD_NQ_INCLUDESMBCAPTURE */
		}
	}
	else if (pResponse->tailLen < READSTRUCT_SIZE)
	{
#ifdef UD_NQ_INCLUDESMBCAPTURE
		NQ_COUNT res =
#endif /* UD_NQ_INCLUDESMBCAPTURE */
		ccTransportReceiveBytes(&pServer->transport, buffer, pResponse->tailLen );
#ifdef UD_NQ_INCLUDESMBCAPTURE
		if (res > 0)
		{
			cmCapturePacketWritePacket(buffer,res );
			cmCapturePacketWriteEnd();
		}
#endif /* UD_NQ_INCLUDESMBCAPTURE */
		count = 0;
	}
	else
	{
		count = 0;
#ifdef UD_NQ_INCLUDESMBCAPTURE
		cmCapturePacketWriteEnd();
#endif /* UD_NQ_INCLUDESMBCAPTURE */
	}
    ccTransportReceiveEnd(&pServer->transport);

	currentTime = (NQ_UINT32)syGetTimeInSec();

    /* call up */
	if ((pMatch->timeCreated + pMatch->setTimeout) > currentTime)
    {
        pMatch->callback(pResponse->header.status == SMB_STATUS_SUCCESS? 0 : (NQ_STATUS)ccErrorsStatusToNq(pResponse->header.status, TRUE), (NQ_UINT)count, pMatch->context, count < pMatch->count);
    }
	else
	{
		/* response timed out */
		LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Read response arrived after timeout. Mid:%d Expected:%d arrived:%d. Will not be handled.",
				pMatch->match.mid, (pMatch->timeCreated + pMatch->setTimeout), currentTime);
	}

	/* release */
	if (NULL != pMatch->match.thread->element.item.guard)
	{
		syMutexDelete(pMatch->match.thread->element.item.guard);
		cmMemoryFree(pMatch->match.thread->element.item.guard);
		pMatch->match.thread->element.item.guard = NULL;
	}
	cmMemoryFree(pMatch->match.response);
    cmListItemDispose((CMItem *)pMatch);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}



static NQ_STATUS doRead(CCFile * pFile, const NQ_BYTE * buffer, NQ_UINT bytesToRead, CCCifsReadCallback callback, void * context, void *hook)
{
	Request         request;			/* request descriptor */
	NQ_STATUS       res;				/* exchange result */
	ReadMatch   *   pMatch;		        /* sync to response */
    CCServer    *   pServer;            /* pointer to server*/

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "file:%p buff:%p bytes:%u callback:%p context:%p", pFile, buffer, bytesToRead, callback, context);

	request.buffer = NULL;

    if (!prepareSingleRequestByShare(&request, pFile->share, SMB2_CMD_READ, (NQ_UINT32)bytesToRead))
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
		res = NQ_ERR_OUTOFMEMORY;
		goto Exit;
	}

    pServer = pFile->share->user->server;
     
	/* compose request */
	writeHeader(&request);
	cmBufferWriteByte(&request.writer, 0x50);					/* padding */
	cmBufferWriteByte(&request.writer, 0);						/* reserved */
	cmBufferWriteUint32(&request.writer, bytesToRead);			/* length */
	cmBufferWriteUint64(&request.writer, &pFile->offset);		/* offset */
	cmBufferWriteBytes(&request.writer, pFile->fid, sizeof(pFile->fid));	/* file ID */
	cmBufferWriteUint32(&request.writer, 0);					/* min count */
	cmBufferWriteUint32(&request.writer, 0);					/* channel */
	cmBufferWriteUint32(&request.writer, 0);					/* remaining bytes */
	cmBufferWriteUint16(&request.writer, 0);					/* write channel info offset */
	cmBufferWriteUint16(&request.writer, 0);					/* write channel info length */
	cmBufferWriteByte(&request.writer, 0);						/* buffer */

	pMatch = (ReadMatch *)cmListItemCreate(sizeof(ReadMatch), NULL , CM_LISTITEM_NOLOCK);
	if (NULL == pMatch)
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
		res = NQ_ERR_OUTOFMEMORY;
		goto Exit;
	}

	pMatch->match.response = (Response *)cmMemoryAllocate(sizeof(Response));
	if (NULL == pMatch->match.response)
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
		res = NQ_ERR_OUTOFMEMORY;
		goto Exit1;
	}

	pMatch->match.thread = cmThreadGetCurrent();
    if (0 == pMatch->match.thread)
    {
    	LOGERR(CM_TRC_LEVEL_ERROR, ">>>No thread object.");
    	res = NQ_ERR_GETDATA;
    	goto Exit1;
    }

	pMatch->match.server = pFile->share->user->server;
	pMatch->match.isResponseAllocated = TRUE;
	pMatch->match.matchExtraInfo = MATCHINFO_READ;
	pMatch->match.cond = NULL;
    pMatch->timeCreated = (NQ_UINT32)syGetTimeInSec();
    pMatch->setTimeout = ccConfigGetTimeout();
	pMatch->callback = callback;
	pMatch->context = context;
	pMatch->count = bytesToRead;
	pMatch->buffer = (NQ_BYTE *)buffer;
	pMatch->hook = hook;


	res = pServer->smb->sendRequest(pFile->share->user->server, pFile->share->user, &request, &pMatch->match, disposeReadWriteCallback);

	if (NQ_SUCCESS != res)
	{
		cmMemoryFree(pMatch->match.response);
		if (pMatch->match.item.master != NULL)
			cmListItemRemoveAndDispose((CMItem *)pMatch);
		else
			cmListItemDispose((CMItem *)pMatch);
	}
	/* responses are processed in the callback */
	goto Exit;
Exit1:
	cmMemoryFree(pMatch);
    pMatch = NULL;

Exit:
	cmBufManGive(request.buffer);
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", res);
	return res;
}

#ifdef UD_CC_INCLUDESECURITYDESCRIPTORS	

static NQ_STATUS doQuerySecurityDescriptor(CCFile * pFile, CMSdSecurityDescriptor * sd)
{
	Request request;		/* request descriptor */
	Response response;		/* response descriptor */
	CCServer * pServer;		/* server object pointer */
	NQ_STATUS res;			/* exchange result */
	NQ_UINT32 responseSize;	/* required response size */
	CMRpcPacketDescriptor in;	/* for parsing SD */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "file:%p sd:%p", pFile, sd);

	request.buffer = NULL;
	response.buffer = NULL;

	pServer = pFile->share->user->server;
	
	/* query with zero buffer to get SD length */
	res = writeQueryInfoRequest(&request, pFile, SMB2_INFO_SECURITY, 0, 0, SMB2_SIF_OWNER | SMB2_SIF_GROUP | SMB2_SIF_DACL);
	if (NQ_SUCCESS != res)
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
		res = NQ_ERR_OUTOFMEMORY;
		goto Exit;
	}
	request.tail.data = NULL;
	request.tail.len = 0;
	
	res = pServer->smb->sendReceive(pServer, pFile->share->user, &request, &response);
    cmBufManGive(request.buffer);
    request.buffer = NULL;
	if (NQ_ERR_MOREDATA != res)
	{
		goto Exit;
	}

	/* parse error response */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT16));	/* offset */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT32));	/* length - should be 4 */
	cmBufferReadUint32(&response.reader, &responseSize);		/* required buffer size */
    cmBufManGive(response.buffer);
    response.buffer = NULL;
	if (responseSize > UD_CM_SECURITYDESCRIPTORLENGTH)
	{
		LOGERR(CM_TRC_LEVEL_FUNC_COMMON," requested buffer size (%d) is larger then maximum SD buffer (%d)" , responseSize , UD_CM_SECURITYDESCRIPTORLENGTH);
		goto Exit;
	}
	/* query with required buffer */
	res = writeQueryInfoRequest(&request, pFile, SMB2_INFO_SECURITY, 0, responseSize, SMB2_SIF_OWNER | SMB2_SIF_GROUP | SMB2_SIF_DACL);
	if (NQ_SUCCESS != res)
	{
		LOGERR(CM_TRC_LEVEL_FUNC_COMMON," writeQueryInfoRequest() failed");
		goto Exit;
	}
	request.tail.data = NULL;
	request.tail.len = 0;
	
	res = pServer->smb->sendReceive(pServer, pFile->share->user, &request, &response);
	if (NQ_SUCCESS != res)
	{
		LOGERR(CM_TRC_LEVEL_FUNC_COMMON," sendReceive() failed");
		goto Exit;
	}

	/* parse response */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT16));	/* offset */
	cmBufferReadUint32(&response.reader, &sd->length);	/* length */
	cmRpcSetDescriptor(&in, cmBufferReaderGetPosition(&response.reader), FALSE);
	cmSdParseSecurityDescriptor(&in, sd);			/* security descriptor */

Exit:
	cmBufManGive(request.buffer);
	cmBufManGive(response.buffer);
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", res);
	return res;
}

static NQ_STATUS doSetSecurityDescriptor(CCFile * pFile, const CMSdSecurityDescriptor * sd)
{
	Request request;		/* request descriptor */
	Response response;		/* response descriptor */
	CCServer * pServer;		/* server object pointer */
	NQ_STATUS res;			/* exchange result */
	CMRpcPacketDescriptor out;	/* for packing SD */
	NQ_BYTE * sdBuffer;			/* buffer for packing SD - the same size as SD itself */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "file:%p sd:%p", pFile, sd);

	request.buffer = NULL;
	response.buffer = NULL;

	pServer = pFile->share->user->server;
	sdBuffer = cmBufManTake((NQ_COUNT)(sd->length + 32));
	if (NULL == sdBuffer)
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
		res = NQ_ERR_OUTOFMEMORY;
		goto Exit;
	}

	/* compose request */
	cmRpcSetDescriptor(&out, sdBuffer, FALSE);
	cmSdPackSecurityDescriptor(&out, sd, 0x0f);
	res = writeSetInfoRequest(
		&request, 
		pFile, 
		SMB2_INFO_SECURITY, 
		0, 
		SMB2_SIF_OWNER | SMB2_SIF_GROUP | SMB2_SIF_DACL, 
		(NQ_UINT32)(out.current - sdBuffer)
		);
	if (NQ_SUCCESS != res)
	{
		goto Exit;
	}
	
	request.tail.data = sdBuffer;
	request.tail.len = (NQ_COUNT)(out.current - sdBuffer);
	
	res = pServer->smb->sendReceive(pServer, pFile->share->user, &request, &response);
	/* parse response */

Exit:
	cmBufManGive(request.buffer);
	cmBufManGive(response.buffer);
	cmBufManGive(sdBuffer);
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", res);
	return res;
}

#endif /* UD_CC_INCLUDESECURITYDESCRIPTORS */


static NQ_STATUS doQueryFileInfoByHandle(CCFile * pFile, CCFileInfo * pInfo)
{
	Request request;		/* request descriptor */
	Response response;		/* response descriptor */
	CCServer * pServer;		/* server object pointer */
	NQ_STATUS res;			/* exchange result */
	NQ_BYTE level[] = {	SMB2_FILEINFO_BASIC,
						SMB2_FILEINFO_STANDARD,
						SMB2_FILEINFO_INTERNAL
					  };
	NQ_COUNT i;

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "file:%p info:%p", pFile, pInfo);

	response.buffer = NULL;
	pServer = pFile->share->user->server;

	for (i = 0; i < sizeof(level)/sizeof(level[0]); i++)
	{
		/* compose request */
		res = writeQueryInfoRequest(
			&request,
			pFile,
			SMB2_INFO_FILE,
			level[i],
			MAXINFORESPONSE_SIZE,
			0
			);
		if (NQ_SUCCESS != res)
		{
			goto Exit;
		}

		request.tail.data = NULL;
		request.tail.len = 0;

		res = pServer->smb->sendReceive(pServer, pFile->share->user, &request, &response);
		cmBufManGive(request.buffer);

		if (NQ_SUCCESS != res)
		{
			goto Exit;
		}
	
		/* parse response */
		cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT16) + sizeof(NQ_UINT32));
		fileInfoResponseParser(&response.reader, pInfo, level[i]);
	
		cmBufManGive(response.buffer);
		response.buffer = NULL;
    }

Exit:
	cmBufManGive(response.buffer);
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", res);
	return res;
}

static NQ_STATUS doQueryFileInfoByName(CCShare * pShare, const NQ_WCHAR * fileName, CCFileInfo * pInfo)
{
	NQ_STATUS res;			/* exchange result */
	CCFile file;			/* open file */
    NQ_BOOL isEmptyName = (*fileName == cmWChar('\\')) ? syMemcmp(fileName + 1, emptyFileName, sizeof(NQ_WCHAR)) == 0 : 
                                                         syMemcmp(fileName, emptyFileName, sizeof(NQ_WCHAR)) == 0;
    
	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "share:%p file:%s info:%p", pShare, cmWDump(fileName), pInfo);

    file.grantedOplock = SMB2_OPLOCK_LEVEL_NONE;
	file.accessMask = SMB_DESIREDACCESS_SYNCHRONISE | SMB_DESIREDACCESS_READATTRIBUTES;
	file.attributes = 0;
	file.disposition = SMB2_CREATEDISPOSITION_OPEN;
	file.options = SMB2_CREATEOPTIONS_NONE;
	file.share = pShare;
	file.sharedAccess = SMB2_SHAREACCESS_WRITE | SMB2_SHAREACCESS_READ | SMB2_SHAREACCESS_DELETE;
    /* special case: durable is required for opening a root folder */
    if (isEmptyName)
    {
        file.durableState = DURABLE_REQUIRED;
        cmGenerateUuid(&file.durableHandle);
    }
    else
    {
        file.durableState = DURABLE_NOTREQUIRED;
        syMemset(&file.durableHandle, 0, sizeof(file.durableHandle));
    }
    file.durableFlags = 0;
    file.durableTimeout = 0;
	file.item.name = cmMemoryCloneWString(fileName);
	if (NULL == file.item.name)
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
		res = NQ_ERR_OUTOFMEMORY;
		goto Exit;
	}

	res = create(&file, TRUE);
	if (NQ_SUCCESS != res)
	{
		goto Exit;
	}
	
	doQueryFileInfoByHandle(&file, pInfo);

	doClose(&file);

Exit:
	cmMemoryFree(file.item.name);
	file.item.name = NULL;
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", res);
	return res;
}

static NQ_STATUS doQueryFsInfo(CCShare * pShare, CCVolumeInfo * pInfo)
{
	Request request;		/* request descriptor */
	Response response;		/* response descriptor */
	CCServer * pServer;		/* server object pointer */
	NQ_STATUS res;			/* exchange result */
	NQ_UINT64 temp64;		/* for parsing 64-bit values */
	NQ_UINT32 temp32;		/* for parsing 32-bit values */
	CCFile file;			/* open file */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "share:%p info:%p", pShare, pInfo);

	request.tail.data = NULL;
	request.tail.len = 0;

	request.buffer = NULL;
	response.buffer = NULL;

	pServer = pShare->user->server;

    file.grantedOplock = SMB2_OPLOCK_LEVEL_NONE;
    file.accessMask = SMB_DESIREDACCESS_SYNCHRONISE | SMB_DESIREDACCESS_READATTRIBUTES;/* 0x00100080 */
	file.attributes = 0;
	file.disposition = SMB2_CREATEDISPOSITION_OPEN;
	file.options =  SMB2_CREATEOPTIONS_SYNCHRONOUS_OPERATIONS | SMB2_CREATEOPTIONS_DIRECTORY_FILE; /*0x21*/
	file.share = pShare;
    file.sharedAccess = SMB2_SHAREACCESS_DELETE | SMB2_SHAREACCESS_READ | SMB2_SHAREACCESS_WRITE;
    file.item.name = emptyFileName;
    /* special case: durable is required for opening a root folder */
    file.durableState = DURABLE_REQUIRED;
    cmGenerateUuid(&file.durableHandle);
    file.durableFlags = 0;
    file.durableTimeout = 0;

    res = create(&file, FALSE);
	if (NQ_SUCCESS != res)
	{
		goto Exit;
	}
	
	/* compose FsSizeInformation request */
	res = writeQueryInfoRequest(
		&request, 
		&file, 
		SMB2_INFO_FILESYSTEM, 
		SMB2_FSINFO_SIZE, 
		MAXINFORESPONSE_SIZE, 
		0 /*cmBufferWriterGetRemaining(&request.writer)*/
		);
	if (NQ_SUCCESS != res)
	{
		goto Error;
	}
	
	res = pServer->smb->sendReceive(pServer, pShare->user, &request, &response);
	if (NQ_SUCCESS != res)
	{
		goto Error;
	}

	/* parse response */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT16) + sizeof(NQ_UINT32));
	cmBufferReadUint64(&response.reader, &temp64);	/* total allocation units */
	pInfo->totalClusters.low = temp64.low;
	pInfo->totalClusters.high = temp64.high;
	cmBufferReadUint64(&response.reader, &temp64);	/* available allocation units */
	pInfo->freeClusters.low = temp64.low;
	pInfo->freeClusters.high = temp64.high;
	cmBufferReadUint32(&response.reader, &temp32);	/* sectors per allocation unit */
	pInfo->sectorsPerCluster = (NQ_UINT)temp32;
	cmBufferReadUint32(&response.reader, &temp32);	/* bytes per sectors */
	pInfo->bytesPerSector = (NQ_UINT)temp32;

	/* compose FsVolumeInformation request */
	cmBufManGive(request.buffer);	/* free buffer since we reuse buffer pointer */
	cmBufManGive(response.buffer);	/* free buffer since we reuse buffer pointer */
	res = writeQueryInfoRequest(
		&request, 
		&file, 
		SMB2_INFO_FILESYSTEM, 
		SMB2_FSINFO_VOLUME, 
		MAXINFORESPONSE_SIZE, 
		0
		);
	if (NQ_SUCCESS != res)
	{
		goto Error;
	}
	
	res = pServer->smb->sendReceive(pServer, pShare->user, &request, &response);
	if (NQ_SUCCESS != res)
	{
		goto Error;
	}

	/* parse response */
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT16) + sizeof(NQ_UINT32));
	cmBufferReaderSkip(&response.reader, sizeof(NQ_UINT64));	/* creation time */
	cmBufferReadUint32(&response.reader, &temp32);				/* volume serial number */
	pInfo->serialNumber = (NQ_UINT)temp32;

	pInfo->fsType = 0;	/* MS Servers always return 0 */

Error:
	doClose(&file);

Exit:
	cmBufManGive(request.buffer);
	cmBufManGive(response.buffer);
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", res);
	return res;
}

static NQ_STATUS doSetFileAttributes(CCFile * pFile, NQ_UINT32 attributes)
{
	Request request;		/* request dscriptor */
	Response response;		/* response descriptor */
	CCServer * pServer;		/* server object pointer */
	NQ_STATUS res;			/* exchange result */
	static const NQ_UINT64 doNotChange = 
	{ 0xFFFFFFFF, 0xFFFFFFFF };	/* the "do-not-change" value in the time fields */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "file:%p attr:0x%x", pFile, attributes);

	pServer = pFile->share->user->server;
	request.buffer = NULL;
	response.buffer = NULL;

	/* compose request */
	res = writeSetInfoRequest(
		&request, 
		pFile, 
		SMB2_INFO_FILE, 
		SMB2_FILEINFO_BASIC, 
		0, 
		40		/* basic info size */
		);
	if (NQ_SUCCESS != res)
	{
		goto Exit;
	}
	
	cmBufferWriteUint64(&request.writer, &doNotChange);	/* creation time */
	cmBufferWriteUint64(&request.writer, &doNotChange);	/* last access time */
	cmBufferWriteUint64(&request.writer, &doNotChange);	/* last write time */
	cmBufferWriteUint64(&request.writer, &doNotChange);	/* change time */
	cmBufferWriteUint32(&request.writer, attributes);	/* file attributes */
	cmBufferWriteUint32(&request.writer, 0);			/* reserved */
	request.tail.data = NULL;
	request.tail.len = 0;
	
	res = pServer->smb->sendReceive(pServer, pFile->share->user, &request, &response);

	/* parse response */

Exit:
	cmBufManGive(request.buffer);
	cmBufManGive(response.buffer);
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", res);
	return res;
}

static NQ_STATUS doSetFileSize(CCFile * pFile, NQ_UINT64 size)
{
	Request request;		/* request descriptor */
	Response response;		/* response descriptor */
	CCServer * pServer;		/* server object pointer */
	NQ_STATUS res;			/* exchange result */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "file:%p size(low,high):%u,%u", pFile, size.low, size.high);

	pServer = pFile->share->user->server;

	request.buffer = NULL;
	response.buffer = NULL;

	/* compose request */
	res = writeSetInfoRequest(
		&request, 
		pFile, 
		SMB2_INFO_FILE, 
		SMB2_FILEINFO_EOF, 
		0, 
		8		/* eof info size */
		);
	if (NQ_SUCCESS != res)
	{
		goto Exit;
	}
	
	cmBufferWriteUint64(&request.writer, &size);	/* end of file */
	request.tail.data = NULL;
	request.tail.len = 0;
	
	res = pServer->smb->sendReceive(pServer, pFile->share->user, &request, &response);

	/* parse response */

Exit:
	cmBufManGive(request.buffer);
	cmBufManGive(response.buffer);
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", res);
	return res;
}

static NQ_STATUS doSetFileTime(CCFile * pFile, NQ_UINT64 creationTime, NQ_UINT64 lastAccessTime, NQ_UINT64 lastWriteTime)
{
	Request request;		/* request descriptor */
	Response response;		/* response descriptor */
	CCServer * pServer;		/* server object pointer */
	NQ_STATUS res;			/* exchange result */
	static const NQ_UINT64 doNotChange = 
	{ 0xFFFFFFFF, 0xFFFFFFFF };	/* the "do-not-change" value in the time fields */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "file:%p creationTime(low,high):%u,%u lastAccessTime(low,high):%u,%u lastWriteTime(low,high):%u,%u", pFile, creationTime.low, creationTime.high, lastAccessTime.low, lastAccessTime.high, lastWriteTime.low, lastWriteTime.high);

	pServer = pFile->share->user->server;
	request.buffer = NULL;
	response.buffer = NULL;

	/* compose request */
	res = writeSetInfoRequest(
		&request, 
		pFile, 
		SMB2_INFO_FILE, 
		SMB2_FILEINFO_BASIC, 
		0, 
		40		/* basic info size */
		);
	if (NQ_SUCCESS != res)
	{
		goto Exit;
	}
	
	cmBufferWriteUint64(&request.writer, &creationTime);	/* creation time */
	cmBufferWriteUint64(&request.writer, &lastAccessTime);	/* last access time */
	cmBufferWriteUint64(&request.writer, &lastWriteTime);	/* last write time */
	cmBufferWriteUint64(&request.writer, &doNotChange);		/* change time */
	cmBufferWriteUint32(&request.writer, 0);				/* file attributes */
	cmBufferWriteUint32(&request.writer, 0);				/* reserved */
	request.tail.data = NULL;
	request.tail.len = 0;
	
	res = pServer->smb->sendReceive(pServer, pFile->share->user, &request, &response);

	/* parse response */

Exit:
	cmBufManGive(request.buffer);
	cmBufManGive(response.buffer);
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", res);
	return res;
}

static NQ_STATUS doSetFileDeleteOnClose(CCFile * pFile)
{
	Request request;		/* request descriptor */
	Response response;		/* response descriptor */
	CCServer * pServer;		/* server object pointer */
	NQ_STATUS res;			/* exchange result */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "file:%p", pFile);

	pServer = pFile->share->user->server;
	request.buffer = NULL;
	response.buffer = NULL;

	/* compose request */
	res = writeSetInfoRequest(
		&request, 
		pFile, 
		SMB2_INFO_FILE, 
		SMB2_FILEINFO_DISPOSITION, 
		0, 
		1		/* basic info size */
		);
	if (NQ_SUCCESS != res)
	{
		goto Exit;
	}
	
	cmBufferWriteByte(&request.writer, 1);	/* delete pending */
	request.tail.data = NULL;
	request.tail.len = 0;

	res = pServer->smb->sendReceive(pServer, pFile->share->user, &request, &response);

	/* parse response */

Exit:
	cmBufManGive(request.buffer);
	cmBufManGive(response.buffer);
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", res);
	return res;
}

static NQ_STATUS doRename(CCFile * pFile, const NQ_WCHAR * newName)
{
	Request request;		/* request descriptor */
	Response response;		/* response descriptor */
	CCServer * pServer;		/* server object pointer */
	NQ_STATUS res;			/* exchange result */
	NQ_UINT32 nameLen;		/* name length */
    NQ_UINT32 dataLen;

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "file:%p name:%s", pFile, cmWDump(newName));

	pServer = pFile->share->user->server;
	request.buffer = NULL;
	response.buffer = NULL;

    nameLen = (NQ_UINT32)(sizeof(NQ_WCHAR) * cmWStrlen(newName));
    dataLen = nameLen+20;
    
	/* compose request */
	res = writeSetInfoRequest(
		&request, 
		pFile, 
		SMB2_INFO_FILE, 
		SMB2_FILEINFO_RENAME, 
		0, 
		dataLen		/* info size */
		);
	if (NQ_SUCCESS != res)
	{
		goto Exit;
	}
	
	cmBufferWriteByte(&request.writer, 0);		/* replace exists == false */
	cmBufferWriterSkip(&request.writer, 7);		/* reserved */
	cmBufferWriteZeroes(&request.writer, 8);	/* root directory */
	cmBufferWriteUint32(&request.writer, nameLen);	/* file name length */
	request.tail.data = (NQ_BYTE *)newName;
	request.tail.len = (NQ_COUNT)nameLen;
	
	res = pServer->smb->sendReceive(pServer, pFile->share->user, &request, &response);

	/* parse response */
Exit:
	cmBufManGive(request.buffer);
	cmBufManGive(response.buffer);
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", res);
	return res;
}

static NQ_STATUS doFlush(CCFile * pFile)
{
	Request request;		/* request descriptor */
	Response response;		/* response descriptor */
	CCServer * pServer;		/* server object pointer */
	CCShare * pShare;		/* share object pointer */
	NQ_STATUS res;			/* exchange result */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "file:%p", pFile);

	pShare = pFile->share;
	pServer = pShare->user->server;
	request.buffer = NULL;
	response.buffer = NULL;

	if (!prepareSingleRequestByShare(&request, pShare, SMB2_CMD_FLUSH, 0))
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
		res = NQ_ERR_OUTOFMEMORY;
		goto Exit;
	}
	
	/* compose request */
	writeHeader(&request);
	cmBufferWriteUint16(&request.writer, 0);		/* reserved1 */
	cmBufferWriteUint32(&request.writer, 0);		/* reserved2 */
	cmBufferWriteBytes(&request.writer, pFile->fid, sizeof(pFile->fid));		/* file ID */

	res = pServer->smb->sendReceive(pServer, pFile->share->user, &request, &response);
	if (NQ_SUCCESS != res)
	{
		goto Exit;
	}

	/* parse response - we ignore response parameters */

Exit:
	cmBufManGive(request.buffer);
	cmBufManGive(response.buffer);
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", res);
	return res;
}

static 	NQ_STATUS doRapTransaction(void * pShare, const CMBlob * inData, CMBlob * outParams, CMBlob * outData)
{
    return NQ_ERR_NOSUPPORT;
}


static NQ_STATUS doEcho(CCShare * pShare)
{
    Request     request;
    Response    response;
    CCServer  * pServer;
    CCUser    * pUser;
    NQ_STATUS   res;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "share:%p", pShare);
    
    pUser = pShare->user;
    pServer = pUser->server;
	request.buffer = NULL;
	response.buffer = NULL;

    if (!prepareSingleRequestByShare(&request, pShare, SMB2_CMD_ECHO, 0))
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
		res = NQ_ERR_OUTOFMEMORY;
		goto Exit;
	}

    writeHeader(&request);
    cmBufferWriteUint16(&request.writer, 0);		/* reserved1 */

    res = pServer->smb->sendReceive(pServer, pUser, &request, &response);
    if (NQ_SUCCESS != res)
	{
		goto Exit;
	}

Exit:
    cmBufManGive(request.buffer);
    cmBufManGive(response.buffer);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", res);
    return res;
}

static void keyDerivation(void * user)
{
	return;
}

static void signalAllMatches(void * trans)
{
	CCTransport * 	pTransport = (CCTransport *)trans;
	CCServer * 		pServer = NULL;
	CMIterator		iterator;

	LOGERR(CM_TRC_LEVEL_ERROR, "Signaling all matches");
	pServer = (CCServer *)pTransport->server;
	/* match with request */
	cmListItemTake((CMItem *)pServer);
	cmListIteratorStart(&pServer->expectedResponses, &iterator);
	while (cmListIteratorHasNext(&iterator))
	{
		Match * pMatch;

		pMatch = (Match *)cmListIteratorNext(&iterator);
		if (pMatch->cond != NULL)
			cmThreadCondSignal(pMatch->cond);
		if (pMatch->isResponseAllocated)
        {
			cmMemoryFree(pMatch->response);
            pMatch->response = NULL;
        }
	}
	cmListIteratorTerminate(&iterator);
	if (NULL != pTransport->cleanupCallback)
		(*pTransport->cleanupCallback)(pTransport->cleanupContext);
	cmListItemGive((CMItem *)pServer);
}

/* This function will be used only in ccsmb30*/
NQ_BOOL ccSmb20PrepareSingleRequestByShare(void * pRequest, const void * pShare, NQ_UINT16 command, NQ_UINT32 dataLen)
{
	return prepareSingleRequestByShare((Request *)pRequest, (const CCShare *)pShare, command, dataLen);
}

static void fileInfoResponseParser(CMBufferReader * pReader, CCFileInfo * pInfo, NQ_BYTE level)
{
	switch (level)
	{
		case SMB2_FILEINFO_BASIC:
		{
			/* basic info */
			cmBufferReadUint64(pReader, &pInfo->creationTime);		/* creation time */
			cmBufferReadUint64(pReader, &pInfo->lastAccessTime);	/* last access time */
			cmBufferReadUint64(pReader, &pInfo->lastWriteTime);		/* last write time */
			cmBufferReadUint64(pReader, &pInfo->changeTime);		/* change time */
			cmBufferReadUint32(pReader, &pInfo->attributes);		/* file attributes */
			cmBufferReaderSkip(pReader, 4);							/* reserved */
			break;
		}
		case SMB2_FILEINFO_STANDARD:
		{
			/* standard info */
			cmBufferReadUint64(pReader, &pInfo->allocationSize);	/* file allocation size */
			cmBufferReadUint64(pReader, &pInfo->endOfFile);			/* file size */
			cmBufferReadUint32(pReader, &pInfo->numberOfLinks);		/* number of links */
			break;
		}
		case SMB2_FILEINFO_INTERNAL:
		{
			/* file ID */
			cmBufferReadUint64(pReader, &pInfo->fileIndex);	        /* file ID */
			break;
		}
		default:
			break;
	}
}

static NQ_BOOL validateNegotiate(void *pServ, void *_pUser, void *pShare)
{
	return TRUE;
}

#ifdef UD_NQ_INCLUDESMB311
static NQ_STATUS smb311ReadNegotiateContexts(CMBufferReader *reader, CCServer *pServer, NQ_UINT16 contextCount)
{
	NQ_COUNT numPreauthIntegContext = 0;
	NQ_UINT16 tempUint16;
	NQ_STATUS res;

	/* read context reply */
	for (; contextCount > 0; --contextCount)
	{
		NQ_UINT16 contextType, dataLength;
		cmBufferReadUint16(reader, &contextType);
		cmBufferReadUint16(reader, &dataLength);
		cmBufferReaderSkip(reader, 4);			/* reserved (4) */

		switch (contextType)
		{
			case SMB2_PREAUTH_INTEGRITY_CAPABILITIES:
				{
					NQ_UINT16 	hashAuthAlgorithm, algorithmCount;
					++numPreauthIntegContext;
				

					cmBufferReadUint16(reader, &algorithmCount);
					cmBufferReadUint16(reader, &tempUint16); /* salt length */
					cmBufferReadUint16(reader, &hashAuthAlgorithm);

					if (algorithmCount > 1 || hashAuthAlgorithm != SHA_512)
					{
						/* we should receive one algorithm, out of the algorithms we proposed on our negotiate packet */
						if (algorithmCount > 1)
						{
							LOGERR(CM_TRC_LEVEL_ERROR, "Illegal hash algorithm values. Algorithm count: %d should be 1.", algorithmCount);
						}
						else
						{
							LOGERR(CM_TRC_LEVEL_ERROR, "Illegal hash algorithm values. Expected algorithm: SHA 512. Received: %d.", hashAuthAlgorithm);
						}
						sySetLastError(NQ_ERR_BADPARAM);
						res = NQ_ERR_BADPARAM;
						goto Exit;
					}

					/* skip salt value */
					cmBufferReaderSkip(reader, tempUint16);
				}
				break;
			case SMB2_ENCRYPTION_CAPABILITIES:
			{
				NQ_UINT16 cipher, cipherCount;

				cmBufferReadUint16(reader, &cipherCount);
				cmBufferReadUint16(reader, &cipher);

				if (cipherCount > 1)
				{
					LOGERR(CM_TRC_LEVEL_ERROR, "Illegal number of ciphers in negotiate context: %d. should be 1.", cipherCount);
					sySetLastError(NQ_ERR_BADPARAM);
					res = NQ_ERR_BADPARAM;
					goto Exit;
				}

				if (cipher == CIPHER_AES128GCM)
				{
					pServer->isAesGcm = TRUE;
				}
				else if(cipher == CIPHER_AES128CCM)
				{
					pServer->isAesGcm = FALSE;
				}
				else
				{
					/* no other cipher is supported as of now - 16.02.16 */
					LOGERR(CM_TRC_LEVEL_ERROR, "Received bad cipher in negotiate context: %d.", cipher);
					sySetLastError(NQ_ERR_BADPARAM);
					res = NQ_ERR_BADPARAM;
					goto Exit;
				}
			}
			break;
			default:
			{
				LOGERR(CM_TRC_LEVEL_ERROR, "Received unsupported negotiation context: %d\n", contextType);
			}
		}

		if (contextCount > 1)
			cmBufferReaderAlign(reader, reader->origin, 8); /* next context is 8 byte aligned */
	}

	/* each SMB 3.1.1 request must have exactly one SMB2_PREAUTH_INTEGRITY_CAPABILITIES context */
	if (numPreauthIntegContext != 1)
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "Starting dialect 3.1.1, negotiate should have at least one context of type PREAUTH_INTEGRITY_CAPABILITIES.");
		sySetLastError(NQ_ERR_BADPARAM);
		res = NQ_ERR_BADPARAM;
		goto Exit;
	}

	res = NQ_SUCCESS;

Exit:
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", res);
	return res;
}
#endif /* UD_NQ_INCLUDESMB311 */

#endif /* UD_NQ_INCLUDESMB2 */
#endif /* UD_NQ_INCLUDECIFSCLIENT */
